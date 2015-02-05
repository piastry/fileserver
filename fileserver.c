#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <endian.h>

#define FILESERVER_PORT 1113
#define MAX_LINE 65536
#define MIN_LINE 4
#define THREAD_DISPATCH_TIMEOUT 1000

#define NUM_THREADS 3

#define DEBUG 1

struct worker {
	pthread_t tid;
	struct event_base *base;
};

#define STATE_NEW  0
#define STATE_ALLOC_BUF 1
#define STATE_GOT_MSG 2

struct client {
	struct worker *worker;
	int file_fd;
	int state;
	char *buf;
	char *cur;
	size_t buf_size;
	size_t remaining_size;
};

static struct worker workers[NUM_THREADS-1];
static struct event_base *accept_base;

#define log(format,args...) \
	do { \
		if (DEBUG) \
			printf(format, ## args); \
	} while(0)

static struct client *
client_init(struct worker *worker)
{
	struct client *client;

	client = malloc(sizeof(struct client));
	if (!client) {
		perror("client malloc");
		return NULL;
	}

	memset(client, 0, sizeof(struct client));

	client->worker = worker;
	client->file_fd = -1;
	return client;
}

static int
process_state_new(struct evbuffer *input, struct client *client)
{
	size_t len = evbuffer_get_length(input);
	uint32_t req_len_be32;

	if (len < MIN_LINE) {
		fprintf(stderr, "evbuffer lenght less than %u\n", MIN_LINE);
		return -1;
	}

	len = evbuffer_remove(input, &req_len_be32, MIN_LINE);
	if (len != MIN_LINE) {
		fprintf(stderr, "can't read %u bytes from the buffer\n", MIN_LINE);
		return -1;
	}

	client->buf_size = be32toh(req_len_be32);
	log("buf_size=%zu\n", client->buf_size);
	if (client->buf_size > MAX_LINE) {
		fprintf(stderr, "too big request\n");
		return -1;
	}

	client->buf = malloc(client->buf_size);
	if (!client->buf) {
		perror("client buf malloc");
		return -1;
	}

	client->cur = client->buf;
	client->remaining_size = client->buf_size;
	client->state = STATE_ALLOC_BUF;
	return 0;
}

static int
process_state_ab(struct evbuffer *input, struct client *client)
{
	size_t len = evbuffer_get_length(input);

	len = evbuffer_remove(input, client->cur, client->remaining_size);
	log("%.*s\n", (int)len, client->cur);
	client->remaining_size -= len;
	client->cur += len;

	if (client->remaining_size == 0) {
		/* got full msg */
		client->state = STATE_GOT_MSG;
	}
	return 0;
}

static int
discard_remaining(struct evbuffer *input)
{
	char buf[1024];
	size_t len;

	while (evbuffer_get_length(input))
		len = evbuffer_remove(input, buf, sizeof(buf));

	return 0;
}

static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input, *output;
	struct client *client = (struct client *)ctx;
	int rc = 0;

	input = bufferevent_get_input(bev);
//	output = bufferevent_get_output(bev);

	log("readcb from %zu thread\n", client->worker->tid);

	while (evbuffer_get_length(input) && !rc) {
		switch (client->state) {
		case STATE_NEW:
			rc = process_state_new(input, client);
			break;
		case STATE_ALLOC_BUF:
			rc = process_state_ab(input, client);
			break;
		case STATE_GOT_MSG:
			rc = discard_remaining(input);
			break;
		default:
			break;
		}
	}

	if (rc) {
		fprintf(stderr, "freeing client\n");
		bufferevent_free(bev);
		free(ctx);
	}
//	evbuffer_add(output, "\n", 1);
}

static void
errorcb(struct bufferevent *bev, short error, void *ctx)
{
	if (error & BEV_EVENT_EOF) {
		/* connection has been closed, do any clean up here */
		/* ... */
	} else if (error & BEV_EVENT_ERROR) {
		/* check errno to see what error occurred */
		/* ... */
	} else if (error & BEV_EVENT_TIMEOUT) {
		/* must be a timeout event handle, handle it */
		/* ... */
	}
	bufferevent_free(bev);
	free(ctx);
}

static int to_thread = 0;

static void
do_accept(evutil_socket_t listener, short event, void *arg)
{
	struct event_base *base = arg;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(struct sockaddr_storage);
	int fd;

	log("got event\n");

	fd = accept(listener, (struct sockaddr*)&ss, &slen);
	log("accept\n");
	if (fd < 0) {
		fprintf(stderr, "accept error\n");
	} else if (fd > FD_SETSIZE) {
		log("close fd\n");
		close(fd);
	} else {
		struct bufferevent *bev;
		struct client *client;

		client = client_init(&workers[to_thread]);
		if (!client) {
			perror("client init");
			close(fd);
			return;
		}

		evutil_make_socket_nonblocking(fd);

		bev = bufferevent_socket_new(workers[to_thread].base, fd,
					     BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
		if (!bev) {
			perror("buffer socket new");
			close(fd);
			free(client);
			return;
		}
		bufferevent_setcb(bev, readcb, NULL, errorcb, client);
		bufferevent_setwatermark(bev, EV_READ, MIN_LINE, MAX_LINE);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		log("setup bufferevent to thread %zu\n", workers[to_thread].tid);
		to_thread = (to_thread + 1) % (NUM_THREADS-1);
	}
}

static void *
worker_thread(void *arg)
{
	struct worker *w = (struct worker *)arg;
	int rc = 0;

	log("start thread %zu\n", w->tid);

	evthread_use_pthreads();
	w->base = event_base_new();
	if (!w->base) {
		fprintf(stderr, "event new error\n");
		rc = -1;
		pthread_exit(&rc);
	}

	evthread_make_base_notifiable(w->base);

	while (event_base_dispatch(w->base) == 1) {
	//	log("before sleep %zu\n", w->tid);
		usleep(THREAD_DISPATCH_TIMEOUT);
	//	log("after sleep %zu\n", w->tid);
	}

	event_base_free(w->base);

	log("finish thread %zu\n", w->tid);
	pthread_exit(&rc);
	return NULL;
}

static int
thread_pool_create(void)
{
	unsigned int i;
	int rc = 0;

	for (i = 0; i < NUM_THREADS-1; i++) {
		rc = pthread_create(&workers[i].tid, NULL, worker_thread, &workers[i]);
		if (rc) {
			fprintf(stderr, "thread create error %zu\n", workers[i].tid);
			return rc;
		}
	}
	return rc;
}

static void
thread_pool_shutdown(void)
{
	unsigned int i;
	int rc = 0, *retval;

	for (i = 0; i < NUM_THREADS-1; i++) {
		rc = event_base_loopexit(workers[i].base, NULL);
		if (rc) {
			fprintf(stderr, "thread shutting error %zu\n", workers[i].tid);
			continue;
		}
		rc = pthread_join(workers[i].tid, (void **)&retval);
		if (rc)
			fprintf(stderr, "thread join error %zu\n", workers[i].tid);
	}
}

static void
sighandler(int signal)
{
	if (event_base_loopexit(accept_base, NULL))
		perror("shutting down server error");
}

static int
fileserver(void)
{
	evutil_socket_t listener;
	struct sockaddr_in sin;
	struct event_base *base;
	struct event *listener_event;
	sigset_t sigset;
	struct sigaction siginfo = {
		.sa_handler = sighandler,
		.sa_mask = sigset,
		.sa_flags = SA_RESTART,
	};

	sigemptyset(&sigset);
	sigaction(SIGINT, &siginfo, NULL);
	sigaction(SIGTERM, &siginfo, NULL);

	evthread_use_pthreads();

	base = event_base_new();
	if (!base) {
		perror("event new");
		return 1;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(FILESERVER_PORT);

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		perror("socket");
		return 1;
	}

	evthread_make_base_notifiable(base);
	evutil_make_socket_nonblocking(listener);

	if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		perror("bind");
		return 1;
	}

	if (listen(listener, SOMAXCONN) < 0) {
		perror("listen");
		return 1;
	}

	if (thread_pool_create())
		return 1;

	listener_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)base);

	if (!listener_event) {
		perror("event new");
		return 1;
	}

	event_add(listener_event, NULL);

	accept_base = base;
	log("fileserver started\n");
	event_base_dispatch(base);

	accept_base = NULL;
	event_base_free(base);

	close(listener);

	thread_pool_shutdown();

	log("fileserver stopped\n");
	return 0;
}

int
main(void)
{
	pid_t pid;

//	pid = fork();
//	if (pid) {
//		printf("parent process\n");
//		return 0;
//	}

	printf("child process\n");
	return fileserver();
}
