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

#define FILESERVER_PORT 1113
#define MAX_LINE 65536
#define THREAD_DISPATCH_TIMEOUT 1000

#define NUM_THREADS 3

struct worker {
	pthread_t tid;
	struct event_base *base;
};

static struct worker workers[NUM_THREADS-1];
static struct event_base *accept_base;

void
readcb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input, *output;
	struct worker *w = (struct worker *)ctx;
	char *line;
	size_t n;
	int i;
	char buf[MAX_LINE];

	input = bufferevent_get_input(bev);
//	output = bufferevent_get_output(bev);

//	printf("readcb from %zu thread\n", w->tid);

	while (evbuffer_get_length(input)) {
		int in;

		in = evbuffer_remove(input, buf, sizeof(buf));
		printf("%.*s", in, buf);
//		evbuffer_add(output, buf, n);
	}
//	printf("\n");
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
}

static int to_thread = 0;

static void
do_accept(evutil_socket_t listener, short event, void *arg)
{
	struct event_base *base = arg;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(struct sockaddr_storage);
	int fd;

	printf("got event\n");

	fd = accept(listener, (struct sockaddr*)&ss, &slen);
	printf("accept\n");
	if (fd < 0) {
		fprintf(stderr, "accept error\n");
	} else if (fd > FD_SETSIZE) {
		printf("close fd\n");
		close(fd);
	} else {
		struct bufferevent *bev;

		evutil_make_socket_nonblocking(fd);

		bev = bufferevent_socket_new(workers[to_thread].base, fd,
					     BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
		bufferevent_setcb(bev, readcb, NULL, errorcb, &workers[to_thread]);
		bufferevent_setwatermark(bev, EV_READ, 0, MAX_LINE);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		printf("setup bufferevent to thread %zu\n", workers[to_thread].tid);
		to_thread = (to_thread + 1) % (NUM_THREADS-1);
	}
}

static void *
worker_thread(void *arg)
{
	struct worker *w = (struct worker *)arg;
	int rc = 0;

	printf("start thread %zu\n", w->tid);

	evthread_use_pthreads();
	w->base = event_base_new();
	if (!w->base) {
		fprintf(stderr, "event new error\n");
		rc = -1;
		pthread_exit(&rc);
	}

	evthread_make_base_notifiable(w->base);

	while (event_base_dispatch(w->base) == 1) {
	//	printf("before sleep %zu\n", w->tid);
		usleep(THREAD_DISPATCH_TIMEOUT);
	//	printf("after sleep %zu\n", w->tid);
	}

	event_base_free(w->base);

	printf("finish thread %zu\n", w->tid);
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
	printf("fileserver started\n");
	event_base_dispatch(base);

	accept_base = NULL;
	event_base_free(base);

	close(listener);

	thread_pool_shutdown();

	printf("fileserver stopped\n");
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
