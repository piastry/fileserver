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
#include <fcntl.h>
#include <openssl/md5.h>
#include <msgpack.h>

#include "proto.h"

#define FILESERVER_PORT 1113
#define THREAD_DISPATCH_TIMEOUT 1000

#define NUM_THREADS 3

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
open_lock_file(struct sfp_open_req *open_req)
{
	int fd, mode = 0;

	if (open_req->mode == SFP_OMODE_READ)
		mode |= O_RDONLY;
	else if (open_req->mode == SFP_OMODE_WRITE)
		mode |= O_WRONLY | O_TRUNC | O_CREAT;

	fd = open(open_req->filename, mode, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0) {
		perror("open file");
		return fd;
	}

	/* lock file */

	return fd;
}

static void
clear_client_buf(struct client *client)
{
	free(client->buf);
	client->buf = client->cur = NULL;
	client->state = STATE_NEW;
	client->buf_size = client->remaining_size = 0;
}

/* parse an open request and send a response */
static int
process_open(msgpack_unpacker *pac, struct sfp_hdr *hdr,
	     struct evbuffer *output, struct client *client)
{
	struct sfp_open_req open_req;
	int rc, fd;
	char *buf = NULL;
	size_t size;

	memcpy(&open_req.hdr, hdr, sizeof(struct sfp_hdr));
	rc = sfp_unpack_open_req(pac, &open_req);
	if (rc)
		return rc;

	fd = open_lock_file(&open_req);
	if (fd >= 0)
		client->file_fd = fd;

	sfp_log("open file %s, mode=%d: fid=%d\n", open_req.filename, open_req.mode, fd);

	buf = sfp_create_open_rsp(fd, &size);
	if (buf) {
		sfp_log("send open resp %s\n", open_req.filename);
		evbuffer_add(output, buf, size);
	}

	free(buf);
	free(open_req.filename);
	clear_client_buf(client);
	return rc;
}

/* parse a write request and send a response */
static int
process_write(msgpack_unpacker *pac, struct sfp_hdr *hdr,
	     struct evbuffer *output, struct client *client)
{
	struct sfp_write_req write_req;
	char *buf;
	size_t size;
	int rc;
	unsigned char md5[MD5_DIGEST_LENGTH];

	memcpy(&write_req.hdr, hdr, sizeof(struct sfp_hdr));
	rc = sfp_unpack_write_req(pac, &write_req);
	if (rc)
		return rc;

	MD5(write_req.buf, write_req.len, md5);
	if (memcmp(write_req.md5, md5, MD5_DIGEST_LENGTH)) {
		fprintf(stderr, "MD5 checksum mismatches");
		return -1;
	}

	if (write_req.fd == client->file_fd)
		rc = write(write_req.fd, write_req.buf, write_req.len);
	else
		rc = -ESTALE;

	sfp_log("write file client_fd=%d, write_fd=%d, return %d\n", client->file_fd, write_req.fd, rc);

	buf = sfp_create_write_rsp(rc, &size);
	if (buf) {
		sfp_log("send write resp\n");
		evbuffer_add(output, buf, size);
	}
	rc = 0;

	free(buf);
	clear_client_buf(client);
	return rc;
}

/* we have the entire message - unpack it and process */
static int
process_message(struct client *client, struct evbuffer *output)
{
	struct sfp_hdr hdr;
	msgpack_unpacker pac;
	int rc;

	msgpack_unpacker_init(&pac, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacker_reserve_buffer(&pac, client->buf_size);
	memcpy(msgpack_unpacker_buffer(&pac), client->buf, client->buf_size);
	msgpack_unpacker_buffer_consumed(&pac, client->buf_size);

	rc = sfp_unpack_hdr(&pac, &hdr);
	if (rc) {
		sfp_log("unpack hdr error\n");
		msgpack_unpacker_destroy(&pac);
		return rc;
	}

	switch (hdr.op) {
	case SFP_OP_OPEN:
		rc = process_open(&pac, &hdr, output, client);
		break;
	case SFP_OP_READ:
		break;
	case SFP_OP_WRITE:
		rc = process_write(&pac, &hdr, output, client);
		break;
	case SFP_OP_CLOSE:
		break;
	dafault:
		break;
	}

	msgpack_unpacker_destroy(&pac);
	return rc;
}

static int
process_state_new(struct evbuffer *input, struct client *client)
{
	size_t len = evbuffer_get_length(input);
	uint32_t req_len_be32;

	if (len < SFP_HEADER_SIZE) {
		fprintf(stderr, "evbuffer lenght less than %u\n",
			SFP_HEADER_SIZE);
		return -1;
	}

	len = evbuffer_remove(input, &req_len_be32, SFP_HEADER_SIZE);
	if (len != SFP_HEADER_SIZE) {
		fprintf(stderr, "can't read %u bytes from the buffer\n",
			SFP_HEADER_SIZE);
		return -1;
	}

	client->buf_size = be32toh(req_len_be32);
	sfp_log("buf_size=%zu\n", client->buf_size);
	if (client->buf_size > SFP_DATA_SIZE) {
		fprintf(stderr, "too big request %zu\n", client->buf_size);
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
	sfp_log("%.*s\n", (int)len, client->cur);
	client->remaining_size -= len;
	client->cur += len;

	if (client->remaining_size == 0) {
		/* got full msg */
		client->state = STATE_GOT_MSG;
	}
	return 0;
}

static void
discard_remaining(struct evbuffer *input)
{
	char buf[1024];
	size_t len;

	while (evbuffer_get_length(input))
		len = evbuffer_remove(input, buf, sizeof(buf));
}

static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input, *output;
	struct client *client = (struct client *)ctx;
	int rc = 0;

	input = bufferevent_get_input(bev);
	output = bufferevent_get_output(bev);

	sfp_log("readcb from %zu thread size=%zu\n", client->worker->tid, evbuffer_get_length(input));

	while (evbuffer_get_length(input) && !rc) {
		switch (client->state) {
		case STATE_NEW:
			rc = process_state_new(input, client);
			break;
		case STATE_ALLOC_BUF:
			rc = process_state_ab(input, client);
			if (!rc && client->state == STATE_GOT_MSG)
				rc = process_message(client, output);
			break;
		case STATE_GOT_MSG:
			discard_remaining(input);
			break;
		default:
			break;
		}
	}

	if (rc) {
		fprintf(stderr, "freeing client\n");
		bufferevent_free(bev);
		free(client->buf);
		if (client->file_fd != -1)
			close(client->file_fd);
		free(client);
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

	sfp_log("got event\n");

	fd = accept(listener, (struct sockaddr*)&ss, &slen);
	sfp_log("accept\n");
	if (fd < 0) {
		perror("accept return -1");
	} else if (fd > FD_SETSIZE) {
		sfp_log("close fd\n");
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
		bufferevent_setwatermark(bev, EV_READ, SFP_HEADER_SIZE, SFP_DATA_SIZE);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
		sfp_log("setup bufferevent to thread %zu\n", workers[to_thread].tid);
		to_thread = (to_thread + 1) % (NUM_THREADS-1);
	}
}

static void *
worker_thread(void *arg)
{
	struct worker *w = (struct worker *)arg;
	int rc = 0;

	sfp_log("start thread %zu\n", w->tid);

	evthread_use_pthreads();
	w->base = event_base_new();
	if (!w->base) {
		fprintf(stderr, "event new error\n");
		rc = -1;
		pthread_exit(&rc);
	}

	evthread_make_base_notifiable(w->base);

	while (event_base_dispatch(w->base) == 1) {
	//	sfp_log("before sleep %zu\n", w->tid);
		usleep(THREAD_DISPATCH_TIMEOUT);
	//	sfp_log("after sleep %zu\n", w->tid);
	}

	event_base_free(w->base);

	sfp_log("finish thread %zu\n", w->tid);
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
	sfp_log("fileserver started\n");
	event_base_dispatch(base);

	accept_base = NULL;
	event_base_free(base);

	close(listener);

	thread_pool_shutdown();

	sfp_log("fileserver stopped\n");
	return 0;
}

int
main(void)
{
	pid_t pid;

//	pid = fork();
//	if (pid) {
//		sfp_log("parent process\n");
//		return 0;
//	}

//	sfp_log("child process\n");
	return fileserver();
}
