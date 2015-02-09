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

#define THREAD_DISPATCH_TIMEOUT 1000

#define DEFAULT_NUM_THREADS 3
#define MAX_THREADS 16

struct worker {
	struct event_base *base;
	char *path;
	pthread_t tid;
};

#define STATE_NEW  0
#define STATE_ALLOC_BUF 1
#define STATE_GOT_MSG 2

struct client {
	struct worker *worker;
	MD5_CTX md5handler;
	unsigned char md5[MD5_DIGEST_LENGTH];
	int file_fd;
	int mode;
	int state;
	char *fname;
	char *buf;
	char *cur;
	size_t buf_size;
	size_t remaining_size;
};

#define SFP_MD5_SUFFIX ".md5"
#define SFP_MD5_SUFFIX_SIZE sizeof(SFP_MD5_SUFFIX)

static int num_threads = DEFAULT_NUM_THREADS;
static struct worker workers[MAX_THREADS - 1];
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
open_file(const char *filename, const uint8_t mode)
{
	int fd, flags = 0;

	if (mode == SFP_OMODE_READ)
		flags |= O_RDONLY;
	else if (mode == SFP_OMODE_WRITE)
		flags |= O_WRONLY | O_TRUNC | O_CREAT;

	fd = open(filename, flags, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0) {
		perror("open file");
		return fd;
	}

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
	size_t size, fnlen;
	char *filename;
	size_t plen = strlen(client->worker->path);

	memcpy(&open_req.hdr, hdr, sizeof(struct sfp_hdr));
	rc = sfp_unpack_open_req(pac, &open_req);
	if (rc)
		return rc;

	fnlen = strlen(open_req.filename);

	filename = malloc(plen + fnlen + 1 + SFP_MD5_SUFFIX_SIZE);
	if (!filename) {
		perror("malloc filename");
		return -1;
	}
	memcpy(filename, client->worker->path, plen);
	memcpy(filename + plen, open_req.filename, fnlen);
	filename[plen + fnlen] = '\0';

	fd = open_file(filename, open_req.mode);
	if (fd >= 0) {
		if (open_req.mode == SFP_OMODE_WRITE)
			MD5_Init(&client->md5handler);
		client->mode = open_req.mode;
		client->file_fd = fd;
		client->fname = filename;
		filename = NULL;
	}

	free(filename);

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
	ssize_t rc;
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

	if (write_req.fd == client->file_fd) {
		rc = write(write_req.fd, write_req.buf, write_req.len);
		MD5_Update(&client->md5handler, write_req.buf, write_req.len);
	} else
		rc = -ESTALE;

	sfp_log("write file client_fd=%d, write_fd=%d, return %zd\n", client->file_fd, write_req.fd, rc);

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

/* parse a read request and send a response */
static int
process_read(msgpack_unpacker *pac, struct sfp_hdr *hdr,
	     struct evbuffer *output, struct client *client)
{
	struct sfp_read_req read_req;
	char *buf, *data;
	size_t size;
	ssize_t rc;

	memcpy(&read_req.hdr, hdr, sizeof(struct sfp_hdr));
	rc = sfp_unpack_read_req(pac, &read_req);
	if (rc)
		return rc;

	data = malloc(read_req.len);
	if (!data) {
		perror("malloc in process_read");
		return -1;
	}

	if (read_req.fd == client->file_fd)
		rc = read(read_req.fd, data, read_req.len);
	else
		rc = -ESTALE;

	sfp_log("read file client_fd=%d, read_fd=%d, return %zd\n", client->file_fd, read_req.fd, rc);

	buf = sfp_create_read_rsp(rc, data, &size);
	if (buf) {
		sfp_log("send read resp\n");
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
		rc = process_read(&pac, &hdr, output, client);
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

static int
store_md5(struct client *client)
{
	int i;
	size_t len = strlen(client->fname);
	FILE *file;

	memcpy(client->fname + len, SFP_MD5_SUFFIX, SFP_MD5_SUFFIX_SIZE);
	client->fname[len + SFP_MD5_SUFFIX_SIZE] = '\0';
	file = fopen(client->fname, "w");
	if (!file) {
		perror("can't create MD5 file");
		return -1;
	}

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		fprintf(file, "%02x", client->md5[i]);

	fprintf(file, "\n");
	fclose(file);
}

static void
free_client(struct client *client)
{
	free(client->buf);
	if (client->file_fd != -1) {
		if (client->mode == SFP_OMODE_WRITE) {
			int i;

			MD5_Final(client->md5, &client->md5handler);
			sfp_log("MD5=");
			for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
				sfp_log("%02x", client->md5[i]);
			}
			sfp_log("\n");
			store_md5(client);
		}
		close(client->file_fd);
		free(client->fname);
	}
	free(client);
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
		fprintf(stderr, "process message error: freeing client\n");
		bufferevent_free(bev);
		free_client(client);
	}
}

static void
errorcb(struct bufferevent *bev, short error, void *arg)
{
	if (error & BEV_EVENT_EOF) {
		/* connection has been closed */
	} else if (error & BEV_EVENT_ERROR) {
		/* check errno */
	} else if (error & BEV_EVENT_TIMEOUT) {
		/* timeout event handle */
	}
	bufferevent_free(bev);
	free_client(arg);
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
		to_thread = (to_thread + 1) % (num_threads-1);
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

	while (event_base_dispatch(w->base) == 1)
		usleep(THREAD_DISPATCH_TIMEOUT);

	event_base_free(w->base);

	sfp_log("finish thread %zu\n", w->tid);
	pthread_exit(&rc);
	return NULL;
}

static int
thread_pool_create(const char *path)
{
	unsigned int i;
	int rc = 0;
	size_t len = strlen(path);

	for (i = 0; i < num_threads - 1; i++) {
		workers[i].path = malloc(len + 1);
		if (!workers[i].path) {
			fprintf(stderr, "thread path malloc error\n");
			return -1;
		}
		memcpy(workers[i].path, path, len);
		workers[i].path[len] = '\0';
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

	for (i = 0; i < num_threads - 1; i++) {
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
fileserver(const char *path, const int port)
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
		return EXIT_FAILURE;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	evthread_make_base_notifiable(base);
	evutil_make_socket_nonblocking(listener);

	if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}

	if (listen(listener, SOMAXCONN) < 0) {
		perror("listen");
		return EXIT_FAILURE;
	}

	if (thread_pool_create(path))
		return EXIT_FAILURE;

	listener_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)base);

	if (!listener_event) {
		perror("event new");
		return EXIT_FAILURE;
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
	return EXIT_SUCCESS;
}

static inline int
isdir(const char *path)
{
	struct stat st;

	if (!stat(path, &st) && (st.st_mode & S_IFDIR))
		return 1;
	return 0;
}

int
main(int argc, char **argv)
{
	pid_t pid;
	char *path = "./", *tofree = NULL;
	int port = SFP_SERVER_PORT;
	int rc;
	size_t len;

	if (argc < 1 || argc > 4) {
		fprintf(stderr, "Usage: fileserver [DIR [PORT [THREADS]]]\n");
		exit(EXIT_FAILURE);
	}

	if (argc > 1) {
		if (!isdir(argv[1])) {
			fprintf(stderr, "error: %s is not a directory\n", argv[1]);
			exit(EXIT_FAILURE);
		}
		len = strlen(argv[1]);
		path = malloc(len + 2);
		if (!path) {
			perror("malloc path");
			exit(EXIT_FAILURE);
		}
		tofree = path;
		memcpy(path, argv[1], len);
		path[len] = '/';
		path[len + 1] = '\0';
	}

	if (argc > 2)
		port = atoi(argv[2]);

	if (argc > 3) {
		num_threads = atoi(argv[3]);
		if (num_threads < 2 || num_threads > 16) {
			fprintf(stderr, "error: wrong number of threads, use between 2 and 16\n");
			exit(EXIT_FAILURE);
		}
	}

	pid = fork();
	if (pid) {
		if (pid > 0)
			exit(EXIT_SUCCESS);
		else {
			fprintf(stderr, "error: can't run fileserver\n");
			exit(EXIT_FAILURE);
		}
	}

	rc = fileserver(path, port);
	free(tofree);
	exit(rc);
}
