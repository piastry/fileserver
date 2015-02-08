#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <libgen.h>
#include <msgpack.h>

#include "proto.h"

#define FILESERVER_PORT 1113
#define PACKED_RSIZE 40

static int
get_bytes(int sock, void *buf, size_t len)
{
	size_t bytes = 0, rc;

	while (len) {
		rc = recv(sock, (char *)buf + bytes, len, 0);
		if (rc <= 0)
			return rc;
		bytes += rc;
		len -= rc;
	}

	return bytes;
}

#define errprint_and_clean(sock,file,format,args...) \
	do { \
		if (sock >= 0) \
			close(sock); \
		if (file) \
			fclose(file); \
		fprintf(stderr, "error: "); \
		fprintf(stderr, format, ## args); \
		fprintf(stderr, "\n"); \
	} while(0)

static char *
sfp_get_resp(const int sock, size_t *len)
{
	char *buf;

	if (get_bytes(sock, len, 4) <= 0) {
		fprintf(stderr, "wrong rsp length\n");
		return NULL;
	}

	*len = be32toh(*len);

	if (*len > SFP_DATA_SIZE) {
		fprintf(stderr, "received buffer is too big\n");
		return NULL;
	}

	buf = malloc(*len);
	if (!buf) {
		fprintf(stderr, "can't malloc buffer\n");
		return NULL;
	}

	if (get_bytes(sock, buf, *len) <= 0) {
		free(buf);
		fprintf(stderr, "can't receive rsp\n");
		return NULL;
	}

	return buf;
}

int
sfp_open_file(const int sock, char *filename, const int flags,
	      struct sfp_open_rsp *open_rsp)
{
	char *msg;
	size_t msg_size;
	char *buf;

	msg = sfp_create_open_req(filename, flags, &msg_size);
	if (!msg)
		return -1;

	if (send(sock, msg, msg_size, 0) <= 0) {
		free(msg);
		fprintf(stderr, "can't send open request\n");
		return -1;
	}

	free(msg);

	msg = sfp_get_resp(sock, &msg_size);
	if (!msg)
		return -1;

	if (sfp_parse_open_rsp(msg, msg_size, open_rsp)) {
		free(msg);
		fprintf(stderr, "can't parse open rsp\n");
		return -1;
	}

	free(msg);

	sfp_log("%*.s\n", 4, open_rsp->hdr.proto);
	sfp_log("%u\n", open_rsp->hdr.op);
	sfp_log("%d\n", open_rsp->hdr.status);
	sfp_log("%u\n", open_rsp->fd);

	if (open_rsp->hdr.status != 0) {
		fprintf(stderr, "server can't open file\n");
		return -1;
	}

	return 0;
}

int
sfp_read_file(const int sock, const int fd, const size_t len, const size_t off,
	      struct sfp_read_rsp *read_rsp)
{
	char *msg;
	size_t msg_size;
	unsigned char md5[MD5_DIGEST_LENGTH];

	msg = sfp_create_read_req(fd, len, off, &msg_size);
	if (!msg) {
		fprintf(stderr, "can't create read req\n");
		return -1;
	}

	if (send(sock, msg, msg_size, 0) <= 0) {
		free(msg);
		fprintf(stderr, "can't send read request\n");
		return -1;
	}

	free(msg);

	msg = sfp_get_resp(sock, &msg_size);
	if (!msg)
		return -1;

	if (sfp_parse_read_rsp(msg, msg_size, read_rsp)) {
		free(msg);
		fprintf(stderr, "can't parse read rsp\n");
		return -1;
	}

	free(msg);

	MD5(read_rsp->buf, read_rsp->len, md5);
	if (memcmp(read_rsp->md5, md5, MD5_DIGEST_LENGTH)) {
		fprintf(stderr, "MD5 checksum mismatches\n");
		return -1;
	}

	sfp_log("%*.s\n", 4, read_rsp->hdr.proto);
	sfp_log("%u\n", read_rsp->hdr.op);
	sfp_log("%d\n", read_rsp->hdr.status);

	return 0;
}

int
main(int argc, char **argv)
{
	int sock = -1;
	struct sockaddr_in server;
	FILE *file = NULL;
	char buf[SFP_DATA_SIZE];
	size_t len, off, msg_size;
	char *msg, *filename;
	struct sfp_open_rsp open_rsp;
	struct sfp_read_rsp read_rsp;
	msgpack_unpacker pac;
	char def_ip[] = "127.0.0.1";
	char *ip = def_ip;
	int port = FILESERVER_PORT;
	int rc;

	if (argc < 2 || argc > 4) {
		fprintf(stderr, "Usage: pull FILENAME [IP [PORT]]\n");
		exit(EXIT_FAILURE);
	}

	if (argc > 2)
		ip = argv[2];

	if (argc > 3)
		port = atoi(argv[3]);

	file = fopen(argv[1], "w");
	if (!file) {
		fprintf(stderr, "can't open file\n");
		exit(EXIT_FAILURE);
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		errprint_and_clean(sock, file, "can't create socket");
		exit(EXIT_FAILURE);
	}

	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		errprint_and_clean(sock, file, "can't connect to the remote server");
		exit(EXIT_FAILURE);
	}

	len = strlen(argv[1]);
	filename = malloc(len + 1);
	if (!filename) {
		errprint_and_clean(sock, file, "out of memory");
		exit(EXIT_FAILURE);
	}

	strncpy(filename, argv[1], len);
	filename[len] = '\0';

	if (sfp_open_file(sock, basename(filename), SFP_OMODE_READ, &open_rsp)) {
		errprint_and_clean(sock, file, "can't process open file");
		exit(EXIT_FAILURE);
	}

	free(filename);

	off = 0;
	do {
		if (sfp_read_file(sock, open_rsp.fd,
				SFP_DATA_SIZE - PACKED_RSIZE, off, &read_rsp)) {
			errprint_and_clean(sock, file, "can't process read file");
			exit(EXIT_FAILURE);
		}

		memcpy(buf, read_rsp.buf, read_rsp.len);
		free(read_rsp.buf);

		off += read_rsp.len;
	} while (len = fwrite(buf, 1, read_rsp.len, file));

	close(sock);
	fclose(file);
	exit(EXIT_SUCCESS);
}
