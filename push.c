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
#define CHUNK_SIZE 65536

static int
get_bytes(int sock, void *buf, size_t len)
{
	size_t bytes = 0, rc;

	while (len) {
		rc = recv(sock, (char *)buf + bytes, len, 0);
		if (rc <= 0)
			return rc;
		bytes += rc;
		len -= bytes;
	}

	return bytes;
}

int
main(int argc, char **argv)
{
	int sock;
	struct sockaddr_in server;
	FILE *file;
	char buf[CHUNK_SIZE+1];
	size_t len, off, msg_size;
	char *msg;
	struct sfp_open_rsp open_rsp;
	struct sfp_write_rsp write_rsp;
	msgpack_unpacker pac;
	int rc;

	if (argc < 2) {
		fprintf(stderr, "specify filename\n");
		return -1;
	}

	file = fopen(argv[1], "r");
	if (!file) {
		fprintf(stderr, "can't open file\n");
		return -1;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(FILESERVER_PORT);

	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("connect");
		return -1;
	}

	msg = sfp_create_open_req(argv[1], SFP_OMODE_WRITE, &len);
	if (!msg) {
		perror("malloc");
		return -1;
	}

	if (send(sock, msg, len, 0) <= 0) {
		perror("open req");
		return -1;
	}

	free(msg);

	if (get_bytes(sock, &len, 4) <= 0) {
		perror("open rsp length");
		return -1;
	}

	len = be32toh(len);
//	printf("going to receive %zu bytes\n", len);

	if (len > CHUNK_SIZE) {
		fprintf(stderr, "error: buffer is to big\n");
		return -1;
	}

	if (get_bytes(sock, buf, len) <= 0) {
		perror("open rsp");
		return -1;
	}

	msgpack_unpacker_init(&pac, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacker_reserve_buffer(&pac, len);
	memcpy(msgpack_unpacker_buffer(&pac), buf, len);
	msgpack_unpacker_buffer_consumed(&pac, len);

	if (sfp_unpack_hdr(&pac, &open_rsp.hdr)) {
		fprintf(stderr, "unpack hdr error\n");
		return -1;
	}

	if (sfp_unpack_open_rsp(&pac, &open_rsp)) {
		fprintf(stderr, "unpack open rsp error\n");
		return -1;
	}

	printf("%*.s\n", 4, open_rsp.hdr.proto);
	printf("%u\n", open_rsp.hdr.op);
	printf("%d\n", open_rsp.hdr.status);
	printf("%u\n", open_rsp.fd);

	if (open_rsp.hdr.status != 0) {
		fprintf(stderr, "server can't open file\n");
		return -1;
	}

	off = 0;
	while ((len = fread(buf, 1, CHUNK_SIZE, file)) > 0) {
		msgpack_unpacker_destroy(&pac);
		msgpack_unpacker_init(&pac, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);

		msg = sfp_create_write_req(open_rsp.fd, buf, len, off,
					   &msg_size);
		if (!msg) {
			perror("malloc write req");
			return -1;
		}

		if (send(sock, msg, msg_size, 0) <= 0) {
			perror("write req send");
			return -1;
		}

		free(msg);
		off += len;

		if ((rc = get_bytes(sock, &len, 4)) <= 0) {
			fprintf(stderr, "write rsp length error %d\n", rc);
			return -1;
		}

		len = be32toh(len);

		if (len > CHUNK_SIZE) {
			fprintf(stderr, "error: buffer is to big\n");
			return -1;
		}

		if (recv(sock, buf, len, 0) <= 0) {
			perror("write rsp");
			return -1;
		}

		msgpack_unpacker_reserve_buffer(&pac, len);
		memcpy(msgpack_unpacker_buffer(&pac), buf, len);
		msgpack_unpacker_buffer_consumed(&pac, len);

		if (sfp_unpack_hdr(&pac, &write_rsp.hdr)) {
			fprintf(stderr, "unpack hdr error\n");
			return -1;
		}

		if (sfp_unpack_write_rsp(&pac, &write_rsp)) {
			fprintf(stderr, "unpack write rsp error\n");
			return -1;
		}

		printf("%*.s\n", 4, write_rsp.hdr.proto);
		printf("%u\n", write_rsp.hdr.op);
		printf("%d\n", write_rsp.hdr.status);
	}

	fclose(file);
	close(sock);
	return 0;
}
