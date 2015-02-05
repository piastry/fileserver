#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>
#include <endian.h>
#include <msgpack.h>

#include "proto.h"

#define FILESERVER_PORT 1113
#define CHUNK_SIZE 65536

static int
pack_hdr(msgpack_packer *pk, uint8_t op, uint32_t status)
{
	int rc;

	rc = msgpack_pack_raw(pk, 4);
	if (rc)
		return rc;
	rc = msgpack_pack_raw_body(pk, " sfp", 4);
	if (rc)
		return rc;
	rc = msgpack_pack_uint8(pk, op);
	if (rc)
		return rc;
	return msgpack_pack_uint32(pk, status);
}

static int
pack_open_req(msgpack_packer *pk, const char *filename, uint8_t mode)
{
	int rc;
	size_t len = strlen(filename);

	rc = pack_hdr(pk, SFP_OP_OPEN, 0);
	if (rc)
		return rc;
	rc = msgpack_pack_uint8(pk, mode);
	if (rc)
		return rc;
	rc = msgpack_pack_raw(pk, len);
	if (rc)
		return rc;
	return msgpack_pack_raw_body(pk, filename, len);
}

static char *
create_open_req(const char *filename, uint8_t mode, size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	size_t len = strlen(filename);
	char *output;
	char *filename_copy;
	uint32_t *req_len;
	int rc;

	buffer = msgpack_sbuffer_new();
	if (!buffer)
		return NULL;

	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	if (!pk) {
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	filename_copy = malloc(len+1);
	if (!filename_copy) {
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	strncpy(filename_copy, filename, len);
	filename_copy[len] = '\0';

	if (pack_open_req(pk, basename(filename_copy), mode)) {
		free(filename_copy);
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	free(filename_copy);

	output = malloc(buffer->size + 4);
	if (!output) {
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	memcpy(output + 4, buffer->data, buffer->size);

	/* store message length as be32*/
	req_len = (uint32_t *)output;
	*req_len = htobe32(buffer->size);

	*size = buffer->size + 4;
	msgpack_packer_free(pk);
	msgpack_sbuffer_free(buffer);
	return output;
}

int
main(int argc, char **argv)
{
	int sock;
	struct sockaddr_in server;
	FILE *file;
	char buf[CHUNK_SIZE+1];
	size_t len;
	char *msg;

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

	msg = create_open_req(argv[1], SFP_OMODE_WRITE, &len);
	if (!msg) {
		perror("malloc");
		return -1;
	}

	if (send(sock, msg, len, 0) <= 0) {
		perror("open req");
		return -1;
	}

	free(msg);

	while ((len = fread(buf, 1, CHUNK_SIZE, file)) > 0) {
		buf[len] = '\0';
		printf("%zu %s\n", len, buf);
		if (send(sock, buf, len, 0) <= 0) {
			perror("send");
			return -1;
		}
	}

	fclose(file);
	close(sock);
	return 0;
}
