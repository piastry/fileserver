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

int
main(int argc, char **argv)
{
	int sock = -1;
	struct sockaddr_in server;
	FILE *file = NULL;
	char buf[SFP_DATA_SIZE - PACKED_RSIZE];
	size_t len, off, msg_size;
	char *msg, *filename;
	struct sfp_open_rsp open_rsp;
	struct sfp_read_rsp read_rsp;
	msgpack_unpacker pac;
	char def_ip[] = "127.0.0.1";
	char *ip = def_ip;
	int port = FILESERVER_PORT;
	unsigned char md5[MD5_DIGEST_LENGTH];
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

	msg = sfp_create_open_req(basename(filename), SFP_OMODE_READ, &len);
	if (!msg) {
		free(filename);
		errprint_and_clean(sock, file, "can't create open req");
		exit(EXIT_FAILURE);
	}

	free(filename);

	if (send(sock, msg, len, 0) <= 0) {
		free(msg);
		errprint_and_clean(sock, file, "can't send open req");
		exit(EXIT_FAILURE);
	}

	free(msg);

	if (get_bytes(sock, &len, 4) <= 0) {
		errprint_and_clean(sock, file, "wrong open rsp length");
		exit(EXIT_FAILURE);
	}

	len = be32toh(len);

	if (len > SFP_DATA_SIZE) {
		errprint_and_clean(sock, file, "received buffer is too big");
		exit(EXIT_FAILURE);
	}

	if (get_bytes(sock, buf, len) <= 0) {
		errprint_and_clean(sock, file, "can't receive open rsp");
		exit(EXIT_FAILURE);
	}

	if (sfp_parse_open_rsp(buf, len, &open_rsp)) {
		errprint_and_clean(sock, file, "can't parse open rsp");
		exit(EXIT_FAILURE);
	}

	sfp_log("%*.s\n", 4, open_rsp.hdr.proto);
	sfp_log("%u\n", open_rsp.hdr.op);
	sfp_log("%d\n", open_rsp.hdr.status);
	sfp_log("%u\n", open_rsp.fd);

	if (open_rsp.hdr.status != 0) {
		errprint_and_clean(sock, file, "server can't open file");
		exit(EXIT_FAILURE);
	}

	off = 0;
	do {
		msg = sfp_create_read_req(open_rsp.fd, SFP_DATA_SIZE - PACKED_RSIZE, off, &msg_size);
		if (!msg) {
			errprint_and_clean(sock, file, "can't create read req");
			exit(EXIT_FAILURE);
		}

		if (send(sock, msg, msg_size, 0) <= 0) {
			free(msg);
			errprint_and_clean(sock, file, "can't send read req");
			exit(EXIT_FAILURE);
		}

		free(msg);

		if ((rc = get_bytes(sock, &len, 4)) <= 0) {
			errprint_and_clean(sock, file, "wrong read rsp length");
			exit(EXIT_FAILURE);
		}

		len = be32toh(len);

		if (len > SFP_DATA_SIZE) {
			errprint_and_clean(sock, file, "received buffer is too big");
			exit(EXIT_FAILURE);
		}

		if (get_bytes(sock, buf, len) <= 0) {
			errprint_and_clean(sock, file, "can't receive read rsp");
			exit(EXIT_FAILURE);
		}

		if (sfp_parse_read_rsp(buf, len, &read_rsp)) {
			errprint_and_clean(sock, file, "can't parse read rsp");
			exit(EXIT_FAILURE);
		}

		memcpy(buf, read_rsp.buf, read_rsp.len);
		free(read_rsp.buf);

		MD5(buf, read_rsp.len, md5);
		if (memcmp(read_rsp.md5, md5, MD5_DIGEST_LENGTH)) {
			errprint_and_clean(sock, file, "MD5 checksum mismatches");
			exit(EXIT_FAILURE);
		}

		off += read_rsp.len;
		sfp_log("%*.s\n", 4, read_rsp.hdr.proto);
		sfp_log("%u\n", read_rsp.hdr.op);
		sfp_log("%d\n", read_rsp.hdr.status);
	} while (len = fwrite(buf, 1, read_rsp.len, file));

	close(sock);
	fclose(file);
	exit(EXIT_SUCCESS);
}
