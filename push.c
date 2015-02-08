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

#include "utils.h"

#define FILESERVER_PORT 1113
#define PACKED_WSIZE 40

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
	struct sfp_write_rsp write_rsp;
	msgpack_unpacker pac;
	char def_ip[] = "127.0.0.1";
	char *ip = def_ip;
	int port = FILESERVER_PORT;
	int rc;

	if (argc < 2 || argc > 4) {
		fprintf(stderr, "Usage: push FILENAME [IP [PORT]]\n");
		exit(EXIT_FAILURE);
	}

	if (argc > 2)
		ip = argv[2];

	if (argc > 3)
		port = atoi(argv[3]);

	file = fopen(argv[1], "r");
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

	if (sfp_open_file(sock, basename(filename), SFP_OMODE_WRITE, &open_rsp)) {
		errprint_and_clean(sock, file, "can't process open file");
		exit(EXIT_FAILURE);
	}

	free(filename);

	off = 0;
	while ((len = fread(buf, 1, SFP_DATA_SIZE - PACKED_WSIZE, file)) > 0) {
		if (sfp_write_file(sock, open_rsp.fd, len, off, buf, &write_rsp)) {
			errprint_and_clean(sock, file, "can't process write file");
			exit(EXIT_FAILURE);
		}

		off += len;
	}

	close(sock);
	fclose(file);
	exit(EXIT_SUCCESS);
}
