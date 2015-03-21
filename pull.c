#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>

#include "utils.h"

#define FILESERVER_PORT 1113
#define PACKED_RSIZE 50

int
main(int argc, char **argv)
{
	int sock = -1;
	struct sockaddr_in server;
	FILE *file = NULL;
	char buf[SFP_DATA_SIZE];
	size_t off;
	ssize_t len;
	char *filename;
	struct sfp_open_rsp open_rsp;
	struct sfp_read_rsp read_rsp;
	char def_ip[] = "127.0.0.1";
	char *ip = def_ip;
	int port = SFP_SERVER_PORT;
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
	} while ((len = fwrite(buf, 1, read_rsp.len, file)) > 0);

	close(sock);
	fclose(file);

	if (len < 0) {
		fprintf(stderr, "error: can't write to the file\n");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
