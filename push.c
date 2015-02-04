#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>

#define FILESERVER_PORT 1113
#define CHUNK_SIZE 65536

int
main(int argc, char **argv)
{
	int sock;
	struct sockaddr_in server;
	const char *message = "Hello!\n";
	FILE *file;
	char buf[CHUNK_SIZE+1];
	size_t len;

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
