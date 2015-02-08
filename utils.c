#include <sys/socket.h>
#include <string.h>
#include <endian.h>

#include "proto.h"

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

static char *
get_resp(const int sock, size_t *len)
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

	msg = get_resp(sock, &msg_size);
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

	msg = get_resp(sock, &msg_size);
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

