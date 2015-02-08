/*
 * The description of the Simple File Protocol.
 */

#ifndef _PROTO_H_
#define _PROTO_H_

#define DEBUG 0

#include <linux/types.h>
#include <string.h>
#include <endian.h>
#include <msgpack.h>
#include <openssl/md5.h>

#ifdef DEBUG
#define sfp_log(format,args...) \
	do { \
		if (DEBUG) \
			printf(format, ## args); \
	} while(0)
#else
#define sfp_log(format,args...) {}
#endif

#define SFP_HEADER_SIZE 4
#define SFP_DATA_SIZE 65532

#define SFP_SERVER_PORT 1115

struct sfp_hdr {
	char proto[4];
	int32_t status;
	uint8_t op;
};

/* SFP operation codes */
#define SFP_OP_OPEN  0
#define SFP_OP_READ  1
#define SFP_OP_WRITE 2
#define SFP_OP_CLOSE 3

struct sfp_open_req {
	struct sfp_hdr hdr;
	uint8_t mode;
	uint32_t fnlen;
	char *filename;
};

/* SFP open modes */
#define SFP_OMODE_READ  0
#define SFP_OMODE_WRITE 1

struct sfp_open_rsp {
	struct sfp_hdr hdr;
	uint32_t fd;
};

struct sfp_write_req {
	struct sfp_hdr hdr;
	uint32_t fd;
	uint64_t len;
	uint64_t off;
	char md5[MD5_DIGEST_LENGTH];
	unsigned char *buf;
};

struct sfp_write_rsp {
	struct sfp_hdr hdr;
	uint64_t len;
};

struct sfp_read_req {
	struct sfp_hdr hdr;
	uint32_t fd;
	uint64_t len;
	uint64_t off;
};

struct sfp_read_rsp {
	struct sfp_hdr hdr;
	uint64_t len;
	char md5[MD5_DIGEST_LENGTH];
	unsigned char *buf;
};

static int inline
unpacked_destroy_and_exit(msgpack_unpacked *msg, int rc)
{
	msgpack_unpacked_destroy(msg);
	return rc;
}

int sfp_pack_hdr(msgpack_packer *pk, struct sfp_hdr *hdr);
int sfp_unpack_hdr(msgpack_unpacker *pac, struct sfp_hdr *hdr);

int sfp_pack_open_req(msgpack_packer *pk, void *data);
int sfp_unpack_open_req(msgpack_unpacker *pac, struct sfp_open_req *open_req);
char * sfp_create_open_req(char *filename, uint8_t mode, size_t *size);

int sfp_pack_open_rsp(msgpack_packer *pk, void *data);
int sfp_unpack_open_rsp(msgpack_unpacker *pac, void *data);
char * sfp_create_open_rsp(const int fd, size_t *size);
int sfp_parse_open_rsp(const char *buf, const size_t size,
		       struct sfp_open_rsp *open_rsp);

int sfp_pack_write_req(msgpack_packer *pk, void *data);
int sfp_unpack_write_req(msgpack_unpacker *pac, struct sfp_write_req *write_req);
char * sfp_create_write_req(const int fd, char *buf, const size_t len,
			    const size_t off, size_t *size);

int sfp_pack_write_rsp(msgpack_packer *pk, void *data);
int sfp_unpack_write_rsp(msgpack_unpacker *pac, void *data);
char * sfp_create_write_rsp(const ssize_t res, size_t *size);
int sfp_parse_write_rsp(const char *buf, const size_t size,
			struct sfp_write_rsp *write_rsp);


int sfp_pack_read_req(msgpack_packer *pk, void *data);
int sfp_unpack_read_req(msgpack_unpacker *pac, struct sfp_read_req *read_req);
char * sfp_create_read_req(const int fd, const size_t len,
			   const size_t off, size_t *size);

int sfp_pack_read_rsp(msgpack_packer *pk, void *data);
int sfp_unpack_read_rsp(msgpack_unpacker *pac, void *data);
char * sfp_create_read_rsp(const ssize_t res, char *buf, size_t *size);
int sfp_parse_read_rsp(const char *buf, const size_t size,
		       struct sfp_read_rsp *read_rsp);

#endif
