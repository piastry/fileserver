/*
 * The description of the Simple File Protocol.
 */

#include <linux/types.h>
#include <string.h>
#include <endian.h>
#include <msgpack.h>

struct sfp_hdr {
	char proto[4];
	uint32_t status;
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

static int inline
unpacked_destroy_and_exit(msgpack_unpacked *msg, int rc)
{
	msgpack_unpacked_destroy(msg);
	return rc;
}

int sfp_pack_hdr(msgpack_packer *pk, uint8_t op, uint32_t status);
int sfp_unpack_hdr(msgpack_unpacker *pac, struct sfp_hdr *hdr);
int sfp_pack_open_req(msgpack_packer *pk, const char *filename, uint8_t mode);
int sfp_unpack_open_req(msgpack_unpacker *pac, struct sfp_open_req *open_req);
char * sfp_create_open_req(const char *filename, uint8_t mode, size_t *size);
