/*
 * The description of the Simple File Protocol.
 */

#include <linux/types.h>

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
