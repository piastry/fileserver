#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <msgpack.h>

#include "proto.h"

#define msgpack_print(object) \
	do { \
		if (DEBUG) {\
			msgpack_object_print(stdout, object); \
			printf("\n"); \
		} \
	} while (0);

int
sfp_pack_hdr(msgpack_packer *pk, struct sfp_hdr *hdr)
{
	int rc;

	rc = msgpack_pack_raw(pk, 4);
	if (rc)
		return rc;
	rc = msgpack_pack_raw_body(pk, " sfp", 4);
	if (rc)
		return rc;
	rc = msgpack_pack_uint8(pk, hdr->op);
	if (rc)
		return rc;
	return msgpack_pack_int32(pk, hdr->status);
}

int
sfp_unpack_hdr(msgpack_unpacker *pac, struct sfp_hdr *hdr)
{
	msgpack_unpacked msg;
	msgpack_object root;

	msgpack_unpacked_init(&msg);

	/* unpack proto string */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_RAW)
		return unpacked_destroy_and_exit(&msg, -1);
	if (root.via.raw.size != 4)
		return unpacked_destroy_and_exit(&msg, -1);
	if (strncmp(root.via.raw.ptr, " sfp", 4))
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(hdr->proto, root.via.raw.ptr, 4);

	/* unpack operation code */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	hdr->op = (uint8_t)root.via.u64;

	/* unpack status code */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type == MSGPACK_OBJECT_POSITIVE_INTEGER)
		hdr->status = (uint32_t)root.via.u64;
	else if (root.type == MSGPACK_OBJECT_NEGATIVE_INTEGER)
		hdr->status = (int32_t)root.via.i64;
	else
		return unpacked_destroy_and_exit(&msg, -1);

	return unpacked_destroy_and_exit(&msg, 0);
}

int
sfp_pack_open_req(msgpack_packer *pk, void *data)
{
	int rc;
	struct sfp_open_req *open_req = (struct sfp_open_req *)data;
	size_t len = strlen(open_req->filename);

	rc = msgpack_pack_uint8(pk, open_req->mode);
	if (rc)
		return rc;
	rc = msgpack_pack_raw(pk, len);
	if (rc)
		return rc;
	return msgpack_pack_raw_body(pk, open_req->filename, len);
}

int
sfp_unpack_open_req(msgpack_unpacker *pac, struct sfp_open_req *open_req)
{
	msgpack_unpacked msg;
	msgpack_object root;

	msgpack_unpacked_init(&msg);

	/* unpack open mode */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	open_req->mode = (uint8_t)root.via.u64;

	/* unpack filename */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_RAW)
		return unpacked_destroy_and_exit(&msg, -1);
	open_req->filename = malloc(root.via.raw.size + 1);
	if (!open_req->filename)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(open_req->filename, root.via.raw.ptr, root.via.raw.size);
	open_req->filename[root.via.raw.size] = '\0';
	open_req->fnlen = root.via.raw.size;

	return unpacked_destroy_and_exit(&msg, 0);
}

int
sfp_pack_open_rsp(msgpack_packer *pk, void *data)
{
	struct sfp_open_rsp *open_rsp = (struct sfp_open_rsp *)data;

	return msgpack_pack_uint32(pk, open_rsp->fd);
}

int
sfp_unpack_open_rsp(msgpack_unpacker *pac, void *data)
{
	msgpack_unpacked msg;
	msgpack_object root;
	struct sfp_open_rsp *open_rsp = (struct sfp_open_rsp *)data;

	msgpack_unpacked_init(&msg);

	/* unpack fid */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	open_rsp->fd = (uint32_t)root.via.u64;

	return unpacked_destroy_and_exit(&msg, 0);
}

static char *
create_message(void *data, int (*pack_data)(msgpack_packer *, void *),
	       size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	char *output;
	uint32_t *len;
	int rc;

	buffer = msgpack_sbuffer_new();
	if (!buffer)
		return NULL;

	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	if (!pk) {
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	if (sfp_pack_hdr(pk, data)) {
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	if (pack_data(pk, data)) {
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	output = malloc(buffer->size + 4);
	if (!output) {
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	memcpy(output + 4, buffer->data, buffer->size);

	/* store message length as be32*/
	len = (uint32_t *)output;
	*len = htobe32(buffer->size);

	*size = buffer->size + 4;
	msgpack_packer_free(pk);
	msgpack_sbuffer_free(buffer);
	return output;
}

static int
parse_message(const char *buf, const size_t size, const int cmd, void *data,
	      int (*unpack_msg)(msgpack_unpacker *, void *data))
{
	msgpack_unpacker pac;
	struct sfp_hdr *hdr = (struct sfp_hdr *)data;

	msgpack_unpacker_init(&pac, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	msgpack_unpacker_reserve_buffer(&pac, size);
	memcpy(msgpack_unpacker_buffer(&pac), buf, size);
	msgpack_unpacker_buffer_consumed(&pac, size);

	if (sfp_unpack_hdr(&pac, hdr)) {
		msgpack_unpacker_destroy(&pac);
		return -1;
	}

	if (hdr->op != cmd) {
		msgpack_unpacker_destroy(&pac);
		return -1;
	}

	if (unpack_msg(&pac, hdr)) {
		msgpack_unpacker_destroy(&pac);
		return -1;
	}

	msgpack_unpacker_destroy(&pac);
	return 0;
}

int
sfp_parse_open_rsp(const char *buf, const size_t size,
		   struct sfp_open_rsp *open_rsp)
{
	return parse_message(buf, size, SFP_OP_OPEN, open_rsp,
			     sfp_unpack_open_rsp);
}

char *
sfp_create_open_req(char *filename, uint8_t mode, size_t *size)
{
	struct sfp_open_req open_req;

	open_req.filename = filename;
	open_req.mode = mode;
	open_req.hdr.op = SFP_OP_OPEN;
	open_req.hdr.status = 0;

	return create_message(&open_req, sfp_pack_open_req, size);
}

char *
sfp_create_open_rsp(const int fd, size_t *size)
{
	struct sfp_open_rsp open_rsp;

	open_rsp.fd = fd >= 0 ? fd : -1;
	open_rsp.hdr.op = SFP_OP_OPEN;
	open_rsp.hdr.status = fd < 0 ? fd : 0;

	return create_message(&open_rsp, sfp_pack_open_rsp, size);
}

int
sfp_pack_write_req(msgpack_packer *pk, void *data)
{
	int rc;
	struct sfp_write_req *write_req = (struct sfp_write_req *)data;
	unsigned char md5[MD5_DIGEST_LENGTH];

	rc = msgpack_pack_uint32(pk, write_req->fd);
	if (rc)
		return rc;
	rc = msgpack_pack_uint64(pk, write_req->len);
	if (rc)
		return rc;
	rc = msgpack_pack_uint64(pk, write_req->off);
	if (rc)
		return rc;
	MD5(write_req->buf, write_req->len, md5);
	rc = msgpack_pack_raw(pk, MD5_DIGEST_LENGTH);
	if (rc)
		return rc;
	rc = msgpack_pack_raw_body(pk, md5, MD5_DIGEST_LENGTH);
	if (rc)
		return rc;
	rc = msgpack_pack_raw(pk, write_req->len);
	if (rc)
		return rc;
	return msgpack_pack_raw_body(pk, write_req->buf, write_req->len);
}

int
sfp_unpack_write_req(msgpack_unpacker *pac, struct sfp_write_req *write_req)
{
	msgpack_unpacked msg;
	msgpack_object root;

	msgpack_unpacked_init(&msg);

	/* unpack fd */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->fd = (uint32_t)root.via.u64;

	/* unpack length */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->len = (uint64_t)root.via.u64;

	/* unpack offset */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->off = (uint64_t)root.via.u64;

	/* unpack MD5 */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_RAW ||
	    root.via.raw.size != MD5_DIGEST_LENGTH)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(write_req->md5, root.via.raw.ptr, root.via.raw.size);

	/* unpack data */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_RAW ||
	    root.via.raw.size != write_req->len)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->buf = malloc(root.via.raw.size);
	if (!write_req->buf)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(write_req->buf, root.via.raw.ptr, root.via.raw.size);

	return unpacked_destroy_and_exit(&msg, 0);
}

int
sfp_pack_write_rsp(msgpack_packer *pk, void *data)
{
	/* Nothing to do here */
	return 0;
}

int
sfp_unpack_write_rsp(msgpack_unpacker *pac, void *data)
{
	/* Nothing to do here */
	return 0;
}

char *
sfp_create_write_req(const int fd, char *buf, const size_t len,
		     const size_t off, size_t *size)
{
	struct sfp_write_req write_req;

	write_req.fd = fd;
	write_req.buf = buf;
	write_req.len = len;
	write_req.off = off;
	write_req.hdr.op = SFP_OP_WRITE;
	write_req.hdr.status = 0;

	return create_message(&write_req, sfp_pack_write_req, size);
}

char *
sfp_create_write_rsp(const int res, size_t *size)
{
	struct sfp_write_rsp write_rsp;

	write_rsp.hdr.op = SFP_OP_WRITE;
	write_rsp.hdr.status = res >= 0 ? 0 : res;

	return create_message(&write_rsp, sfp_pack_write_rsp, size);
}

int
sfp_parse_write_rsp(const char *buf, const size_t size,
		    struct sfp_write_rsp *write_rsp)
{
	return parse_message(buf, size, SFP_OP_WRITE, write_rsp,
			     sfp_unpack_write_rsp);
}

int
sfp_pack_read_req(msgpack_packer *pk, void *data)
{
	int rc;
	struct sfp_read_req *read_req = (struct sfp_read_req *)data;

	rc = msgpack_pack_uint32(pk, read_req->fd);
	if (rc)
		return rc;
	rc = msgpack_pack_uint64(pk, read_req->len);
	if (rc)
		return rc;
	return msgpack_pack_uint64(pk, read_req->off);
}

int
sfp_unpack_read_req(msgpack_unpacker *pac, struct sfp_read_req *read_req)
{
	msgpack_unpacked msg;
	msgpack_object root;

	msgpack_unpacked_init(&msg);

	/* unpack fd */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	read_req->fd = (uint32_t)root.via.u64;

	/* unpack length */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	read_req->len = (uint64_t)root.via.u64;

	/* unpack offset */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	read_req->off = (uint64_t)root.via.u64;

	return unpacked_destroy_and_exit(&msg, 0);
}

int
sfp_pack_read_rsp(msgpack_packer *pk, void *data)
{
	int rc;
	struct sfp_read_rsp *read_rsp = (struct sfp_read_rsp *)data;
	unsigned char md5[MD5_DIGEST_LENGTH];

	rc = msgpack_pack_uint64(pk, read_rsp->len);
	if (rc)
		return rc;
	MD5(read_rsp->buf, read_rsp->len, md5);
	rc = msgpack_pack_raw(pk, MD5_DIGEST_LENGTH);
	if (rc)
		return rc;
	rc = msgpack_pack_raw_body(pk, md5, MD5_DIGEST_LENGTH);
	if (rc)
		return rc;
	rc = msgpack_pack_raw(pk, read_rsp->len);
	if (rc)
		return rc;
	return msgpack_pack_raw_body(pk, read_rsp->buf, read_rsp->len);
}

int
sfp_unpack_read_rsp(msgpack_unpacker *pac, void *data)
{
	struct sfp_read_rsp *read_rsp = (struct sfp_read_rsp *)data;
	msgpack_unpacked msg;
	msgpack_object root;

	msgpack_unpacked_init(&msg);

	/* unpack length */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	read_rsp->len = (uint64_t)root.via.u64;

	/* unpack MD5 */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_RAW ||
	    root.via.raw.size != MD5_DIGEST_LENGTH)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(read_rsp->md5, root.via.raw.ptr, root.via.raw.size);

	/* unpack data */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_print(root);
	if (root.type != MSGPACK_OBJECT_RAW ||
	    root.via.raw.size != read_rsp->len)
		return unpacked_destroy_and_exit(&msg, -1);
	read_rsp->buf = malloc(root.via.raw.size);
	if (!read_rsp->buf)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(read_rsp->buf, root.via.raw.ptr, root.via.raw.size);

	return unpacked_destroy_and_exit(&msg, 0);
}

char *
sfp_create_read_req(const int fd, const size_t len,
		    const size_t off, size_t *size)
{
	struct sfp_read_req read_req;

	read_req.fd = fd;
	read_req.len = len;
	read_req.off = off;
	read_req.hdr.op = SFP_OP_READ;
	read_req.hdr.status = 0;

	return create_message(&read_req, sfp_pack_read_req, size);
}

char *
sfp_create_read_rsp(const ssize_t res, char *buf, size_t *size)
{
	struct sfp_read_rsp read_rsp;
	char tmpbuf[0];

	read_rsp.hdr.op = SFP_OP_READ;
	read_rsp.hdr.status = res >= 0 ? 0 : res;
	if (!read_rsp.hdr.status) {
		read_rsp.buf = buf;
		read_rsp.len = res;
	} else {
		read_rsp.len = 0;
		read_rsp.buf = tmpbuf;
	}

	return create_message(&read_rsp, sfp_pack_read_rsp, size);
}

int
sfp_parse_read_rsp(const char *buf, const size_t size,
		   struct sfp_read_rsp *read_rsp)
{
	return parse_message(buf, size, SFP_OP_READ, read_rsp,
			     sfp_unpack_read_rsp);
}
