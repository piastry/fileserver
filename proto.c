#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <msgpack.h>

#include "proto.h"

int
sfp_pack_hdr(msgpack_packer *pk, uint8_t op, int32_t status)
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
	return msgpack_pack_int32(pk, status);
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
	msgpack_object_print(stdout, root);
	printf("\n");
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
	msgpack_object_print(stdout, root);
	printf("\n");
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	hdr->op = (uint8_t)root.via.u64;

	/* unpack status code */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
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

	rc = sfp_pack_hdr(pk, SFP_OP_OPEN, 0);
	if (rc)
		return rc;
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
	msgpack_object_print(stdout, root);
	printf("\n");
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	open_req->mode = (uint8_t)root.via.u64;

	/* unpack filename */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
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
	int rc;
	struct sfp_open_rsp *open_rsp = (struct sfp_open_rsp *)data;

	rc = sfp_pack_hdr(pk, SFP_OP_OPEN, open_rsp->hdr.status);
	if (rc)
		return rc;
	return msgpack_pack_uint32(pk, open_rsp->fd);
}

int
sfp_unpack_open_rsp(msgpack_unpacker *pac, struct sfp_open_rsp *open_rsp)
{
	msgpack_unpacked msg;
	msgpack_object root;

	msgpack_unpacked_init(&msg);

	/* unpack fid */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
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

char *
sfp_create_open_req(char *filename, uint8_t mode, size_t *size)
{
	struct sfp_open_req open_req;

	open_req.filename = filename;
	open_req.mode = mode;

	return create_message(&open_req, sfp_pack_open_req, size);
}

char *
sfp_create_open_rsp(const int fd, size_t *size)
{
	struct sfp_open_rsp open_rsp;

	open_rsp.fd = fd >= 0 ? fd : -1;
	open_rsp.hdr.status = fd < 0 ? fd : 0;

	return create_message(&open_rsp, sfp_pack_open_rsp, size);
}

int
sfp_pack_write_req(msgpack_packer *pk, void *data)
{
	int rc;
	struct sfp_write_req *write_req = (struct sfp_write_req *)data;
	unsigned char md5[MD5_DIGEST_LENGTH];

	rc = sfp_pack_hdr(pk, SFP_OP_WRITE, 0);
	if (rc)
		return rc;
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
	msgpack_object_print(stdout, root);
	printf("\n");
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->fd = (uint32_t)root.via.u64;

	/* unpack length */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->len = (uint64_t)root.via.u64;

	/* unpack offset */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	write_req->off = (uint64_t)root.via.u64;

	/* unpack MD5 */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
	if (root.type != MSGPACK_OBJECT_RAW ||
	    root.via.raw.size != MD5_DIGEST_LENGTH)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(write_req->md5, root.via.raw.ptr, root.via.raw.size);

	/* unpack data */
	if (!msgpack_unpacker_next(pac, &msg))
		return unpacked_destroy_and_exit(&msg, -1);
	root = msg.data;
	msgpack_object_print(stdout, root);
	printf("\n");
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
sfp_pack_write_rsp(msgpack_packer *pk, const int32_t status)
{
	return sfp_pack_hdr(pk, SFP_OP_WRITE, status);
}

int
sfp_unpack_write_rsp(msgpack_unpacker *pac, struct sfp_write_rsp *write_rsp)
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

	return create_message(&write_req, sfp_pack_write_req, size);
}

char *
sfp_create_write_rsp(const int res, size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	char *output;
	uint32_t *rsp_len;
	int rc;

	buffer = msgpack_sbuffer_new();
	if (!buffer)
		return NULL;

	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	if (!pk) {
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	if (sfp_pack_write_rsp(pk, res >= 0 ? 0 : res)) {
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
	rsp_len = (uint32_t *)output;
	*rsp_len = htobe32(buffer->size);

	*size = buffer->size + 4;
	msgpack_packer_free(pk);
	msgpack_sbuffer_free(buffer);
	return output;
}
