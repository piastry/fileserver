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
sfp_pack_open_req(msgpack_packer *pk, const char *filename, uint8_t mode)
{
	int rc;
	size_t len = strlen(filename);

	rc = sfp_pack_hdr(pk, SFP_OP_OPEN, 0);
	if (rc)
		return rc;
	rc = msgpack_pack_uint8(pk, mode);
	if (rc)
		return rc;
	rc = msgpack_pack_raw(pk, len);
	if (rc)
		return rc;
	return msgpack_pack_raw_body(pk, filename, len);
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
sfp_pack_open_rsp(msgpack_packer *pk, const uint32_t fd, const int32_t status)
{
	int rc;

	rc = sfp_pack_hdr(pk, SFP_OP_OPEN, status);
	if (rc)
		return rc;
	return msgpack_pack_uint32(pk, fd);
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

char *
sfp_create_open_req(const char *filename, uint8_t mode, size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	char *output;
	uint32_t *req_len;
	int rc;

	buffer = msgpack_sbuffer_new();
	if (!buffer)
		return NULL;

	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	if (!pk) {
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	if (sfp_pack_open_req(pk, filename, mode)) {
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
	req_len = (uint32_t *)output;
	*req_len = htobe32(buffer->size);

	*size = buffer->size + 4;
	msgpack_packer_free(pk);
	msgpack_sbuffer_free(buffer);
	return output;
}

char *
sfp_create_open_rsp(const int fd, size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	char *output;
	uint32_t *rsp_len;

	buffer = msgpack_sbuffer_new();
	if (!buffer)
		return NULL;

	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	if (!pk) {
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	if (sfp_pack_open_rsp(pk, fd >= 0 ? fd : -1, fd < 0 ? fd : 0)) {
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

int
sfp_pack_write_req(msgpack_packer *pk, const int fd, const uint64_t len,
		   const uint64_t off, const char *buf)
{
	int rc;
	unsigned char md5[MD5_DIGEST_LENGTH];

	rc = sfp_pack_hdr(pk, SFP_OP_WRITE, 0);
	if (rc)
		return rc;
	rc = msgpack_pack_uint32(pk, fd);
	if (rc)
		return rc;
	rc = msgpack_pack_uint64(pk, len);
	if (rc)
		return rc;
	rc = msgpack_pack_uint64(pk, off);
	if (rc)
		return rc;
	MD5(buf, len, md5);
	rc = msgpack_pack_raw(pk, MD5_DIGEST_LENGTH);
	if (rc)
		return rc;
	rc = msgpack_pack_raw_body(pk, md5, MD5_DIGEST_LENGTH);
	if (rc)
		return rc;
	rc = msgpack_pack_raw(pk, len);
	if (rc)
		return rc;
	return msgpack_pack_raw_body(pk, buf, len);
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
sfp_create_write_req(const int fd, const char *buf, const size_t len,
		     const size_t off, size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	char *output;
	uint32_t *req_len;
	int rc;

	buffer = msgpack_sbuffer_new();
	if (!buffer)
		return NULL;

	pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
	if (!pk) {
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	if (sfp_pack_write_req(pk, fd, len, off, buf)) {
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
	req_len = (uint32_t *)output;
	*req_len = htobe32(buffer->size);

	*size = buffer->size + 4;
	msgpack_packer_free(pk);
	msgpack_sbuffer_free(buffer);
	return output;
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
