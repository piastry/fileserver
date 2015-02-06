#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <msgpack.h>
#include <libgen.h>

#include "proto.h"

int
sfp_pack_hdr(msgpack_packer *pk, uint8_t op, uint32_t status)
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
	return msgpack_pack_uint32(pk, status);
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
	if (root.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return unpacked_destroy_and_exit(&msg, -1);
	hdr->status = (uint32_t)root.via.u64;

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
	open_req->filename = malloc(root.via.raw.size);
	if (!open_req->filename)
		return unpacked_destroy_and_exit(&msg, -1);
	memcpy(open_req->filename, root.via.raw.ptr, root.via.raw.size);
	open_req->fnlen = root.via.raw.size;

	return unpacked_destroy_and_exit(&msg, 0);
}

char *
sfp_create_open_req(const char *filename, uint8_t mode, size_t *size)
{
	msgpack_sbuffer *buffer;
	msgpack_packer *pk;
	size_t len = strlen(filename);
	char *output;
	char *filename_copy;
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

	filename_copy = malloc(len+1);
	if (!filename_copy) {
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	strncpy(filename_copy, filename, len);
	filename_copy[len] = '\0';

	if (sfp_pack_open_req(pk, basename(filename_copy), mode)) {
		free(filename_copy);
		msgpack_packer_free(pk);
		msgpack_sbuffer_free(buffer);
		return NULL;
	}

	free(filename_copy);

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

