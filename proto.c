#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <msgpack.h>

#include "proto.h"

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

