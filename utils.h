
#ifndef _UTILS_H_
#define _UTILS_H_

#include "proto.h"

#define errprint_and_clean(sock,file,format,args...) \
	do { \
		if (sock >= 0) \
			close(sock); \
		if (file) \
			fclose(file); \
		fprintf(stderr, "error: "); \
		fprintf(stderr, format, ## args); \
		fprintf(stderr, "\n"); \
	} while(0)

int sfp_open_file(const int sock, char *filename, const int flags,
		  struct sfp_open_rsp *open_rsp);

int sfp_read_file(const int sock, const int fd, const size_t len,
		  const size_t off, struct sfp_read_rsp *read_rsp);

#endif
