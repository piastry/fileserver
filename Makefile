CC=gcc
SRV_LDFLAGS=-levent -levent_pthreads -lpthread -lmsgpack
CLI_LDFLAGS=-lmsgpack

all: fileserver push

fileserver: fileserver.c
	$(CC) $< -o $@ $(SRV_LDFLAGS)

push: push.c
	$(CC) $< -o $@ $(CLI_LDFLAGS)

clean:
	rm -rf *.o fileserver push
