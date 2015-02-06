CC=gcc
SRV_LDFLAGS=-levent -levent_pthreads -lpthread -lmsgpack
CLI_LDFLAGS=-lmsgpack

all: fileserver push

fileserver: fileserver.c proto.o
	$(CC) $< proto.o -o $@ $(SRV_LDFLAGS)

push: push.c proto.o
	$(CC) $< proto.o -o $@ $(CLI_LDFLAGS)

proto.o: proto.c
	$(CC) -c $< -o $@

clean:
	rm -rf *.o fileserver push
