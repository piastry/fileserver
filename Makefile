CC=gcc
SRV_LDFLAGS=-levent -levent_pthreads -lpthread -lmsgpack -lcrypto
CLI_LDFLAGS=-lmsgpack -lcrypto

all: fileserver push pull

fileserver: fileserver.c proto.o
	$(CC) $< proto.o -o $@ $(SRV_LDFLAGS)

push: push.c proto.o utils.o
	$(CC) $< proto.o utils.o -o $@ $(CLI_LDFLAGS)

pull: pull.c proto.o utils.o
	$(CC) $< proto.o utils.o -o $@ $(CLI_LDFLAGS)

utils.o: utils.c
	$(CC) -c $< -o $@

proto.o: proto.c
	$(CC) -c $< -o $@

clean:
	rm -rf *.o fileserver push pull
