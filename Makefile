CC=gcc
CFLAGS=-Wall -std=c99
LDFLAGS=-lcrypto
SOURCES=pkg_dec.c
EXECUTABLE=pkg_dec
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
