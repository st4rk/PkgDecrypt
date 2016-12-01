CC=gcc
CFLAGS=-Wall
LDFLAGS=-lcrypto
SOURCES=pkg_dec.c
EXECUTABLE=pkg_dec
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
