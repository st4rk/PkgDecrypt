CC=gcc
CFLAGS=-Wall -std=c99
LDFLAGS=-L./aes -laes
SOURCES=pkg_dec.c
EXECUTABLE=pkg_dec

all:
	$(MAKE) -C aes
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	$(MAKE) -C aes clean
	rm -rf $(EXECUTABLE)
