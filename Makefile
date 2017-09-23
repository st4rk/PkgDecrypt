CC=gcc
CFLAGS=-Ilibb64/ -Wall -std=c99
LDFLAGS=-L./aes -L./libb64 -laes -lb64 -lz
SOURCES=pkg_dec.c
EXECUTABLE=pkg_dec
SOURCES_MKKEY=make_key.c
EXECUTABLE_MKKEY=make_key

all: deps pkg_dec make_key
	
deps:
	$(MAKE) -C aes
	$(MAKE) -C libb64
	
pkg_dec:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
	
make_key:
	$(CC) $(CFLAGS) $(SOURCES_MKKEY) $(LDFLAGS) -o $(EXECUTABLE_MKKEY)

clean:
	$(MAKE) -C aes clean
	$(MAKE) -C libb64 clean
	rm -rf $(EXECUTABLE) $(EXECUTABLE_MKKEY)
