LIBRARIES = libb64.a

CFLAGS += -O3 -Wall

SOURCES = cdecode.c  cencode.c

TARGETS = $(LIBRARIES)

LINK.o = gcc

CFLAGS += -I./ -Werror -pedantic

.PHONY : clean

all: $(TARGETS)

libb64.a: cencode.o cdecode.o
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f *.exe* *.o $(TARGETS) *.bak *~


