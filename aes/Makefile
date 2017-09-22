CC           = gcc
LD           = ld
CFLAGS       = -Wall -O2 -Wl,-Map,test.map
OBJCOPY      = objcopy
SOURCES      = aes.c
TARGET_LIB   = libaes.a

.SILENT:
.PHONY: all

all: $(SOURCES)
	$(CC) $(CFLAGS) -c $(SOURCES) -o $(TARGET_LIB)

clean:
	rm -f *.OBJ *.LST *.o *.gch *.out *.hex *.map *.a

