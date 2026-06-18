CC ?= x86_64-w64-mingw32-gcc
CFLAGS = -O2 -Wall
LIBS = -lfltuser

struct_fuzz.exe: struct_fuzz.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f struct_fuzz.exe

.PHONY: clean