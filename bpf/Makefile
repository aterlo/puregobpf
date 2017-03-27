CFLAGS=-Wall

all: simple_map.o

simple_map.o: simple_map.c
	clang $(CFLAGS) -O2 -emit-llvm -g -c simple_map.c -o - | llc -march=bpf -filetype=obj -o simple_map.o

clean:
	rm simple_map.o
