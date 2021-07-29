DEPS = params.h bench.h

.PHONY: all
all: mini target 01_fork 02_vfork 03_fork_server 04_memcpy_restore remap_anon

.PHONY: clean
clean:
	rm -rf mini mini.o target 01_fork 02_vfork 03_fork_server pmparser.o 04_memcpy_restore.o 04_memcpy_restore remap_anon.o

.PHONY: test
test: all
	./01_fork
	./02_vfork
	./03_fork_server
	./04_memcpy_restore

mini: mini.S
	nasm -f elf64 mini.S -o mini.o
	ld mini.o -o mini

target: target.c
	$(CC) -O3 -o $@ $<

01_fork: 01_fork.c $(DEPS)
	$(CC) -O3 -o $@ $<

02_vfork: 02_vfork.c $(DEPS)
	$(CC) -O3 -o $@ $<

03_fork_server: 03_fork_server.c $(DEPS)
	$(CC) -O3 -o $@ $<

pmparser.o: pmparser.c
	$(CC) -O3 -o $@ -c $<

04_memcpy_restore.o: 04_memcpy_restore.c $(DEPS)
	$(CC) -O3 -o $@ -c $<

04_memcpy_restore: 04_memcpy_restore.o pmparser.o
	$(CC) -O3 -o $@ 04_memcpy_restore.o pmparser.o

remap_anon.o: remap_anon.c $(DEPS)
	$(CC) -o $@ -c $<

remap_anon: remap_anon.o pmparser.o
	$(CC) -o $@ -no-pie -Wl,--section-start=.remap=0x13370000,--section-start=.writesafe=0x13380000,--section-start=.bss=0x500000 -pthread -static remap_anon.o pmparser.o
