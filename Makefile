BENCH_DEPS = params.h bench.h

REMAP_ADDR = 0x13370000
WRITE_IGNORED_ADDR = 0x13380000
GOT_PLT_ADDR = 0x500000
DATA_SECTION_ADDR = 0x600000
ADDRESS_DEFINES = -DREMAP_ADDR=$(REMAP_ADDR) -DWRITE_IGNORED_ADDR=$(WRITE_IGNORED_ADDR) -DGOT_PLT_ADDR=$(GOT_PLT_ADDR) -DDATA_SECTION_ADDR=$(DATA_SECTION_ADDR)

.PHONY: all
all: target 01_fork 02_vfork 03_fork_server 04_memcpy_restore

.PHONY: clean
clean:
	rm -rf target 01_fork 02_vfork 03_fork_server pmparser.o 04_memcpy_restore.o 04_memcpy_restore

.PHONY: test
test: all
	./01_fork
	./02_vfork
	./03_fork_server
	./04_memcpy_restore

target: target.c
	$(CC) -O3 -o $@ $<

01_fork: 01_fork.c $(BENCH_DEPS)
	$(CC) -O3 -o $@ $<

02_vfork: 02_vfork.c $(BENCH_DEPS)
	$(CC) -O3 -o $@ $<

03_fork_server: 03_fork_server.c $(BENCH_DEPS)
	$(CC) -O3 -o $@ $<

pmparser.o: pmparser.c
	$(CC) -O3 -o $@ -c $<

04_memcpy_restore.o: 04_memcpy_restore.c $(BENCH_DEPS)
	$(CC) $(ADDRESS_DEFINES) -o $@ -c $<

04_memcpy_restore: 04_memcpy_restore.o pmparser.o
	$(CC) -o $@ -no-pie -Wl,--section-start=.remap=$(REMAP_ADDR),--section-start=.writeignored=$(WRITE_IGNORED_ADDR),--section-start=.got.plt=$(GOT_PLT_ADDR),--section-start=.data=$(DATA_SECTION_ADDR) -pthread -static 04_memcpy_restore.o pmparser.o
