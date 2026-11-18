CLANG ?= clang
BPFTOOL ?= bpftool
BUILD := build

PKGS := libbpf yaml-0.1 ncurses
CFLAGS := -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -Isrc -I$(BUILD)

LIBS := $(shell pkg-config --libs $(PKGS))
STATIC_LIBS := -static $(shell pkg-config --static --libs $(PKGS))

CORE := src/rules.c src/proctree.c src/engine.c src/output.c src/response.c
SRCS := src/main.c src/loader.c src/tui.c $(CORE)
HDRS := $(wildcard src/*.h)
TESTS := $(patsubst tests/%.c,$(BUILD)/%,$(wildcard tests/test_*.c))

.DELETE_ON_ERROR:

all: falco-lite

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/falco.bpf.o: bpf/falco.bpf.c src/event.h $(BUILD)/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -Isrc -I$(BUILD) -c $< -o $@

$(BUILD)/falco.skel.h: $(BUILD)/falco.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

falco-lite: $(SRCS) $(HDRS) $(BUILD)/falco.skel.h
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LIBS)

static: $(SRCS) $(HDRS) $(BUILD)/falco.skel.h
	$(CC) $(CFLAGS) $(SRCS) -o falco-lite $(STATIC_LIBS)

$(BUILD)/test_%: tests/test_%.c tests/check.h $(CORE) $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -Itests $< $(CORE) -o $@ $(shell pkg-config --libs yaml-0.1)

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

demo: falco-lite
	sudo bash demo/run.sh

clean:
	rm -rf $(BUILD) falco-lite

.PHONY: all static test demo clean
