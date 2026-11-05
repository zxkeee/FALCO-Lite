# Falco-lite
#
#   make              зібрати ./falco-lite (потрібні clang і ядро з BTF для vmlinux.h)
#   make test         юніт-тести: без root, без eBPF, без clang
#   make e2e          атаки з демо проти живого агента (sudo)
#   make STATIC=1     статичний бінарник
#   make V=1          показувати команди повністю

OUTPUT      := .output
CLANG       ?= clang
CC          ?= cc
ARCH        ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

LIBBPF_SRC  := $(abspath libbpf/src)
BPFTOOL_SRC := $(abspath bpftool/src)
LIBBPF_OBJ  := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL     ?= $(BPFTOOL_OUT)/bootstrap/bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
VMLINUX_H   := $(OUTPUT)/vmlinux.h

APP   := falco-lite
TESTS := falco-lite-tests

INCLUDES := -I$(OUTPUT) -Iinclude -Isrc -I$(abspath libbpf/include/uapi)
CFLAGS   ?= -g -O2
CFLAGS   += -Wall -Wextra -std=gnu11
LIBS     := -lyaml -lncursesw -lelf -lz

ifeq ($(STATIC),1)
LDFLAGS  += -static
LIBS     := $(shell pkg-config --static --libs yaml-0.1 ncursesw libelf zlib)
endif

ifeq ($(V),1)
Q   :=
msg :=
else
Q   := @
msg  = @printf '  %-8s %s\n' "$(1)" "$(2)";
endif

# Системні include-шляхи clang: потрібні BPF-коду при -target bpf.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Усе, крім main.c і loader.c, збирається без libbpf — саме це й тестується.
CORE_SRCS := pipeline.c rules.c engine.c proctree.c action.c output.c \
             out_json.c out_syslog.c tui.c record.c util.c
CORE_OBJS := $(addprefix $(OUTPUT)/,$(CORE_SRCS:.c=.o))
TEST_OBJS := $(patsubst tests/unit/%.c,$(OUTPUT)/tests/%.o,$(wildcard tests/unit/*.c))
HEADERS   := $(wildcard src/*.h) include/events.h

.PHONY: all test e2e clean
.DELETE_ON_ERROR:

all: $(APP)

$(OUTPUT) $(OUTPUT)/libbpf $(OUTPUT)/tests $(BPFTOOL_OUT):
	$(Q)mkdir -p $@

# libbpf із сабмодуля: libbpf.a + заголовки в $(OUTPUT)/bpf/
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# bpftool із сабмодуля: потрібен лише для vmlinux.h і skeleton
$(BPFTOOL): | $(BPFTOOL_OUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUT)/ -C $(BPFTOOL_SRC) bootstrap

# Типи ядра для CO-RE. Бінарник потім працює й на інших ядрах 5.8+ з BTF.
$(VMLINUX_H): | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(OUTPUT)/falco.bpf.o: bpf/falco.bpf.c include/events.h $(LIBBPF_OBJ) $(VMLINUX_H) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $(OUTPUT)/falco.tmp.bpf.o
	$(Q)$(BPFTOOL) gen object $@ $(OUTPUT)/falco.tmp.bpf.o

$(OUTPUT)/falco.skel.h: $(OUTPUT)/falco.bpf.o | $(BPFTOOL)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/loader.o: $(OUTPUT)/falco.skel.h $(LIBBPF_OBJ)

$(OUTPUT)/%.o: src/%.c $(HEADERS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(APP): $(OUTPUT)/main.o $(OUTPUT)/loader.o $(CORE_OBJS) $(LIBBPF_OBJ)
	$(call msg,LINK,$@)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

# ---------- тести ----------

$(OUTPUT)/tests/%.o: tests/unit/%.c $(wildcard tests/unit/*.h) $(HEADERS) | $(OUTPUT)/tests
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TESTS): $(TEST_OBJS) $(CORE_OBJS)
	$(call msg,LINK,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lyaml -lncursesw -o $@

test: $(TESTS)
	./$(TESTS)

# Бінарник називається php-fpm, щоб comm процесу був "php-fpm".
$(OUTPUT)/e2e/php-fpm: tests/e2e/fake_phpfpm.c
	$(Q)mkdir -p $(dir $@)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $< -o $@

e2e: $(APP) $(OUTPUT)/e2e/php-fpm
	sudo bash tests/e2e/run.sh

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP) $(TESTS)
