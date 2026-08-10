CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BUILD_DIR := build
VMLINUX := src/vmlinux.h
BPF_OBJECT := $(BUILD_DIR)/monitor.bpf.o
SKELETON := $(BUILD_DIR)/monitor.skel.h
MONITOR := $(BUILD_DIR)/monitor
INVALID_OBJECT := $(BUILD_DIR)/invalid_memory.bpf.o
TEST_BINS := $(BUILD_DIR)/syscall_stress $(BUILD_DIR)/rate_limit_test $(BUILD_DIR)/page_fault_test

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Wextra \
	-Wno-missing-declarations \
	-I$(CURDIR)/src -I$(CURDIR)/include
USER_CFLAGS := -g -O2 -Wall -Wextra -std=gnu11 -I$(CURDIR)/include \
	-I$(CURDIR)/$(BUILD_DIR) $(shell $(PKG_CONFIG) --cflags libbpf)
USER_LIBS := $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

.PHONY: all clean distclean vmlinux tests verifier-test help
.DELETE_ON_ERROR:

all: $(MONITOR)

help:
	@echo "Targets: all vmlinux tests verifier-test clean distclean"

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX): /sys/kernel/btf/vmlinux | $(BUILD_DIR)
	@echo "  BTF     $@"
	$(BPFTOOL) btf dump file $< format c > $@.tmp
	mv $@.tmp $@

vmlinux: $(VMLINUX)

$(BPF_OBJECT): src/monitor.bpf.c include/monitor.h $(VMLINUX) | $(BUILD_DIR)
	@echo "  BPF     $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKELETON): $(BPF_OBJECT) | $(BUILD_DIR)
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(MONITOR): src/monitor.c include/monitor.h $(SKELETON) | $(BUILD_DIR)
	@echo "  CC      $@"
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

$(INVALID_OBJECT): verifier_tests/invalid_memory.bpf.c $(VMLINUX) | $(BUILD_DIR)
	@echo "  BPF     $@ (intentionally invalid at load time)"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/syscall_stress: tests/syscall_stress.c | $(BUILD_DIR)
	$(CC) -g -O2 -Wall -Wextra -pthread $< -o $@

$(BUILD_DIR)/rate_limit_test: tests/rate_limit_test.c | $(BUILD_DIR)
	$(CC) -g -O2 -Wall -Wextra $< -o $@

$(BUILD_DIR)/page_fault_test: tests/page_fault_test.c | $(BUILD_DIR)
	$(CC) -g -O2 -Wall -Wextra $< -o $@

tests: $(TEST_BINS)

verifier-test: all $(INVALID_OBJECT)
	./scripts/test_verifier.sh

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -f $(VMLINUX)
	rm -f artifacts/*.log artifacts/*.txt artifacts/*.data
