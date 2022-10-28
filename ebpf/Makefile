# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath libbpf/src)
BPFTOOL_SRC := $(abspath bpftool/src)
LIBBPF := $(abspath $(OUTPUT)/libbpf)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
KERN_RELEASE ?= $(shell uname -r)
KERN_BUILD_PATH = /lib/modules/$(KERN_RELEASE)/build
KERN_SRC_PATH = $(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BUILD_PATH))
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(LIBBPF)/include -Ilibbpf/include/uapi

MODULE = probe

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(MODULE).skel.h

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(MODULE).skel.h

$(OUTPUT) $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 PREFIX=$@ install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
$(OUTPUT)/%.bpf.o: %.h %.bpf.c $(LIBBPF) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)

ifeq ($(CORE),1)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(BPF_CFLAGS) $(INCLUDES) -I$(dir $(VMLINUX)) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
else
	$(Q)$(CLANG) -S -D__BPF_TRACING__ -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) $(INCLUDES) \
		-include $(KERN_SRC_PATH)/include/linux/kconfig.h \
		-I$(KERN_SRC_PATH)/arch/$(ARCH)/include \
		-I$(KERN_SRC_PATH)/arch/$(ARCH)/include/uapi \
		-I$(KERN_BUILD_PATH)/arch/$(ARCH)/include/generated \
		-I$(KERN_BUILD_PATH)/arch/$(ARCH)/include/generated/uapi \
		-I$(KERN_SRC_PATH)/include \
		-I$(KERN_BUILD_PATH)/include \
		-I$(KERN_SRC_PATH)/include/uapi \
		-I$(KERN_BUILD_PATH)/include/generated \
		-I$(KERN_BUILD_PATH)/include/generated/uapi \
		$(CLANG_BPF_SYS_INCLUDES) \
		-Wunused -Wall -Wno-frame-address -Wno-unused-value -Wno-unknown-warning-option \
		-Wno-pragma-once-outside-header -Wno-pointer-sign -Wno-gnu-variable-sized-type-not-at-end \
		-Wno-deprecated-declarations -Wno-compare-distinct-pointer-types -Wno-address-of-packed-member \
		-fno-stack-protector -fno-jump-tables -fno-unwind-tables -fno-asynchronous-unwind-tables \
		-xc -nostdinc -O2 -emit-llvm -c -g \
		-c $(filter %.c,$^) -o - | \
		$(LLC) -march=bpf -filetype=obj -o $@
endif

	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
