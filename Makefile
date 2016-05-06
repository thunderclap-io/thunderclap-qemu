# SPDX-License-Identifier: BSD-2-Clause
# 
# Copyright (c) 2015-2018 Colin Rothwell
# Copyright (c) 2015-2018 A. Theodore Markettos
# 
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
# 
# We acknowledge the support of EPSRC.
# 
# We acknowledge the support of Arm Ltd.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


SEP :=, 
TARGETS = beri$(SEP)native

ifndef PCIE_QEMU_CHERI_SDK
$(error Variable PCIE_QEMU_CHERI_SDK is not set)
endif

ifndef PCIE_QEMU_LIBRARY_ROOT
$(error PCIE_QEMU_LIBRARY_ROOT is not set)
# PCIE_QEMU_LIBRARY_ROOT should be the directory into which the .txz libraries
# have been extracted. It should contain a usr directory.
endif

ifndef PCIE_QEMU_SYSROOT
$(error PCIE_QEMU_SYSROOT is not set)
# This must be a BERI sysroot, to avoid including the CHERI memcpy, for example.
endif

# Remove instances of SEP from the TARGET, then search for TARGET follwed by
# SEP in the list of TARGETS followed by SEP to guarentee that an exact match
# for TARGET is in the TARGET list.
ifeq (,$(findstring $(filter-out $(SEP), $(TARGET))$(SEP), $(TARGETS)$(SEP)))
$(error $(TARGET) is not a valid target: choices are $(TARGETS))
endif

ifeq ($(TARGET),native)
	POSTGRES ?=1
	PCIE_DEBUG ?=1
else
	POSTGRES ?=0
	PCIE_DEBUG ?=0
endif

TARGET_DIR=build-$(TARGET)

LDFLAGS := -static #-target mips64-unknown-freebsd #-G0
LIBS := glib-2.0 pixman-1
LDLIBS := -lz -lexecinfo -lelf -lpixman-1 -lpcre
LDLIBS := $(LDLIBS) -lutil -lglib-2.0 -liconv -lintl -lm -lthr

CFLAGS := $(CFLAGS) -O3

ifeq ($(PCIE_DEBUG),1)
CFLAGS := $(CFLAGS) -DPCIE_DEBUG
endif

ifeq ($(TARGET),beri)
$(info Building for BERI)
SDK = $(PCIE_QEMU_CHERI_SDK)/sdk
CC = $(SDK)/bin/clang
OBJDUMP = $(SDK)/bin/objdump
#CC=/home/cr437/cheri-sdk/sdk/bin/gcc
EXTRA_USR=$(PCIE_QEMU_LIBRARY_ROOT)/usr
CFLAGS := $(CFLAGS) $(addprefix "-I$(EXTRA_USR)/local/include/",$(LIBS))
#CFLAGS := $(CFLAGS) --target=mips64-unknown-freebsd
CFLAGS := $(CFLAGS) --sysroot=$(PCIE_QEMU_SYSROOT)
CFLAGS := $(CFLAGS) -I$(EXTRA_USR)/local/lib/glib-2.0/include
CFLAGS := $(CFLAGS) -DTARGET=TARGET_BERI -G0 -mxgot -O2 -ftls-model=local-exec
LDFLAGS := $(LDFLAGS) --sysroot=$(PCIE_QEMU_SYSROOT)
LDFLAGS := $(LDFLAGS) -L$(EXTRA_USR)/local/lib
else ifeq ($(TARGET),native)
$(info Building native)
CC = clang
OBJDUMP = objdump
CFLAGS := $(CFLAGS) $(shell pkg-config --cflags $(LIBS))
CFLAGS := $(CFLAGS) -DTARGET=TARGET_NATIVE
LDLIBS := $(LDLIBS) $(shell pkg-config --libs $(LIBS))
ifeq ($(POSTGRES),1)
CFLAGS := $(CFLAGS) -DPOSTGRES -I$(shell pg_config --includedir)
LDFLAGS := $(LDFLAGS) -L$(shell pg_config --libdir)
LDLIBS := $(LDLIBS) -lpq -lssl -lcrypto
endif #POSTGRES
endif

CFLAGS := $(CFLAGS) -g
CFLAGS := $(CFLAGS) -Itcg/tci -Islirp
#CFLAGS := $(CFLAGS) -ferror-limit=1
CFLAGS := $(CFLAGS) -I. -Ihw/net -Ilinux-headers -Itarget-i386 -Itcg
CFLAGS := $(CFLAGS) -Ix86_64-softmmu -Ihw/core -Ii386-softmmu
CFLAGS := $(CFLAGS) -D NEED_CPU_H -D TARGET_X86_64 -D CONFIG_BSD
# NEED_CPU_H to stop poison...
#CFLAGS := $(CFLAGS) -Wno-error=initializer-overrides
CFLAGS := $(CFLAGS) -D_GNU_SOURCE # To pull in pipe2 -- seems dodgy

DONT_FIND_TEMPLATES := $(shell grep "include \".*\.c\"" -Roh . | sort | uniq | sed 's/include /! -name /g')
SOURCES := $(shell find . -name "*.c" $(DONT_FIND_TEMPLATES) | sed 's|./||')
O_FILES := $(addprefix $(TARGET_DIR)/,$(SOURCES:.c=.o))
HEADERS := $(shell find . -name "*.h")

$(TARGET_DIR)/test: $(O_FILES)
	@echo "Linking..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)

$(TARGET_DIR)/test-no-source.dump: $(TARGET_DIR)/test
	$(OBJDUMP) -Cdz $< > $@

$(TARGET_DIR)/test.dump: $(TARGET_DIR)/test
	$(OBJDUMP) -ChdS $< > $@

$(TARGET_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# Cancel implicit rule
%.o : %.c

.PHONY: clean
clean:
	rm -f $(shell find . -name "*.o")
