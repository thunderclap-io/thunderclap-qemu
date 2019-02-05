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
TARGETS = arm$(SEP)beribsd$(SEP)postgres
TARGET ?= arm
VICTIMS = macos-el-capitan$(SEP)macos-high-sierra$(SEP)freebsd
VICTIM ?= macos-el-capitan
DUMMY ?= 0
LOG ?= 0
PRINT_IDS ?= 0
PROFILE ?= 0
#ifeq ($(TARGET),arm)
#WORDSIZE=32
#CFLAGS := $(CFLAGS) -DPCIETXRX32
#else
WORDSIZE=64
#endif

# Remove instances of SEP from the TARGET, then search for TARGET follwed by
# SEP in the list of TARGETS followed by SEP to guarentee that an exact match
# for TARGET is in the TARGET list.
ifeq (,$(findstring $(filter-out $(SEP), $(TARGET))$(SEP), $(TARGETS)$(SEP)))
$(error $(TARGET) is not a valid target: choices are $(TARGETS))
endif

ifeq ($(TARGET),postgres)
	POSTGRES ?=1
else
	POSTGRES ?=0
	PCIE_DEBUG ?=0
endif

TARGET_DIR=build-$(TARGET)

BACKEND_beribsd = pcie-altera.c
BACKEND_arm = pcie-altera.c
BACKEND_postgres = pcie-postgres.c

ifeq ($(VICTIM),macos-el-capitan)
	CFLAGS := $(CFLAGS) -DVICTIM_MACOS -DVICTIM_MACOS_EL_CAPITAN
else ifeq ($(VICTIM),macos-high-sierra)
	CFLAGS := $(CFLAGS) -DVICTIM_MACOS -DVICTIM_MACOS_HIGH_SIERRA
else ifeq ($(VICTIM),freebsd)
	CFLAGS := $(CFLAGS) -DVICTIM_FREEBSD
else
$(error $(VICTIM) is not a valid target: choices are $(VICTIMS))
endif

LIBS := glib-2.0 pixman-1
LDLIBS := -lz -lpixman-1 -lpcre
LDLIBS := $(LDLIBS) -lutil -lglib-2.0 -lpthread -lm -lc

CFLAGS := $(CFLAGS) -Wall
#CFLAGS := $(CFLAGS) -ferror-limit=10
CFLAGS := $(CFLAGS) -DTHUNDERCLAP -DWORD_SIZE_$(WORDSIZE)
CFLAGS := $(CFLAGS) -O0 
#CFLAGS |= $(CFLAGS) --save-temps

ifeq ($(ASAN),1)
CFLAGS := -fsanitize=address
LDFLAGS := -fsanitize=address
endif

ifeq ($(DUMMY),1)
CFLAGS := $(CFLAGS) -DDUMMY
TARGET_DIR :=$(TARGET_DIR)-dummy
endif

ifeq ($(PCIE_DEBUG),1)
CFLAGS := $(CFLAGS) -DPCIE_DEBUG
endif

ifeq ($(LOG),1)
CFLAGS := $(CFLAGS) -DLOG
endif

ifeq ($(PRINT_IDS),1)
CFLAGS := $(CFLAGS) -DPRINT_IDS
endif

ifeq ($(PROFILE),1)
CFLAGS := $(CFLAGS) -pg
LDFLAGS := $(LDFLAGS) -pg
endif

ifeq ($(TARGET),beribsd)
$(info Building for BERI)

ifndef PCIE_QEMU_CHERI_SDK
$(error Variable PCIE_QEMU_CHERI_SDK is not set)
endif

# This must be a BERI sysroot, to avoid including the CHERI memcpy, for example.
PCIE_QEMU_SYSROOT ?= $(PCIE_QEMU_CHERI_SDK)/sdk/sysroot

CFLAGS := $(CFLAGS) -DCONFIG_BSD=1
LDFLAGS := -static -target cheri-unknown-freebsd -G0

SDK = $(PCIE_QEMU_CHERI_SDK)/sdk
CC = $(SDK)/bin/clang
OBJDUMP = $(SDK)/bin/objdump
LD = $(CC)
CROSS_USR=freebsd-packages/usr
CFLAGS := $(CFLAGS) --sysroot=$(PCIE_QEMU_SYSROOT) -isystem$(PCIE_QEMU_SYSROOT)/usr/include
CFLAGS := $(CFLAGS) $(addprefix -I$(CROSS_USR)/local/include/,$(LIBS))
CFLAGS := $(CFLAGS) -I$(CROSS_USR)/include
CFLAGS := $(CFLAGS) --target=cheri-unknown-freebsd
CFLAGS := $(CFLAGS) -integrated-as -mdouble-float
CFLAGS := $(CFLAGS) -I$(CROSS_USR)/local/lib/glib-2.0/include
CFLAGS := $(CFLAGS) -DTARGET=TARGET_BERI -G0 -mxgot -ftls-model=local-exec
CFLAGS := $(CFLAGS) -DBERIBSD -DPLATFORM_BERI -DHOST_WORDS_BIGENDIAN
CFLAGS := $(CFLAGS) -B$(SDK)
LDFLAGS := $(LDFLAGS) --sysroot=$(PCIE_QEMU_SYSROOT)
LDFLAGS := $(LDFLAGS) -L$(CROSS_USR)/local/lib
LDLIBS := $(LDLIBS) -lexecinfo -lelf -liconv -lintl
else ifeq ($(TARGET),postgres)
$(info Building postgres)
CC = clang
LD = clang
OBJDUMP = objdump
CFLAGS := $(CFLAGS) $(shell pkg-config --cflags $(LIBS))
CFLAGS := $(CFLAGS) -DTARGET=TARGET_NATIVE -D__linux__ -DCONFIG_LINUX
LDLIBS := $(LDLIBS) $(shell pkg-config --libs $(LIBS))
ifeq ($(POSTGRES),1)
CFLAGS := $(CFLAGS) -DPOSTGRES -I$(shell pg_config --includedir)
LDFLAGS := $(LDFLAGS) -L$(shell pg_config --libdir)
LDLIBS := $(LDLIBS) -lpq -lssl -lcrypto
endif #POSTGRES
else ifeq ($(TARGET),arm)
$(info Building for ARM)
WORDSIZE=32
CROSS_USR = linux-packages/usr
CC=clang
CFLAGS := $(CFLAGS) -mcpu=cortex-a9
CFLAGS := $(CFLAGS) -mfpu=neon
CFLAGS := $(CFLAGS) -mfloat-abi=hard
CFLAGS := $(CFLAGS) -I.
CFLAGS := $(CFLAGS) -I/usr/arm-linux-gnueabihf/include
CFLAGS := $(CFLAGS) -I$(CROSS_USR)/include/glib-2.0
CFLAGS := $(CFLAGS) -I$(CROSS_USR)/lib/arm-linux-gnueabihf/glib-2.0/include
CFLAGS := $(CFLAGS) -I$(CROSS_USR)/include/pixman-1
CFLAGS := $(CFLAGS) -I$(CROSS_USR)/include/gio-unix-2.0
CFLAGS := $(CFLAGS) -D__linux__ -DCONFIG_LINUX -DPLATFORM_ARM
LD := clang -target arm-linux-gnueabihf
LDFLAGS := $(LDFLAGS) -mcpu=cortex-a9
LDFLAGS := $(LDFLAGS) -mfpu=neon
LDFLAGS := $(LDFLAGS) -mfloat-abi=hard
LDFLAGS := $(LDFLAGS) -L/usr/arm-linux-gnueabihf/lib
LDFLAGS := $(LDFLAGS) -Llinux-packages/lib/arm-linux-gnueabihf
LDFLAGS := $(LDFLAGS) -L$(CROSS_USR)/lib/arm-linux-gnueabihf
OBJDUMP := arm-linux-gnueabihf-objdump
endif

CFLAGS := $(CFLAGS) -g
CFLAGS := $(CFLAGS) -Itcg/tci -Islirp
#CFLAGS := $(CFLAGS) -ferror-limit=1
CFLAGS := $(CFLAGS) -I. -Ihw/net -Ilinux-headers -Itarget-i386 -Itcg
CFLAGS := $(CFLAGS) -Ix86_64-softmmu -Ihw/core -Ii386-softmmu
CFLAGS := $(CFLAGS) -D NEED_CPU_H -D TARGET_X86_64
# NEED_CPU_H to stop poison...
#CFLAGS := $(CFLAGS) -Wno-error=initializer-overrides
CFLAGS := $(CFLAGS) -D_GNU_SOURCE # To pull in pipe2 -- seems dodgy

ifeq ($(DUMMY),1)
SOURCES := test.c log.c beri-io.c baremetal/baremetalsupport.c
SOURCES += $(BACKEND_$(TARGET))
else
DONT_FIND_TEMPLATES := $(shell grep "include \".*\.c\"" -roh . | sort | uniq | sed 's/include /! -name /g')
SOURCES := $(shell find . \
	! -name "pcie-*.c" \
	! -name "tap-*" $(DONT_FIND_TEMPLATES) -name "*.c" \
	| sed '/niosbare/d' \
	| sed '/beribare/d' \
	| sed '/snoop-mac/d' \
	| sed '/ats-dummy/d' \
	| sed '/print-macos-mbuf-pages/d' \
	| sed '/linux-packages/d' \
	| sed 's|./||') $(BACKEND_$(TARGET))
endif

ifeq ($(TARGET),arm)
SOURCES := $(SOURCES) net/tap-linux.c
else ifeq ($(TARGET),beribsd)
SOURCES := $(SOURCES) net/tap-bsd.c
else ifeq ($(TARGET),postgres)
SOURCES := $(SOURCES) net/tap-linux.c
else
$(error "Don't understand backend for target ", $(TARGET))
endif

O_FILES := $(addprefix $(TARGET_DIR)/,$(SOURCES:.c=.o))
HEADERS := $(shell find . -name "*.h")

$(TARGET_DIR)/test: $(O_FILES)
	@echo "Linking..."
	@$(LD) $(LDFLAGS) -o $@ $^ $(LOADLIBS) $(LDLIBS)

SNOOP_O_FILES := macos-mbuf-manipulation.o snoop-mac.o pcie.o beri-io.o
SNOOP_O_FILES := crhexdump.o $(SNOOP_O_FILES) $(BACKEND_$(TARGET):.c=.o)
SNOOP_PREREQS := $(addprefix $(TARGET_DIR)/,$(SNOOP_O_FILES))
$(TARGET_DIR)/snoop-mac: $(SNOOP_PREREQS)
	@echo "Linking..."
	@$(LD) $(LDFLAGS) -o $@ $^ $(LOADLIBS) $(LDLIBS)

.PHONY: snoop-mac
snoop-mac: $(TARGET_DIR)/snoop-mac
	@echo "Built snoop-mac as $(TARGET_DIR)/snoop-mac"

ATS_O_FILES := ats-dummy.o pcie-core.o beri-io.o hexdump.o $(BACKEND_$(TARGET):.c=.o)
ATS_PREREQS := $(addprefix $(TARGET_DIR)/,$(ATS_O_FILES))
$(TARGET_DIR)/ats-dummy: $(ATS_PREREQS)
	@echo "Linking..."
	@$(LD) $(LDFLAGS) -o $@ $^ $(LOADLIBS) $(LDLIBS)

.PHONY: ats-dummy
ats-dummy: $(TARGET_DIR)/ats-dummy

TS_O_FILES := test_secret_position.o secret_position.o
TS_PREREQS = $(addprefix $(TARGET_DIR)/,$(TS_O_FILES))
$(TARGET_DIR)/test_secret_position: $(TS_PREREQS)
	$(CC) $(LDFLAGS) -o $@ $^ $ch(LOADLIBS) $(LDLIBS)

PM_O_FILES := print-macos-mbuf-pages.o macos-mbuf-manipulation.o
PM_PREREQS = $(addprefix $(TARGET_DIR)/,$(PM_O_FILES))
$(TARGET_DIR)/print-macos-mbuf-pages: $(PM_PREREQS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LOADLIBS) $(LDLIBS)

$(TARGET_DIR)/%-no-source.dump: $(TARGET_DIR)/%
	$(OBJDUMP) -Cdz $< > $@

$(TARGET_DIR)/%.dump: $(TARGET_DIR)/%
	$(OBJDUMP) -ChdS $< > $@

$(TARGET_DIR)/pcie-altera-beri.o: pcie.h
$(TARGET_DIR)/%.o: %.c
	@echo "Building $<..."
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

readme.html: README.md readme-style.css
	pandoc -sS --toc -o readme.html README.md -c https://fonts.googleapis.com/css?family=Lato -c readme-style.css

# Cancel implicit rule
%.o : %.c

.PHONY: clean
clean:
	rm -f $(shell find . -name "*.o")
