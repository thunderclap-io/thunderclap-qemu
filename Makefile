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

CC = /home/cr437/cheri-sdk/sdk/bin/clang
EXTRA_USR=/home/cr437/iommu/iommu/beri-fake-peripherals/usr

LIBS := glib-2.0 pixman-1
CFLAGS := $(addprefix "-I$(EXTRA_USR)/local/include/",$(LIBS))
CFLAGS := $(CFLAGS) -I$(EXTRA_USR)/local/lib/glib-2.0/include

LDFLAGS := -L$(EXTRA_USR)/local/lib -lglib-2.0 -lpixman-1 -lpcre -lthr -lm -lz
LDFLAGS := $(LDFLAGS) -lutil -liconv -lintl
CFLAGS := $(CFLAGS) -g
CFLAGS := $(CFLAGS) -Itcg/tci -Islirp
#CFLAGS := $(CFLAGS) -ferror-limit=1
CFLAGS := $(CFLAGS) -I. -Ihw/net -Ilinux-headers -Itarget-i386 -Itcg
CFLAGS := $(CFLAGS) -Ix86_64-softmmu -Ihw/core -Ii386-softmmu
CFLAGS := $(CFLAGS) -D NEED_CPU_H -D TARGET_X86_64 -D CONFIG_BSD
# NEED_CPU_H to stop poison...
CFLAGS := $(CFLAGS) -Wno-error=initializer-overrides
CFLAGS := $(CFLAGS) -D_GNU_SOURCE # To pull in pipe2 -- seems dodgy
DONT_FIND_TEMPLATES := $(shell grep "include \".*\.c\"" -Roh . | sort | uniq | sed 's/include /! -name /g')
SOURCES := $(shell find . -name "*.c" $(DONT_FIND_TEMPLATES))
O_FILES := $(SOURCES:.c=.o)
HEADERS := $(shell find . -name "*.h")

test: test.o $(O_FILES)

.PHONY: clean
clean:
	rm -f $(shell find . -name "*.o")
