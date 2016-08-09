SDK_BIN?=/anfs/bigdisc/atm26/mips/sdk/bin
SYSROOT?=/anfs/bigdisc/atm26/mips/sdk/
CLANG_INC?=/anfs/bigdisc/atm26/mips/lib
BINUTILS?=/anfs/bigdisc/atm26/mips/binutils/
#SDK_BIN=~cr437/cheri-sdk/sdk/bin/
#$(PCIE_QEMU_CHERI_SDK)/sdk/bin
TOOLS_DIR?=/anfs/bigdisc/atm26/ctsrd/cherilibs/trunk/tools
#../../../../cherilibs/trunk/tools

CLANG=$(SDK_BIN)/clang --sysroot $(SYSROOT)/ -B $(SDK_BIN) -isystem $(CLANG_INC)/clang/3.8.0/include/
#AS=$(CLANG)
#AS=mips64-as
AS=$(BINUTILS)/bin/mips64-as
#ASFLAGS=-g -c -fno-pic -target mips64 -integrated-as -EB -fverbose-asm
ASFLAGS=-EB -march=mips64 -mabi=64 -G0 -ggdb

#CC=/usr/groups/ecad/mips/sde-6.06/bin/sde-gcc
CC=$(CLANG)
CFLAGS=-gdwarf-2 -c -fno-pic -target mips64 -integrated-as -EB
#-Werror=all -target cheri-unknown-freebsd -integrated-as
CFLAGS+=-O2 -ffunction-sections -fno-builtin

#LD=mips64-ld
LD=$(BINUTILS)/bin/mips64-ld

OBJCOPY=$(BINUTILS)/bin/mips64-objcopy
OBJDUMP=$(BINUTILS)/bin/mips64-objdump

LDSCRIPT=script.ld
INIT_OBJ=init.o
LIB_OBJ=lib.o

all: test.dump test.mif

test.o:

test.mem:

test.elf:

$(INIT_OBJ):

$(LIB_OBJ):

%.elf: $(LIB_OBJ) %.o $(INIT_OBJ)
	$(LD) -EB -G0 -T $(LDSCRIPT) $^ -o $@ -m elf64bmip -M > test.map
# elf64-tradbigmips

%.mem: %.elf
	$(OBJCOPY) -S -O binary $< $@

%.dump: %.mem
	$(OBJDUMP) -SD -EB -m mips -b binary  --adjust-vma=0x9000000080000000 $< > $@
	$(OBJDUMP) -S -EB -m mips test.elf > test.elf.dump

%.mif: %.mem
	$(TOOLS_DIR)/memConv.py -b $< mif
	cp initial256.mif ../../boards/terasic_de5/onchip_mem.mif
	

update_mif: test.mif
	cp initial256.mif ../../boards/terasic_de5/onchip_mem.mif
	make -C ../../boards/terasic_de5 update_mif

.PHONY: clean
clean:
	rm -f *.o *.mem *.hex *.dump *.elf
