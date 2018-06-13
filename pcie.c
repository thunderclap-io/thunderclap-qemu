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

#include "freebsd-queue.h"
#include "hw/pci/pci.h"
#include "pcie.h"
#include "pcie-backend.h"
#include "pcie-debug.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

static inline uint64_t
uint64_min(uint64_t left, uint64_t right)
{
	return (left < right) ? left : right;
}

/* Request is not a whole number of dwords, so we need to read one more dword,
 * then use the lastbe to select the parts we want. I had to work this out on
 * paper. It works.
 */
struct byte_enables {
	uint8_t first;
	uint8_t last;
};

static inline uint16_t
calculate_dword_length(uint16_t byte_len)
{
	return ((byte_len + 3) / 4) * 4;
}

static inline uint8_t
last_be_for_length(uint16_t byte_len)
{
	return ((1 << (4 - (calculate_dword_length(byte_len) - byte_len))) - 1);
}

static inline struct byte_enables
calculate_bes_for_length(uint16_t byte_len)
{
	struct byte_enables bes;
	bes.last = last_be_for_length(byte_len);
	if (calculate_dword_length(byte_len) / sizeof(TLPDoubleWord) == 1) {
		bes.first = bes.last;
		bes.last = 0;
	} else {
		bes.first = 0xF;
	}
	return bes;
}

/* length is used as the PCIe field, so is in DWords i.e. units of 32 bits. */
void
create_completion_header(struct RawTLP *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress)
{
	/*printf("Creating a completion header.");*/
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp->header[0] = 0;
	tlp->header[1] = 0;
	tlp->header[2] = 0;

	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)(tlp->header);
	if (direction == TLPD_READ
		&& completion_status == TLPCS_SUCCESSFUL_COMPLETION) {
		set_fmt(header0, TLPFMT_3DW_DATA);
		set_length(header0, 1);
	} else {
		set_fmt(header0, TLPFMT_3DW_NODATA);
		set_length(header0, 0);
	}
	set_type(header0, CPL);

	struct TLP64CompletionDWord1 *header1 =
		(struct TLP64CompletionDWord1 *)(tlp->header) + 1;
	set_completer_id(header1,completer_id);
	set_status(header1, completion_status);
	set_bytecount(header1, bytecount);

	struct TLP64CompletionDWord2 *header2 =
		(struct TLP64CompletionDWord2 *)(tlp->header) + 2;
	set_requester_id(header2, requester_id);
	header2->tag = tag;
	header2->loweraddress = loweraddress;
}

void
create_memory_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	enum tlp_at at, uint16_t length, uint16_t requester_id, uint8_t tag,
	uint8_t lastbe, uint8_t firstbe, uint64_t address)
{
	bool large_address = (address >= (1LL << 32));

	int i;

	for (i = 0; i < 4; ++i) {
		tlp->header[i] = 0;
	}
	if (large_address) {
		tlp->header_length = 16;
	} else {
		tlp->header_length = 12;
	}
	if (direction == TLPD_READ) {
		tlp->data_length = 0;
	} else {
		tlp->data_length = length * sizeof(TLPDoubleWord);
	}

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp->header;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(tlp->header + 1);
	TLPDoubleWord *address_dword2 = (tlp->header + 2);
	TLPDoubleWord *address_dword3 = (tlp->header + 3);

	enum tlp_fmt fmt = 0;
	if (tlp->header_length == 16) {
		fmt = TLPFMT_4DW;
	}
	if (direction == TLPD_WRITE) {
		fmt |= TLPFMT_WITHDATA;
	}
	set_fmt(dword0, fmt);
	set_at(dword0, at);
	set_length(dword0, length);
	set_type(dword0, M);

	set_requester_id(request_dword1,requester_id);
	request_dword1->tag = tag;
	set_lastbe(request_dword1, lastbe);
	set_firstbe(request_dword1, firstbe);

	if (large_address) {
		*address_dword2 = (TLPDoubleWord)(address >> 32);
		*address_dword3 = (TLPDoubleWord)address;
	} else {
		*address_dword2 = (TLPDoubleWord)address;
	}
}

void
create_config_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	uint16_t requester_id, uint8_t tag, uint8_t firstbe, uint16_t devfn,
	uint16_t address)
{
	assert((address & 0x3) == 0);
	assert(address < 4096);

	int i;
	for (i = 0; i < 4; ++i) {
		tlp->header[i] = 0;
	}
	tlp->header_length = 12;
	if (direction == TLPD_READ) {
		tlp->data_length = 0;
	} else {
		tlp->data_length = 4;
	}

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp->header;
	struct TLP64RequestDWord1 *dword1 =
		(struct TLP64RequestDWord1 *)(tlp->header + 1);
	struct TLP64ConfigRequestDWord2 *dword2 =
		(struct TLP64ConfigRequestDWord2 *)(tlp->header + 2);

	enum tlp_fmt fmt = 0;
	if (direction == TLPD_WRITE) {
		fmt |= TLPFMT_WITHDATA;
	}
	set_fmt(dword0, fmt);
	set_type(dword0, CFG_0);
	set_length(dword0, 1);
	set_requester_id(dword1,requester_id);
	dword1->tag = tag;
	set_firstbe(dword1, firstbe);
	set_device_id(dword2, devfn);
	dword2->ext_reg_num = address >> 8;
	dword2->reg_num = address & uint32_mask(8);
}

void
print_tlp(struct RawTLP *tlp)
{
	enum tlp_direction tlp_direction = get_tlp_direction(tlp);
	enum tlp_type tlp_type = get_tlp_type(tlp);
	fputs(tlp_type_str(tlp_type), stdout);
	putchar(' ');
	fputs(tlp_direction_str(tlp_direction), stdout);
	puts(" type TLP.");
}

#define TLP_BUFFER_SIZE 512
#define TLP_BUFFER_COUNT 32

bool tlp_buffer_in_use[TLP_BUFFER_COUNT];
TLPQuadWord tlp_buffer[TLP_BUFFER_SIZE * TLP_BUFFER_COUNT / sizeof(TLPQuadWord)];

STAILQ_HEAD(UnhandledTLPListHead, unhandled_tlp_list_entry)
	unhandled_tlp_list_head = STAILQ_HEAD_INITIALIZER(unhandled_tlp_list_head);

__attribute__((constructor))
void init_tlp_buffer()
{
	STAILQ_INIT(&unhandled_tlp_list_head);

	for (int i = 0; i < TLP_BUFFER_COUNT; ++i) {
		tlp_buffer_in_use[i] = false;
		tlp_buffer[i] = 0xDEADBEEFEA7EBEDE;
	}
}

struct unhandled_tlp_list_entry {
	struct RawTLP tlp;
	STAILQ_ENTRY(unhandled_tlp_list_entry) unhandled_tlp_list;
};

static inline bool
is_cpl_d(struct RawTLP *tlp)
{
	assert(tlp->header_length != -1);
	assert(tlp->header != NULL);
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp->header;
	return get_type(dword0) == CPL && tlp_fmt_has_data(get_fmt(dword0));
}

static inline TLPQuadWord *
tlp_buffer_address(int i)
{
	return (tlp_buffer + (i * TLP_BUFFER_SIZE / sizeof(TLPQuadWord)));
}

static inline int
tlp_buffer_number(TLPQuadWord *addr)
{
	ptrdiff_t size_in_quadwords = (addr - tlp_buffer);
	return ((size_in_quadwords * sizeof(TLPQuadWord)) / TLP_BUFFER_SIZE);
}

void
print_tlp_list()
{
	struct unhandled_tlp_list_entry *tlp_entry;
	STAILQ_FOREACH(tlp_entry, &unhandled_tlp_list_head, unhandled_tlp_list) {
		print_raw_tlp(&tlp_entry->tlp);
	}
}

void
alloc_raw_tlp_buffer(struct RawTLP *tlp)
{
	/*if (is_raw_tlp_valid(tlp)) {*/
		/*fputs("Trying to allocate already allocated RawTLP!\n", stderr);*/
	/*}*/
	for (int i = 0; i < TLP_BUFFER_COUNT; ++i) {
		if (!tlp_buffer_in_use[i]) {
			tlp_buffer_in_use[i] = true;
			tlp->header = (TLPDoubleWord *)tlp_buffer_address(i);
			return;
		}
	}
	fputs("Couldn't allocate TLP Buffer!\n", stderr);
	printf("TLP LIST:\n");
	print_tlp_list();
	exit(0);
}

void
free_raw_tlp_buffer(struct RawTLP *tlp)
{
	int buffer_number = tlp_buffer_number((TLPQuadWord *)tlp->header);
	/*if (buffer_number != 0) {*/
		/*printf("(0 alloced by %p) f%d\n", call_sites[0], buffer_number);*/
	/*}*/
	if (buffer_number >= 0 && buffer_number <= TLP_BUFFER_COUNT) {
		tlp_buffer_in_use[buffer_number] = false;
		set_raw_tlp_invalid(tlp);
	} else {
		fprintf(stderr, "Trying to free unallocated buffer %d at %p\n.",
			buffer_number, tlp->header);
	}
}

/*
 * All TLPs that come from these two functions have been malloc'ed, and so
 * must be freed by the consumer using the provided free_raw_tlp_buffer
 * function.
 *
 * TODO: This could work with pointers to RawTLP pointers, rather than just
 * RawTLP pointers. At the moment, we have to copy the contents of the RawTLP
 * about, although this is likely to not be a severe performance limitation.
 */
void
next_tlp(struct RawTLP *out)
{
	struct unhandled_tlp_list_entry *candidate =
		STAILQ_FIRST(&unhandled_tlp_list_head);
	if (candidate == NULL) {
		alloc_raw_tlp_buffer(out);
		wait_for_tlp((TLPQuadWord *)out->header, TLP_BUFFER_SIZE, out);
	} else {
		/*fputs("dq ", stdout);*/
		/*puts(tlp_type_str(get_tlp_type(out)));*/
		STAILQ_REMOVE_HEAD(&unhandled_tlp_list_head, unhandled_tlp_list);
		*out = candidate->tlp;
		/*printf("dq %d.\n", tlp_buffer_number((TLPQuadWord *)out->header));*/
		free(candidate);
		assert(is_raw_tlp_valid(out));
	}
}

/*
 * Consumes incoming TLPs until a completion type TLP is received. This
 * function is blocking. Unhandled TLPs are added to an internal queue, and
 * will be yielded by subsequent calls to the next_tlp function. Because this
 * is the only function that adds packets to the internal queue, and it will
 * always return a completion type TLP and never add it to the internal queue,
 * the internal queue will never contain a completion type TLP, so we don't
 * have to check the internal queue for completion type TLPs
 */
void
next_completion_tlp(struct RawTLP *out)
{
	for (int i = 0; i < 10; ++i) {
		alloc_raw_tlp_buffer(out);
		wait_for_tlp((TLPQuadWord *)out->header, TLP_BUFFER_SIZE, out);
		if (is_raw_tlp_valid(out)) {
			if (get_tlp_type(out) == CPL) {
				return;
			} else {
				/*printf("q %d.\n", tlp_buffer_number((TLPQuadWord *)out->header));*/
				/*puts(tlp_type_str(get_tlp_type(out)));*/
				struct unhandled_tlp_list_entry *entry;
				entry = malloc(sizeof(struct unhandled_tlp_list_entry));
				entry->tlp = *out;
				STAILQ_INSERT_TAIL(
					&unhandled_tlp_list_head, entry, unhandled_tlp_list);
			}
		} else {
			free_raw_tlp_buffer(out);
		}
	}
	/* A bit counter intuitive, but otherwise we might return the trail. */
	alloc_raw_tlp_buffer(out);
	set_raw_tlp_invalid(out);
}
/* Simple wrapper over perform_dma_read to allow reads longer than 512 to
 * be performed: reads happen in chunks.
 */
enum dma_read_response
perform_dma_long_read(uint8_t* buf, uint64_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
{
	int result;
	for (uint64_t i = 0; i < length; i += 512) {
		result = perform_dma_read((buf + i), uint64_min(512, length - i),
			requester_id, tag, (address + i));
		if (result != 0) {
			return result;
		}
	}
	return result;
}

