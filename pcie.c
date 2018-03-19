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

#include "pcie.h"
#include "pcie-debug.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* length is used as the PCIe field, so is in DWords i.e. units of 32 bits. */
void
create_completion_header(struct RawTLP *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress)
{
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp->header[0] = 0;
	tlp->header[1] = 0;
	tlp->header[2] = 0;

	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)(tlp->header);
	if (direction == TLPD_READ
		&& completion_status == TLPCS_SUCCESSFUL_COMPLETION) {
		header0->fmt = TLPFMT_3DW_DATA;
		header0->length = 1;
	} else {
		header0->fmt = TLPFMT_3DW_NODATA;
		header0->length = 0;
	}
	header0->type = CPL;

	struct TLP64CompletionDWord1 *header1 =
		(struct TLP64CompletionDWord1 *)(tlp->header) + 1;
	header1->completer_id = completer_id;
	header1->status = completion_status;
	header1->bytecount = bytecount;

	struct TLP64CompletionDWord2 *header2 =
		(struct TLP64CompletionDWord2 *)(tlp->header) + 2;
	header2->requester_id = requester_id;
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

	dword0->fmt = 0;
	if (tlp->header_length == 16) {
		dword0->fmt |= TLPFMT_4DW;
	}
	if (direction == TLPD_WRITE) {
		dword0->fmt |= TLPFMT_WITHDATA;
	}
	dword0->at = at;
	dword0->length = length;
	dword0->type = M;

	request_dword1->requester_id = requester_id;
	request_dword1->tag = tag;
	request_dword1->lastbe = lastbe;
	request_dword1->firstbe = firstbe;

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

	if (direction == TLPD_WRITE) {
		dword0->fmt |= TLPFMT_WITHDATA;
	}
	dword0->type = CFG_0;
	dword0->length = 1;
	dword1->requester_id = requester_id;
	dword1->tag = tag;
	dword1->firstbe = firstbe;
	dword2->device_id = devfn;
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

