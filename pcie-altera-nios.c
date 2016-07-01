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
 * We acknowledge the support of Arm Ltd.
 * 
 * We acknowledge the support of EPSRC.
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
#include "system.h"
#include "pcie.h"
#include "mask.h"
#include "pcie-debug.h"
#include "pciefpga.h"
#include "beri-io.h"
#include "log.h"

#include "sys/alt_timestamp.h"
#include "io.h"

volatile uint8_t *physmem;
volatile uint8_t *led_phys_mem;

void
initialise_leds()
{
#define LED_BASE		0x7F006000LL
#define LED_LEN			0x1

#ifdef BERIBSD
		led_phys_mem = open_io_region(LED_BASE, LED_LEN);
#else
		led_phys_mem = (volatile uint8_t *) LED_BASE;

#undef LED_LEN
#undef LED_BASE
#endif
}

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem)
{
#ifdef BERIBSD
	*physmem = open_io_region(PCIEPACKET_REGION_BASE, PCIEPACKET_REGION_LENGTH);
#else
	*physmem = (volatile uint8_t *) PCIEPACKET_REGION_BASE;
#endif
	initialise_leds();
	return 0;
}

unsigned long
read_hw_counter()
{
	unsigned long retval;
	retval = alt_timestamp();
	return retval;
}



/* tlp_len is length of the buffer in bytes. */
/* Return -1 if 1024 attempts to poll the buffer fail. */
int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{

	/* Real approach: no POSTGRES */
	volatile PCIeStatus pciestatus;
	volatile TLPDoubleWord pciedata1, pciedata0;
	volatile int ready;
	int i = 0; // i is "length of TLP so far received in doublewords.

	do {
		ready = IORD(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
	} while (ready == 0);

	do {
		pciestatus.word = IORD(PCIEPACKETRECEIVER_0_BASE,
			PCIEPACKETRECEIVER_STATUS);
		// start at the beginning of the buffer once we get start of packet
		if (pciestatus.bits.startofpacket) {
			i = 0;
		}
		pciedata1 = IORD(PCIEPACKETRECEIVER_0_BASE,PCIEPACKETRECEIVER_UPPER32);
		pciedata0 = IORD(PCIEPACKETRECEIVER_0_BASE,PCIEPACKETRECEIVER_LOWER32DEQ);
		tlp[i++] = pciedata0;
		tlp[i++] = pciedata1;
		if ((i * 4) > tlp_len) {
			writeString("TLP RECV OVERFLOW\r\n");
//			PDBG("ERROR: TLP Larger than buffer.");
			return -1;
		}
/*
		write_uint_32_hex(pciestatus.word, ' ');
		write_uint_32(pciestatus.bits.pad1, ' '); putchar('P');
		write_uint_32(pciestatus.bits.byteenable, ' '); putchar('N');
		write_uint_32(pciestatus.bits.startofpacket, ' '); putchar('S');
		write_uint_32(pciestatus.bits.endofpacket, ' '); putchar('Z');
		write_uint_32(pciestatus.bits.pad2, ' '); putchar('p');
		write_uint_32(i,' '); putchar('i');
*/
	} while (!pciestatus.bits.endofpacket);

	return (i * 4);

}

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	int quad_word_index;
	volatile PCIeStatus statusword;
	TLPDoubleWord upperword=0, lowerword=0;

	log(LS_SEND_LENGTH, LIF_INT_32, tlp_len, true);

	assert(tlp_len / 8 < 64);

	// Stops the TX queue from draining whilst we're filling it.
	IOWR(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);

	int ceil_tlp_len = tlp_len + 7;

	for (quad_word_index = 0; quad_word_index < (ceil_tlp_len / 8);
			++quad_word_index) {
		statusword.word = 0;
		statusword.bits.startofpacket = (quad_word_index == 0);
		statusword.bits.endofpacket =
			((quad_word_index + 1) >= (ceil_tlp_len / 8));

		if ((quad_word_index+1) >= tlp_len)
			upperword = 0;
		else
			upperword = (tlp[quad_word_index]>>32);

		lowerword = tlp[quad_word_index] & 0xFFFFFFFF;

		// Write status word.
		IOWR(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_STATUS,
			statusword.word);
		// write upper 32 bits
		IOWR(PCIEPACKETTRANSMITTER_0_BASE,PCIEPACKETTRANSMITTER_UPPER32,
			upperword);
		// write lower 32 bits and send word
		IOWR(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_LOWER32SEND,
			lowerword);
		//printf("Sending upper word %08x lower word %08x status %08x\n", upperword, lowerword, statusword.word);
	}
	// Release queued data
	IOWR(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	record_time();
	log(LS_PACKET_SENT, LIF_NONE, 0, true);

	return 0;
}

void
close_connections()
{
}

