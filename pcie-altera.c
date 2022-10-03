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

#include <stdint.h>
#include <stdio.h>
#include "qemu/bswap.h"
#include "hw/pci/pci.h"
#include "pcie.h"
#include "mask.h"
#include "pcie-debug.h"
#include "pciefpga.h"
#include "peripheral-io.h"
#include "pcie.h"
#include "pcie-backend.h"
#include "log.h"

volatile uint8_t *led_phys_mem;

static inline uint64_t
bswap32_within_64(uint64_t input)
{
	uint32_t low_word = bswap32((uint32_t)input);
	uint32_t high_word = bswap32((uint32_t)(input >> 32));
	return ((uint64_t)(high_word) << 32) | low_word;
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

static inline uint64_t
uint64_min(uint64_t left, uint64_t right)
{
	return (left < right) ? left : right;
}

static inline enum tlp_data_alignment
tlp_get_alignment_from_header(TLPDoubleWord *header)
{
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)header;
	if ((tlp_get_type(dword0) == M || tlp_get_type(dword0) == M_LK) &&
		tlp_fmt_is_4dw(tlp_get_fmt(dword0))) {
/*		if (print)
			printf("4DW M Header. Addr: %x. Aligned? %d.", header[3],
				(header[3] % 8) == 0);
*/		/* 64 bit address */
		return (header[3] % 8) == 0 ? TDA_ALIGNED : TDA_UNALIGNED;
	} else {
/*		if (print)
			printf("3DW M Header. Addr: %x. Aligned? %d.", header[2],
				(header[2] % 8) == 0);
*/		/* Lower bits of relevant address are always in the same place. */
		return (header[2] % 8) == 0 ? TDA_ALIGNED : TDA_UNALIGNED;
	}
}


/* tlp_len is length of the buffer in bytes. */
/* This is non block -- will return if nothing to do, because the main loop
 * has to be interspersed with. */
void
wait_for_tlp(TLPQuadWord *buffer, int buffer_len, struct RawTLP *out)
{
	/* Real approach: no POSTGRES */
	uint64_t ready, status;
	TLPQuadWord pciedata;
	int i = 0; // i is "length of TLP so far received in doublewords.
	int retry_attempt = 0;
	fflush(stdout);
	do {
		ready = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
//		printf("%d: %016llx", ready);
		++retry_attempt;
	} while (ready == 0 && retry_attempt < 1000);

	if (!ready) {
		set_raw_tlp_invalid(out);
		return;
	}

//	puts("About to read status.");

	do {
		status = IORD64(PCIEPACKETRECEIVER_0_BASE,
			PCIEPACKETRECEIVER_STATUS);
//		printf("s=%016llx", status);
//		fflush(stdout);
		// start at the beginning of the buffer once we get start of packet
		if (status_get_start_of_packet(status)) {
			i = 0;
		}
//		puts("About to read data.");
		pciedata = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);

#ifdef PLATFORM_ARM
        // Empirical results suggest...
//		pciedata = bswap32_within_64(pciedata);
#endif

//		printf("%d: %016llx", i, pciedata);
		buffer[i++] = pciedata;
//		printf(" (%016llx)\n", buffer[i-1]);
//		print_tlp_dwords(pciedata);
		if ((i * 8) > buffer_len) {
			puts("TLP RECV OVERFLOW");
			set_raw_tlp_invalid(out);
			return;
		}
	} while (!status_get_end_of_packet(status));

	/* There isn't a great way to deal with the fact that the PCIe core moves
	 * data around depending on the address of the data. As we would rather
	 * not have higher layers understand, the recieve function needs to know
	 * an unfortunate amount about the semantics of the TLP.
	 */

	out->header = (TLPDoubleWord *)buffer;
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)out->header;
//	printf("fmt: %x\n", tlp_get_fmt(dword0));

	switch (tlp_get_fmt(dword0)) {
	case TLPFMT_3DW_NODATA:
	case TLPFMT_3DW_DATA:
		out->header_length = 12;
		break;
	case TLPFMT_4DW_NODATA:
	case TLPFMT_4DW_DATA:
		out->header_length = 16;
		break;
	default:
		assert(false);
	}

	/* The TLPs that carry data are Memory Write, Memory Write Locked, IO
	 * Write, Config Write Types 0 and 1, Completion with Data, Completion
	 * with Data Locked. */

	if (tlp_fmt_has_data(tlp_get_fmt(dword0))) {
		if (tlp_get_alignment_from_header(out->header) == TDA_ALIGNED) {
			out->data = out->header + 4;
		} else {
			if (tlp_fmt_is_4dw(tlp_get_fmt(dword0))) {
				out->data = out->header + 5;
			} else {
				out->data = out->header + 3;
			}
		}
	} else {
		out->data = NULL;
		out->data_length = 0;
	}
}


void
initialise_leds()
{
#define LED_BASE		0x7F006000LL
#define LED_LEN			0x1

	led_phys_mem = open_io_region(LED_BASE, LED_LEN);

#undef LED_LEN
#undef LED_BASE
}

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem)
{
	*physmem = open_io_region(PCIEPACKET_REGION_BASE, PCIEPACKET_REGION_LENGTH);
	/*initialise_leds();*/
	return 0;
}

void
drain_pcie_core()
{
	fflush(stdout);
	while (IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY)) {
		IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_STATUS);
		IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		for (int i = 0; i < (1 << 10); ++i) {
			asm("nop");
		}
	}
}

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(struct RawTLP *tlp)
{
	/* XXX: This function used to take quad word pointers -- now it takes a
	 * raw_tlp, and makes assumptions about alignment. It should be
	 * reconstructed. It is potentially an unsafe cast.
	 */

	 fflush(stdout);
	/* Special case for:
	 * 3DW, Unaligned data. Send qword of remaining header dword, first data.
	 *   Construct qwords from unaligned data and send.
	 */
#define WR_STATUS(STATUS) \
	do {																	\
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_STATUS,	\
			STATUS);														\
	} while (0)
		//printf("status:=%#016llx ", STATUS);	\

#define WR_DATA(DATA) \
	do {																	\
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_DATA,	\
			DATA);										\
	} while (0)
		//printf("data:=%#016llx ", DATA);	\

	int byte_index;
	uint64_t status = status_set_start_of_packet(0);
	TLPQuadWord *header = (TLPQuadWord *)tlp->header;
	TLPDoubleWord *data = tlp->data;
	TLPQuadWord sendqword;

	enum tlp_data_alignment data_alignment =
		tlp_get_alignment_from_header(tlp->header);
/*
	printf("Header len=%d, data len=%d, align=%x\n", tlp->header_length, tlp->data_length,
		data_alignment);
	for (int i=0; i < (tlp->header_length+7)/8; i++) {
		printf("%#16llx ", header[i]);
	}
	printf("\n");

	printf("Disabling queue.\n");
*/
	// Stops the TX queue from draining whilst we're filling it.
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);
	//IOWR(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_UPPER32, 1);



	sendqword = header[0];
/*#ifdef PLATFORM_ARM
	sendqword = header[0];
#else
	sendqword = bswap32_within_64(header[0]);
#endif
*/
//	printf("Sending first header %#016llx.\n", sendqword);
//	usleep(1000);
	WR_STATUS(status);
	WR_DATA(sendqword);
//	putchar('\n');

	status = 0;

	assert(tlp->header_length == 12 || tlp->header_length == 16);

//	data_alignment = TDA_UNALIGNED; // FIXME
	if (tlp->header_length == 12 && data_alignment == TDA_UNALIGNED) {
		/* Because this is big endian, the bits of the dword with the smallest
		 * offset are the most significant. The header word has the smallest
		 * offset from the start, so has to be shifted in to the most
		 * significant bits.
		 */
		/*TLPDoubleWord merge_data = (TLPDoubleWord)(data[0] & 0xFFFFFFFFLL);*/
		/*merge_data = bswap32(merge_data);*/
//		printf("Sending unaligned third header dword %#016llx.\n", header[1]);

		sendqword = header[1];
/*#ifdef PLATFORM_ARM
		sendqword = header[1];
#else
		sendqword = (TLPQuadWord)(bswap32(header[1] >> 32)) << 32;
#endif*/

		if (tlp->data_length > 0) {
			sendqword = data32_to_64(data64_get_first32(header[1]), tlp->data[0]);
		}
		if (tlp->data_length <= 4) {
//			printf("It's EOP.\n");
			status = status_set_end_of_packet(status);
		}
		WR_STATUS(status);
		WR_DATA(sendqword);
//		putchar('\n');
		/* XXX THIS MIGHT NOT WORK XXX */
		for (byte_index = 4; byte_index < tlp->data_length; byte_index += 8) {
			if ((byte_index + 8) >= tlp->data_length) {
				status_set_end_of_packet(status);
			}
			sendqword = data32_to_64(tlp->data[byte_index / 4], tlp->data[byte_index / 4] + 1);
//			sendqword = (TLPQuadWord)(tlp->data[byte_index / 4]) << 32;
//			sendqword |= tlp->data[(byte_index / 4) + 1];
			WR_STATUS(status);
			WR_DATA(sendqword);
		}
	} else {
		if (tlp->data_length == 0) {
//			printf("eop\n");
			status = status_set_end_of_packet(status);
		}

		sendqword = header[1];
		// if we have a 3DW header, clear the 4th word
		if (tlp->header_length == 12) {
//			sendqword = header[1] & 0xffffffffLL;
			TLPDoubleWord firstdata32 = 0xc0dcafe;
			// we shouldn't need to send any data here, but is seems the doc lies
/*			if (tlp->data_length > 0) {
				firstdata32 = data[0];
//				sendqword |= (data[0] & 0xffffffffLL)<<32LL;
				tlp->data_length -= 4;
				if (tlp->data_length == 0) {
					printf("wrong eop\n");
					status = status_set_end_of_packet(status);
				}

//			} else {
//				sendqword |= 0xc0dcafe00000000;

			}
*/
			sendqword = data32_to_64(data64_get_first32(header[1]), firstdata32);

		}
/*#ifdef PLATFORM_ARM
		sendqword = header[1];
#else
		sendqword = bswap32_within_64(header[1]);
#endif*/
		WR_STATUS(status);

		WR_DATA(sendqword);
//		printf("\nSending first data word %#016llx, status=%#016llx\n", sendqword, status);
		status = 0;

		for (byte_index = 0; byte_index < tlp->data_length; byte_index += 8) {
			if ((byte_index + 8) >= tlp->data_length) {
//				printf("eop\n");
				status = status_set_end_of_packet(status);
			}
			sendqword = data32_to_64(tlp->data[byte_index / 4], tlp->data[byte_index / 4] + 1);
//			sendqword = data[byte_index / 8];
			if ((tlp->data_length - byte_index) == 4) {
				// clear the second Dword if we only have one to send
				sendqword = data32_to_64(tlp->data[byte_index / 4], 0);
//				sendqword = sendqword & 0xffffffffLL;
//				sendqword |= 0xdeadbeef00000000;
			}
			WR_STATUS(status);
			WR_DATA(sendqword);
//			printf("\nSending %d th data word %#016llx, status=%#016llx\n", byte_index/8, sendqword, status);
		}
	}
	fflush(stdout);
	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	return 0;
#undef WR_STATUS
#undef WR_DATA
}

static inline enum dma_read_response
_perform_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, enum tlp_at at, uint64_t address)
{
	/* This should be extracted from Max_Read_Request_Size in the Device
	 * Control Register. */

	enum dma_read_response return_value = DRR_SUCCESS;

	assert(length > 0);
	if (length > 512) {
		printf("Bad dma read.\n");
	}
	assert(length <= 512);
	assert(buf != NULL);

	TLPQuadWord read_req_tlp_buffer[2];
	struct RawTLP read_req_tlp;
	read_req_tlp.header = (TLPDoubleWord *)read_req_tlp_buffer;

	struct RawTLP read_resp_tlp;
	set_raw_tlp_invalid(&read_resp_tlp);
	struct TLP64DWord0 *read_resp_dword0;
	struct TLP64CompletionDWord1 *read_resp_dword1;

	uint16_t ceil_length = calculate_dword_length(length);
	struct byte_enables bes = calculate_bes_for_length(length);

	/*PDBG("length: %d, ceil_length: %d, lastbe: 0x%x, firstbe: 0x%x.",*/
		/*length, ceil_length, lastbe, firstbe);*/
	struct TLP64DWord0 *dword0;

	create_memory_request_header(&read_req_tlp, TLPD_READ, at,
		ceil_length / 4, requester_id, tag, bes.last, bes.first,
		address);
	int send_result = send_tlp(&read_req_tlp);
	assert(send_result != -1);

	/* i is total amount of data read; j is data from specific completion.
	 * Data for long reads (more than 32 dwords) will come back as multiple
	 * completions.
	 */
	int i = 0, j;

	while (i < length) {
		next_completion_tlp(&read_resp_tlp);

		if (!is_raw_tlp_valid(&read_resp_tlp)) {
			free_raw_tlp_buffer(&read_resp_tlp);
			return DRR_NO_RESPONSE;
		}

		assert(&read_resp_tlp != NULL);
		assert(read_resp_tlp.header != NULL);
		assert(read_resp_tlp.header_length != -1);
		assert(is_raw_tlp_valid(&read_resp_tlp));

		read_resp_dword0 = (struct TLP64DWord0 *)(read_resp_tlp.header);
		assert(tlp_get_type(read_resp_dword0) == CPL);

		read_resp_dword1 = (struct TLP64CompletionDWord1 *)(
			read_resp_tlp.header + 1);

		if (tlp_get_status(read_resp_dword1) == TLPCS_UNSUPPORTED_REQUEST) {
			free_raw_tlp_buffer(&read_resp_tlp);
			return DRR_UNSUPPORTED_REQUEST;
		}

		dword0 = (struct TLP64DWord0 *)read_resp_tlp.header;

		assert(tlp_fmt_has_data(tlp_get_fmt(dword0)));

		for (j = 0; j < (tlp_get_length(dword0) * sizeof(TLPDoubleWord)) &&
				(i + j) < length; ++j) {
			buf[i + j] = ((uint8_t *)(read_resp_tlp.data))[j];
			/*PDBG("i: %d, j: %d, i + j: %d, buf[i + j]: %d.",*/
				/*i, j, i + j, buf[i + j]);*/
		}

		i += (tlp_get_length(dword0) * sizeof(TLPDoubleWord));

		/*if (dword0->length != 1) {*/
			/*printf("Non standard completion packet; i is now %d.\n", i);*/
		/*}*/
		/*PDBG("i: %d. length: %d", i, length);*/
		free_raw_tlp_buffer(&read_resp_tlp);
	}
	/*if (dword0->length != 1) {*/
		/*puts("Done!");*/
	/*}*/

	/*PDBG("Done reading.");*/

	return return_value;
}

enum dma_read_response
perform_translated_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
{
	return _perform_dma_read(buf, length, requester_id, tag, TLP_AT_TRANSLATED,
		address);
}


enum dma_read_response
perform_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
{
	return _perform_dma_read(buf, length, requester_id, tag,
		TLP_AT_UNTRANSLATED, address);
}


/*
 * We should handle tags with more sophistication than we do -- each part of
 * the core should use a specific tag, but this would require modifying calls
 * to pci_dma_read. For tags see page 88 of the manual. I use 8, which is the
 * transmit side reading from memory.
 */
int
pci_dma_read(PCIDevice *dev, dma_addr_t addr, void *buf, dma_addr_t len)
{
	return perform_dma_read((uint8_t *)buf, len, dev->devfn, 8, addr);
}

int
perform_dma_write(const uint8_t* buf, int16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
{
	const uint16_t SEND_LIMIT = 128; /* bytes */
	TLPQuadWord write_req_header_buffer[2];
	TLPQuadWord *write_data = aligned_alloc(8, ((length + 7) / 8) * 8);
	/* TODO: Only do this if the data is confirmed to be misaligned. */

	for (int i = 0; i < length; ++i) {
		((uint8_t *)write_data)[i] = ((const uint8_t *)buf)[i];
	}

	uint16_t send_amount, send_dwords, left_to_send, cursor = 0;
	uint16_t dword_length = calculate_dword_length(length);

	struct RawTLP write_req_tlp;
	write_req_tlp.header = (TLPDoubleWord *)write_req_header_buffer;

	do {
		write_req_tlp.data = (TLPDoubleWord *)(write_data +
			cursor / sizeof(TLPQuadWord));
		left_to_send = length - cursor;
		send_amount = left_to_send < SEND_LIMIT ? left_to_send : SEND_LIMIT;
		struct byte_enables bes = calculate_bes_for_length(send_amount);
		send_dwords = calculate_dword_length(send_amount);
		create_memory_request_header(&write_req_tlp, TLPD_WRITE,
			TLP_AT_UNTRANSLATED, send_dwords / sizeof(TLPDoubleWord),
			requester_id, tag, bes.last, bes.first, address + cursor);
		int send_result = send_tlp(&write_req_tlp);
		assert(send_result != -1);
		cursor += send_dwords;
	} while (cursor < dword_length);

	free(write_data);
	return 0;
}

int
pci_dma_write(PCIDevice *dev, dma_addr_t addr, const void *buf, dma_addr_t len)
{
	return perform_dma_write(buf, len, dev->devfn, 0, addr);
}

void
close_connections()
{
}
