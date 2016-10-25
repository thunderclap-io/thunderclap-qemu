#include <stdint.h>
#include <stdio.h>
#include "qemu/bswap.h"
#include "hw/pci/pci.h"
#include "pcie.h"
#include "mask.h"
#include "pcie-debug.h"
#include "pciefpga.h"
#include "beri-io.h"
#include "pcie-backend.h"
#include "log.h"

/*
 * We should handle tags with more sophistication than we do -- each part of
 * the core should use a specific tag, but this would require modifying calls
 * to pci_dma_read. For tags see page 88 of the manual. I use 8, which is the
 * transmit side reading from memory.
 */
int pci_dma_read(PCIDevice *dev, dma_addr_t addr, void *buf, dma_addr_t len)
{
	assert(addr < (1L << 33));
	assert(len < 512);
	/* This should be extracted from Max_Read_Request_Size in the Device
	 * Control Register. */

	TLPQuadWord read_req_tlp_buffer[2];
	struct RawTLP read_req_tlp;
	read_req_tlp.header = (TLPDoubleWord *)read_req_tlp_buffer;

	TLPQuadWord read_resp_tlp_buffer[66];
	struct RawTLP read_resp_tlp;
	set_raw_tlp_invalid(&read_resp_tlp);

	create_memory_request_header(&read_req_tlp, TLPD_READ, len, dev->devfn, 8,
		0xFF, 0xFF, addr);
	int send_result = send_tlp(&read_req_tlp);
	assert(send_result != -1);

	do {
		wait_for_tlp(read_resp_tlp_buffer, sizeof(read_resp_tlp_buffer),
			&read_resp_tlp);
	} while (!is_raw_tlp_valid(&read_resp_tlp));

	for (int i = 0; i < len; ++i) {
		((uint8_t *)buf)[i] = ((uint8_t *)(read_resp_tlp.data))[i];
	}

	return 0;
}

int pci_dma_write(PCIDevice *dev, dma_addr_t addr, const void *buf,
	dma_addr_t len)
{
	assert(addr < (1L << 33));

	TLPQuadWord write_req_header_buffer[2];
	TLPQuadWord *write_data = malloc(len);

	for (int i = 0; i < len; ++i) {
		((uint8_t *)write_data)[i] = ((const uint8_t *)buf)[i];
	}

	struct RawTLP write_req_tlp;
	write_req_tlp.header = (TLPDoubleWord *)write_req_header_buffer;
	write_req_tlp.data = (TLPDoubleWord *)write_data;
	write_req_tlp.data_length = len;

	create_memory_request_header(&write_req_tlp, TLPD_WRITE, len, dev->devfn,
		0, 0xFF, 0xFF, addr);
	int send_result = send_tlp(&write_req_tlp);
	assert(send_result != -1);

	free(write_data);
	return 0;
}

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
	asm volatile("rdhwr %0, $2"
		: "=r"(retval));
	return retval;
}

static inline enum tlp_data_alignment
tlp_get_alignment_from_header(TLPDoubleWord *header)
{
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)header;
	if ((dword0->type == M || dword0->type == M_LK) &&
		tlp_fmt_is_4dw(dword0->fmt)) {
		/* 64 bit address */
		return (header[3] % 8) == 0 ? TDA_ALIGNED : TDA_UNALIGNED;
	} else {
		/* Lower bits of relevant address are always in the same place. */
		return (header[2] % 8) == 0 ? TDA_ALIGNED : TDA_UNALIGNED;
	}
}

/* tlp_len is length of the buffer in bytes. */
/* This is non block -- will return if nothing to do, because the main loop
 * has to be interspersed with. */
void
wait_for_tlp(volatile TLPQuadWord *buffer, int buffer_len, struct RawTLP *out)
{
	/* Real approach: no POSTGRES */
	volatile PCIeStatus pciestatus;
	volatile TLPQuadWord pciedata;
	volatile int ready;
	int i = 0; // i is "length of TLP so far received in doublewords.
	int retry_attempt = 0;

	do {
		ready = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
		++retry_attempt;
	} while (ready == 0 && retry_attempt < 10000);

	if (!ready) {
		set_raw_tlp_invalid(out);
		return;
	}

	do {
		pciestatus.word = IORD64(PCIEPACKETRECEIVER_0_BASE,
			PCIEPACKETRECEIVER_STATUS);
		// start at the beginning of the buffer once we get start of packet
		if (pciestatus.bits.startofpacket) {
			i = 0;
		}
		pciedata = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		buffer[i++] = pciedata;
		if ((i * 8) > buffer_len) {
			puts("TLP RECV OVERFLOW\r\n");
			set_raw_tlp_invalid(out);
			return;
		}
	} while (!pciestatus.bits.endofpacket);

	/* There isn't a great way to deal with the fact that the PCIe core moves
	 * data around depending on the address of the data. As we would rather
	 * not have higher layers understand, the recieve function needs to know
	 * an unfortunate amount about the semantics of the TLP.
	 */

	out->header = (TLPDoubleWord *)buffer;
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)out->header;

	switch (dword0->fmt) {
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

	bool aligned;
	if (tlp_fmt_has_data(dword0->fmt)) {
		if (tlp_get_alignment_from_header(out->header) == TDA_ALIGNED) {
			out->data = out->header + 4;
		} else {
			if (tlp_fmt_is_4dw(dword0->fmt)) {
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
drain_pcie_core()
{
	while (IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY)) {
		IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_STATUS);
		IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		for (int i = 0; i < (1 << 10); ++i) {
			asm("nop");
		}
	}
}

static inline uint64_t
bswap32_within_64(uint64_t input)
{
	uint32_t low_word = bswap32((uint32_t)input);
	uint32_t high_word = bswap32((uint32_t)(input >> 32));
	return ((uint64_t)(high_word) << 32) | low_word;
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

	/* Special case for:
	 * 3DW, Unaligned data. Send qword of remaining header dword, first data.
	 *   Construct qwords from unaligned data and send.
	 */
#define WR_STATUS(STATUS) \
	do {																	\
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_STATUS,	\
			STATUS);														\
	} while (0)

#define WR_DATA(DATA) \
	do {																	\
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_DATA,	\
			DATA);										\
	} while (0)

	int byte_index;
	volatile PCIeStatus statusword;
	TLPQuadWord *header = (TLPQuadWord *)tlp->header;
	TLPQuadWord *data = (TLPQuadWord *)tlp->data;
	TLPQuadWord sendqword;

	enum tlp_data_alignment data_alignment =
		tlp_get_alignment_from_header(tlp->header);

	// Stops the TX queue from draining whilst we're filling it.
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);

	statusword.word = 0;
	statusword.bits.startofpacket = 1;
	WR_STATUS(statusword.word);
	WR_DATA(bswap32_within_64(header[0]));

	statusword.word = 0;

	if (tlp->header_length == 12 && data_alignment == TDA_UNALIGNED) {
		/* Because this is big endian, the bits of the dword with the smallest
		 * offset are the most significant. The header word has the smallest
		 * offset from the start, so has to be shifted in to the most
		 * significant bits.
		 */
		/*TLPDoubleWord merge_data = (TLPDoubleWord)(data[0] & 0xFFFFFFFFLL);*/
		/*merge_data = bswap32(merge_data);*/

		TLPDoubleWord header_dword = header[1] >> 32;
		sendqword = (TLPQuadWord)(bswap32(header[1] >> 32)) << 32;
		if (tlp->data_length > 0) {
			sendqword |= tlp->data[0];
		}
		statusword.bits.endofpacket = (tlp->data_length <= 4);
		WR_STATUS(statusword.word);
		WR_DATA(sendqword);
		for (byte_index = 4; byte_index < tlp->data_length; byte_index += 8) {
			while (1) {
				printf("PROBABLY BROKEN LOOP!");
				for (int i = 0; i < 100000; ++i) {
					asm("nop");
				}
			}
			statusword.bits.endofpacket =
				((byte_index + 8) >= tlp->data_length);
			sendqword = (TLPQuadWord)(tlp->data[byte_index / 4]) << 32;
			sendqword |= tlp->data[(byte_index / 4) + 1];
			WR_STATUS(statusword.word);
			WR_DATA(sendqword);
		}
	} else {
		statusword.bits.endofpacket = (tlp->data_length == 0);
		WR_STATUS(statusword.word);
		WR_DATA(bswap32_within_64(header[1]));
		for (byte_index = 0; byte_index < tlp->data_length; byte_index += 8) {
			statusword.bits.endofpacket = ((byte_index + 8) >= tlp->data_length);
			WR_STATUS(statusword.word);
			WR_DATA(data[byte_index / 8]);
		}
	}

	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	return 0;
#undef WR_STATUS
#undef WR_DATA
}

void
close_connections()
{
}
