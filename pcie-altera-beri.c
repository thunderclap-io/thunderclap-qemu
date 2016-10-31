#include <stdint.h>
#include <stdio.h>
#include "qemu/bswap.h"
#include "hw/pci/pci.h"
#include "pcie.h"
#include "mask.h"
#include "pcie-debug.h"
#include "pciefpga.h"
#include "beri-io.h"
#include "pcie.h"
#include "pcie-backend.h"
#include "log.h"

static inline bool
is_cpl_d(struct RawTLP *tlp)
{
	assert(tlp->header_length != -1);
	assert(tlp->header != NULL);
	assert(is_raw_tlp_valid(tlp));
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp->header;
	return dword0->type == CPL && tlp_fmt_has_data(dword0->fmt);
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

/* length is in bytes. */
int
perform_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
{
	/* This should be extracted from Max_Read_Request_Size in the Device
	 * Control Register. */

	assert(length > 0);

	uint8_t lastbe = 0xF, firstbe = 0xF;

	assert(buf != NULL);
	assert(address < (1L << 33));
	assert(length < 512);

	TLPQuadWord read_req_tlp_buffer[2];
	struct RawTLP read_req_tlp;
	read_req_tlp.header = (TLPDoubleWord *)read_req_tlp_buffer;

	TLPQuadWord read_resp_tlp_buffer[66];
	struct RawTLP read_resp_tlp;
	set_raw_tlp_invalid(&read_resp_tlp);

	uint16_t ceil_length = calculate_dword_length(length);
	struct byte_enables bes = calculate_bes_for_length(length);

	/*PDBG("length: %d, ceil_length: %d, lastbe: 0x%x, firstbe: 0x%x.",*/
		/*length, ceil_length, lastbe, firstbe);*/

	create_memory_request_header(&read_req_tlp, TLPD_READ,
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
		while (true) {
			wait_for_tlp(read_resp_tlp_buffer, sizeof(read_resp_tlp_buffer),
				&read_resp_tlp);

			if (is_raw_tlp_valid(&read_resp_tlp)) {
				if (is_cpl_d(&read_resp_tlp)) {
					break;
				}
			}
		}

		struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)read_resp_tlp.header;

		assert(tlp_fmt_has_data(dword0->fmt));
		assert(read_resp_tlp.header != NULL);
		assert(read_resp_tlp.data != NULL);

		for (j = 0; j < (dword0->length * sizeof(TLPDoubleWord)) &&
				(i + j) < length; ++j) {
			buf[i + j] = ((uint8_t *)(read_resp_tlp.data))[j];
			/*PDBG("i: %d, j: %d, i + j: %d, buf[i + j]: %d.",*/
				/*i, j, i + j, buf[i + j]);*/
		}

		i += (dword0->length * sizeof(TLPDoubleWord));
		/*PDBG("i: %d. length: %d", i, length);*/
	}

	/*PDBG("Done reading.");*/

	return 0;
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
	assert(address < (1L << 33));

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
			send_dwords / sizeof(TLPDoubleWord), requester_id, tag,
			bes.last, bes.first, address + cursor);
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
		/*if (print)*/
			/*PDBG("4DW M Header. Addr: %x. Aligned? %d.", header[3],*/
				/*(header[3] % 8) == 0);*/
		/* 64 bit address */
		return (header[3] % 8) == 0 ? TDA_ALIGNED : TDA_UNALIGNED;
	} else {
		/*if (print)*/
			/*PDBG("3DW M Header. Addr: %x. Aligned? %d.", header[2],*/
				/*(header[2] % 8) == 0);*/
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
	} while (ready == 0 && retry_attempt < 1000);

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

	assert(tlp->header_length == 12 || tlp->header_length == 16);

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
