#include <stdint.h>
#include "qemu/bswap.h"
#include "pcie.h"
#include "mask.h"
#include "pcie-debug.h"
#include "pciefpga.h"
#include "beri-io.h"
#include "pcie-backend.h"
#include "log.h"

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



/* tlp_len is length of the buffer in bytes. */
/* Return -1 if 1024 attempts to poll the buffer fail. */
int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	/* Real approach: no POSTGRES */
	volatile PCIeStatus pciestatus;
	volatile TLPQuadWord pciedata;
	volatile int ready;
	int i = 0; // i is "length of TLP so far received in doublewords.

	do {
		ready = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
	} while (ready == 0);

	do {
		pciestatus.word = IORD64(PCIEPACKETRECEIVER_0_BASE,
			PCIEPACKETRECEIVER_STATUS);
		// start at the beginning of the buffer once we get start of packet
		if (pciestatus.bits.startofpacket) {
			i = 0;
		}
		pciedata = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		tlp[i++] = pciedata;
		if ((i * 8) > tlp_len) {
//			PDBG("ERROR: TLP Larger than buffer.");
			puts("TLP RECV OVERFLOW\r\n");
			return -1;
		}
	} while (!pciestatus.bits.endofpacket);

	return (i * 8);

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
send_tlp(TLPQuadWord *header, int header_len, TLPQuadWord *data, int data_len,
	enum tlp_data_alignment data_alignment)
{
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
	TLPQuadWord sendqword;
	TLPDoubleWord *data_dword = (TLPDoubleWord *)data;

	// Stops the TX queue from draining whilst we're filling it.
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);

	statusword.word = 0;
	statusword.bits.startofpacket = 1;
	WR_STATUS(statusword.word);
	WR_DATA(bswap32_within_64(header[0]));

	statusword.word = 0;

	if (header_len == 12 && data_alignment == TDA_UNALIGNED) {
		/* Because this is big endian, the bits of the dword with the smallest
		 * offset are the most significant. The header word has the smallest
		 * offset from the start, so has to be shifted in to the most
		 * significant bits.
		 */
		/*TLPDoubleWord merge_data = (TLPDoubleWord)(data[0] & 0xFFFFFFFFLL);*/
		/*merge_data = bswap32(merge_data);*/

		TLPDoubleWord header_dword = header[1] >> 32;
		sendqword = (TLPQuadWord)(bswap32(header[1] >> 32)) << 32;
		if (data_len > 0) {
			/*sendqword |= merge_data;*/
			sendqword |= bswap32((TLPDoubleWord)data[0]);
		}
		statusword.bits.endofpacket = (data_len <= 4);
		WR_STATUS(statusword.word);
		WR_DATA(sendqword);
		for (byte_index = 4; byte_index < data_len; byte_index += 8) {
			while (1) {
				printf("PROBABLY BROKEN LOOP!");
				for (int i = 0; i < 100000; ++i) {
					asm("nop");
				}
			}
			statusword.bits.endofpacket = ((byte_index + 8) >= data_len);
			sendqword = (TLPQuadWord)(data_dword[byte_index / 4]) << 32;
			sendqword |= data_dword[(byte_index / 4) + 1];
			WR_STATUS(statusword.word);
			WR_DATA(sendqword);
		}
	} else {
		statusword.bits.endofpacket = (data_len == 0);
		WR_STATUS(statusword.word);
		WR_DATA(bswap32_within_64(header[1]));
		for (byte_index = 0; byte_index < data_len; byte_index += 8) {
			statusword.bits.endofpacket = ((byte_index + 8) >= data_len);
			WR_STATUS(statusword.word);
			WR_DATA(data[byte_index / 8]);
		}
	}

	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	/*if (header_len == 12 && data_alignment == TDA_UNALIGNED) {*/
		/*printf("data[0]: 0x%0lx. sendqword: 0x%0lx. data_len: %d. \n",*/
			/*data[0], sendqword, data_len);*/
		/*[>printf("Took special path.\n");<]*/
		/*[>printf("Last sendqword was: %lx.\n", sendqword);<]*/
		/*[>printf("data_len was: %d. endofpacket?: %d\n", data_len,<]*/
			/*[>statusword.bits.endofpacket);<]*/
	/*}*/

	return 0;
#undef WR_STATUS
#undef WR_DATA
}

void
close_connections()
{
}
