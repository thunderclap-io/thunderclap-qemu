#include <stdint.h>
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

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	int quad_word_index;
	volatile PCIeStatus statusword;

	log(LS_SEND_LENGTH, LIF_INT_32, tlp_len, true);

	assert(tlp_len / 8 < 64);

	// Stops the TX queue from draining whilst we're filling it.
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);

	int ceil_tlp_len = tlp_len + 7;

	for (quad_word_index = 0; quad_word_index < (ceil_tlp_len / 8);
			++quad_word_index) {
		statusword.word = 0;
		statusword.bits.startofpacket = (quad_word_index == 0);
		statusword.bits.endofpacket =
			((quad_word_index + 1) >= (ceil_tlp_len / 8));

		// Write status word.
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_STATUS,
			statusword.word);
		// Write data
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_DATA,
			tlp[quad_word_index]);
		log(LS_SENDING_DWORD, LIF_UINT_64_HEX, tlp[quad_word_index], true);
	}
	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	record_time();
	log(LS_PACKET_SENT, LIF_NONE, 0, true);

	return 0;
}

void
close_connections()
{
}

