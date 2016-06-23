/*
 * Device classes seem to be constructed using type_init. This is a call to
 * module_init(*, MODULE_INIT_QOM)
 *
 * Macros in qemu/module.h
 * __attribute__((constructor_)), means the function will be called by default
 * before entering main. Horrible horrible horrible!
 *
 * So, register_dso_module_init(e1000_register_types, MODULE_INIT_QOM) will
 * get called. This sets up a list of "dso_inits".
 *
 * This places the function onto a list of functions, with MODULE_INIT_QOM
 * attached. At some point, this function is presumably called.
 *
 * Function for adding a device from the command line is qdev_device_add in
 * qdev-monitor.c
 *
 * I use a bunch of initialisation functions from hw/i386/pc_q35.c to get the
 * appropriate busses set up -- the main initialisation function is called
 * pc_q35_init, and I am slowly cannibalising it.
 */

#include "parameters.h"

#include "pcie.h"
#include "pcie-debug.h"
#include "pciefpga.h"
#include "beri-io.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BUTTONS (0x900000007F009000ULL)

#define IO_RD_BYTE(x) (*(volatile unsigned char*)(x))
#define IO_RD(x) (*(volatile unsigned long long*)(x))
#define IO_RD32(x) (*(volatile int*)(x))
#define IO_WR(x, y) (*(volatile unsigned long long*)(x) = y)
#define IO_WR_BYTE(x, y) (*(volatile unsigned char*)(x) = y)


static void
writeUARTChar(char c)
{
	//Code for SOPC Builder serial output
	while ((IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE)+4) &
	    0xFFFF) == 0) {
		asm("add $v0, $v0, $0");
	}
	//int i;
	//for (i=0;i<10000;i++);
	IO_WR_BYTE(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE), c);
}

static void
writeString(char* s)
{
	while(*s)
	{
		writeUARTChar(*s);
		++s;
	}
}

void
writeHex(unsigned long long n)
{
	unsigned int i;
	for(i = 0;i < 16; ++i)
	{
		unsigned long long hexDigit = (n & 0xF000000000000000L) >> 60L;
//		unsigned long hexDigit = (n & 0xF0000000L) >> 28L;
		char hexDigitChar = (hexDigit < 10) ? ('0' + hexDigit) : ('A' + hexDigit - 10);
		writeUARTChar(hexDigitChar);
		n = n << 4;
	}
}

void
writeDigit(unsigned long long n)
{
	unsigned int i;
	unsigned int top;
	char tmp[17];
	char str[17];
	
	for(i = 0;i < 17; ++i) str[i] = 0;
	i = 0;
	while(n > 0) {
		tmp[i] = '0' + (n % 10);
		n /= 10;
		i = i + 1;
	}
	i--;
	top = i;
	while(i > 0) {
		str[top - i] = tmp[i];
		i--;
	}
	str[top] = tmp[0];
	writeString(str);
}

char
readUARTChar()
{
	int i;
	char out;
	i = IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE));
	while((i & 0x00800000) == 0)
	{
		i = IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE));
	}
	
	i = i >> 24;
	out = (char)i;
	return out;
}

static unsigned long
read_hw_counter()
{
	unsigned long retval;
	asm volatile("rdhwr %0, $2"
		: "=r"(retval));
	return retval;
}

#define TIME_POINTS 64
char markers[TIME_POINTS];
unsigned long times[TIME_POINTS];

static void
print_times()
{
	writeUARTChar(markers[0]);
	writeUARTChar(' ');
	writeDigit(times[0]);
	writeUARTChar('\n');
	for (int i = 1; i < TIME_POINTS; ++i) {
		writeUARTChar(markers[i]);
		writeUARTChar(' ');
		writeDigit(times[i]);
		writeUARTChar(' ');
		writeDigit(times[i] - times[i-1]);
		writeUARTChar('\n');
	}
}

static inline void
record_time(char marker)
{
	static int next_point = 0;
	markers[next_point] = marker;
	times[next_point] = read_hw_counter();
	next_point = (next_point + 1) % TIME_POINTS;
	if (next_point == 0) {
		print_times();
	}
}


/* tlp_len is length of the buffer in bytes. */
/* Return -1 if 1024 attempts to poll the buffer fail. */
int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
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
		pciedata = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		tlp[i++] = pciedata;
		if ((i * 8) > tlp_len) {
			PDBG("ERROR: TLP Larger than buffer.");
			return -1;
		}
	} while (!pciestatus.bits.endofpacket);

	record_time('R');

	return (i * 8);
}

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	int quad_word_index;
	volatile PCIeStatus statusword;

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
	}
	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	record_time('S');

	return 0;
}


static inline void
create_completion_header(volatile TLPDoubleWord *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress)
{
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp[0] = 0;
	tlp[1] = 0;
	tlp[2] = 0;

	volatile struct TLP64DWord0 *header0 = (volatile struct TLP64DWord0 *)(tlp);
	if (direction == TLPD_READ
		&& completion_status == TLPCS_SUCCESSFUL_COMPLETION) {
		header0->fmt = TLPFMT_3DW_DATA;
		header0->length = 1;
	} else {
		header0->fmt = TLPFMT_3DW_NODATA;
		header0->length = 0;
	}
	header0->type = CPL;

	volatile struct TLP64CompletionDWord1 *header1 =
		(volatile struct TLP64CompletionDWord1 *)(tlp) + 1;
	header1->completer_id = completer_id;
	header1->status = completion_status;
	header1->bytecount = bytecount;

	volatile struct TLP64CompletionDWord2 *header2 =
		(volatile struct TLP64CompletionDWord2 *)(tlp) + 2;
	header2->requester_id = requester_id;
	header2->tag = tag;
	header2->loweraddress = loweraddress;
}

volatile uint8_t *led_phys_mem;

void
initialise_leds()
{
#define LED_BASE		0x7F006000LL
#define LED_LEN			0x1

		led_phys_mem = open_io_region(LED_BASE, LED_LEN);

#undef LED_LEN
#undef LED_BASE
}

static inline void
write_leds(uint8_t data)
{
	*led_phys_mem = ~data;
}

int
main(int argc, char *argv[])
{
	physmem = open_io_region(PCIEPACKET_REGION_BASE, PCIEPACKET_REGION_LENGTH);
	initialise_leds();

	int i, tlp_in_len = 0, tlp_out_len, send_length, send_result, bytecount;
	enum tlp_direction dir;
	enum tlp_completion_status completion_status;
	char *type_string;
	bool read_error = false;
	bool write_error = false;
	bool ignore_next_io_completion = false;
	bool mask_next_io_completion_data = false;
	uint16_t length, device_id, requester_id;
	uint32_t io_completion_mask, loweraddress;
	uint64_t addr, req_addr;

	TLPDoubleWord tlp_in[64], tlp_out[64];
	TLPDoubleWord *tlp_out_body = (tlp_out + 3);
	TLPQuadWord *tlp_in_quadword = (TLPQuadWord *)tlp_in;
	TLPQuadWord *tlp_out_quadword = (TLPQuadWord *)tlp_out;

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp_in;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(tlp_in + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(tlp_in + 2);

	struct TLP64ConfigReq *config_req = (struct TLP64ConfigReq *)tlp_in;
	struct TLP64DWord0 *h0bits = &(config_req->header0);
	struct TLP64RequestDWord1 *req_bits = &(config_req->req_header);

	int received_count = 0;
	write_leds(received_count);

	for (i = 0; i < 64; ++i) {
		tlp_in[i] = 0xDEADBEE0 + (i & 0xF);
		tlp_out[i] = 0xDEADBEE0 + (i & 0xF);
	}

	writeString("PCIE Test run. LEDs count up for each packet.\n");

	int card_reg = -1;

	while (1) {
		tlp_in_len = wait_for_tlp(tlp_in_quadword, sizeof(tlp_in));

		dir = ((dword0->fmt & 2) >> 1);
		const char *direction_string = (dir == TLPD_READ) ? "read" : "write";


		switch (dword0->type) {
		case M:
			assert(dword0->length == 1);
			/* This isn't in the spec, but seems to be all we've found in our
			 * trace. */

			bytecount = 0;

			if (dir == TLPD_READ) {
				PDBG("Reading region %s offset 0x%lx", target_region->name,
					rel_addr);

				read_error = false;
				tlp_out_body[0] = 0xBEDEBEDE;
			}

			for (i = 0; i < 4; ++i) {
				if ((request_dword1->firstbe >> i) & 1) {
					if (dir == TLPD_READ) {
						if (bytecount == 0) {
							loweraddress = tlp_in[2] + i;
						}
						++bytecount;
					} else { /* dir == TLPD_WRITE */
						write_error = false;
					}
				}
			}

			if (dir == TLPD_WRITE) {
				break;
			}

			create_completion_header(tlp_out, dir, device_id,
				TLPCS_SUCCESSFUL_COMPLETION, bytecount, requester_id,
				req_bits->tag, loweraddress);

			send_result = send_tlp(tlp_out_quadword, 16);
			assert(send_result != -1);

			break;
		case CFG_0:
			assert(dword0->length == 1);
			requester_id = request_dword1->requester_id;
			req_addr = config_request_dword2->ext_reg_num;
			req_addr = (req_addr << 6) | config_request_dword2->reg_num;
			req_addr <<= 2;

			if ((config_request_dword2->device_id & uint32_mask(3)) == 0) {
				/* Mask to get function num -- we are 0 */
				completion_status = TLPCS_SUCCESSFUL_COMPLETION;
				device_id = config_request_dword2->device_id;

				if (dir == TLPD_READ) {
					send_length = 16;

					tlp_out_body[0] = 0xBEDEBEDE;

					/*PDBG("CfgRd0 from %lx, Value 0x%x",*/
						/*req_addr, tlp_out_body[0]);*/

					++received_count;
					write_leds(received_count);

				} else {
					send_length = 12;

					for (i = 0; i < 4; ++i) {
						if ((request_dword1->firstbe >> i) & 1) {
						}
					}
				}
			}
			else {
				completion_status = TLPCS_UNSUPPORTED_REQUEST;
				send_length = 12;
			}

			create_completion_header(
				tlp_out, dir, device_id, completion_status, 4,
				requester_id, req_bits->tag, 0);

			send_result = send_tlp(tlp_out_quadword, send_length);
			assert(send_result != -1);

			break;
		case IO:
			assert(request_dword1->firstbe == 0xf); /* Only seen trace. */

			/*
			 * The process for interacting with the device over IO is rather
			 * convoluted.
			 *
			 * 1) A packet is sent writing an address to a register.
			 * 2) A completion happens.
			 *
			 * 3) A packet is then sent reading or writing another register.
			 * 4) The completion for this is effectively for the address that
			 * was written in 1).
			 *
			 * So we need to ignore the completion for the IO packet after the
			 * completion for 2)
			 *
			 */

			if (dir == TLPD_WRITE) {
				send_length = 12;
			} else {
				send_length = 16;
				tlp_out_body[0] = 0xBEDEBEDE;

				/*PDBG("Read CARD REG 0x%x = 0x%x", card_reg, *tlp_out_body);*/
			}

			create_completion_header(tlp_out, dir, device_id,
				TLPCS_SUCCESSFUL_COMPLETION, 4, requester_id, req_bits->tag, 0);

			send_result = send_tlp(tlp_out_quadword, send_length);
			assert(send_result != -1);

			break;
		case CPL:
			assert(false);
			break;
		default:
			type_string = "Unknown";
		}
	}

	return 0;
}
