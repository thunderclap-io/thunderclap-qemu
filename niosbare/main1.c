/*
 * "Hello World" example.
 *
 * This example prints 'Hello from Nios II' to the STDOUT stream. It runs on
 * the Nios II 'standard', 'full_featured', 'fast', and 'low_cost' example
 * designs. It runs with or without the MicroC/OS-II RTOS and requires a STDOUT
 * device in your system's hardware.
 * The memory footprint of this hosted application is ~69 kbytes by default
 * using the standard reference design.
 *
 * For a reduced footprint version of this template, and an explanation of how
 * to reduce the memory footprint for a given application, see the
 * "small_hello_world" template.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include "system.h"
#include "io.h"
#include "sys/alt_timestamp.h"
#include "altera_avalon_timer.h"
#include "pcie.h"
#include "pciefpga.h"
#include "pcietlp.h"
#include "baremetalsupport.h"
#include "pcie-backend.h"

#define ENDIAN_SWAP(x) (((x & 0xFF)<<24) | ((x & 0xFF00)<<8) | ((x & 0xFF0000)>>8) | ((x & 0xFF000000)>>24))

//#define COMPLETER_ID 0x0000
//#define COMPLETER_ID 0x0100
#define COMPLETER_ID 0xC500

#if 0
int displayTLP(TLPDoubleWord *tlp, int tlpLen)
{
	int i=0, j=0;
	TLPHeader0 h0;
	TLPHeaderReq h1;
	uint32_t address0, address1;
	if (tlpLen > 0) {
		h0 = (TLPHeader0) tlp[i++];
		printf("TLP header word 0=0x%08x: fmt=0x%x, type=0x%x, twentythree=0x%x, tc=0x%x, sixteen=0x%x, td=0x%x, ep=0x%x, attr=0x%x, at=0x%x, length=0x%x\n",
			tlp[0],
			h0.bits.fmt, h0.bits.type, h0.bits.twentythree,
			h0.bits.tc, h0.bits.sixteen, h0.bits.td,
			h0.bits.ep, h0.bits.attr, h0.bits.at,
			h0.bits.length);

	} else return;
	if (tlpLen > 1) {
		h1 = (TLPHeaderReq) tlp[i++];
		printf("TLP header word 1=0x%08x: requesterid=0x%04x, tag=0x%x, lastbe=0x%x, firstbe=0x%x\n",
			tlp[1],
			h1.bits.requesterid, h1.bits.tag,
			h1.bits.lastbe, h1.bits.firstbe);

	} else return;
	address0 = (uint32_t) tlp[i++];
        if (h0.bits.fmt & 0x1) {
		address1 = tlp[i++];
		printf("TLP 64 bit address = 0x%08x %08x\n", address0, address1);
	} else {
		printf("TLP 32 bit address = 0x%08x\n", address0);
	}
	
	for (j=i; j<tlpLen; j++)
	{
		printf("TLP word %d=0x%08x\n", j, tlp[j]);
	}
	return 0;
}

/* send a TLP over PCIe 
 * buffer: pointer to TLP
 * bufferLen: length of TLP in bytes
 */
#if 0
int sendTLP(TLPDoubleWord *buffer, int bufferLen)
{
	int i;
	int sop=1, eop=0;
	volatile PCIeStatus statusword;
	TLPDoubleWord upperword=0;

	assert(bufferLen/4<64);
	// stop the tx queue from draining as we fill it
	IOWR(PCIEPACKETTRANSMITTER_0_BASE,PCIEPACKETTRANSMITTER_QUEUEENABLE,0);		
	for (i=0; i<(bufferLen/4); i+=2)
	{
		statusword.word = 0;
		statusword.bits.startofpacket = (i==0);
		// end of packet if we're on the last or penultimate 32 bit word
		// round up to 64 bit sizes
		statusword.bits.endofpacket = (i+2 >= bufferLen/4);
		// if we're sending an odd number of words, pad with zeroes
		if ((i+1) >= bufferLen)
			upperword = 0;
		else
			upperword = buffer[i+1];
		// write start/end of packet flags
		//printf("%d: status=%08x, ", i, (unsigned int) statusword.word);
		IOWR(PCIEPACKETTRANSMITTER_0_BASE,PCIEPACKETTRANSMITTER_STATUS,statusword.word);
		// write upper 32 bits
		//printf("upper=%08x, ", (unsigned int) upperword);
		IOWR(PCIEPACKETTRANSMITTER_0_BASE,PCIEPACKETTRANSMITTER_UPPER32,upperword);
		// write lower 32 bits and send word
		//printf("lower=%08x\n", (unsigned int) buffer[i]);
		IOWR(PCIEPACKETTRANSMITTER_0_BASE,PCIEPACKETTRANSMITTER_LOWER32SEND,buffer[i]);
	}
	// release the queued data
	IOWR(PCIEPACKETTRANSMITTER_0_BASE,3,1);
	return 0;
}
#endif

int memoryResponseTLP(TLPDoubleWord *tlpIn, int tlpLen)
{
	TLPDoubleWord tlpOut[64];
	TLPHeader0 *h0;
	TLPHeaderCompl0 *h1;
	TLPHeaderCompl1 *h2;

	TLPHeader0 in0;
	TLPHeaderReq in1;

	int tlpOutSize = 0;

	assert(tlpIn);
	assert(tlpLen > 0);

	memset(tlpOut, 0, sizeof(tlpOut));

	h0 = (TLPHeader0 *) &tlpOut[0];
	h1 = (TLPHeaderCompl0 *) &tlpOut[1];
	h2 = (TLPHeaderCompl1 *) &tlpOut[2];

	in0.word = tlpIn[0];
	in1.word = tlpIn[1];

	printf("Send memory response - FIXME\n");

	h0->word = 0;
	h0->bits.fmt = 2;	// 3 DW header with data
	h0->bits.type = Completion;
	h0->bits.length = 1;
	
	h1->word = 0;
	h1->bits.completerid = COMPLETER_ID;
	h1->bits.status = SC;
	h1->bits.bytecount = 4;
	
	h2->word = 0;
	h2->bits.requesterid = in1.bits.requesterid;
	h2->bits.tag = in1.bits.tag;
	h2->bits.loweraddress = 0;

	sendTLP(tlpOut, 4*sizeof(TLPDoubleWord));
	printf("Sent memoryResponse TLP %08x, %08x, %08x\n", h0->word, h1->word, h2->word);

	return 0;
}

int parseInboundTLP(TLPDoubleWord *tlpIn, int tlpLen)
{

//	displayTLP(tlpIn, tlpLen);
	TLPHeader0 h0 = (TLPHeader0) tlpIn[0];
	TLPHeaderReq h1 = (TLPHeaderReq) tlpIn[1];
	TLPDirection dir;

	switch (h0.bits.type) {
		case MemoryReq:
			dir = (TLPDirection) (h0.bits.fmt & 2)>>1;
			printf("Memory %d=%s TLP\n", dir, (dir!=0) ? "write":"read");
			memoryResponseTLP(tlpIn, tlpLen);
			break;
		case Completion:
			printf("Completion %08x %08x %08x %08x\n", tlpIn[0], tlpIn[1], tlpIn[2], tlpIn[3]);
			break;
		default:
			printf("Unrecognised TLP type=0x%0x\n", h0.bits.type);
			break;
	}
	return 0;
}

/* waitForTLP: wait for a TLP to arrive and store it in a buffer
 * tlp: buffer to hold received TLP
 * tlpLen: length of buffer in bytes
 * returned: number of bytes received
 */
#if 0
int waitForTLP(TLPDoubleWord *tlp, int tlpLen)
{
	volatile PCIeStatus pciestatus;
	volatile TLPDoubleWord pciedata1, pciedata0;
	volatile int ready;
	int i=0;

	do {
		ready = IORD(PCIEPACKETRECEIVER_0_BASE,PCIEPACKETRECEIVER_READY);
	} while (ready==0);

	do {
		pciestatus.word = IORD(PCIEPACKETRECEIVER_0_BASE,PCIEPACKETRECEIVER_STATUS);
		pciedata1 = IORD(PCIEPACKETRECEIVER_0_BASE,PCIEPACKETRECEIVER_UPPER32);
		pciedata0 = IORD(PCIEPACKETRECEIVER_0_BASE,PCIEPACKETRECEIVER_LOWER32DEQ);
	//	printf("Received data = %08lx%08lx, sop = %x, eop = %x\n", pciedata1, pciedata0, pciestatus.bits.startofpacket, pciestatus.bits.endofpacket);
		if (pciestatus.bits.startofpacket) {
			// keep the most recent sop to eop: if there are multiple sops then only
			// keep the last
			i=0;
		}

		tlp[i++] = pciedata0;
		tlp[i++] = pciedata1;
		if (i*4 > tlpLen)
		{
			printf("ERROR: TLP received %d larger than buffer %d - leaving remainder undrained\n", i*4, tlpLen);
			return i*4;
		}

	} while (!pciestatus.bits.endofpacket);

	return i*4;
}
#endif
#endif
/* Make a memory request to the host, fetching a single 32 bit word.
 * Parameters:
 * address: 64 bit address to request
 * timeout: time in ns until we give up
 * Returns:
 * MemoryResponse structure containing details of response packet
 */

int memoryRequest(uint64_t address, uint64_t timeout,
	uint32_t *data_buffer, uint64_t data_buffer_length,
	uint32_t *returned_length)
{
	TLPDoubleWord tlp[64];
/*	TLPHeader0 h0;
	TLPHeaderReq h1;
	TLPHeaderCompl0 c1;
	TLPHeaderCompl1 c2;*/
	static unsigned int tag=0;
	unsigned int tagSent = 0;
	int receivedCount = 0;
	int tlpLen = 0;
	unsigned long startTime = 0;
//	uint64_t timeoutCycles = (alt_timestamp_freq() * timeout) / 1000000000LL;
	unsigned long timeoutCycles = timeout*1000;
	int response;
//	uint32_t data_buffer[256];
	int status=0;

/*
	h0.word = 0;
	h0.bits.type = MemoryReq;
	h0.bits.length = 1;
	h0.bits.at = 0x0;
	h1.word = 0;
	h1.bits.requesterid = COMPLETER_ID;
	tagSent = tag & 0xFF;
	h1.bits.tag = tagSent;
	h1.bits.firstbe = 0xf;
	h1.bits.lastbe = 0;
	tlp[0] = h0.word;
	tlp[1] = h1.word;
	if (address >= (1LL<<32)) {
		h0.bits.fmt = 1;
		tlp[2] = (address>>32);
		tlp[3] = (address & 0xFFFFFFFF);
		tlpLen = 4*4;
	} else {
		h0.bits.fmt = 0;
		tlp[2] = (address & 0xFFFFFFFF);
		tlpLen = 3*4;
	}
*/
	//puts("Created request TLP");
	tlpLen = create_memory_request(tlp, sizeof(tlp), TLPD_READ, 
		COMPLETER_ID /* requester id */, tag, 0 /* loweraddress */,
		address, 4);

	//puts("Sending request TLP, tag = ");
	//write_uint_32_hex(tag, ' ');
	startTime = read_hw_counter();
	send_tlp((TLPQuadWord *) tlp,tlpLen);
	tagSent = tag;
	tag = (tag+1) % 32;


	do {
		enum tlp_completion_status completion_status=0;
		uint16_t completer_id=0, requester_id=0;
		uint8_t tag=0;
		//uint32_t returned_length=0;
		receivedCount = wait_for_tlp((TLPQuadWord *) tlp, sizeof(tlp));
		if (receivedCount < 3*4)
			continue;

		//puts("Received a TLP");
		status = parse_memory_response(tlp, receivedCount,
			data_buffer, data_buffer_length,
			&completion_status, &completer_id, &requester_id,
			&tag, returned_length);
/*			puts("Received completion: address / status/tag/completion_status/length/word=");
			write_uint_64_hex(address, ' ');
			write_uint_32_hex(status,' ');
			write_uint_32(tag, ' ');
			write_uint_32(completion_status, ' ');
			write_uint_32(returned_length, ' ');
			write_uint_32_hex(data_buffer[0], ' ');
			writeUARTChar('\n');
*/

		if ((status==0) && (completion_status == TLPCS_SUCCESSFUL_COMPLETION) && (tag == tagSent)) {
/*			puts("Matched completion: status/tag/completion_status/length/word=");
			write_uint_32_hex(status,' ');
			write_uint_32(tag, ' ');
			write_uint_32(completion_status, ' ');
			write_uint_32(returned_length, ' ');
			write_uint_32_hex(data_buffer[0], ' ');
			writeUARTChar('\n');
*/			return status;
		}
/*
		h0.word = tlp[0];
		c1.word = tlp[1];
		c2.word = tlp[2];
		if ((h0.bits.fmt & TLPFMT_4DW)==0 && (h0.bits.type == Completion)) {
			// completion
			if (c2.bits.tag == tagSent) {
				response.status = c1.bits.status;
				if (h0.bits.fmt & TLPFMT_WITHDATA)
					response.data32 = tlp[3];

				else
					response.data32 = 0xdeaddead;
				printf("Matched completion %d, status=%x, data=%08x ", tagSent, response.status, response.data32);
				return response;
			}
		}
*/
	} while(read_hw_counter()<(startTime+timeoutCycles));

//	response.status = RequestTimeout;

	return status;

}

int main()
{
  volatile int ready;
  volatile TLPDoubleWord pciedata1, pciedata0;
  volatile PCIeStatus pciestatus;
  TLPDoubleWord tlp[64];
  uint32_t data_buffer[256];
  uint32_t returned_length=0;
  int i=0,j=0;
  uint64_t addr=0, startAddr=0, lastAddr;
  int r;
  enum tlp_completion_status lastCompletion=TLPCS_REQUEST_TIMEOUT;
  uint64_t delta = 4*1024;
  const char *progress="\\|/-";
  int progress_pos;


  printf("Hello from Nios II!\n");
  usleep(2*1000*1000);
  printf("Starting...\n");
  alt_timestamp_start();

/*
  pciestatus.bits.startofpacket = 1;
  pciestatus.bits.endofpacket = 0;
  IOWR(PCIEPACKETTRANSMITTER_0_BASE,2,pciestatus.word);
  IOWR(PCIEPACKETTRANSMITTER_0_BASE,1,0xcafefeed);
  IOWR(PCIEPACKETTRANSMITTER_0_BASE,0,0xc0ffee0f);
  pciestatus.bits.startofpacket = 0;
  pciestatus.bits.endofpacket = 1;
  IOWR(PCIEPACKETTRANSMITTER_0_BASE,2,pciestatus.word);
  IOWR(PCIEPACKETTRANSMITTER_0_BASE,1,0xbeebfade);
  IOWR(PCIEPACKETTRANSMITTER_0_BASE,0,0xfacebead);
*/
  TLPDoubleWord mrd64[] = { 0x20000001, 0x01000c0f, 0x1, 0};

  TLPDoubleWord vendor_broadcast[] = { 0x33000001, 0x0100be7e, 0x0000cafe, 0};

  uint64_t victim_address = 0xc35000;
  while (1) {
	data_buffer[0]=0xdeadbeef;
	r = memoryRequest(victim_address+i,100000, data_buffer, sizeof(data_buffer), &returned_length);
	printf("Reading %x, status = %d, returnedlength = %x, data_buffer[0]=%x\n", (uint32_t) (victim_address+i), r, returned_length, data_buffer[0]);
	if (data_buffer[0] != 0xdeadbeef) break;
  }
  
  i=0;
  addr=0*1024*1024;
  //addr = 0x100000000;
  while (0)
  {
  	uint32_t addrH, addrL;
  	addrH = (uint32_t) (addr>>32LL);
  	addrL = (uint32_t) (addr & 0xFFFFFFFFLL);
//	sendTLP(tlp,j*4);
	//send_tlp(mrd64, sizeof(mrd64));
	//send_tlp(vendor_broadcast, sizeof(vendor_broadcast));
//	i = waitForTLP(tlp, sizeof(tlp));
//	parseInboundTLP(tlp,i);
  	while (1)
  	{
	  	r = memoryRequest(addr,100000, data_buffer, sizeof(data_buffer),
	  		&returned_length);
	//  	write_uint_64_hex(addr,'0');
	//  	writeUARTChar('=');
	//  	write_uint_32_hex(data_buffer[0],'0');
	//  	writeUARTChar('\n');
	  	if (r >= 0)
	  		break;
	 }
	progress_pos = (progress_pos + 1) % 4;
	//writeUARTChar(progress[progress_pos]);
	//writeUARTChar('\r');
  	//usleep(1000);
  	if (r != lastCompletion)
  	{
	  	uint32_t startAddrH, startAddrL;
	  	startAddrH = (uint32_t) (startAddr>>32LL);
	  	startAddrL = (uint32_t) (startAddr & 0xFFFFFFFFLL);

	  	uint64_t lastAddr = addr-delta;
	  	uint32_t lastAddrH, lastAddrL;
	  	lastAddrH = (uint32_t) (lastAddr>>32LL);
	  	lastAddrL = (uint32_t) (lastAddr & 0xFFFFFFFFLL);

  		writeString("Range ");
  		write_uint_32_hex(startAddrH,'0');
  		write_uint_32_hex(startAddrL,'0');
  		writeUARTChar('-');
  		write_uint_32_hex(lastAddrH,'0');
  		write_uint_32_hex(lastAddrL,'0');
  		writeUARTChar('=');
  		write_int_32(lastCompletion,' ');
  		writeUARTChar('\n');
  		//write_uint_32(startAddrH%08x_%08x to %08x_%08x, status %d\n", startAddrH, startAddrL, lastAddrH, lastAddrL, lastCompletion);
  		lastCompletion = r;
  		startAddr = addr;
  	}
  	i++;
  	addr+=delta;
  }

  return 0;
}
