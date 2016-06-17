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

#define ENDIAN_SWAP(x) (((x & 0xFF)<<24) | ((x & 0xFF00)<<8) | ((x & 0xFF0000)>>8) | ((x & 0xFF000000)>>24))

#define COMPLETER_ID 0xC400


int displayTLP(TLPWord *tlp, int tlpLen)
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

int sendTLP(TLPWord *buffer, int bufferLen)
{
	int i;
	int sop=1, eop=0;
	volatile PCIeStatus statusword;
	TLPWord upperword=0;

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

int memoryResponseTLP(TLPWord *tlpIn, int tlpLen)
{
	TLPWord tlpOut[64];
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

	sendTLP(tlpOut, 4*sizeof(TLPWord));
	printf("Sent memoryResponse TLP %08x, %08x, %08x\n", h0->word, h1->word, h2->word);

	return 0;
}

int parseInboundTLP(TLPWord *tlpIn, int tlpLen)
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

int waitForTLP(TLPWord *tlp, int tlpLen)
{
	volatile PCIeStatus pciestatus;
	volatile TLPWord pciedata1, pciedata0;
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

/* Make a memory request to the host, fetching a single 32 bit word.
 * Parameters:
 * address: 64 bit address to request
 * timeout: time in ns until we give up
 * Returns:
 * MemoryResponse structure containing details of response packet
 */

MemoryResponse memoryRequest(uint64_t address, uint64_t timeout)
{
	TLPWord tlp[64];
	TLPHeader0 h0;
	TLPHeaderReq h1;
	TLPHeaderCompl0 c1;
	TLPHeaderCompl1 c2;
	static unsigned int tag=0;
	unsigned int tagSent = 0;
	int receivedCount = 0;
	int tlpLen = 0;
	alt_timestamp_type startTime = 0;
	uint64_t timeoutCycles = (alt_timestamp_freq() * timeout) / 1000000000LL;
	MemoryResponse response;

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

	startTime = alt_timestamp();
	sendTLP(tlp,tlpLen);
	tag = (tag+1) % 32;


	do {
		receivedCount = waitForTLP(tlp, sizeof(tlp));
		if (receivedCount < 3*4)
			continue;
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
				//printf("Matched completion %d, status=%x, data=%08x ", tagSent, response.status, response.data32);
				return response;
			}
		}

	} while(alt_timestamp()<(startTime+timeoutCycles));

	response.status = RequestTimeout;

	return response;

}

int main()
{
  volatile int ready;
  volatile TLPWord pciedata1, pciedata0;
  volatile PCIeStatus pciestatus;
  TLPWord tlp[64];
  int i=0,j=0;
  Address addr=0, startAddr=0, lastAddr;
  MemoryResponse r;
  TLPCompletionStatus lastCompletion=RequestTimeout;
  Address delta = 4*1024;


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
  TLPWord mrd64[] = { 0x20000001, 0x01000c0f, 0x1, 0};

  TLPWord vendor_broadcast[] = { 0x33000001, 0x0100be7e, 0x0000cafe, 0};

  i=0;
  addr=0*1024*1024;
  //addr = 0x100000000;
  while (1)
  {
  	uint32_t addrH, addrL;
  	addrH = (uint32_t) (addr>>32LL);
  	addrL = (uint32_t) (addr & 0xFFFFFFFFLL);
//	sendTLP(tlp,j*4);
//	sendTLP(mrd64, sizeof(mrd64));
//	sendTLP(vendor_broadcast, sizeof(vendor_broadcast));
//	i = waitForTLP(tlp, sizeof(tlp));
//	parseInboundTLP(tlp,i);
  	r = memoryRequest(addr,100000);
  	if (r.status != lastCompletion)
  	{
	  	uint32_t startAddrH, startAddrL;
	  	startAddrH = (uint32_t) (startAddr>>32LL);
	  	startAddrL = (uint32_t) (startAddr & 0xFFFFFFFFLL);

	  	Address lastAddr = addr-delta;
	  	uint32_t lastAddrH, lastAddrL;
	  	lastAddrH = (uint32_t) (lastAddr>>32LL);
	  	lastAddrL = (uint32_t) (lastAddr & 0xFFFFFFFFLL);

  		printf("Range %08x_%08x to %08x_%08x, status %d\n", startAddrH, startAddrL, lastAddrH, lastAddrL, lastCompletion);
  		lastCompletion = r.status;
  		startAddr = addr;
  	}
//  	if (r.status!=UR)
//  		printf("Memory read addr %08x_%08x = %08x (code=%x)\n",addrH, addrL , r.data32, r.status);
  	i++;
  	addr+=delta;
  }

  return 0;
}
