/*
 * NIOS PCIe memory transaction generator
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

#define COMPLETER_ID 0x0000
//#define COMPLETER_ID 0x0100
//#define COMPLETER_ID 0xC400


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

  TLPDoubleWord mrd64[] = { 0x20000001, 0x01000c0f, 0x1, 0};

  TLPDoubleWord vendor_broadcast[] = { 0x33000001, 0x0100be7e, 0x0000cafe, 0};

  i=0;
  addr=0*1024*1024;
  //addr = 0x100000000;
  while (1)
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
