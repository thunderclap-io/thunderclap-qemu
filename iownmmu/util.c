/** Utility functions. */


#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

/**
 * Hexdump from some forgotten source on the internet. Useful for debugging.
 *
 * Parameters:
 *  mem: a buffer to hexdump (NIOS address space)
 *  len: the length of the hexdump
 */
void hexdump(void *mem, uint32_t len) {
  const uint32_t HEXDUMP_COLS = 16;

  for(uint32_t i = 0; i < len +
      ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
    // row label
    if(i % HEXDUMP_COLS == 0) {
      printf("0x%06lx: ", i);
    }

    // values
    if(i < len) {
      printf("%02x ", 0xFF & ((uint8_t *)mem)[i]);
    } else {
      printf("   ");
    }

    // ASCII
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
      for(uint32_t j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
        if(j >= len) {
          putchar(' ');
        } else if(isprint(((uint8_t *)mem)[j])) {
          putchar(0xFF & ((uint8_t *)mem)[j]);
        } else {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}
