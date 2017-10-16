#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "hexdump.h"

void
hexdump(uint8_t* data, uint64_t length)
{
	assert(data != NULL);
	const uint64_t BYTES_PER_LINE = 16;
	uint64_t char_offset, offset = 0;
	while (offset < length) {
		if (offset % BYTES_PER_LINE == 0) {
			printf("%04lx  ", offset);
		}
		printf("%02x", data[offset]);
		++offset;
		if ((offset % BYTES_PER_LINE == 0) || offset >= length) {
			putchar(' ');
			for (char_offset = offset - BYTES_PER_LINE; char_offset < offset;
				++char_offset) {
				if (data[char_offset] >= 0x20 && data[char_offset] <= 126) {
					putchar(data[char_offset]);
				} else {
					putchar(' ');
				}
			}
			putchar('\n');
		} else {
			putchar(' ');
		}
	}
}
