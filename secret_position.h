#ifndef SECRET_POSITION_H
#define SECRET_POSITION_H

#include <stdint.h>

/*
 * Searches a page for a sequence of characters pattern_length long,
 * consisting only of secret_char starting at start_position at the earliest.
 *
 * Returns -1 if the page does not contain an instance of the pattern,
 * otherwise the index within the page of the first instance of secret_char
 * that occurs as part of a run of pattern_length.
 */
int
secret_position(uint8_t page[4096], int start_position, uint8_t secret_char,
	int pattern_length);

#endif
