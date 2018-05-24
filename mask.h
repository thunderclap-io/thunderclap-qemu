#ifndef MASK_H
#define MASK_H

#ifdef BAREMETAL
#include "baremetalsupport.h"
#else
#include <assert.h>
#endif
#include <stdint.h>



#define MASK(type, width)		(((type)1 << (width)) - 1)
// Top bit of unshift mask is in position (high - low)
// High is the top bit to modify, low is the bottom bit to modify.
#define MASK_ENABLE_BITS(type, high, low)		\
	((MASK(type, (high) - (low) + 1)) << low)

#define SET_BITS_FUNCTION(type)											\
static inline type type ## _set_bits(									\
		type original, uint32_t high, uint32_t low, type value) {		\
	type new_value = original & ~MASK_ENABLE_BITS(type, high, low);		\
	new_value |= value << low;											\
	return new_value;													\
}
/* These define
uint8_t_set_bits(...)
uint16_t_set_bits(...)
Expressed like this in comment for ease of grepping :)
*/
SET_BITS_FUNCTION(uint8_t);
SET_BITS_FUNCTION(uint16_t);

/* These define
uint8_t_get_bits(...)
uint16_t_get_bits(...)
*/
#define GET_BITS_FUNCTION(type)											\
static inline type type ## _get_bits(								\
		type source, uint32_t high, uint32_t low) {						\
	return source & MASK_ENABLE_BITS(type, high, low) >> low;			\
}

GET_BITS_FUNCTION(uint8_t);
GET_BITS_FUNCTION(uint16_t);

static inline uint32_t
uint32_mask(uint32_t width) {
	assert(width <= 32);
	return (MASK(uint32_t, width));
}

static inline uint32_t
uint32_mask_enable_bits(uint32_t high, uint32_t low) {
	assert(high >= low);
	assert(high <= 31);
	return (MASK_ENABLE_BITS(uint32_t, high, low));
}

static inline uint64_t
uint64_mask(uint64_t width) {
	assert(width <= 64);
	return (MASK(uint64_t, width));
}

static inline uint64_t
page_base_address(uint64_t address) {
	return address & ~uint64_mask(12);
}

#if 0
#include <stdio.h>

#define TEST(high, low) \
	printf("Mask [%d, %d] = %x\n", high, low, MASK_ENABLE_BITS(high, low))

int
main(int argc, char* argv[])
{
	printf("%lx\n", uint64_mask(12));
	return 0;
}
#endif

#endif
