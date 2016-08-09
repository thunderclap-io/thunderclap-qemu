#ifndef MASK_H
#define MASK_H

#ifdef BAREMETAL
#include "baremetalsupport.h"
#else
#include <assert.h>
#endif
#include <stdint.h>



#define UINT32_MASK(width)		((1 << (width)) - 1)
// Top bit of unshift mask is in position (high - low)
#define UINT32_MASK_ENABLE_BITS(high, low)		\
	((UINT32_MASK((high) - (low) + 1)) << low)

static inline uint32_t
uint32_mask(uint32_t width) {
	assert(width <= 32);
	return (UINT32_MASK(width));
}

static inline uint32_t
uint32_mask_enable_bits(uint32_t high, uint32_t low) {
	assert(high >= low);
	assert(high <= 31);
	return (UINT32_MASK_ENABLE_BITS(high, low));
}

#if 0
#include <stdio.h>

#define TEST(high, low) \
	printf("Mask [%d, %d] = %x\n", high, low, UINT32_MASK_ENABLE_BITS(high, low))

int
main(int argc, char* argv[])
{
	TEST(0, 0);
	TEST(1, 0);
	TEST(1, 1);
	TEST(2, 1);
	return 0;
}
#endif

#endif
