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
#define MASK_ENABLE_BITS(type, high, low)		\
	((MASK(type, (high) - (low) + 1)) << low)

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
