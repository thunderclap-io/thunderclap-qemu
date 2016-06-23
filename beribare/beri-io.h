#ifndef BERI_IO_H
#define BERI_IO_H

#include "pciefpga.h"

volatile uint8_t *open_io_region(uint64_t address, uint64_t length);

extern volatile uint8_t *physmem;

static inline volatile uint32_t IORD(uint64_t base, uint64_t offset)
{
	volatile uint32_t *pointer =
		(uint32_t *)(physmem+base-PCIEPACKET_REGION_BASE);
	return pointer[offset];
}

static inline volatile uint64_t IORD64(uint64_t base, uint64_t offset)
{
	volatile uint64_t *pointer =
		(uint64_t *)(physmem+base-PCIEPACKET_REGION_BASE);
	return pointer[offset];
}

static inline void IOWR(uint64_t base, uint64_t offset, uint32_t data)
{
	volatile uint32_t *pointer =
		(uint32_t *) (physmem+base-PCIEPACKET_REGION_BASE);
	pointer[offset] = data;
}

static inline void IOWR64(uint64_t base, uint64_t offset, uint64_t data)
{
	volatile uint64_t *pointer =
		(uint64_t *)(physmem+base-PCIEPACKET_REGION_BASE);
	pointer[offset] = data;
}

typedef uint64_t alt_timestamp_type;

static inline alt_timestamp_type alt_timestamp(void)
{
	return 42LL;
}

static inline alt_timestamp_type alt_timestamp_freq(void)
{
	return 42LL;
}


static inline void alt_timestamp_start(void)
{
	return;
}

#endif
