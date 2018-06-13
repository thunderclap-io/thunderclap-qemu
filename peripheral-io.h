#ifndef PERIPHERAL_IO_H
#define PERIPHERAL_IO_H

/*
 * The interesting thing here is doing 64-bit reads on a 32-bit host.
 * In order to make sure that they happen in a consistent order, they
 * always access (that is, read or write) the high bits of the address first,
 * then the low bits.
 */

volatile uint8_t *open_io_region(uint64_t address, uint64_t length);

extern volatile uint8_t *physmem;
extern volatile uint8_t *led_phys_mem;

static inline volatile uint32_t IORD(uint64_t base, uint64_t offset)
{
	volatile uint32_t *pointer = (uint32_t *)(
		physmem - PCIEPACKET_REGION_BASE + base + offset);
	return *pointer;
}

static inline volatile uint64_t IORD64(uint64_t base, uint64_t offset)
{
#ifdef WORD_SIZE_64
	volatile uint64_t *pointer = (uint64_t *)(
		physmem - PCIEPACKET_REGION_BASE + base + offset);
	uint64_t v;
#ifdef PLATFORM_ARM
// force an atomic 64 bit load
	asm("ldrd\t%0, [%1]" : "=&r" (v) : "r" (pointer));
#else
	v = *pointer;
#endif
	return v;

#elif defined WORD_SIZE_32
	uint64_t ret;
	volatile uint32_t *low_bits = (uint32_t *)(
		physmem - PCIEPACKET_REGION_BASE + base + offset);
	volatile uint32_t *high_bits = low_bits + 1;
	ret = (*high_bits);
	ret <<= 32;
	ret |= *low_bits;
	return ret;
#else
#error "One of either WORD_SIZE_32 or WORD_SIZE_64 must be defined."
#endif
}

static inline void IOWR(uint64_t base, uint64_t offset, uint32_t data)
{
	volatile uint32_t *pointer = (uint32_t *)(
		physmem - PCIEPACKET_REGION_BASE + base + offset);
	*pointer = data;
}

static inline void IOWR64(uint64_t base, uint64_t offset, uint64_t data)
{
#ifdef WORD_SIZE_64
	volatile uint64_t *pointer = (uint64_t *)(
		physmem - PCIEPACKET_REGION_BASE + base + offset);
#ifdef PLATFORM_ARM
// force an atomic 64 bit store
//	asm("nop");
	asm("strd\t%0, [%1]" : : "r" (data), "r" (pointer));
#else
	*pointer = data;
#endif
#elif defined WORD_SIZE_32
	volatile uint32_t *low_data = (uint32_t *)(
		physmem - PCIEPACKET_REGION_BASE + base + offset);
	volatile uint32_t *high_data = low_data + 1;
	*high_data = (uint32_t)(data >> 32);
	*low_data = (uint32_t)(data & 0xFFFFFFFF);
#else
#error "One of either WORD_SIZE_32 or WORD_SIZE_64 must be defined."
#endif
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
