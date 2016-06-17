#include <stdint.h>
#include "baremetalsupport.h"

static inline unsigned long long
to_the(unsigned long long base, unsigned long long exponent)
{
	if (exponent == 0) {
		return 1;
	}
	int i;
	unsigned long long rvalue = base;
	for (i = 1; (i * 2) < exponent; i *= 2) {
		rvalue *= rvalue;
	}
	for (; i < exponent; ++i) {
		rvalue *= base;
	}
	return rvalue;
}

/* Use '\0' to not pad numbers. */

static inline void
writeNumber(uint32_t digits, uint64_t base, bool check_sign,
	uint64_t n, char pad)
{
	int64_t sn = n;
	if (check_sign) {
		if (sn < 0) {
			writeUARTChar('-');
			n = -sn;
		}
	}
	bool had_non_pad = false;
	for (int i = (digits - 1); i >= 0; --i) {
		unsigned long long digit = (n / (to_the(base, i))) % base;
		if (digit == 0 && !had_non_pad && i != 0) {
			if (pad != '\0') {
				writeUARTChar(pad);
			}
		} else {
			had_non_pad = true;
			if (digit < 10) {
				writeUARTChar('0' + digit);
			} else {
				writeUARTChar('A' - 10 + digit);
			}
		}
	}
}

void
writeDigit(unsigned long long n, char pad)
{
	writeNumber(20, 10, false, n, pad);
}

void
write_uint_32(uint32_t n, char pad)
{
	writeNumber(10, 10, false, n, pad);
}

void
write_uint_32_hex(uint32_t n, char pad)
{
	writeNumber(8, 16, false, n, pad);
}

void
write_uint_64(uint64_t n, char pad)
{
	writeNumber(20, 10, false, n, pad);
}

void
write_uint_64_hex(uint64_t n, char pad)
{
	writeNumber(16, 16, false, n, pad);
}

void
write_int_32(int32_t n, char pad)
{
	writeNumber(10, 10, true, n, pad);
}

void
write_int_64(uint64_t n, char pad)
{
	writeNumber(19, 10, true, n, pad);
}

#ifdef BAREMETAL

void
writeUARTChar(char c)
{
	//Code for SOPC Builder serial output
	while ((IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE)+4) &
	    0xFFFF) == 0) {
		asm("add $v0, $v0, $0");
	}
	//int i;
	//for (i=0;i<10000;i++);
	IO_WR_BYTE(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE), c);
}

void
writeString(char* s)
{
	while(*s)
	{
		writeUARTChar(*s);
		++s;
	}
}

void
writeHex(unsigned long long n)
{
	unsigned int i;
	for(i = 0;i < 16; ++i)
	{
		unsigned long long hexDigit = (n & 0xF000000000000000L) >> 60L;
//		unsigned long hexDigit = (n & 0xF0000000L) >> 28L;
		char hexDigitChar = (hexDigit < 10) ? ('0' + hexDigit) : ('A' + hexDigit - 10);
		writeUARTChar(hexDigitChar);
		n = n << 4;
	}
}


char
readUARTChar()
{
	int i;
	char out;
	i = IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE));
	while((i & 0x00800000) == 0)
	{
		i = IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE));
	}
	
	i = i >> 24;
	out = (char)i;
	return out;
}


int usleep(useconds_t usec)
{
	unsigned long start_counter = read_hw_counter();
	uint64_t sleep_clocks = (((uint64_t) usec)*1000000LL)/CLOCKS_PER_SEC;
	while ((read_hw_counter() - ((uint64_t) start_counter))<sleep_clocks)
	{
	}
	return 0;
}

void *memset(void *s, int c, size_t n)
{
	uint8_t *p = (uint8_t *) s;
	for (int i=0; i<n; i++)
		p[i] = (uint8_t) c;
}

#endif
