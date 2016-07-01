/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * Copyright (c) 2015-2018 Colin Rothwell
 * Copyright (c) 2015-2018 A. Theodore Markettos
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 * 
 * We acknowledge the support of Arm Ltd.
 * 
 * We acknowledge the support of EPSRC.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stddef.h>
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

#if defined(BAREMETAL) && defined(BERI)

void
writeUARTChar(char c)
{
	//Code for SOPC Builder serial output
	while ((IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE)+4) &
	    0xFFFF) == 0) {
//		asm("add $v0, $v0, $0");
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

void *memcpy(void *d, void *s, size_t n)
{
	uint8_t *dest = (uint8_t *) d;
	uint8_t *src = (uint8_t *) s;
	for (int i=0; i<n; i++)
		dest[i] = src[i];
}

#else

void
writeUARTChar(char c)
{
	putchar(c);
}

void writeString(char* s)
{
	puts(s);
}

char
readUARTChar()
{
	return (char) getchar();
}
#endif
