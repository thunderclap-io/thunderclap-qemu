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

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "pcie.h"

uint8_t byte_enable(uint64_t address, uint32_t length, bool first)
{
	uint8_t byteenable=0, demuxed=0, end_phase=0;
	uint32_t sat_length = 0;
	uint64_t end = 0;
	uint8_t firstbe = 0, lastbe = 0;

	// if the transaction is greater or equal to a DWord, fill first BE with ones
	sat_length = (length<4) ? length : 4;
	// BE bits can be either 0, 1, 3, 7 or 15
	demuxed = (1<<(sat_length)) - 1;
	// first BE depends on address as well as length
	// if len = 1, firstbe = 0001 << (address % 4)
	// if len = 2, firstbe = 0011 << (address % 4)
	// etc, all truncated to 4 bits
	firstbe = (demuxed << (address % 4)) & 0xF;

	// zero length is special
	// (we expect a length of 1024 words to be converted to
	// length field=0 downstream of this function)
	if (length == 0)
		firstbe = 0;

	// last BE only depends on (address+length) % 4
	// but twisted, so
	// aligned (a+l)%4=0 means 1<<3
	// 1 byte  (a+l)%4=1 means 1<<0
	// 2 bytes (a+l)%4=2 means 1<<1, etc
	end = (address + (uint64_t) length);
	end_phase = (uint8_t) ((end-1LL) % 4);
	lastbe = (1<<(end_phase+1)) - 1;
	if (length <= 4)
		lastbe = 0;
	
	if (first)
		return firstbe;
	else
		return lastbe;
}

#ifdef TEST_BYTE_ENABLE
#include <stdio.h>
#include <inttypes.h>

void test_byte_enable_value(uint64_t address, uint32_t length, bool first, uint8_t expected)
{
	uint8_t result=0;

	result = byte_enable(address, length, first);
	if (result != expected)
	{
		fprintf(stderr, "Failed: byte_enable(address=%"PRIx64", length=%x, first=%d) returned %x, expected %x\n",
			address, length, first, result, expected);		
	}
}

void test_byte_enable(void)
{
	uint64_t base=0;
	uint32_t len=0;
	

	for (base = 0; base < 64; base += 4) {
		// if no data, first BE should be zero
		test_byte_enable_value(base+0LL, 0, true, 0);
		test_byte_enable_value(base+1LL, 0, true, 0);
		test_byte_enable_value(base+2LL, 0, true, 0);
		test_byte_enable_value(base+3LL, 0, true, 0);

		// for short words, it's the length of the word shifted
		test_byte_enable_value(base+0LL, 1, true, 0x1);
		test_byte_enable_value(base+1LL, 1, true, 0x2);
		test_byte_enable_value(base+2LL, 1, true, 0x4);
		test_byte_enable_value(base+3LL, 1, true, 0x8);

		test_byte_enable_value(base+0LL, 2, true, 0x3);
		test_byte_enable_value(base+1LL, 2, true, 0x6);
		test_byte_enable_value(base+2LL, 2, true, 0xC);
		test_byte_enable_value(base+3LL, 2, true, 0x8);

		test_byte_enable_value(base+0LL, 3, true, 0x7);
		test_byte_enable_value(base+1LL, 3, true, 0xE);
		test_byte_enable_value(base+2LL, 3, true, 0xC);
		test_byte_enable_value(base+3LL, 3, true, 0x8);

		// if only one word, last BE should be zero
		test_byte_enable_value(base+0LL, 0, false, 0);
		test_byte_enable_value(base+0LL, 1, false, 0);
		test_byte_enable_value(base+0LL, 2, false, 0);
		test_byte_enable_value(base+0LL, 3, false, 0);
		for (len = 4; len < 64; len += 4) {
			//printf("base=%"PRIx64", len=%x\n", base,len);	
			test_byte_enable_value(base+0LL, len+0, true, 0xF);
			test_byte_enable_value(base+0LL, len+1, true, 0xF);
			test_byte_enable_value(base+0LL, len+2, true, 0xF);
			test_byte_enable_value(base+0LL, len+3, true, 0xF);
			test_byte_enable_value(base+1LL, len+0, true, 0xE);
			test_byte_enable_value(base+1LL, len+1, true, 0xE);
			test_byte_enable_value(base+1LL, len+2, true, 0xE);
			test_byte_enable_value(base+1LL, len+3, true, 0xE);
			test_byte_enable_value(base+2LL, len+0, true, 0xC);
			test_byte_enable_value(base+2LL, len+1, true, 0xC);
			test_byte_enable_value(base+2LL, len+2, true, 0xC);
			test_byte_enable_value(base+2LL, len+3, true, 0xC);
			test_byte_enable_value(base+3LL, len+0, true, 0x8);
			test_byte_enable_value(base+3LL, len+1, true, 0x8);
			test_byte_enable_value(base+3LL, len+2, true, 0x8);
			test_byte_enable_value(base+3LL, len+3, true, 0x8);

			// special cases if only one word
			test_byte_enable_value(base+0LL, len+0, false, (len==4) ? 0:0xF);
			test_byte_enable_value(base+0LL, len+1, false, 0x1);
			test_byte_enable_value(base+0LL, len+2, false, 0x3);
			test_byte_enable_value(base+0LL, len+3, false, 0x7);
			test_byte_enable_value(base+1LL, len+0, false, (len==4) ? 0:0x1);
			test_byte_enable_value(base+1LL, len+1, false, 0x3);
			test_byte_enable_value(base+1LL, len+2, false, 0x7);
			test_byte_enable_value(base+1LL, len+3, false, 0xF);
			test_byte_enable_value(base+2LL, len+0, false, (len==4) ? 0:0x3);
			test_byte_enable_value(base+2LL, len+1, false, 0x7);
			test_byte_enable_value(base+2LL, len+2, false, 0xF);
			test_byte_enable_value(base+2LL, len+3, false, 0x1);
			test_byte_enable_value(base+3LL, len+0, false, (len==4) ? 0:0x7);
			test_byte_enable_value(base+3LL, len+1, false, 0xF);
			test_byte_enable_value(base+3LL, len+2, false, 0x1);
			test_byte_enable_value(base+3LL, len+3, false, 0x3);
		}
	}
}

int main(void)
{
	test_byte_enable();
	printf("Success\n");
	return 0;
}
#endif
