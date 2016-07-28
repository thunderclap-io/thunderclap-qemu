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

#include "pciebyteenable.h"

#ifdef TEST_BYTE_ENABLE
#include <stdio.h>
#include <inttypes.h>

void test_byte_enable_value(uint64_t address, uint32_t length, bool first, uint8_t expected)
{
	uint8_t result=0;

	if (first)
		result = first_byte_enable(address, length);
	else
		result = last_byte_enable(address, length);

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
