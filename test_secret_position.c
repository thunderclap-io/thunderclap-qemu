/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * Copyright (c) 2015-2018 Colin Rothwell
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 * 
 * We acknowledge the support of EPSRC.
 * 
 * We acknowledge the support of Arm Ltd.
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "secret_position.h"

int run_test(uint8_t *page, char *test_string)
{
	strncpy(page, test_string, 4096);
	return secret_position(page, 0, 'i', 4);
}

int test_secret_position_main(int argc, char *argv[])
{
	uint8_t page[4096];
	char *test1 = "aaaaaaaaiiiaaiiiaiii";
	printf("t1 (-1?): %d\n", run_test(page, test1));

	char *test2 = "iiiiaa";
	printf("t2 (0?): %d\n", run_test(page, test2));

	char *test3 = "aiiiia";
	printf("t3 (1?): %d\n", run_test(page, test3));

	char *test4 = "aiiiiia";
	printf("t4 (1?): %d\n", run_test(page, test4));

	char *test5 = "iiiiaaaaiiii";
	strncpy(page, test5, 4096);
	int pos1, pos2;
	pos1 = secret_position(page, 0, 'i', 4);
	pos2 = secret_position(page, (pos1 + 4), 'i', 4);
	printf("t5 p1 (0?): %d; p2 (8?): %d\n", pos1, pos2);

	char *test6 = "iiiiiaaaaiiii";
	strncpy(page, test6, 4096);
	pos1 = secret_position(page, 0, 'i', 4);
	pos2 = secret_position(page, (pos1 + 4), 'i', 4);
	printf("t6 p1 (0?): %d; p2 (9?): %d\n", pos1, pos2);

	char *test7 = "iiiiiiii";
	strncpy(page, test7, 4096);
	pos1 = secret_position(page, 0, 'i', 4);
	pos2 = secret_position(page, (pos1 + 4), 'i', 4);
	printf("t7 p1 (0?): %d; p2 (4?): %d\n", pos1, pos2);

	page[0] = 0;
	page[1] = 1;
	page[2] = 2;
	page[3] = 0xFF;
	page[4] = 0xFF;
	page[5] = 0xFF;
	page[6] = 0xFF;
	page[7] = 8;
	page[8] = 9;
	printf("t8 (3?): %d\n", secret_position(page, 0, 0xFF, 4));

	return 0;
}
