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
#ifdef BAREMETAL
#include "baremetalsupport.h"
#endif
#include "log.h"

struct log_entry {
	int							string_id;
	enum log_item_format		format;
	uint64_t					data_item;
	bool						trailing_new_line;
};

#ifdef LOG
static char **log_strings_dict;
static struct log_entry log_entries[LOG_LENGTH];
static int next_log_record = 0;
#endif

void
log_set_strings(char *strings[])
{
#ifdef LOG
	log_strings_dict = strings;
#endif
}

void
log_log(int string_id, enum log_item_format format, uint64_t data_item,
	bool trailing_new_line)
{
#ifdef LOG
	log_entries[next_log_record].string_id = string_id;
	log_entries[next_log_record].format = format;
	log_entries[next_log_record].data_item = data_item;
	log_entries[next_log_record].trailing_new_line = trailing_new_line;

	++next_log_record;

	if (next_log_record >= LOG_LENGTH) {
		log_print();
	}
#endif
}

void
log_print()
{
#ifdef LOG
	for (int i = 0; i < next_log_record; ++i) {
		struct log_entry entry = log_entries[i];
		if (entry.string_id >= 0) {
			writeString(log_strings_dict[entry.string_id]);
		}
		switch (entry.format) {
		case LIF_BOOL:
			if (entry.data_item) {
				writeString("true");
			} else {
				writeString("false");
			}
			break;
		case LIF_INT_32:
			write_int_32(entry.data_item, ' ');
			break;
		case LIF_UINT_32:
			write_uint_32(entry.data_item, ' ');
			break;
		case LIF_UINT_32_HEX:
			write_uint_32_hex(entry.data_item, '0');
			break;
		case LIF_INT_64:
			write_int_64(entry.data_item, ' ');
			break;
		case LIF_UINT_64:
			write_uint_64(entry.data_item, ' ');
			break;
		case LIF_UINT_64_HEX:
			write_uint_64_hex(entry.data_item, '0');
			break;
		case LIF_NONE:
			break;
		}
		if (entry.trailing_new_line) {
			writeUARTChar('\r');
			writeUARTChar('\n');
		}
	}
	next_log_record = 0;
#endif
}

bool
log_last_data_for_string(int string_id, uint64_t *data)
{
#ifdef LOG
	for (int i = (next_log_record - 1); i >= 0; --i) {
		struct log_entry entry = log_entries[i];
		if (entry.string_id == string_id) {
			*data = entry.data_item;
			return true;
		}
	}
#endif
	return false;
}
