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

#include "pcie-backend.h"

#include <stdint.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/endian.h>


#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/i386/pc.h"
#include "hw/pci-host/q35.h"
#include "qapi/qmp/qerror.h"
#include "qemu/config-file.h"

#include "libpq-fe.h"

#include "pcie.h"
#include "mask.h"
#include "pcie-debug.h"

static PGconn *postgres_connection_downstream;
static PGconn *postgres_connection_upstream;

extern bool ignore_next_postgres_completion;
extern bool mask_next_postgres_completion_data;
extern uint32_t postgres_completion_mask;


#define PG_REPR_TEXTUAL		0
#define PG_REPR_BINARY		1

unsigned long
read_hw_counter()
{
	return 0;
}

void
print_backtrace(int signum)
{
	void *addrlist[32];
	size_t size;
	char **backtrace_lines;
	
	size = backtrace(addrlist, 32);
	backtrace_lines = backtrace_symbols(addrlist, 32);

	for (size_t i = 0; i < size; ++i) {
		DEBUG_PRINTF("%s\n", backtrace_lines[i]);
	}
	
	free(backtrace_lines);
}



DeviceClass
*qdev_get_device_class(const char **driver, Error **errp)
{
    ObjectClass *oc;
    DeviceClass *dc;

    oc = object_class_by_name(*driver);

    if (!object_class_dynamic_cast(oc, TYPE_DEVICE)) {
        error_setg(errp, "'%s' is not a valid device model name", *driver);
        return NULL;
    }

    if (object_class_is_abstract(oc)) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "driver",
                   "non-abstract device type");
        return NULL;
    }

    dc = DEVICE_CLASS(oc);
    if (dc->cannot_instantiate_with_device_add_yet ||
        (qdev_hotplug && !dc->hotpluggable)) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "driver",
                   "pluggable device type");
        return NULL;
    }

    return dc;
}

enum postgres_tlp_type {
	PG_CFG_RD_0,
	PG_CFG_WR_0,
	PG_CPL,
	PG_CPL_D,
	PG_IO_RD,
	PG_IO_WR,
	PG_M_RD_32,
	PG_M_WR_32,
	PG_MSG_D
};

static enum postgres_tlp_type
get_postgres_tlp_type(const PGresult *result)
{
	int tlp_type_field_num = PQfnumber(result, "tlp_type");
	const char * const field_text = PQgetvalue(result, 0, tlp_type_field_num);
	if (strcmp(field_text, "CfgRd0") == 0) {
		return PG_CFG_RD_0;
	} else if (strcmp(field_text, "CfgWr0") == 0) {
		return PG_CFG_WR_0;
	} else if (strcmp(field_text, "Cpl") == 0) {
		return PG_CPL;
	} else if (strcmp(field_text, "CplD") == 0) {
		return PG_CPL_D;
	} else if (strcmp(field_text, "IORd") == 0) {
		return PG_IO_RD;
	} else if (strcmp(field_text, "IOWr") == 0) {
		return PG_IO_WR;
	} else if (strcmp(field_text, "MRd(32)") == 0) {
		return PG_M_RD_32;
	} else if (strcmp(field_text, "MWr(32)") == 0) {
		return PG_M_WR_32;
	} else if (strcmp(field_text, "MsgD") == 0) {
		return PG_MSG_D;
	} else {
		assert(false);
		return -1;
	}
}

enum postgres_msg_routing { BROADCAST = 3, LOCAL = 4 };

static enum postgres_msg_routing
get_postgres_msg_routing(const PGresult *result)
{
	int msg_routing_field_num = PQfnumber(result, "msg_routing");
	const char * const field_text =
		PQgetvalue(result, 0, msg_routing_field_num);
	if (strcmp(field_text, "Broadcast") == 0) {
		return BROADCAST;
	} else if (strcmp(field_text, "Local") == 0) {
		return LOCAL;
	} else {
		PDBG("Invalid msg_routing type: '%s'", field_text);
		assert(false);
		return -1;
	}
}

enum postgres_message_code { SET_SLOT_POWER_LIMIT = 0x50 };

static enum postgres_message_code
get_postgres_message_code(const PGresult *result)
{
	int message_code_field_num = PQfnumber(result, "message_code");
	const char * const field_text =
		PQgetvalue(result, 0, message_code_field_num);
	if (strcmp(field_text, "Set_Slot_Power_Limit") == 0) {
		return SET_SLOT_POWER_LIMIT;
	} else {
		assert(false);
		return -1;
	}
}

enum postgres_cpl_status { PG_SC = 0x0, PG_UR = 0x1 };

static enum postgres_cpl_status
get_postgres_cpl_status(const PGresult *result)
{
	int cpl_status_field_num = PQfnumber(result, "cpl_status");
	const char * const field_text =
		PQgetvalue(result, 0, cpl_status_field_num);
	if (strcmp(field_text, "SC") == 0) {
		return PG_SC;
	} else if (strcmp(field_text, "UR") == 0) {
		return PG_UR;
	} else {
		PDBG("ERROR! Invalid cpl_status: '%s'\n", field_text);
		assert(false);
		return -1;
	}
}

#define		POSTGRES_INT_FIELD(FIELD_NAME)									\
	static inline uint32_t													\
	get_postgres_##FIELD_NAME(const PGresult *result)						\
	{																		\
		int field_num = PQfnumber(result, #FIELD_NAME);						\
		return be32toh(*(uint32_t *)PQgetvalue(result, 0, field_num));		\
	}

POSTGRES_INT_FIELD(pk);
POSTGRES_INT_FIELD(packet);
POSTGRES_INT_FIELD(length);
POSTGRES_INT_FIELD(requester_id);
POSTGRES_INT_FIELD(tag);
POSTGRES_INT_FIELD(completer_id);
POSTGRES_INT_FIELD(device_id);
POSTGRES_INT_FIELD(register);
POSTGRES_INT_FIELD(first_be);
POSTGRES_INT_FIELD(last_be);
POSTGRES_INT_FIELD(byte_cnt);
POSTGRES_INT_FIELD(bcm);
POSTGRES_INT_FIELD(lwr_addr);

#define		POSTGRES_BIGINT_FIELD(FIELD_NAME)								\
	static inline uint64_t													\
	get_postgres_##FIELD_NAME(const PGresult *result)						\
	{																		\
		int field_num = PQfnumber(result, #FIELD_NAME);						\
		return be64toh(*(uint64_t *)PQgetvalue(result, 0, field_num));		\
	}

POSTGRES_BIGINT_FIELD(address);
POSTGRES_BIGINT_FIELD(data);

static int
swap_bottom_bits(unsigned int number_of_bits, int to_swap) {
	int out = 0;
	for (int i = 0; i < number_of_bits; ++i) {
		out |= (((to_swap >> i) & 1) << (number_of_bits - 1 - i));
	}
	return out;
}

static inline int
swap_be(int to_swap) {
	return swap_bottom_bits(4, to_swap);
}


/* Generates a TLP given a PGresult that has as row 0 a record from the trace
 * table. Returns the length of the TLP in bytes. */
/* TLPDoubleWord is a more natural way to manipulate the TLP Data */
static int
tlp_from_postgres(PGresult *result, TLPDoubleWord *buffer, int buffer_len)
{
	/* Strictly, this should probably all be done with a massive union. */
	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)buffer;

	struct TLP64MessageRequestDWord1 *message_req =
		(struct TLP64MessageRequestDWord1 *)(buffer + 1);

	struct TLP64RequestDWord1 *header_req =
		(struct TLP64RequestDWord1 *)(buffer + 1);

	struct TLP64CompletionDWord1 *compl_dword1 =
		(struct TLP64CompletionDWord1 *)(buffer + 1);

	TLPDoubleWord *dword2 = (buffer + 2);

	struct TLP64ConfigRequestDWord2 *config_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(buffer + 2);

	struct TLP64CompletionDWord2 *compl_dword2 =
		(struct TLP64CompletionDWord2 *)(buffer + 2);

	TLPDoubleWord *dword3 = (buffer + 3);
	TLPDoubleWord *dword4 = (buffer + 4);

	header0->tc = 0; // Assume traffic class best effort
	header0->th = 0; // Assume no traffic processing hints.
	header0->td = 0; // Assume no TLP digest
	header0->ep = 0; // Assume TLP is not poisoned, as you do.
	header0->length = get_postgres_length(result);

	int data_length = 0;
	int length = -1;
	enum postgres_tlp_type tlp_type = get_postgres_tlp_type(result);

	/* This is up here so we can get data alignment correct in results. */
	uint32_t reg = get_postgres_register(result);

#ifdef PRINT_IDS
	DEBUG_PRINTF("%d.\n", get_postgres_packet(result));
#endif
	switch (tlp_type) {
	case PG_CFG_RD_0:
	case PG_CFG_WR_0:
		if (tlp_type == PG_CFG_RD_0) {
			/*DEBUG_PRINTF("CfgRd0 TLP");*/
			header0->fmt = TLPFMT_3DW_NODATA;
		} else {
			/*DEBUG_PRINTF("CfgWr0 TLP");*/
			header0->fmt = TLPFMT_3DW_DATA;
			data_length = 4;
		}
		header0->type = CFG_0;
		header_req->requester_id = get_postgres_requester_id(result);
		header_req->tag = get_postgres_tag(result);
		header_req->lastbe = get_postgres_last_be(result);
		header_req->firstbe = swap_be(get_postgres_first_be(result));
		assert(PQntuples(result) == 1);
		config_dword2->device_id = get_postgres_device_id(result);
		config_dword2->ext_reg_num = reg >> 6;
		config_dword2->reg_num = (reg & uint32_mask(8));
		length = 12;
		if (tlp_type == PG_CFG_WR_0 && reg >= 0x10 && reg <= 0x24) {
			/*PDBG("pk: %d; packet: %d",*/
				/*get_postgres_pk(result), get_postgres_packet(result));*/
		}
		if (tlp_type == PG_CFG_RD_0 && (reg == 0x30 || reg > 0x3C)) {
			/* ROM bar and capability list. */
			ignore_next_postgres_completion = true;
		}
		break;
	case PG_CPL:
	case PG_CPL_D:
		if (tlp_type == PG_CPL) {
			/*DEBUG_PRINTF("Cpl TLP");*/
			header0->fmt = TLPFMT_3DW_NODATA;
			data_length = 0;
		} else {
			/*DEBUG_PRINTF("CplD TLP");*/
			header0->fmt = TLPFMT_3DW_DATA;
			data_length = get_postgres_length(result) * 4;
		}
		header0->type = CPL;
		compl_dword1->completer_id = get_postgres_completer_id(result);
		compl_dword1->status = get_postgres_cpl_status(result);
		compl_dword1->bcm = get_postgres_bcm(result);
		compl_dword1->bytecount = get_postgres_byte_cnt(result);
		compl_dword2->requester_id = get_postgres_requester_id(result);
		compl_dword2->tag = get_postgres_tag(result);
		compl_dword2->loweraddress = get_postgres_lwr_addr(result);
		length = (12 + data_length);
		break;
	case PG_IO_RD:
	case PG_IO_WR:
		if (tlp_type == PG_IO_RD) {
			header0->fmt = TLPFMT_3DW_NODATA;
			data_length = 0;
		} else {
			header0->fmt = TLPFMT_3DW_DATA;
			data_length = 4;
		}
		header0->type = IO;
		header_req->requester_id = get_postgres_requester_id(result);
		header_req->tag = get_postgres_tag(result);
		header_req->lastbe = 0;
		header_req->firstbe = swap_be(get_postgres_first_be(result));
		*dword2 = (TLPDoubleWord)(get_postgres_address(result) >> 32);
		length = (12 + data_length);
		break;
	case PG_MSG_D:
		/*DEBUG_PRINTF("MsgD TLP");*/
		header0->fmt = TLPFMT_4DW_DATA;
		header0->type = ((1 << 4) | get_postgres_msg_routing(result));
		message_req->requester_id = get_postgres_requester_id(result);
		message_req->tag = get_postgres_tag(result);
		message_req->message_code = get_postgres_message_code(result);

		if (message_req->message_code == SET_SLOT_POWER_LIMIT) {
			buffer[2] = 0;
			buffer[3] = 0;
			buffer[4] = get_postgres_data(result);
			length = (5 * 8);
		}

		break;
	case PG_M_RD_32:
	case PG_M_WR_32:
		if (tlp_type == PG_M_RD_32) {
			header0->fmt = TLPFMT_3DW_NODATA;
			data_length = 0;
		} else {
			header0->fmt = TLPFMT_3DW_DATA;
			data_length = 4;
		}
		header0->type = M;
		header_req->requester_id = get_postgres_requester_id(result);
		header_req->tag = get_postgres_tag(result);
		header_req->lastbe = get_postgres_last_be(result);
		header_req->firstbe = swap_be(get_postgres_first_be(result));
		*dword2 = get_postgres_address(result);
		length = 12 + data_length;
		break;
	default:
		PDBG("ERROR! Unknown TLP type: %s",
			PQgetvalue(result, 0, PQfnumber(result, "tlp_type")));
		assert(false);
	}

	/*DEBUG_PRINTF(" (packet %d)\n", get_postgres_packet(result));*/

	int i;


	if (data_length > 0) {
		uint64_t data = get_postgres_data(result);
		TLPDoubleWord *data_dword = (TLPDoubleWord *)&data;
		TLPDoubleWord *data_dest;
		if (tlp_type == PG_CFG_WR_0 && (reg % 8 == 0)) {
			data_dest = dword4;
		} else {
			data_dest = dword3;
		}
		for (i = 0; i < (data_length / sizeof(TLPDoubleWord)); ++i) {
			data_dest[i] = data_dword[i];
		}
	}

	return length;
}

/* We also use this to intercept BAR settings so that we don't send memory
 * read requests we don't have adequate responses to. */

#define IGNORE_REGION_COUNT				4

#define SECOND_CARD_REGION_MEM_INDEX	0
#define SECOND_CARD_REGION_IO_INDEX		1
#define SECOND_CARD_REGION_ROM_INDEX	2
#define FIRST_CARD_REGION_ROM_INDEX		3

static int32_t io_region =  -1;
static int32_t ignore_regions[IGNORE_REGION_COUNT] = {-1, -1, -1, -1};
static int32_t ignore_region_mask[IGNORE_REGION_COUNT] = {
	UINT32_MASK_ENABLE_BITS(31, 17),
	UINT32_MASK_ENABLE_BITS(31, 5),
	UINT32_MASK_ENABLE_BITS(31, 17),
	UINT32_MASK_ENABLE_BITS(31, 17)
};

static int32_t skip_sending = 0;

static inline bool
tlp_expects_response(PGresult *result)
{
	enum postgres_tlp_type type = get_postgres_tlp_type(result);
	return type != PG_M_WR_32 && type != PG_MSG_D;
}

static inline bool
should_receive_tlp_for_result(PGresult *result)
{
	if (PQntuples(result) < 1) {
		return false;
	}
	bool skip = false;
	uint32_t packet = get_postgres_packet(result);
	uint32_t device_id = get_postgres_device_id(result);
	uint64_t address = get_postgres_address(result);
	uint32_t region = bswap32(get_postgres_data(result));
	if (get_postgres_tlp_type(result) == PG_CFG_WR_0) {
		if (device_id == 256) {
			if (get_postgres_register(result) == 0x30) {
				ignore_regions[FIRST_CARD_REGION_ROM_INDEX] = region;
			}
		} else if (device_id == 257) {
			switch(get_postgres_register(result)) {
			case 0x10:
				ignore_regions[SECOND_CARD_REGION_MEM_INDEX] = region;
				break;
			case 0x18:
				ignore_regions[SECOND_CARD_REGION_IO_INDEX] = region;
				break;
			case 0x30:
				ignore_regions[SECOND_CARD_REGION_ROM_INDEX] = region;
				break;
			}
		/*PDBG("!!! Setting second card region: 0x%x", second_card_region);*/
		}
	}

	bool skip_due_to_this_region = false;
	for (int i = 0; i < IGNORE_REGION_COUNT; ++i) {
		uint32_t mask = ignore_region_mask[i];
		skip_due_to_this_region = (
			ignore_regions[i] != -1 && address != 0 &&
			(address & mask) == (ignore_regions[i] & mask));
		if (skip_due_to_this_region) {
			/*PDBG("%d: Skipping due to region %d", packet, i);*/
		}
		skip = skip || skip_due_to_this_region;
		skip_due_to_this_region = false;
	}

	if (device_id == 257) {
		/*PDBG("%d: Skipping due to device id is 257.", packet);*/
		skip = true;
	}

	if (skip && tlp_expects_response(result)) {
		++skip_sending;
		assert(skip_sending >= 0);
	}

	return !skip;
}

#define		ID_BUFFER_SIZE		8
static uint32_t last_recvd_ids[ID_BUFFER_SIZE];
static int recvd_count = 0;

static uint32_t last_sent_ids[ID_BUFFER_SIZE];
static int sent_count = 0;

static void
print_circular_uint_buffer(uint32_t *buffer, int count, int buffer_size)
{
	for (int i = (count - buffer_size); i < count; ++i) {
		DEBUG_PRINTF("%d\n", buffer[(i % buffer_size)]);
	}
}

static inline uint32_t
circular_buffer_last(uint32_t *buffer, int count, int buffer_size)
{
	return buffer[(count - 1) % buffer_size];
}

static uint32_t
last_recvd_packet_id()
{
	return circular_buffer_last(last_recvd_ids, recvd_count, ID_BUFFER_SIZE);
}

void
print_last_recvd_packet_ids()
{
	DEBUG_PRINTF("Last received ids...\n");
	print_circular_uint_buffer(last_recvd_ids, recvd_count, ID_BUFFER_SIZE);
}

static uint32_t
last_sent_packet_id()
{
	return circular_buffer_last(last_sent_ids, sent_count, ID_BUFFER_SIZE);
}

static void
print_last_sent_packet_ids()
{
	DEBUG_PRINTF("Last sent ids...\n");
	print_circular_uint_buffer(last_sent_ids, sent_count, ID_BUFFER_SIZE);
}


/* tlp_len is length of the buffer in bytes. */
/* Return -1 if 1024 attempts to poll the buffer fail. */
int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	int ret_value;
	/* TODO: Check we don't buffer overrun. */
	PGresult *result = PQgetResult(postgres_connection_downstream);
	
	while (!should_receive_tlp_for_result(result)) {
		/*PDBG("Skipping receiving %d", get_postgres_packet(result));*/
		PQclear(result);
		result = PQgetResult(postgres_connection_downstream);
		if (result == NULL) {
			return TRACE_COMPLETE;
		}
	}

	TLPDoubleWord *tlp_dword = (TLPDoubleWord *)tlp;
#ifdef PRINT_IDS
	DEBUG_PRINTF("Simulating receiving ");
#endif
	ret_value = tlp_from_postgres(result, tlp_dword, tlp_len);
	last_recvd_ids[(recvd_count % ID_BUFFER_SIZE)] = get_postgres_packet(result);
	++recvd_count;

	assert(PQntuples(result) == 1);
	if (get_postgres_register(result) == 0x18 &&
		get_postgres_tlp_type(result) == PG_CFG_WR_0 &&
		get_postgres_device_id(result) == 256) {
		io_region = tlp_dword[3]; /* Endianness swapped. */
	}

	PQclear(result);
	return ret_value;
}

void
drain_pcie_core()
{
}

static inline bool
should_send_tlp_for_result(PGresult *result)
{
	bool skip = false;
	/* Consume a completion for a packet that is in the trace, but not sent */
	if (skip_sending != 0) {
		skip = true;
		--skip_sending;
		/*PDBG("Paying off skip sending.");*/
	}
	return !skip;
}

int TLPS_CHECKED = 0;

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(TLPQuadWord *header, int header_len, TLPQuadWord *data, int data_len,
	enum tlp_data_alignment data_alignment)
{
	assert(header_len == 12 || header_len == 16);
	assert(data_len % 4 == 0);

	int i, response;
	int tlp_len = header_len + data_len;

	PGresult *result = PQgetResult(postgres_connection_upstream);
	assert(result != NULL);

	TLPQuadWord expected[64];
	int buffer_len = 64 * sizeof(TLPQuadWord);
	assert(tlp_len <= buffer_len);
	memset(expected, 0, buffer_len);
#ifdef PRINT_IDS
	DEBUG_PRINTF("Simulating sending ");
#endif

	while (!should_send_tlp_for_result(result)) {
		/*PDBG("Skipping sending %d", get_postgres_packet(result));*/
		PQclear(result);
		result = PQgetResult(postgres_connection_upstream);
	}

	last_sent_ids[sent_count % ID_BUFFER_SIZE] = get_postgres_packet(result);
	++sent_count;

	/*PDBG("Recvd: %d; Sent: %d", last_recvd_packet_id(), last_sent_packet_id());*/
	if (last_sent_packet_id() < last_recvd_packet_id()) {
		PDBG("Checked: %d", TLPS_CHECKED);
		print_last_recvd_packet_ids();
		print_last_sent_packet_ids();

		assert(last_sent_packet_id() > last_recvd_packet_id());
	}

	response = tlp_from_postgres(result, (TLPDoubleWord *)expected, buffer_len);

	bool match = true;

	if (response != tlp_len) {
		PDBG("Trying to send tlp of length %d. Exected %d. Packet %d. Checked %d.",
			tlp_len, response, get_postgres_packet(result), sent_count);
		print_last_recvd_packet_ids();
		print_last_sent_packet_ids();
		assert(response == tlp_len);
		match = false;
	}

	TLPDoubleWord *expected_dword = (TLPDoubleWord *)expected;
	TLPDoubleWord *data_dword = (TLPDoubleWord *)data;

	if (mask_next_postgres_completion_data) {
		mask_next_postgres_completion_data = false;
		expected_dword[3] = expected_dword[3] & postgres_completion_mask;
		*data_dword = (*data_dword) & postgres_completion_mask;
	}

	uint8_t *expected_byte = (uint8_t *)expected;
	uint8_t *header_byte = (uint8_t *)header;
	uint8_t *data_byte = (uint8_t *)data;

#define TLP_BYTE(K) \
	((K < header_len) ? header_byte[K] : data_byte[K - header_len])

	uint8_t actual;

	for (i = 0; i < tlp_len; ++i) {
		match = match && (expected_byte[i] == TLP_BYTE(i));
	}
	
	if (ignore_next_postgres_completion) {
		match = true;
		ignore_next_postgres_completion = false;
	} else {
		++TLPS_CHECKED;
	}

	if (!match) {
		PDBG("Attempted packet send mismatch (checked %d, packet %d)",
			TLPS_CHECKED, get_postgres_packet(result));
		for (i = 0; i < tlp_len; ++i) {
			DEBUG_PRINTF("%03d: Exp - 0x%02x; Act - 0x%02x",
				i, expected_byte[i], TLP_BYTE(i));
			if (expected_byte[i] != TLP_BYTE(i)) {
				DEBUG_PRINTF(" !");
			}
			DEBUG_PRINTF("\n");
		}
		print_last_recvd_packet_ids();
		return -1;
	}

	return 0;
#undef TLP_BYTE
}


static void
print_result(PGresult *result)
{
	Oid field_type;
	int32_t int_value;
	int64_t int64_value;
	uint32_t network_value32;
	uint64_t network_value64;
	int field_num, field_name_length, size;
	int longest_field_name_length = 0;
	int field_count = PQnfields(result);
	for (field_num = 0; field_num < field_count; ++field_num) {
		field_name_length = strlen(PQfname(result, field_num));
		if (field_name_length > longest_field_name_length) {
			longest_field_name_length = field_name_length;
		}
	}
	for (field_num = 0; field_num < field_count; ++field_num) {
		field_type = PQftype(result, field_num);
		size = PQgetlength(result, 0, field_num);
		printf("%-*s %s %2d %8d ",
			longest_field_name_length,
			PQfname(result, field_num),
			PQfformat(result, field_num) == PG_REPR_TEXTUAL ? "text" : "bin",
			size,
			field_type);

		if (PQgetisnull(result, 0, field_num)) {
			printf("NULL");
		}
		else if (field_type == 23) {
			network_value32 = *(uint32_t *)PQgetvalue(result, 0, field_num);
			int_value = (int32_t)be32toh(network_value32);
			printf("%u", int_value);
		} else if (field_type == 20) {
			network_value64 = *(uint64_t *)PQgetvalue(result, 0, field_num);
			int64_value = (int64_t)be64toh(network_value64);
			printf("%lu", int64_value);
		} else {
			printf("%s", PQgetvalue(result, 0, field_num));
		}
		printf("\n");
	}
}

static int
check_connection_status(const PGconn *connection)
{
	ConnStatusType conn_status = PQstatus(connection);
	if (conn_status == CONNECTION_OK) {
		printf("Success!\n");
		return 0;
	} else {
		assert(conn_status == CONNECTION_BAD);
		printf("Error when connecting to database: %s",
			PQerrorMessage(postgres_connection_downstream));
		return 2;
	}
}

static int
start_binary_single_row_query(PGconn *connection, const char *query)
{
	int query_status = PQsendQueryParams(
		connection,
		query,
		0, // Zero parameters
		NULL, // Types
		NULL, // Values
		NULL, // Lengths
		NULL, // Formats
		PG_REPR_BINARY // Binary response, please
	);
	if (query_status == 0) {
		printf("Error when querying trace database: %s",
			PQerrorMessage(connection));
		return 3;
	}
	query_status = PQsetSingleRowMode(connection);
	if (query_status == 0) {
		printf("Error when entering single row mode: %s",
			PQerrorMessage(connection));
		return 4;
	}
	return 0;
}



void
close_connections()
{
	PQfinish(postgres_connection_downstream);
	PQfinish(postgres_connection_upstream);
}

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem)
{
	int connection_status, query_status;

	if (argc != 2) {
		printf("Usage: %s CONNECTION_STRING\n", argv[0]);
		return 1;
	}
	printf("Creating connection for downstream packets...\n");
	atexit(close_connections);
	postgres_connection_downstream = PQconnectdb(argv[1]);
	connection_status = check_connection_status(postgres_connection_downstream);
	if (connection_status != 0) {
		return connection_status;
	}
	printf("Creating connection for upstream packets...\n");
	postgres_connection_upstream = PQconnectdb(argv[1]);
	connection_status = check_connection_status(postgres_connection_upstream);
	if (connection_status != 0) {
		return connection_status;
	}

	query_status = start_binary_single_row_query(
		postgres_connection_downstream,
		"SELECT * FROM qemu_trace WHERE link_dir = 'Downstream' ORDER BY packet ASC");
	if (query_status != 0) {
		return query_status;
	}

	query_status = start_binary_single_row_query(
		postgres_connection_upstream,
		"SELECT * FROM qemu_trace WHERE link_dir = 'Upstream' ORDER BY packet ASC");
	if (query_status != 0) {
		return query_status;
	}

	return 0;
}
