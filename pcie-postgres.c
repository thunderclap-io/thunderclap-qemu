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

static bool mask_next_completion_data = false;
static TLPDoubleWord completion_data_mask;

static inline
void set_next_completion_data_mask(TLPDoubleWord mask)
{
	return; /* XXX: CORRECT THIS! */
	mask_next_completion_data = true;
	completion_data_mask = mask;
}

static PGconn *postgres_connection_downstream;
static PGconn *postgres_connection_upstream;

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
	PG_MSG,
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
	} else if (strcmp(field_text, "Msg") == 0) {
		return PG_MSG;
	} else if (strcmp(field_text, "MsgD") == 0) {
		return PG_MSG_D;
	} else {
		printf("Unknown tlp_type: '%s'\n", field_text);
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

enum postgres_message_code {
	PME_TURN_OFF = 0x19,
	SET_SLOT_POWER_LIMIT = 0x50,
	VENDOR_DEFINED_TYPE_1 = 0x7F
};

static enum postgres_message_code
get_postgres_message_code(const PGresult *result)
{
	int message_code_field_num = PQfnumber(result, "message_code");
	const char * const field_text =
		PQgetvalue(result, 0, message_code_field_num);
	if (strcmp(field_text, "Set_Slot_Power_Limit") == 0) {
		return SET_SLOT_POWER_LIMIT;
	} else if (strcmp(field_text, "Vendor_Defined_Type1") == 0) {
		return VENDOR_DEFINED_TYPE_1;
	} else if (strcmp(field_text, "PME_Turn_Off") == 0) {
		return PME_TURN_OFF;
	} else {
		printf("Unrecognised message code: '%s'\n.", field_text);
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

/* Generates a TLP given a PGresult that has as row 0 a record from the trace
 * table. Returns the length of the TLP in bytes. */
/* TLPDoubleWord is a more natural way to manipulate the TLP Data */
static void
tlp_from_postgres(PGresult *result, TLPQuadWord *buffer, int buffer_len,
	struct RawTLP *out)
{
	/* Strictly, this should probably all be done with a massive union. */
	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)buffer;

	struct TLP64MessageRequestDWord1 *message_req =
		(struct TLP64MessageRequestDWord1 *)(header0 + 1);

	struct TLP64RequestDWord1 *header_req =
		(struct TLP64RequestDWord1 *)(header0 + 1);

	struct TLP64CompletionDWord1 *compl_dword1 =
		(struct TLP64CompletionDWord1 *)(header0 + 1);

	TLPDoubleWord *dword2 = (((TLPDoubleWord *)buffer) + 2);

	struct TLP64ConfigRequestDWord2 *config_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(dword2);

	struct TLP64CompletionDWord2 *compl_dword2 =
		(struct TLP64CompletionDWord2 *)(dword2);

	TLPDoubleWord *dword3 = dword2 + 1;
	TLPDoubleWord *dword4 = dword3 + 1;

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
		header_req->firstbe = get_postgres_first_be(result);
		assert(PQntuples(result) == 1);
		config_dword2->device_id = get_postgres_device_id(result);
		config_dword2->ext_reg_num = reg >> 8;
		config_dword2->reg_num = (reg & uint32_mask(8));
		length = 12;
		break;
	case PG_CPL:
	case PG_CPL_D:
		if (tlp_type == PG_CPL) {
			header0->fmt = TLPFMT_3DW_NODATA;
			data_length = 0;
		} else {
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
		header_req->firstbe = get_postgres_first_be(result);
		*dword2 = (TLPDoubleWord)(get_postgres_address(result));
		length = (12 + data_length);
		break;
	case PG_MSG:
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
		header_req->firstbe = get_postgres_first_be(result);
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

	if (tlp_fmt_is_4dw(header0->fmt)) {
		out->header_length = 16;
	} else {
		out->header_length = 12;
	}

	out->header = (TLPDoubleWord *)buffer;

	if (data_length > 0) {
		uint64_t data = get_postgres_data(result);
		TLPDoubleWord *data_dword = (TLPDoubleWord *)&data;
		if (tlp_type == PG_CFG_WR_0 && (reg % 8 == 0)) {
			out->data = dword4;
		} else {
			out->data = dword3;
		}
		for (i = 0; i < (data_length / sizeof(TLPDoubleWord)); ++i) {
			out->data[i] = data_dword[i];
		}
	}
	out->data_length = data_length;
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
	MASK_ENABLE_BITS(uint32_t, 31, 17),
	MASK_ENABLE_BITS(uint32_t, 31, 5),
	MASK_ENABLE_BITS(uint32_t, 31, 17),
	MASK_ENABLE_BITS(uint32_t, 31, 17)
};

static int32_t skip_sending = 0;

static inline bool
tlp_expects_response(PGresult *result)
{
	enum postgres_tlp_type type = get_postgres_tlp_type(result);
	return type != PG_M_WR_32 && type != PG_MSG && type != PG_MSG_D;
}

static inline bool
should_receive_tlp_for_result(PGresult *result)
{
	if (PQntuples(result) < 1) {
		return false;
	}
	bool skip = false;
	enum postgres_tlp_type type = get_postgres_tlp_type(result);
	uint32_t packet = get_postgres_packet(result);
	uint32_t device_id = get_postgres_device_id(result);
	uint64_t address = get_postgres_address(result);
	uint32_t region = bswap32(get_postgres_data(result));
	if (type == PG_CFG_WR_0) {
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
			PDBG("%d: Skipping due to region %d", packet, i);
		}
		skip = skip || skip_due_to_this_region;
		skip_due_to_this_region = false;
	}

	if (device_id == 257 || (
			type == PG_MSG &&
			get_postgres_message_code(result) == PME_TURN_OFF)) {
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

int last_packet;

void
wait_for_tlp(volatile TLPQuadWord *buffer, int buffer_len, struct RawTLP *out)
{
	/* This gives us an approximation to packets not arriving, so lets us run
	 * the main loop. It probably isn't worth doing anything more elaborate
	 * (checking against timestamp? */
	static int call_count = 0;
	++call_count;
	if (call_count % 2 != 0) {
		set_raw_tlp_invalid(out);
		return;
	}
	/* TODO: Check we don't buffer overrun. */
	PGresult *result = PQgetResult(postgres_connection_downstream);
	
	while (!should_receive_tlp_for_result(result)) {
		/*PDBG("Skipping receiving %d", get_postgres_packet(result));*/
		PQclear(result);
		result = PQgetResult(postgres_connection_downstream);
		if (result == NULL) {
			return set_raw_tlp_trace_finished(out);
		}
	}

	last_packet = get_postgres_packet(result);

#ifdef PRINT_IDS
	DEBUG_PRINTF("Simulating receiving ");
#endif
	tlp_from_postgres(result, buffer, buffer_len, out);
	last_recvd_ids[(recvd_count % ID_BUFFER_SIZE)] =
		get_postgres_packet(result);
	++recvd_count;

	static bool read_semaphore = false;

	switch (get_postgres_tlp_type(result)) {
	case PG_CFG_RD_0:
		switch (get_postgres_register(result)) {
		case 0x0: /* device ID */
			set_next_completion_data_mask(0xFFFF00FF);
			break;
		case 0x8: /* revision mask */
			set_next_completion_data_mask(0x00FFFFFF);
			break;
		case 0xC: /* header type. A bit odd. */
			set_next_completion_data_mask(0xFFFF00FF);
			break;
		case 0xC8:
			set_next_completion_data_mask(0xFFFF0000);
			break;
		case 0xE0:
			set_next_completion_data_mask(0xFF0FFFFF);
			break;
		case 0xE4: /* PCIe Device Capabilities */
			set_next_completion_data_mask(0x0000FFFF);
			break;
		case 0x100: /* Some sort of extention register */
			set_next_completion_data_mask(0xFFFF0000);
			break;
		case 0x104: /* Uncorrectable error status? Hopefully unreproducable. */
			set_next_completion_data_mask(0xFFFFEFFF);
			break;
		case 0x1C: /* BAR 3 -- think this an MSI-X problem/difference? */
		case 0x30: /* Expansion ROM -- simulated NIC doesn't have one. */
		case 0xA0: /* No idea... */
		case 0xA4: /* Seems to be some capability wholesale ignored. */
		case 0xA8:
		case 0xCC: /* Power management. Hopefully safe to ignore. */
		case 0xE8: /* Device Status and Control */
		case 0xEC: /* Link Capabilities */
		case 0xF0: /* Link status and control */
			set_next_completion_data_mask(0x0);
			break;
		}
		break;
	case PG_M_RD_32:
		switch (get_postgres_address(result) & 0x1FFFF) {
		case 0x10: /* EEPROM register */
			set_next_completion_data_mask(0);
			break;
		case 0xF00: /* A reserved bit, the QEMU gets more right... */
			/* And something weird to do with MDIO */
			set_next_completion_data_mask(~bswap32(0x28));
			break;
		case 0x5B50:
			if (!read_semaphore) {
				/* First value is wrong for some reason. */
				set_next_completion_data_mask(0);
				read_semaphore = true;
			}
			break;
		}
		break;
	}

	PQclear(result);
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

int
send_tlp(struct RawTLP *actual)
{
	assert(actual->header_length == 12 || actual->data_length == 16);
	assert(actual->data_length % 4 == 0);

	int i, response;

	PGresult *result = PQgetResult(postgres_connection_upstream);
	assert(result != NULL);

	struct RawTLP expected;
	TLPQuadWord expected_buffer[64];
	int buffer_len = 64 * sizeof(TLPQuadWord);
	memset(expected_buffer, 0, buffer_len);
#ifdef PRINT_IDS
	DEBUG_PRINTF("Simulating sending ");
#endif

	int pk, packet;
	pk = get_postgres_pk(result);
	packet = get_postgres_packet(result);

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

	tlp_from_postgres(result, expected_buffer, buffer_len, &expected);

	assert(actual->header_length == expected.header_length);
	if (actual->data_length != expected.data_length) {
		printf("Data length mismatch procession packet %d with pk %d. "
		   "Expected %d. Actual %d", packet, pk, expected.data_length,
		   actual->data_length);
		assert(false);
	}

	++TLPS_CHECKED;

#define MASK_DATA(index, mask) 										do { \
	actual->data[index] = actual->data[index] & mask;					 \
	expected.data[index] = expected.data[index] & mask;				 \
} while (0)

	if (mask_next_completion_data) {
		mask_next_completion_data = false;
		MASK_DATA(0, completion_data_mask);
	}

#undef MASK_DATA

	for (i = 0; i < (actual->header_length / sizeof(TLPDoubleWord)); ++i) {
		assert(actual->header[i] == expected.header[i]);
	}

	for (i = 0; i < (actual->data_length / sizeof(TLPDoubleWord)); ++i ) {
		if (actual->data[i] != expected.data[i]) {
			printf("Data mismatch processing packet with pk %d: %d.\n"
				"dword %d. Expected: 0x%08x. Actual 0x%08x.\n",
				pk, packet, i, expected.data[i], actual->data[i]);
			/*assert(false);*/
		}
	}


	return 0;
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


int
pci_dma_read(PCIDevice *dev, dma_addr_t addr, void *buf, dma_addr_t len)
{
	printf("WARNING! Postgres backend doesn't simulate host memory.\n");
	return 0;
}

int
pci_dma_write(PCIDevice *dev, dma_addr_t addr, const void *buf, dma_addr_t len)
{
	printf("WARNING! Postgres backend doesn't simulate host memory.\n");
	return 0;
}

enum dma_read_response
perform_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
{
	printf("WARNING! Postgres backend doesn't simulate host memory.\n");
	return DRR_UNSUPPORTED_REQUEST;
}
