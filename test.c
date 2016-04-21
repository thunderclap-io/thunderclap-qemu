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

/*
 * Device classes seem to be constructed using type_init. This is a call to
 * module_init(*, MODULE_INIT_QOM)
 *
 * Macros in qemu/module.h
 * __attribute__((constructor_)), means the function will be called by default
 * before entering main. Horrible horrible horrible!
 *
 * So, register_dso_module_init(e1000_register_types, MODULE_INIT_QOM) will
 * get called. This sets up a list of "dso_inits".
 *
 * This places the function onto a list of functions, with MODULE_INIT_QOM
 * attached. At some point, this function is presumably called.
 *
 * Function for adding a device from the command line is qdev_device_add in
 * qdev-monitor.c
 *
 * I use a bunch of initialisation functions from hw/i386/pc_q35.c to get the
 * appropriate busses set up -- the main initialisation function is called
 * pc_q35_init, and I am slowly cannibalising it.
 */

#define TARGET_BERI		1
#define TARGET_NATIVE	2

#include <execinfo.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/endian.h>

#ifdef POSTGRES
#include <libpq-fe.h>
#endif

#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/i386/pc.h"
#include "hw/pci-host/q35.h"
#include "qapi/qmp/qerror.h"
#include "qemu/config-file.h"

#include "pcie.h"
#include "pciefpga.h"
#include "beri-io.h"

#ifdef PCIE_DEBUG
#define PDBG(...)				do {									\
	fprintf(stderr, "%s(%s:%d): ", __func__, __FILE__, __LINE__);		\
	fprintf(stderr, __VA_ARGS__);										\
	fprintf(stderr, "\n");												\
} while (0)

#define DEBUG_PRINTF(...)		do {									\
	fprintf(stderr, __VA_ARGS__);										\
} while (0)
#else
#define PDBG(...)
#define DBG_PRINTF(...)
#endif


#ifdef POSTGRES

#define PG_REPR_TEXTUAL		0
#define PG_REPR_BINARY		1

static PGconn *postgres_connection_downstream;
static PGconn *postgres_connection_upstream;

void
close_connections()
{
	PQfinish(postgres_connection_downstream);
	PQfinish(postgres_connection_upstream);
}

#endif

void
print_backtrace(int signum)
{
	void *addrlist[32];
	size_t size;
	char **backtrace_lines;
	
	size = backtrace(addrlist, 32);
	backtrace_lines = backtrace_symbols(addrlist, 32);

	for (size_t i = 0; i < size; ++i) {
		PDBG("%s\n", backtrace_lines[i]);
	}
	
	free(backtrace_lines);
}

static DeviceClass
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

#ifdef POSTGRES

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

static inline uint32_t
uint32_mask(uint32_t width) {
	assert(width <= 32);
	return ((1 << (width + 1)) - 1);
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

	struct TLP64ConfigRequestDWord2 *config_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(buffer + 2);

	struct TLP64CompletionDWord2 *compl_dword2 =
		(struct TLP64CompletionDWord2 *)(buffer + 2);

	TLPDoubleWord *dword3 = (buffer + 3);

	header0->tc = 0; // Assume traffic class best effort
	header0->th = 0; // Assume no traffic processing hints.
	header0->td = 0; // Assume no TLP digest
	header0->ep = 0; // Assume TLP is not poisoned, as you do.
	header0->length = get_postgres_length(result);

	int data_length = 0;
	int length = -1;
	enum postgres_tlp_type tlp_type = get_postgres_tlp_type(result);
	
	switch (tlp_type) {
	case PG_CFG_RD_0:
	case PG_CFG_WR_0:
		if (tlp_type == PG_CFG_RD_0) {
			DEBUG_PRINTF("CfgRd0 TLP.\n");
			header0->fmt = TLPFMT_3DW_NODATA;
		} else {
			DEBUG_PRINTF("CfgWr0 TLP.\n");
			header0->fmt = TLPFMT_3DW_DATA;
			data_length = 4;
		}
		header0->type = CFG_0;
		header_req->requester_id = get_postgres_requester_id(result);
		header_req->tag = get_postgres_tag(result);
		header_req->lastbe = get_postgres_last_be(result);
		header_req->firstbe = get_postgres_first_be(result);
		config_dword2->device_id = get_postgres_device_id(result);
		uint32_t reg = get_postgres_register(result);
		config_dword2->ext_reg_num = reg >> 8;
		config_dword2->reg_num = reg >> 2 & uint32_mask(6);
		length = 12;
		break;
	case PG_CPL:
	case PG_CPL_D:
		if (tlp_type == PG_CPL) {
			DEBUG_PRINTF("Cpl TLP.\n");
			header0->fmt = TLPFMT_3DW_NODATA;
			data_length = 0;
		} else {
			DEBUG_PRINTF("CplD TLP.\n");
			header0->fmt = TLPFMT_3DW_DATA;
			data_length = get_postgres_byte_cnt(result);
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
	case PG_MSG_D:
		DEBUG_PRINTF("MsgD TLP.\n");
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
	default:
		PDBG("ERROR! Unknown TLP type: %s",
			PQgetvalue(result, 0, PQfnumber(result, "tlp_type")));
		assert(false);
	}

	if (data_length > 0) {
		uint64_t data = get_postgres_data(result);
		TLPDoubleWord *data_dword = (TLPDoubleWord *)&data;
		for (int i = 0; i < (data_length / sizeof(TLPDoubleWord)); ++i) {
			dword3[i] = bswap32(data_dword[i]);
		}
	}
	return length;
}

#endif //ifdef POSTGRES

/* tlp_len is length of the buffer in bytes. */
/* Return -1 if 1024 attempts to poll the buffer fail. */
int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
#ifdef POSTGRES
	int ret_value;
	/* TODO: Check we don't buffer overrun. */
	PGresult *result = PQgetResult(postgres_connection_downstream);
	assert(result != NULL);

	TLPDoubleWord *tlp_dword = (TLPDoubleWord *)tlp;
	DEBUG_PRINTF("Simulating receiving TLP ");
	ret_value = tlp_from_postgres(result, tlp_dword, tlp_len);

	PQclear(result);
	return ret_value;
#else /* Real approach: no POSTGRES */
	volatile PCIeStatus pciestatus;
	volatile TLPQuadWord pciedata;
	volatile int ready;
	int i = 0; // i is "length of TLP so far received in doublewords.

	do {
		ready = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
	} while (ready == 0);

	do {
		pciestatus.word = IORD64(PCIEPACKETRECEIVER_0_BASE,
			PCIEPACKETRECEIVER_STATUS);
		pciedata = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		tlp[i++] = pciedata;
		if ((i * 8) > tlp_len) {
			PDBG("ERROR: TLP Larger than buffer.");
			return -1;
		}
	} while (!pciestatus.bits.endofpacket);

	return (i * 8);
#endif
}

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
#ifdef POSTGRES
	int i, response;

	PGresult *result = PQgetResult(postgres_connection_upstream);
	assert(result != NULL);

	TLPQuadWord expected[64];
	int buffer_len = 64 * sizeof(TLPQuadWord);
	assert(tlp_len <= buffer_len);
	memset(expected, 0, buffer_len);
	DEBUG_PRINTF("Simulating sending ");
	response = tlp_from_postgres(result, (TLPDoubleWord *)expected, buffer_len);

	if (response != tlp_len) {
		PDBG("Trying to send tlp of length %d. Exected %d.", tlp_len, response);
		assert(response == tlp_len);
	}

	uint8_t *expected_byte = (uint8_t *)expected;
	uint8_t *actual_byte = (uint8_t *)tlp;

	bool match = true;
	for (i = 0; i < tlp_len; ++i) {
		/* This is an exemption for the model num */
		if (!(i == 14 && expected_byte[i] == 0x5e && actual_byte[i] == 0xd3)) {
			match = match && (expected_byte[i] == actual_byte[i]);
		}
	}

	if (!match) {
		for (i = 0; i < tlp_len; ++i) {
			DEBUG_PRINTF("%03d: Exp - 0x%02x; Act - 0x%02x (%p)",
				i, expected_byte[i], actual_byte[i], &actual_byte[i]);
			if (expected_byte[i] != actual_byte[i]) {
				DEBUG_PRINTF(" !");
			}
			DEBUG_PRINTF("\n");
		}
		return -1;
	}

	return 0;
#else
	int quad_word_index;
	volatile PCIeStatus statusword;

	assert(tlp_len / 8 < 64);

	// Stops the TX queue from draining whilst we're filling it.
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);

	for (quad_word_index = 0; quad_word_index < (tlp_len / 8);
			++quad_word_index) {
		statusword.word = 0;
		statusword.bits.startofpacket = (quad_word_index == 0);
		statusword.bits.endofpacket =
			((quad_word_index + 1) >= (tlp_len / 8));

		// Write status word.
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_STATUS,
			statusword.word);
		// Write data
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_DATA,
			tlp[quad_word_index]);
	}
	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	return 0;
#endif
}


static inline void
create_config_completion_header(volatile TLPDoubleWord *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum TLPCompletionStatus completion_status, uint16_t requester_id,
	uint8_t tag)
{
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp[0] = 0;
	tlp[1] = 0;
	tlp[2] = 0;

	volatile struct TLP64DWord0 *header0 = (volatile struct TLP64DWord0 *)(tlp);
	header0->fmt = ((direction == TLPD_READ) ?
		TLPFMT_3DW_DATA : TLPFMT_3DW_NODATA);
	header0->type = CPL;
	header0->length = ((direction == TLPD_READ) ? 1 : 0);

	volatile struct TLP64CompletionDWord1 *header1 =
		(volatile struct TLP64CompletionDWord1 *)(tlp) + 1;
	header1->completer_id = completer_id;
	header1->status = completion_status;
	header1->bytecount = 4;

	volatile struct TLP64CompletionDWord2 *header2 =
		(volatile struct TLP64CompletionDWord2 *)(tlp) + 2;
	header2->requester_id = requester_id;
	header2->tag = tag;
}

MachineState *current_machine;
volatile uint8_t *led_phys_mem;

void
initialise_leds()
{
#ifdef BERI
#define LED_BASE		0x7F006000LL
#define LED_LEN			0x1

		led_phys_mem = open_io_region(LED_BASE, LED_LEN);

#undef LED_LEN
#undef LED_BASE
#endif
}

static inline void
write_leds(uint8_t data)
{
#ifdef BERI
	*led_phys_mem = ~data;
#endif
}

int
blink_main(int argc, char *argv[])
{
	printf("It's blinky time!\n");
#ifdef BERI
	initialise_leds();

	uint8_t led_value = 0x55; // 0b0101

	while (1) {
		write_leds(led_value);
		led_value = ~led_value;
		putchar('.');
		fflush(stdout);
		usleep(100000);
	}
#endif
	return 0;
}

#ifdef POSTGRES

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

#endif

int
main(int argc, char *argv[])
{
	int connection_status, query_status;
#ifdef POSTGRES
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
		"SELECT * FROM trace "
		"WHERE link_dir = 'Downstream' "
		"ORDER BY packet ASC;");
	if (query_status != 0) {
		return query_status;
	}

	query_status = start_binary_single_row_query(
		postgres_connection_upstream,
		"SELECT * FROM trace "
		"WHERE link_dir = 'Upstream' "
		"ORDER BY packet ASC;");
	if (query_status != 0) {
		return query_status;
	}

#endif

	printf("Starting.\n");
	/*const char *driver = "e1000-82540em";*/
	const char *driver = "e1000e";
	const char *id = "the-e1000e";

	MachineClass *machine_class;
    DeviceClass *dc;
    DeviceState *dev;
    Error *err = NULL;

	/* This needs to be called, otherwise the types are never registered. */
	module_call_init(MODULE_INIT_QOM);

    qemu_add_opts(&qemu_netdev_opts);
    qemu_add_opts(&qemu_net_opts);

	/* Stuff needs to exist within the context of a mchine, apparently. The
	 * device attempts to realize the machine within the course of getting
	 * realized itself
	 */
    module_call_init(MODULE_INIT_MACHINE);
    machine_class = find_default_machine();

	printf("Initialised modules, found default machine.\n");

	current_machine = MACHINE(object_new(object_class_get_name(
                          OBJECT_CLASS(machine_class))));

	printf("Created machine, attached to root object.\n");

    object_property_add_child(object_get_root(), "machine",
                              OBJECT(current_machine), &error_abort);

	printf("Attached machine to root object.\n");

	/* This sets up the appropriate address spaces. */
	cpu_exec_init_all();

	printf("Done cpu init.\n");

	MemoryRegion *pci_memory;
	pci_memory = g_new(MemoryRegion, 1);
	memory_region_init(pci_memory, NULL, "pci", UINT64_MAX);

	printf("Created pci memory region.\n");

	// Something to do with interrupts
	GSIState *gsi_state = g_malloc0(sizeof(*gsi_state));
	qemu_irq *gsi = qemu_allocate_irqs(gsi_handler, gsi_state, GSI_NUM_PINS);

	printf("Done gsi stuff.\n");

	Q35PCIHost *q35_host;
	q35_host = Q35_HOST_DEVICE(qdev_create(NULL, TYPE_Q35_HOST_DEVICE));
    /*q35_host->mch.ram_memory = ram_memory;*/
    q35_host->mch.pci_address_space = pci_memory;
    q35_host->mch.system_memory = get_system_memory();
    q35_host->mch.address_space_io = get_system_io();
    /*q35_host->mch.below_4g_mem_size = below_4g_mem_size;*/
    /*q35_host->mch.above_4g_mem_size = above_4g_mem_size;*/
    /*q35_host->mch.guest_info = guest_info;*/

	printf("Created q35.\n");

	// Actually get round to creating the bus!
	PCIHostState *phb;
	PCIBus *pci_bus;

    qdev_init_nofail(DEVICE(q35_host));
    phb = PCI_HOST_BRIDGE(q35_host);
    pci_bus = phb->bus;

	printf("Created bus.\n");

	if (net_init_clients() < 0) {
		printf("Failed to initialise network clients :(\n");
		exit(1);
	}
	printf("Network clients initialised.\n");

    /* find driver */
    dc = qdev_get_device_class(&driver, &err);
    if (!dc) {
		printf("Didn't find NIC device class -- failing :(\n");
        return 1;
    }

	printf("Found device class.\n");

    /* find bus */
	if (!pci_bus /*|| qbus_is_full(bus)*/) {
		error_setg(&err, "No '%s' bus found for device '%s'",
			dc->bus_type, driver);
		return 2;
	}

	printf("Creating device...\n");
    /* create device */
    dev = DEVICE(object_new(driver));

	printf("Setting parent bus...\n");

    if (pci_bus) {
        qdev_set_parent_bus(dev, &(pci_bus->qbus));
    }

	printf("Setting device id...\n");
	dev->id = id;

    /*if (dev->id) {*/
        /*object_property_add_child(qdev_get_peripheral(), dev->id,*/
                                  /*OBJECT(dev), NULL);*/
	/*}*/

	printf("Setting device realized...\n");
	// This will realize the device if it isn't already, shockingly.
	object_property_set_bool(OBJECT(dev), true, "realized", &err);

	PCIDevice *pci_dev = PCI_DEVICE(dev);
	// Use pci_host_config read common to reply to read responses.
	printf("%x.\n", pci_host_config_read_common(pci_dev, 0, 4, 4));

#ifndef POSTGRES
	physmem = open_io_region(PCIEPACKET_REGION_BASE, PCIEPACKET_REGION_LENGTH);
	initialise_leds();
#endif

	int i, tlp_in_len = 0, tlp_out_len, send_length, send_result;
	enum tlp_direction dir;
	char *type_string;
	bool print;
	uint16_t length, device_id, requester_id;
	uint64_t addr, req_addr;

	TLPDoubleWord tlp_in[64], tlp_out[64];
	TLPDoubleWord *tlp_out_body = (tlp_out + 3);
	TLPQuadWord *tlp_in_quadword = (TLPQuadWord *)tlp_in;
	TLPQuadWord *tlp_out_quadword = (TLPQuadWord *)tlp_out;

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp_in;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(tlp_in + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(tlp_in + 2);

	struct TLP64ConfigReq *config_req = (struct TLP64ConfigReq *)tlp_in;
	struct TLP64DWord0 *h0bits = &(config_req->header0);
	struct TLP64RequestDWord1 *req_bits = &(config_req->req_header);

	int received_count = 0;
	write_leds(received_count);

	tlp_in[0] = 0xDEADBEE0;
	tlp_in[1] = 0xDEADBEE1;
	tlp_in[2] = 0xDEADBEE2;
	tlp_in[3] = 0xDEADBEE3;

	memset(tlp_out, 0, 64 * sizeof(TLPDoubleWord));

	printf("LEDs clear; let's go.\n");

	while (1) {
		/*printf("Waiting for TLP.\n");*/
		/*putchar('.');*/
		/*fflush(stdout);*/
		tlp_in_len = wait_for_tlp(tlp_in_quadword, sizeof(tlp_in));
		/*printf("Received TLP.\n");*/

		dir = ((dword0->fmt & 2) >> 1);
		const char *direction_string = (dir == TLPD_READ) ? "read" : "write";

		print = true;

		switch (dword0->type) {
		case M:
			print = false;

			break;
		case CFG_0:
			print = false;

			assert(dword0->length == 1);
			requester_id = request_dword1->requester_id;
			device_id = config_request_dword2->device_id;
			req_addr = config_request_dword2->ext_reg_num;
			req_addr = (req_addr << 6) | config_request_dword2->reg_num;
			req_addr <<= 2;

			if (dir == TLPD_READ) {
				send_length = 16;

				tlp_out_body[0] = pci_host_config_read_common(
					pci_dev, req_addr, 4, 4);

				++received_count;
				write_leds(received_count);

			} else {
				send_length = 12;

				pci_host_config_write_common(
					pci_dev, req_addr, 4, tlp_in[3], 4);
			}

			create_config_completion_header(
				tlp_out, dir, device_id, TLPCS_SUCCESSFUL_COMPLETION,
				requester_id, req_bits->tag);

			send_result = send_tlp(tlp_out_quadword, send_length);
			assert(send_result != -1);

			break;
		case IO:
			type_string = "IO";
			break;
		case CPL:
			type_string = "Completion";
			break;
		default:
			type_string = "Unknown";
		}
	}

	return 0;
}
