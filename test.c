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

#include <stdint.h>
#include <stdbool.h>
#include "pcie-debug.h"
#ifndef DUMMY
#include "hw/net/e1000_regs.h"
#endif

#define TARGET_BERI		1
#define TARGET_NATIVE	2

#ifndef BAREMETAL
#include <execinfo.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/endian.h>
#endif

#include <stdbool.h>

#ifndef DUMMY
#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/i386/pc.h"
#include "hw/pci-host/q35.h"
#include "qapi/qmp/qerror.h"
#include "qemu/config-file.h"
#endif

#include "pcie-backend.h"
#include "log.h"

#include "baremetal/baremetalsupport.h"
#include "pcie.h"

#ifndef POSTGRES
#include "pciefpga.h"
#include "beri-io.h"
#endif

#include "mask.h"


#ifdef POSTGRES
bool ignore_next_postgres_completion;
bool mask_next_postgres_completion_data;
uint32_t postgres_completion_mask;

#define PG_STATUS_MASK \
	bswap32(~(E1000_STATUS_FD | E1000_STATUS_ASDV_100 | E1000_STATUS_ASDV_1000 \
		| E1000_STATUS_GIO_MASTER_ENABLE ))


/* The capbility list is different for many small reasons, which is why we
 * want this. */

void
print_last_recvd_packet_ids();

#endif

#ifndef DUMMY
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
#endif

static inline void
create_completion_header(TLPDoubleWord *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress)
{
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp[0] = 0;
	tlp[1] = 0;
	tlp[2] = 0;

	volatile struct TLP64DWord0 *header0 = (volatile struct TLP64DWord0 *)(tlp);
	if (direction == TLPD_READ
		&& completion_status == TLPCS_SUCCESSFUL_COMPLETION) {
		header0->fmt = TLPFMT_3DW_DATA;
		header0->length = 1;
	} else {
		header0->fmt = TLPFMT_3DW_NODATA;
		header0->length = 0;
	}
	header0->type = CPL;

	volatile struct TLP64CompletionDWord1 *header1 =
		(volatile struct TLP64CompletionDWord1 *)(tlp) + 1;
	header1->completer_id = completer_id;
	header1->status = completion_status;
	header1->bytecount = bytecount;

	volatile struct TLP64CompletionDWord2 *header2 =
		(volatile struct TLP64CompletionDWord2 *)(tlp) + 2;
	header2->requester_id = requester_id;
	header2->tag = tag;
	header2->loweraddress = loweraddress;
}

#ifndef BAREMETAL
#ifndef DUMMY
MachineState *current_machine;
#endif
#endif
volatile uint8_t *led_phys_mem;


static inline void
write_leds(uint32_t data)
{
#ifdef BERI
	*led_phys_mem = ~data;
#endif
}

#ifndef DUMMY
long
timespec_diff_in_ns(struct timespec *left, struct timespec *right) {
	return 1000000000L * ((right->tv_sec) - (left->tv_sec)) +
		(right->tv_nsec - left->tv_nsec);
}
#endif

extern int last_packet;

struct PacketGeneratorState {
	uint64_t next_read;
};

void
initialise_packet_generator_state(struct PacketGeneratorState *state)
{
	state->next_read = 0;
}

void
generate_packet(struct PacketGeneratorState *state,
	TLPDoubleWord *tlp_out_header, int *tlp_out_header_len,
	TLPDoubleWord *tlp_out_data, int *tlp_out_data_len)
{
}

enum packet_response {
	PR_NO_RESPONSE, PR_RESPONSE_UNALIGNED, PR_RESPONSE_ALIGNED
};

enum packet_response
respond_to_packet(PCIDevice *pci_dev, TLPQuadWord *tlp_in_quadword,
	int *header_length, int *data_length,
	TLPQuadWord *tlp_out_header, TLPQuadWord *tlp_out_data)
{
	int i, tlp_in_len = 0, bytecount;
	enum tlp_direction dir;
	enum tlp_completion_status completion_status;
	bool read_error = false;
	bool write_error = false;
	bool ignore_next_io_completion = false;
	bool mask_next_io_completion_data = false;
	uint16_t length, device_id, requester_id;
	uint32_t io_completion_mask, loweraddress;
	uint64_t addr, req_addr;

	TLPDoubleWord *tlp_in = (TLPDoubleWord *)tlp_in_quadword;
	TLPDoubleWord *tlp_out_header_dword = (TLPDoubleWord *)tlp_out_header;
	TLPDoubleWord *tlp_out_data_dword = (TLPDoubleWord *)tlp_out_data;
	uint16_t *tlp_out_data_word = (uint16_t *)tlp_out_data;

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp_in;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(tlp_in + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(tlp_in + 2);

	struct TLP64ConfigReq *config_req = (struct TLP64ConfigReq *)tlp_in;
	struct TLP64DWord0 *h0bits = &(config_req->header0);
	struct TLP64RequestDWord1 *req_bits = &(config_req->req_header);

	enum packet_response response = PR_NO_RESPONSE;

#ifndef DUMMY
	PCIIORegion *pci_io_region;
	MemoryRegion *target_region;
	hwaddr rel_addr;
#endif

	*header_length = 0;
	*data_length = 0;

	/* Has to be static due to the way reading over IO space works. */
	static int card_reg = -1;

	dir = ((dword0->fmt & 2) >> 1);
	const char *direction_string = (dir == TLPD_READ) ? "read" : "write";

	switch (dword0->type) {
	case M:
		assert(dword0->length == 1);
		/* This isn't in the spec, but seems to be all we've found in our
		 * trace. */

		bytecount = 0;
#ifndef DUMMY
		/* TODO: Different operation for flash? */
		pci_io_region = &(pci_dev->io_regions[0]);
		assert(pci_io_region->addr != PCI_BAR_UNMAPPED);
		assert(tlp_in[2] >= pci_io_region->addr);
		target_region = pci_io_region->memory;
		rel_addr = tlp_in[2] - pci_io_region->addr;
		loweraddress = rel_addr;
#endif

		if (dir == TLPD_READ) {
#ifdef DUMMY
			read_error = false;
			tlp_out_data_dword[0] = 0xBEDEBEDE;
#else
			read_error = io_mem_read(target_region,
				rel_addr,
				tlp_out_data,
				4);

			response = (rel_addr % 8) == 0 ?
				PR_RESPONSE_ALIGNED : PR_RESPONSE_UNALIGNED;
#endif
			/* We have read a dword size chunk into a qword. The relevant data
			 * is the least significant bits, so goes at a larger offset. We
			 * want the data in the correct dword pointer, so we move it from
			 * where it is.
			 */
			tlp_out_data_dword[0] = (TLPDoubleWord)tlp_out_data[0];

#ifdef POSTGRES
			if (read_error) {
				print_last_recvd_packet_ids();
			}

			if (rel_addr == 0x0) {
				mask_next_postgres_completion_data = true;
				postgres_completion_mask =
					bswap32(~uint32_mask_enable_bits(19, 19));
				/* 19 is apparently a software controllable IO pin, so I
				 * don't think we particularly care. */
			} else if (rel_addr == 0x8) {
				mask_next_postgres_completion_data = true;
				postgres_completion_mask = PG_STATUS_MASK;
			} else if (rel_addr == 0x10 || rel_addr == 0x5B58) {
				/* 1) EEPROM or Flash
				 * 2) Second software semaphore, not present on this
				 * card.
				 */
				ignore_next_postgres_completion = true;
			} else if (rel_addr == 0x8) {
				mask_next_postgres_completion_data = true;
				postgres_completion_mask = PG_STATUS_MASK;
			}
#endif
			assert(!read_error);

			for (i = 0; i < 4; ++i) {
				if ((request_dword1->firstbe >> i) & 1) {
					if (bytecount == 0) {
						loweraddress += i;
					}
					++bytecount;
				}
			}

			*header_length = 12;
			*data_length = 4;
			create_completion_header(tlp_out_header_dword, dir, device_id,
				TLPCS_SUCCESSFUL_COMPLETION, bytecount, requester_id,
				req_bits->tag, loweraddress);
		} else { /* dir == TLPD_WRITE */
			uint32_t write_data = bswap32(
				(rel_addr % 8 == 0) ? tlp_in[4] : tlp_in[3]);

			io_mem_write(target_region, rel_addr, write_data, 4);
		}

		break;
	case CFG_0:
		assert(dword0->length == 1);
		response = PR_RESPONSE_ALIGNED;
		requester_id = request_dword1->requester_id;

		req_addr = config_request_dword2->ext_reg_num;
		req_addr = (req_addr << 8) | config_request_dword2->reg_num;

		if ((config_request_dword2->device_id & uint32_mask(3)) == 0) {
			/* Mask to get function num -- we are 0 */
			completion_status = TLPCS_SUCCESSFUL_COMPLETION;
			device_id = config_request_dword2->device_id;

			if (dir == TLPD_READ) {
				*data_length = 4;
#ifdef DUMMY
				tlp_out_data_dword[0] = 0xBEDEBEDE;
#else
				tlp_out_data_dword[0] = pci_host_config_read_common(
					pci_dev, req_addr, req_addr + 4, 4);
#endif

#ifdef POSTGRES
				if (req_addr == 0 || req_addr == 0xC) {
					/* Model number and ?cacheline size? */
					mask_next_postgres_completion_data = true;
					postgres_completion_mask = 0xFFFF00FF;
				} else if (req_addr == 4) {
					mask_next_postgres_completion_data = true;
					postgres_completion_mask = 0x00FFFFFF;
				} else if (req_addr == 8) {
					/* Revision ID */
					mask_next_postgres_completion_data = true;
					postgres_completion_mask = 0x00FFFFFF;
				} else if (req_addr == 0x2C) {
					/* Subsystem ID and Subsystem vendor ID */
					ignore_next_postgres_completion = true;
				}
#endif

			} else {
				*data_length = 0;
#ifndef DUMMY
#define TLP_DATA	((req_addr % 8 == 0) ? tlp_in[4] : tlp_in[3])
				for (i = 0; i < 4; ++i) {
					if ((request_dword1->firstbe >> i) & 1) {
						pci_host_config_write_common(
							pci_dev, req_addr + i, req_addr + 4,
							(TLP_DATA >> ((3 - i) * 8)) & 0xFF, 1);
					}
				}
#undef TLP_DATA
#endif
			}
		}
		else {
			completion_status = TLPCS_UNSUPPORTED_REQUEST;
			*data_length = 0;
		}

		*header_length = 12;
		create_completion_header(
			tlp_out_header_dword, dir, device_id, completion_status, 4,
			requester_id, req_bits->tag, 0);

		break;
	case IO:
		assert(request_dword1->firstbe == 0xf); /* Only seen trace. */

		response = PR_RESPONSE_ALIGNED;
		*header_length = 12;

		/*
		 * The process for interacting with the device over IO is rather
		 * convoluted.
		 *
		 * 1) A packet is sent writing an address to a register.
		 * 2) A completion happens.
		 *
		 * 3) A packet is then sent reading or writing another register.
		 * 4) The completion for this is effectively for the address that
		 * was written in 1).
		 *
		 * So we need to ignore the completion for the IO packet after the
		 * completion for 2)
		 *
		 */
#ifndef DUMMY
		req_addr = tlp_in[2];
		pci_io_region = &(pci_dev->io_regions[2]);
		assert(pci_io_region->addr != PCI_BAR_UNMAPPED);
		if (req_addr < pci_io_region->addr) {
			PDBG("Trying to map req with addr %x in BAR with addr %x.",
				req_addr, pci_io_region->addr);
			PDBG("Last packet: %d", last_packet);
		}
		assert(req_addr >= pci_io_region->addr);
		target_region = pci_io_region->memory;
		rel_addr = req_addr - pci_io_region->addr;
#endif

		if (dir == TLPD_WRITE) {
			*data_length = 0;
#ifndef DUMMY
			assert(io_mem_write(target_region, rel_addr, tlp_in[3], 4)
				== false);
#endif
		} else {
			*data_length = 4;
#ifdef DUMMY
			tlp_out_data[0] = 0xBEDEBEDE;
#else
			assert(io_mem_read(target_region, rel_addr,
					(uint64_t *)tlp_out_data, 4)
				== false);
#endif
		}

#ifdef POSTGRES
		if (ignore_next_io_completion) {
			ignore_next_io_completion = false;
			ignore_next_postgres_completion = true;
		}
#endif

		create_completion_header(tlp_out_header_dword, dir, device_id,
			TLPCS_SUCCESSFUL_COMPLETION, 4, requester_id, req_bits->tag, 0);

#ifdef POSTGRES
		if (dir == TLPD_WRITE && card_reg == 0x10) {
			ignore_next_io_completion = true;
		} else if (dir == TLPD_READ && card_reg == 0x8) {
			mask_next_postgres_completion_data = true;
			postgres_completion_mask = PG_STATUS_MASK;
		}
#endif

		break;
	case CPL:
		assert(false);
		break;
	default:
		log_log(LS_RECV_UNKNOWN, LIF_NONE, 0, LOG_NEWLINE);
	}

	for (i = 0; i < *data_length / 4; ++i) {
		tlp_out_data_dword[i] = bswap32(tlp_out_data_dword[i]);
	}

	return response;
}


int
main(int argc, char *argv[])
{
	log_set_strings(log_strings);
	puts("Starting.");
	/*const char *driver = "e1000-82540em";*/
#ifndef DUMMY
	const char *driver = "e1000e";
	const char *id = "the-e1000e";

	MachineClass *machine_class;
    DeviceClass *dc;
    DeviceState *dev;
    Error *err = NULL;

	/* Otherwise it will try to delete a non-existent clock - segfault. */
	init_clocks();

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
	memory_region_init(pci_memory, NULL, "my-pci-memory", UINT64_MAX);

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
	PDBG("System IO name: %s", get_system_io()->name);
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
	/* Use pci_host_config read common to reply to read responses.
	 * This calls the config_read function on the device.
	 * For the e1000e, this is a thin wrapper over pci_default_read_config,
	 * from hw/pci/pci.c
	 */
	printf("%x.\n", pci_host_config_read_common(pci_dev, 0, 4, 4));
#endif // not DUMMY

    int init = pcie_hardware_init(argc, argv, &physmem);
    if (init)
    	return init;

	int i, tlp_in_len = 0, send_result;
	int header_length, data_length;
	bool ignore_next_io_completion = false;
	bool mask_next_io_completion_data = false;
	uint16_t length, device_id, requester_id;
	uint32_t io_completion_mask, loweraddress;
	uint64_t addr, req_addr;

	enum packet_response response;
	enum tlp_data_alignment alignment;

	TLPQuadWord tlp_in_quadword[32];
	TLPQuadWord tlp_out_header[2];
	TLPQuadWord tlp_out_data[16];

	int received_count = 0;
	write_leds(received_count);

	drain_pcie_core();
	puts("PCIe Core Drained. Let's go.");

	while (1) {
		do {
			tlp_in_len = wait_for_tlp(tlp_in_quadword, sizeof(tlp_in_quadword));
		} while (tlp_in_len == -1);

#ifdef POSTGRES
		if (tlp_in_len == TRACE_COMPLETE) {
			PDBG("Reached end of trace! Checked %d TLPs.", TLPS_CHECKED);
			exit(0);
		}
#endif

		response = respond_to_packet(pci_dev, tlp_in_quadword, &header_length,
			&data_length, tlp_out_header, tlp_out_data);

		if (response != PR_NO_RESPONSE) {
			alignment = (response == PR_RESPONSE_ALIGNED) ?
				TDA_ALIGNED : TDA_UNALIGNED;

			send_result = send_tlp(tlp_out_header, header_length, tlp_out_data,
				data_length, alignment);

			assert(send_result != -1);
		}
	}

	return 0;
}
