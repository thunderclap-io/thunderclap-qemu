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
#include "pcie-debug.h"
#include "hw/net/e1000_regs.h"

#define TARGET_BERI		1
#define TARGET_NATIVE	2

#include <execinfo.h>
#include <stdio.h>
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

#include "pcie.h"
#include "pciefpga.h"
#include "beri-io.h"
#include "mask.h"
#include "pcie-backend.h"


#ifdef POSTGRES
bool ignore_next_postgres_completion;
bool mask_next_postgres_completion_data;
uint32_t postgres_completion_mask;

#define PG_STATUS_MASK \
	~(E1000_STATUS_FD | E1000_STATUS_ASDV_100 | E1000_STATUS_ASDV_1000)

/* The capbility list is different for many small reasons, which is why we
 * want this. */

void
print_last_recvd_packet_ids();

#endif


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


static inline void
create_completion_header(volatile TLPDoubleWord *tlp,
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

MachineState *current_machine;
volatile uint8_t *led_phys_mem;


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


int
main(int argc, char *argv[])
{

	printf("Starting.\n");
	/*const char *driver = "e1000-82540em";*/
	const char *driver = "e1000e";
	const char *id = "the-e1000e";

	MachineClass *machine_class;
    DeviceClass *dc;
    DeviceState *dev;
    Error *err = NULL;

    int init = pcie_hardware_init(argc, argv, &physmem);

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
	// Use pci_host_config read common to reply to read responses.
	printf("%x.\n", pci_host_config_read_common(pci_dev, 0, 4, 4));


	int i, tlp_in_len = 0, tlp_out_len, send_length, send_result, bytecount;
	enum tlp_direction dir;
	enum tlp_completion_status completion_status;
	char *type_string;
	bool read_error = false;
	bool write_error = false;
	bool ignore_next_io_completion = false;
	bool mask_next_io_completion_data = false;
	uint16_t length, device_id, requester_id;
	uint32_t io_completion_mask, loweraddress;
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

	MemoryRegionSection target_section;
	MemoryRegion *target_region;
	hwaddr rel_addr;

	int received_count = 0;
	write_leds(received_count);

	tlp_in[0] = 0xDEADBEE0;
	tlp_in[1] = 0xDEADBEE1;
	tlp_in[2] = 0xDEADBEE2;
	tlp_in[3] = 0xDEADBEE3;

	memset(tlp_out, 0, 64 * sizeof(TLPDoubleWord));

	printf("LEDs clear; let's go.\n");

	int card_reg = -1;

	while (1) {
		/*printf("Waiting for TLP.\n");*/
		/*putchar('.');*/
		/*fflush(stdout);*/
		tlp_in_len = wait_for_tlp(tlp_in_quadword, sizeof(tlp_in));
		/*printf("Received TLP.\n");*/

		dir = ((dword0->fmt & 2) >> 1);
		const char *direction_string = (dir == TLPD_READ) ? "read" : "write";


		switch (dword0->type) {
		case M:
			assert(dword0->length == 1);
			/* This isn't in the spec, but seems to be all we've found in our
			 * trace. */

			bytecount = 0;

			target_section = memory_region_find(pci_memory, tlp_in[2], 4);
			target_region = target_section.mr;
			rel_addr = target_section.offset_within_region;

			if (dir == TLPD_READ) {
				read_error = io_mem_read( target_region,
					rel_addr,
					(uint64_t *)tlp_out_body,
					4);
#ifdef POSTGRES
				if (read_error) {
					print_last_recvd_packet_ids();
				}
				if (rel_addr == 0x10 || rel_addr == 0x5B58) {
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
			}

			for (i = 0; i < 4; ++i) {
				if ((request_dword1->firstbe >> i) & 1) {
					/*PDBG("Reading REG %s offset 0x%lx", target_region->name,*/
						   /*(rel_addr + i));*/
					if (dir == TLPD_READ) {
						if (bytecount == 0) {
							loweraddress = tlp_in[2] + i;
						}
						++bytecount;
					} else { /* dir == TLPD_WRITE */
						write_error = io_mem_write(
							target_region,
							rel_addr + i,
							*((uint64_t *)((uint8_t *)tlp_in + 12 + i)),
							1);
						assert(!write_error);
					}
				}
			}

			if (dir == TLPD_WRITE) {
				break;
			}

			create_completion_header(tlp_out, dir, device_id,
				TLPCS_SUCCESSFUL_COMPLETION, bytecount, requester_id,
				req_bits->tag, loweraddress);

			send_result = send_tlp(tlp_out_quadword, 16);
			assert(send_result != -1);

			break;
		case CFG_0:
			assert(dword0->length == 1);
			requester_id = request_dword1->requester_id;
			req_addr = config_request_dword2->ext_reg_num;
			req_addr = (req_addr << 6) | config_request_dword2->reg_num;
			req_addr <<= 2;

			if ((config_request_dword2->device_id & uint32_mask(3)) == 0) {
				/* Mask to get function num -- we are 0 */
				completion_status = TLPCS_SUCCESSFUL_COMPLETION;
				device_id = config_request_dword2->device_id;

				if (dir == TLPD_READ) {
					send_length = 16;

					tlp_out_body[0] = pci_host_config_read_common(
						pci_dev, req_addr, req_addr + 4, 4);

					/*PDBG("CfgRd0 from %lx, Value 0x%x",*/
						/*req_addr, tlp_out_body[0]);*/

					++received_count;
					write_leds(received_count);

				} else {
					send_length = 12;

					for (i = 0; i < 4; ++i) {
						if ((request_dword1->firstbe >> i) & 1) {
							pci_host_config_write_common(
								pci_dev, req_addr + i, req_addr + 4,
								tlp_in[3] >> (i * 8), 1);
						}
					}
				}
			}
			else {
				completion_status = TLPCS_UNSUPPORTED_REQUEST;
				send_length = 12;
			}

			create_completion_header(
				tlp_out, dir, device_id, completion_status, 4,
				requester_id, req_bits->tag, 0);

			send_result = send_tlp(tlp_out_quadword, send_length);
			assert(send_result != -1);

			break;
		case IO:
			assert(request_dword1->firstbe == 0xf); /* Only seen trace. */

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

			target_section = memory_region_find(get_system_io(), tlp_in[2], 4);
			target_region = target_section.mr;
			rel_addr = target_section.offset_within_region;

			if (dir == TLPD_WRITE) {
				send_length = 12;
				assert(io_mem_write(target_region, rel_addr, tlp_in[3], 4)
					== false);

				if (rel_addr == 0) {
					card_reg = tlp_in[3];
				}
				else if (rel_addr == 4 && card_reg == 0x8) {
					PDBG("Setting CARD REG 0x%x <= 0x%x",
						card_reg, tlp_in[3]);
				}
			} else {
				send_length = 16;
				assert(io_mem_read(target_region, rel_addr,
						(uint64_t *)tlp_out_body, 4)
					== false);

				if (rel_addr == 4 && card_reg == 0x8) {
					PDBG("Read CARD REG 0x%x = 0x%x", card_reg, *tlp_out_body);
				}
			}

#ifdef POSTGRES
			if (ignore_next_io_completion) {
				ignore_next_io_completion = false;
				ignore_next_postgres_completion = true;
			}
#endif

			create_completion_header(tlp_out, dir, device_id,
				TLPCS_SUCCESSFUL_COMPLETION, 4, requester_id, req_bits->tag, 0);

#ifdef POSTGRES
			if (dir == TLPD_WRITE && card_reg == 0x10) {
				ignore_next_io_completion = true;
			} else if (dir == TLPD_READ && card_reg == 0x5B50) {
				/*PDBG("Reading software semaphore.");*/
				/*mask_next_postgres_completion_data = true;*/
				postgres_completion_mask = ~2;
				/* EEPROM semaphore bit */
			} else if (dir == TLPD_READ && card_reg == 0x8) {
				mask_next_postgres_completion_data = true;
				postgres_completion_mask = PG_STATUS_MASK;
			}
#endif

			send_result = send_tlp(tlp_out_quadword, send_length);
			assert(send_result != -1);

			break;
		case CPL:
			assert(false);
			break;
		default:
			type_string = "Unknown";
		}
	}

	return 0;
}
