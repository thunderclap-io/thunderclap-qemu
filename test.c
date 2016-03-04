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

#include "stdio.h"
#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"

#include "hw/i386/pc.h"
#include "hw/pci-host/q35.h"
#include "qapi/qmp/qerror.h"

#include "pcie.h"
#include "pciefpga.h"
#include "beri-io.h"

static DeviceClass *qdev_get_device_class(const char **driver, Error **errp)
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

/* tlp_len is length of the buffer in bytes. */
int
wait_for_tlp(TLPDoubleWord *tlp, int tlp_len)
{
	volatile PCIeStatus pciestatus;
	volatile TLPDoubleWord pciedata;
	volatile TLPWord pciedata1, pciedata0;
	volatile uint64_t *data, *status;
	volatile int ready;
	int i = 0; // i is "length of TLP so far received in doublewords.

	do {
		ready = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
	} while (ready == 0);

	do {
		data = (uint64_t *)(physmem + 0x50101000LL);
		status = (uint64_t *)(physmem + 0x50101010LL);
		pciestatus.word = *status;
		pciedata = *data;
		pciedata0 = pciedata >> 32LL;
		pciedata1 = pciedata & 0xffffffffLL;
		if (pciestatus.bits.startofpacket) {
			i = 0;
		}
		tlp[i++] = pciedata;
		if ((i * 8) > tlp_len) {
			printf("ERROR: TLP Larger than buffer.\n");
			return -1;
		}
	} while (!pciestatus.bits.endofpacket);

	return (i * 8);
}

int
create_config_read_completion(TLPDouble *tlp)
{
	// Clear buffer
	memset(tlp, 0, 16);

	struct TLP64HeaderWord0 *header0 = (struct TLP64HeaderWord0 *)&tlp;
	header0->fmt = TLPFMT_3DW_NODATA;
	header0->type = Completion;
	header0->length = 1;

}

/* tlp length is the legnth of the buffer in bytes. */
int
send_tlp(TLPDoubleWord *tlp, int tlp_len)
{
	assert(false); // NOT IMPLEMENTED!
	int i;
	for (i = 0; i < (tlp_len / 8); ++i)
	{
	}
	return 0;
}


MachineState *current_machine;

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

	physmem = open_io_region(0LL, 1LL<<32LL);

	int tlp_len = 0;
	TLPDoubleWord tlp[64];
	TLP64Header01 h0and1;
	TLPDirection dir;
	char *type_string;
	bool print;
	uint16_t length, requester_id;
	struct TLP64ConfigReq *config_req = &tlp;
	struct TLP64Header0Bits *h0bits = &(config_req->header0);
	struct TLP64HeaderReqBits *req_bits = &(config_req->req);
	uint64_t addr, req_addr;
	while (1) {
		tlp_len = wait_for_tlp(tlp, sizeof(tlp));
		h0and1.word = tlp[0];

		dir = (TLPDirection)((h0and1.bits.header0.bits.fmt & 2) >> 1);
		const char *direction_string = (dir == 0) ? "read" : "write";

		print = true;

		uint8_t type = h0and1.bits.header0.bits.type;
		switch (type) {
		case MemoryReq:
			type_string = "Memory";
			break;
		case Conf0:
			print = false;
			length = h0bits->lengthH << 8 | h0bits->lengthL;
			requester_id = req_bits->requesteridH << 8 | req_bits->requesteridL;
			req_addr = config_req->ext_reg_num;
			req_addr = (req_addr << 6) | config_req->reg_num;
			req_addr <<= 2;
			printf("Config %s TLP.\n  Length: %#x\n  Requester ID: %#x\n"
				"  Tag: %#x\n  ReqAddr: %#x",
				direction_string, length, requester_id, req_bits->tag, req_addr);
			break;
		case IOReq:
			type_string = "IO";
			break;
		case Completion:
			type_string = "Completion";
			break;
		case 0x13: //Broadcast packets, can drop.
			print = false;
			break;
		default:
			type_string = "Unknown";
		}

		if (print) {
			printf("%s (%#x) %s TLP.\n", type_string, type, direction_string);
		}
	}

	return 0;
}
