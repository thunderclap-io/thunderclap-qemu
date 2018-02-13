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
 * before entering main.
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
#include "hw/pci/pci.h"
#include "exec/memory.h"
#include "exec/memory-internal.h"
#include "hw/net/e1000_regs.h"
#include "hw/net/e1000e_core.h"
#endif

#define TARGET_BERI		1
#define TARGET_NATIVE	2

#ifndef BAREMETAL
#include <execinfo.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#endif

#include <stdbool.h>

#include "block/coroutine.h"/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than CLBYTES (the software page size), and,
 * on machines that exchange pages of input or output buffers with mbuf
 * clusters (MAPPED_MBUFS), MCLBYTES must also be an integral multiple
 * of the hardware page size.
 */
#define	MSIZESHIFT	8			/* 256 */
#define	MSIZE		(1 << MSIZESHIFT)	/* size of an mbuf */
#define	MCLSHIFT	11			/* 2048 */
#define	MCLBYTES	(1 << MCLSHIFT)		/* size of an mbuf cluster */
#define	MBIGCLSHIFT	12			/* 4096 */
#define	MBIGCLBYTES	(1 << MBIGCLSHIFT)	/* size of a big cluster */
#define	M16KCLSHIFT	14			/* 16384 */
#define	M16KCLBYTES	(1 << M16KCLSHIFT)	/* size of a jumbo cluster */

#ifndef DUMMY
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci-host/q35.h"
#include "qapi/qmp/qerror.h"
#include "qemu/config-file.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "sysemu/cpus.h"
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

uint32_t global_devfn;

FILE *GLOBAL_BINARY_FILE;

#ifdef POSTGRES

void
print_last_recvd_packet_ids();

#endif

#ifndef DUMMY

static Object *qdev_get_peripheral(void)
{
    static Object *dev;

    if (dev == NULL) {
        dev = container_get(qdev_get_machine(), "/peripheral");
    }

    return dev;
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
#endif


#ifndef BAREMETAL
#ifndef DUMMY
MachineState *current_machine;
#endif
#endif

#ifndef DUMMY
long
timespec_diff_in_ns(struct timespec *left, struct timespec *right) {
	return 1000000000L * ((right->tv_sec) - (left->tv_sec)) +
		(right->tv_nsec - left->tv_nsec);
}
#endif

extern int last_packet;


enum packet_response {
	PR_NO_RESPONSE, PR_RESPONSE
};

struct PacketGeneratorState {
	PCIDevice *pci_dev;

	uint64_t next_read;
};

void
initialise_packet_generator_state(struct PacketGeneratorState *state)
{
	state->next_read = 0;
}

static bool
e1000e_ats_enabled(PCIDevice *pci_dev)
{
	return pci_get_word(pci_dev->config + E1000E_ATS_OFFSET + 6) & (1 << 15);
}

enum packet_response
generate_packet(struct PacketGeneratorState *state, struct RawTLP *out)
{
	if (state->pci_dev->devfn == -1) {
		return PR_NO_RESPONSE;
	}

	if (e1000e_ats_enabled(state->pci_dev)) {
		create_memory_request_header(out, TLPD_READ, TLP_AT_TRANSLATED, 8,
			state->pci_dev->devfn, 0, 0xF, 0xF, state->next_read);
	}

	return PR_RESPONSE;
}

enum packet_response
respond_to_packet(struct PacketGeneratorState *state, struct RawTLP *in,
	struct RawTLP *out)
{
	int i, bytecount;
	enum tlp_direction dir;
	enum tlp_completion_status completion_status;
	bool read_error = false;
	uint16_t requester_id;
	uint32_t loweraddress;
	uint64_t req_addr, data_buffer;

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)in->header;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(in->header + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(in->header + 2);

	struct TLP64ConfigReq *config_req = (struct TLP64ConfigReq *)in->header;
	struct TLP64RequestDWord1 *req_bits = &(config_req->req_header);

	enum packet_response response = PR_NO_RESPONSE;

#ifndef DUMMY
	bool found_subregion;
	PCIIORegion *pci_io_region;
	MemoryRegion *target_region, *subregion;
	hwaddr rel_addr;
#endif

	out->header_length = 0;
	out->data_length = 0;

	dir = ((dword0->fmt & 2) >> 1);

	switch (dword0->type) {
	case M:
		/*puts("Dealing with M req.");*/
		assert(dword0->length == 1);
		/* This isn't in the spec, but seems to be all we've found in our
		 * trace. */

		bytecount = 0;
#ifndef DUMMY
		/* TODO: Different operation for flash? */
		for (i = 0; i < PCI_NUM_REGIONS; ++i) {
			pci_io_region = &(state->pci_dev->io_regions[i]);
			if (((pci_io_region->type & PCI_BASE_ADDRESS_SPACE) ==
				PCI_BASE_ADDRESS_SPACE_MEMORY) &&
				in->header[2] >= pci_io_region->addr &&
				in->header[2] < pci_io_region->addr + pci_io_region->size) {
				break;
			} else {
				pci_io_region = NULL;
			}
		}
		if (pci_io_region == NULL) {
			printf("Memory req for unmappedd address 0x%X. BAR?",
				in->header[2]);
			assert(false);
		}
		target_region = pci_io_region->memory;
		rel_addr = in->header[2] - pci_io_region->addr;
		/* Memory regions can contain other regions. We should do a recursive
		 * search really, but QEMU's functions for doing it are complicated
		 * and slow.
		 */
		if (!memory_region_access_valid(target_region, rel_addr, 4, false)) {
			found_subregion = false;

			QTAILQ_FOREACH(subregion, &target_region->subregions,
					subregions_link) {
				if (rel_addr >= subregion->addr &&
						rel_addr <
						(subregion->addr + int128_get64(subregion->size))) {
					target_region = subregion;
					rel_addr -= subregion->addr;
					found_subregion = true;
					break;
				}
			}

			assert(found_subregion);
		}

		loweraddress = rel_addr;
#endif

		if (dir == TLPD_READ) {
			/*puts("M Read.");*/
			requester_id = request_dword1->requester_id;
#ifdef DUMMY
			read_error = false;
			out->data[0] = 0xBEDEBEDE;
#else
			read_error = io_mem_read(target_region, rel_addr, &data_buffer, 4);
			out->data[0] = data_buffer;
			response = PR_RESPONSE;
			/*puts("Set response to PR_RESPONSE");*/
#endif

#ifdef POSTGRES
			if (read_error) {
				print_last_recvd_packet_ids();
			}
#endif
			if (read_error) {
				printf("READ ERROR!! Whilst attempting memory read of address "
					"0x%lx.\n", rel_addr);
			}
			assert(!read_error);

			for (i = 0; i < 4; ++i) {
				if ((request_dword1->firstbe >> i) & 1) {
					if (bytecount == 0) {
						loweraddress += i;
					}
					++bytecount;
				}
			}

			out->header_length = 12;
			out->data_length = 4;
			create_completion_header(out, dir, state->pci_dev->devfn,
				TLPCS_SUCCESSFUL_COMPLETION, bytecount, requester_id,
				req_bits->tag, loweraddress);
		} else { /* dir == TLPD_WRITE */
			io_mem_write(target_region, rel_addr, bswap32(in->data[0]), 4);
		}

		break;
	case CFG_0:
		assert(dword0->length == 1);
		response = PR_RESPONSE;
		requester_id = request_dword1->requester_id;

		req_addr = get_config_req_addr(in);

		if ((config_request_dword2->device_id & uint32_mask(3)) == 0) {
			/* Mask to get function num -- we are 0 */
			completion_status = TLPCS_SUCCESSFUL_COMPLETION;
			state->pci_dev->devfn = config_request_dword2->device_id;
			global_devfn = state->pci_dev->devfn;

			if (dir == TLPD_READ) {
				out->data_length = 4;
#ifdef DUMMY
				out->data[0] = 0xBEDEBEDE;
#else
				out->data[0] = pci_host_config_read_common(
					state->pci_dev, req_addr, req_addr + 4, 4);

				/*printf("CfgRd0 of 0x%x: data 0x%x.\n",*/
					/*req_addr, out->data[0]);*/
#endif
			} else {
				out->data_length = 0;
#ifndef DUMMY
				for (i = 0; i < 4; ++i) {
					if ((request_dword1->firstbe >> i) & 1) {
						pci_host_config_write_common(
							state->pci_dev, req_addr + i, req_addr + 4,
							(in->data[0] >> ((3 - i) * 8)) & 0xFF, 1);
					}
				}
#endif
			}
		}
		else {
			completion_status = TLPCS_UNSUPPORTED_REQUEST;
			out->data_length = 0;
		}

		out->header_length = 12;
		create_completion_header(out, dir, state->pci_dev->devfn,
			completion_status, 4, requester_id, req_bits->tag, 0);

		break;
	case IO:
		assert(request_dword1->firstbe == 0xf); /* Only seen trace. */

		response = PR_RESPONSE;
		requester_id = request_dword1->requester_id;
		out->header_length = 12;

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
		req_addr = in->header[2];
		pci_io_region = &(state->pci_dev->io_regions[2]);
		assert(pci_io_region->addr != PCI_BAR_UNMAPPED);
		if (req_addr < pci_io_region->addr) {
			PDBG("Trying to map req with addr %lx in BAR with addr %lx.",
				req_addr, pci_io_region->addr);
			/*PDBG("Last packet: %d", last_packet);*/
		}
		assert(req_addr >= pci_io_region->addr);
		target_region = pci_io_region->memory;
		rel_addr = req_addr - pci_io_region->addr;
#endif

		if (dir == TLPD_WRITE) {
			out->data_length = 0;
#ifndef DUMMY
			assert(io_mem_write(target_region, rel_addr, in->data[0], 4)
				== false);
#endif
		} else {
			out->data_length = 4;
#ifdef DUMMY
			out->data[0] = 0xBEDEBEDE;
#else
			assert(io_mem_read(target_region, rel_addr, &data_buffer, 4)
				== false);
			out->data[0] = data_buffer;
#endif
		}

		create_completion_header(out, dir, state->pci_dev->devfn,
			TLPCS_SUCCESSFUL_COMPLETION, 4, requester_id, req_bits->tag, 0);

		break;
	case CPL:
		fputc('!', stderr);
		fflush(stderr);
		/*fputs("CPL Packet in ", stdout);*/
		/*fputs(__func__, stdout);*/
		/*puts(". Likely mistake.");*/
		/*print_raw_tlp(in);*/
		/*if (tlp_fmt_has_data(dword0->fmt)) {*/
			/*assert(in->data != NULL);*/
			/*uint64_t *qword_data_p = (uint64_t *)in->data;*/
			/*uint64_t qword_data = le64_to_cpu(*qword_data_p);*/
			/*printf("CPL Data: %lx: %lx\n", state->next_read, qword_data);*/
			/*state->next_read += 4096;*/
		/*}*/
		break;
	default:
		log_log(LS_RECV_UNKNOWN, LIF_NONE, 0, LOG_NEWLINE);
	}

	for (i = 0; i < out->data_length / 4; ++i) {
		out->data[i] = bswap32(out->data[i]);
	}

	return response;
}

void coroutine_fn process_packet(void *opaque)
{
	printf("Starting packet processing coroutine.\n");

	const char *driver = "e1000e";
	const char *nic_id = "the-e1000e";
	const char *netdev_id = "the-netdev";

	MachineClass *machine_class;
    DeviceClass *dc;
    DeviceState *dev;
    Error *err = NULL;
	MemoryRegion *pci_memory;
	struct Netdev netdev;
	struct NetClientOptions net_client_options;
	struct NetdevUserOptions nuo;

	/* Stuff needs to exist within the context of a mchine, apparently. The
	 * device attempts to realize the machine within the course of getting
	 * realized itself
	 */
    module_call_init(MODULE_INIT_MACHINE);
    machine_class = find_default_machine();
	current_machine = MACHINE(object_new(object_class_get_name(
                          OBJECT_CLASS(machine_class))));
    /*object_property_add_child(object_get_root(), "machine",*/
                              /*OBJECT(current_machine), &error_abort);*/
	pci_memory = g_new(MemoryRegion, 1);
	memory_region_init(pci_memory, NULL, "my-pci-memory", UINT64_MAX);
	// Something to do with interrupts
	GSIState *gsi_state = g_malloc0(sizeof(*gsi_state));
	qemu_irq *gsi = qemu_allocate_irqs(gsi_handler, gsi_state, GSI_NUM_PINS);
	Q35PCIHost *q35_host;
	q35_host = Q35_HOST_DEVICE(qdev_create(NULL, TYPE_Q35_HOST_DEVICE));
    q35_host->mch.pci_address_space = pci_memory;
    q35_host->mch.system_memory = get_system_memory();
    q35_host->mch.address_space_io = get_system_io();
	PCIHostState *phb;
	PCIBus *pci_bus;
    qdev_init_nofail(DEVICE(q35_host));
    phb = PCI_HOST_BRIDGE(q35_host);
    pci_bus = phb->bus;
	if (net_init_clients() < 0) {
		printf("Failed to initialise network clients :(\n");
		exit(1);
	}
	/* Create a client netdev */
	netdev.id = (char *)netdev_id;
	netdev.opts = &net_client_options;

	net_client_options.kind = NET_CLIENT_OPTIONS_KIND_USER;
	net_client_options.user = &nuo;

	memset(&nuo, 0, sizeof(nuo));
	nuo.has_hostname = false;
	nuo.has_q_restrict = true;
	nuo.has_q_restrict = false;
	nuo.has_ip = false;
	nuo.has_net = false;
	nuo.has_host = false;
	nuo.has_tftp = false;
	nuo.has_bootfile = false;
	nuo.has_dhcpstart = false;
	nuo.has_dns = false;
	nuo.has_dnssearch = false;
	nuo.has_smb = false;

	net_client_netdev_init(&netdev, &err);
	assert(err == NULL);

    /* find driver */
    dc = qdev_get_device_class(&driver, &err);
    if (!dc) {
		printf("Didn't find NIC device class -- failing :(\n");
        exit(1);
    }
    /* find bus */
	if (!pci_bus /*|| qbus_is_full(bus)*/) {
		error_setg(&err, "No '%s' bus found for device '%s'",
			dc->bus_type, driver);
		exit(2);
	}
    dev = DEVICE(object_new(driver));
    if (pci_bus) {
        qdev_set_parent_bus(dev, &(pci_bus->qbus));
    }

	printf("Setting device nic_id...\n");
	dev->id = nic_id;

	if (dev->id) {
		object_property_add_child(qdev_get_peripheral(), dev->id,
								  OBJECT(dev), &err);
		assert(err == NULL);
	}

	object_property_set_str(OBJECT(dev), netdev_id, "netdev", &err);
	if (err != NULL) {
		qerror_report_err(err);
		error_free(err);
		assert(false);
	}

	// This will realize the device if it isn't already, shockingly.
	object_property_set_bool(OBJECT(dev), true, "realized", &err);
	PCIDevice *pci_dev = PCI_DEVICE(dev);

	int send_result;

#ifdef POSTGRES
	bool finished_trace = false;
#endif

	bool is_valid;
	enum packet_response response;
	TLPQuadWord tlp_out_header[2];
	TLPQuadWord tlp_out_data[16];
	struct RawTLP raw_tlp_in;
	struct RawTLP raw_tlp_out;
	raw_tlp_out.header = (TLPDoubleWord *)tlp_out_header;
	raw_tlp_out.data = (TLPDoubleWord *)tlp_out_data;
	struct PacketGeneratorState packet_generator_state;

	initialise_packet_generator_state(&packet_generator_state);
	packet_generator_state.pci_dev = pci_dev;

	E1000ECore *core = &(E1000E(pci_dev)->core);

	printf("Init done. Let's go.\n");

	while (true) {
		next_tlp(&raw_tlp_in);

#ifdef POSTGRES
		if (is_raw_tlp_trace_finished(&raw_tlp_in)) {
			if (!finished_trace) {
				PDBG("Reached end of trace! Checked %d TLPs.", TLPS_CHECKED);
				finished_trace = true;
			}
			exit(0);
		}
#endif

		response = PR_NO_RESPONSE;
		is_valid = is_raw_tlp_valid(&raw_tlp_in);
		if (is_valid) {
			response = respond_to_packet(&packet_generator_state, &raw_tlp_in,
				&raw_tlp_out);
		} else {
			/*response = generate_packet(&packet_generator_state, &raw_tlp_out);*/
		}

		if (response != PR_NO_RESPONSE) {
			/*puts("Sending response TLP.");*/
			send_result = send_tlp(&raw_tlp_out);
			assert(send_result != -1);
		}

		free_raw_tlp_buffer(&raw_tlp_in);
		if (!is_valid) {
			/*check_windows_for_secret();*/
#if 0
			change_check_time = clock();
			if ((change_check_time - last_change_check_time) > (CLOCKS_PER_SEC)) {
				putchar('.');
				fflush(stdio);
				write_window_if_changed(core);
				last_change_check_time = change_check_time;
			}
#endif
			qemu_coroutine_yield();
		}
	}
}

void enter_co_bh(void *opaque)
{
	Coroutine *co = opaque;
	qemu_coroutine_enter(co, NULL);
}

void handle_sigtrap(int signum, siginfo_t *siginfo, void *uctx)
{
	assert(signum == SIGTRAP);
	printf("SIGTRAP! Fault on: %p.\n", siginfo->si_addr);
}

void handle_sigint(int arg)
{
	exit(2);
}

void handle_exit_call()
{
	printf("Caught signal or exit. Closing File.\n");
	fclose(GLOBAL_BINARY_FILE);
}

int
main(int argc, char *argv[])
{
	struct sigaction sigtrap_action = {
		.sa_sigaction = handle_sigtrap,
		.sa_flags = SA_SIGINFO
	};

	sigaction(SIGTRAP, &sigtrap_action, NULL);


    Error *err = NULL;
	use_icount = 0;

	log_set_strings(log_strings);
	puts("Starting.");

	address_space_io.name = "ATTEMPTING TO USE SYSTEM IO ADDRESS SPACE. "
		"ILLEGAL.";
	address_space_memory.name = "ATTEMPTING TO USE SYSTEM MEMORY ADDRESS "
		"SPACE. ILLEGAL.";

	/*printf("MHSIZE: 0x%x.\n", MHSIZE);*/
	/*printf("MPKTHSIZE: 0x%x.\n", MPKTHSIZE);*/
	/*const char *driver = "e1000-82540em";*/
#ifndef DUMMY
	/* Initiliase main loop, which has to run to shuttle data between NIC and
	 * client. */
	qemu_init_main_loop(&err);
	assert(err == NULL);

	/* This sets up a load of mutexes and condition variables for the main
	 * loop. Locking of the iothread seems to have to happen directly after
	 * it. I have no idea why. */
	qemu_init_cpu_loop();
    qemu_mutex_lock_iothread();

	/* This needs to be called, otherwise the types are never registered. */
	module_call_init(MODULE_INIT_QOM);
	/* This sets up the appropriate address spaces. */
	cpu_exec_init_all();

    qemu_add_opts(&qemu_netdev_opts);
    qemu_add_opts(&qemu_net_opts);

#endif // not DUMMY

    int init = pcie_hardware_init(argc, argv, &physmem);
    if (init)
    	return init;

	drain_pcie_core();
	puts("PCIe Core Drained. Let's go.");

	Coroutine *co = qemu_coroutine_create(process_packet);
	QEMUBH *start_bh = qemu_bh_new(enter_co_bh, co);

	vm_start();

	/*
	printf("About to start main loop. This build built on EMH MK1.\n");

	if (argc != 2) {
		printf("Error! Must be called with a hexdump file as argument.\n");
		return 1;
	}

	GLOBAL_BINARY_FILE = fopen(argv[1], "wb");
	signal(SIGINT, handle_sigint);
	atexit(handle_exit_call);
	*/

	while (1) {
		qemu_bh_schedule(start_bh);
		main_loop_wait(true);
	}

	return 0;
}
