#ifndef ATTACKS_H
#define ATTACKS_H

#include "hw/net/e1000e_core.h"

enum DescriptorType { DT_TRANSMIT, DT_RECEIVE };

struct Descriptor {
	enum DescriptorType type;
	uint64_t buffer_addr;
	uint16_t length;
};

typedef const struct Descriptor * const ConstDescriptorP;

typedef void (*OperateOnDescriptor)(E1000ECore *core,
	ConstDescriptorP descriptor);

void
for_each_descriptor_address(E1000ECore *core, enum DescriptorType which_ring,
	OperateOnDescriptor loop_body, void (*done)());

/*
 * Before the NIC begins processing its transmit ring, loop_body is called
 * with every transmit descriptor in the transmit ring.
 *
 * Note that the register call will override the previously registered
 * handler.
 */
void
register_pre_xmit_hook(OperateOnDescriptor loop_body, void (*done)());

#endif
