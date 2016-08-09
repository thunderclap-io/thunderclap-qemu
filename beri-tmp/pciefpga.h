#ifndef PCIE_FPGA_H
#define PCIE_FPGA_H
// register locations for the PCIePacketTransmitter and PCIePacketReceiver Bluespec cores

#define PCIEPACKETTRANSMITTER_QUEUEENABLE	3	// set to 1 to allow the outbound queue to be drained by the PCIe IP
#define PCIEPACKETTRANSMITTER_STATUS		2	// start of packet, end of packet
#define PCIEPACKETTRANSMITTER_DATA		0	// start of packet, end of packet

#define PCIEPACKETRECEIVER_READY			3	// non-zero when there is a valid data word
#define PCIEPACKETRECEIVER_STATUS			2	// start of packet, end of packet
#define PCIEPACKETRECEIVER_DATA				0	// reading will dequeue the 64-bit word


#define UNCACHED_BASE			0x9000000000000000LL

#define PCIEPACKETTRANSMITTER_0_BASE	((uint64_t) (UNCACHED_BASE + 0x50101800LL))
#define PCIEPACKETRECEIVER_0_BASE	((uint64_t) (UNCACHED_BASE + 0x50101000LL))

#define PCIEPACKET_REGION_BASE		0x0LL
#define PCIEPACKET_REGION_LENGTH	0x100000000LL

#endif
