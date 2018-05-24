#ifndef PCIE_FPGA_H
#define PCIE_FPGA_H
// register locations for the PCIePacketTransmitter and PCIePacketReceiver Bluespec cores

#ifdef PCIETXRX32
// set to 1 to allow the outbound queue to be drained by the PCIe IP
#define PCIEPACKETTRANSMITTER_QUEUEENABLE	0xC
// start of packet, end of packet
#define PCIEPACKETTRANSMITTER_STATUS		0x8
#define PCIEPACKETTRANSMITTER_UPPER32		0x4
// writing here will send the 64-bit word
#define PCIEPACKETTRANSMITTER_LOWER32SEND	0
#define PCIEPACKETTRANSMITTER_DATA		0

// non-zero when there is a valid data word
#define PCIEPACKETRECEIVER_READY		0xC
// start of packet, end of packet
#define PCIEPACKETRECEIVER_STATUS		0x8
#define PCIEPACKETRECEIVER_UPPER32		0x4
// reading will dequeue the 64-bit word
#define PCIEPACKETRECEIVER_LOWER32DEQ		0
#define PCIEPACKETRECEIVER_DATA			0

#else

// set to 1 to allow the outbound queue to be drained by the PCIe IP
#define PCIEPACKETTRANSMITTER_QUEUEENABLE	24
// start of packet, end of packet
#define PCIEPACKETTRANSMITTER_STATUS		16
#define PCIEPACKETTRANSMITTER_DATA		0

// non-zero when there is a valid data word
#define PCIEPACKETRECEIVER_READY		24
// start of packet, end of packet
#define PCIEPACKETRECEIVER_STATUS		16
// reading will dequeue the 64-bit word
#define PCIEPACKETRECEIVER_DATA			0

#endif // PCIETXRX32

#ifdef PLATFORM_BERI
#define PCIEPACKETTRANSMITTER_0_BASE	0x50101800LL
#define PCIEPACKETRECEIVER_0_BASE	0x50101000LL
#define PCIEPACKET_REGION_BASE		0x50101000LL
#define PCIEPACKET_REGION_LENGTH	0x00001000LL
#elif defined PLATFORM_ARM
#define PCIEPACKETRECEIVER_0_BASE	0xC0040000LL
#define PCIEPACKETTRANSMITTER_0_BASE	0xC0040400LL
#define PCIEPACKET_REGION_BASE		0xC0040000LL
#define PCIEPACKET_REGION_LENGTH	0x00001000LL
#else
#error "No defined PCIE Hard Core for platform"
#endif

#endif
