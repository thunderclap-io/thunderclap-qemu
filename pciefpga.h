#ifndef PCIE_FPGA_H
#define PCIE_FPGA_H
// register locations for the PCIePacketTransmitter and PCIePacketReceiver Bluespec cores

#ifdef PCIETXRX32
#define PCIEPACKETTRANSMITTER_QUEUEENABLE	3	// set to 1 to allow the outbound queue to be drained by the PCIe IP
#define PCIEPACKETTRANSMITTER_STATUS		2	// start of packet, end of packet
#define PCIEPACKETTRANSMITTER_UPPER32		1
#define PCIEPACKETTRANSMITTER_LOWER32SEND	0	// writing here will send the 64-bit word

#define PCIEPACKETRECEIVER_READY			3	// non-zero when there is a valid data word
#define PCIEPACKETRECEIVER_STATUS			2	// start of packet, end of packet
#define PCIEPACKETRECEIVER_UPPER32			1
#define PCIEPACKETRECEIVER_LOWER32DEQ		0	// reading will dequeue the 64-bit word

#else

#define PCIEPACKETTRANSMITTER_QUEUEENABLE	3	// set to 1 to allow the outbound queue to be drained by the PCIe IP
#define PCIEPACKETTRANSMITTER_STATUS		2	// start of packet, end of packet
#define PCIEPACKETTRANSMITTER_DATA		0	// start of packet, end of packet

#define PCIEPACKETRECEIVER_READY			3	// non-zero when there is a valid data word
#define PCIEPACKETRECEIVER_STATUS			2	// start of packet, end of packet
#define PCIEPACKETRECEIVER_DATA				0	// reading will dequeue the 64-bit word

#endif // PCIETXRX32

#ifdef PLATFORM_BERI
#define PCIEPACKETTRANSMITTER_0_BASE	0x50101800LL	//
#define PCIEPACKETRECEIVER_0_BASE	0x50101000LL	//
#define PCIEPACKET_REGION_BASE		0x50101000LL
#define PCIEPACKET_REGION_LENGTH	0x00001000LL
#elif defined PLATFORM_ARM
#define PCIEPACKETRECEIVER_0_BASE	0xC0004000LL	//
#define PCIEPACKETTRANSMITTER_0_BASE	0xC0004400LL	//
#define PCIEPACKET_REGION_BASE		0xC0004000LL
#define PCIEPACKET_REGION_LENGTH	0x00001000LL
#else
#error "No defined PCIE Hard Core for platform"
#endif

#endif
