// register locations for the PCIePacketTransmitter and PCIePacketReceiver Bluespec cores

#define PCIEPACKETTRANSMITTER_QUEUEENABLE	3	// set to 1 to allow the outbound queue to be drained by the PCIe IP
#define PCIEPACKETTRANSMITTER_STATUS		2	// start of packet, end of packet
#define PCIEPACKETTRANSMITTER_UPPER32		1
#define PCIEPACKETTRANSMITTER_LOWER32SEND	0	// writing here will send the 64-bit word

#define PCIEPACKETRECEIVER_READY			3	// non-zero when there is a valid data word
#define PCIEPACKETRECEIVER_STATUS			2	// start of packet, end of packet
#define PCIEPACKETRECEIVER_UPPER32			1
#define PCIEPACKETRECEIVER_LOWER32DEQ		0	// reading will dequeue the 64-bit word
