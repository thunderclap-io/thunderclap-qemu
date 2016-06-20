#ifndef PCIE_H
#define PCIE_H

typedef uint64_t TLPQuadWord;
typedef uint32_t TLPDoubleWord;

enum tlp_type {
	M					= 0x0, // Memory
	M_LK				= 0x1, // Memory Locked
	IO					= 0x2,
	CFG_0				= 0x4,
	CFG_1				= 0x5,
	CPL					= 0xA, // Completion
	CPL_LK				= 0x0B, // Completion Locked
	MSG					= 0x10, // Message Request
	T_CFG				= 0x1B, // These are deprecated
};

enum tlp_direction {
	TLPD_READ = 0, TLPD_WRITE = 1
};

enum tlp_fmt {
	TLPFMT_3DW_NODATA	= 0,
	TLPFMT_4DW_NODATA	= 1,
	TLPFMT_3DW_DATA		= 2,
	TLPFMT_4DW_DATA		= 3,
	TLPFMT_PREFIX		= 4
};

#define TLPFMT_4DW			0x1
#define TLPFMT_WITHDATA		0x2
#define TLPFMT_PREFIX		0x4

typedef union {
	struct {
		uint32_t pad1:16;
		uint32_t byteenable:8;
		uint32_t startofpacket:1;
		uint32_t endofpacket:1;
		uint32_t pad2:6;
		//uint64_t pad2:22;
		//uint64_t startofpacket55:8;
		//uint64_t endofpacketEE:8;
	} bits;
	uint32_t word;
} PCIeStatus;

/* TLP Structure Naming Scheme:
 * TLP64 -- Namespace. Structures for sending TLPs 64 bits at a time.
 * <TLP Type> -- String representing the applicable types of TLP.
 * DWord<n> -- The offset from the prefix section in DWords that the header
 * DWord appears at.
 *
 * Unions for conversion between dwords and the struct, have the suffix "int".
 *
 * In line with style(9) the struct and union keywords are not typedefed
 * away.
 */

struct TLP64DWord0 {
	uint32_t length:10;
	uint32_t at:2;
	uint32_t attr:2;
	uint32_t ep:1;
	uint32_t td:1;
	uint32_t th:1;
	uint32_t reserved1:3;
	uint32_t tc:3;
	uint32_t reserved0:1;
	enum tlp_type type:5;
	enum tlp_fmt fmt:3;
};

union TLP64DWord0Int {
        struct TLP64DWord0 bits;
        uint32_t word;
};

struct TLP64RequestDWord1 {
	uint32_t firstbe:4;
	uint32_t lastbe:4;
	uint32_t tag:8;
	uint32_t requester_id:16;
};

union TLP64RequestDWord1Int {
        struct TLP64RequestDWord1 bits;
        uint32_t word;
};

struct TLP64MessageRequestDWord1 {
	uint32_t message_code:8;
	uint32_t tag:8;
	uint32_t requester_id:16;
};

struct TLP64CompletionDWord1 {
	uint32_t	bytecount:12;
	uint32_t	bcm:1;
	uint32_t	status:3;
	uint32_t	completer_id:16;
};

union TLP64CompletionDWord1Int {
	struct TLP64CompletionDWord1 bits;
	uint32_t word;
};

struct TLP64CompletionDWord2 {
	uint32_t	loweraddress:7; // byte 0 L
	uint32_t	reserved:1;
	uint32_t	tag:8;
	uint32_t	requester_id:16;
};

union TLP64CompletionDWord2Int {
	struct TLP64CompletionDWord2 bits;
	uint32_t word;
};

enum tlp_completion_status {
	TLPCS_SUCCESSFUL_COMPLETION	= 0,
	TLPCS_UNSUPPORTED_REQUEST		= 1,
	TLPCS_CONFIGURATION_REQUEST_RETRY = 2,
	TLPCS_RESERVED_LITERAL_3		= 3,
	TLPCS_COMPLETER_ABORT			= 4,
	TLPCS_RESERVED_LITERAL_5		= 5,
	TLPCS_REQUEST_TIMEOUT			= -1
};

struct TLP64ConfigRequestDWord2 {
	uint32_t reg_num:8;
	uint32_t ext_reg_num:4;
	uint32_t reserved0:4;
	uint32_t device_id:16;
	//uint32_t reserved1:2;
};

static inline
uint16_t get_config_request_addr(struct TLP64ConfigRequestDWord2 *dword)
{
	//uint16_t *packet_start = (uint16_t *)dword;
	//return *(packet_start + 1);
	return ((dword->ext_reg_num << 8) | (dword->reg_num << 2));
}

struct TLP64ConfigReq {
	struct TLP64DWord0 header0;
	struct TLP64RequestDWord1 req_header;
	struct TLP64ConfigRequestDWord2 dword2;
};

#endif
