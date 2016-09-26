#ifndef PCIE_H
#define PCIE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t TLPQuadWord;
typedef uint32_t TLPDoubleWord;

/*
 * Length fields are in bytes.
 */
struct RawTLP {
	int header_length;
	TLPDoubleWord *header;
	int data_length;
	TLPDoubleWord *data;
};

inline void
set_raw_tlp_invalid(struct RawTLP *out)
{
	out->header_length = -1;
	out->header = NULL;
	out->data_length = -1;
	out->data = NULL;
}

inline bool
is_raw_tlp_valid(struct RawTLP *tlp)
{
	return tlp->header_length != -1;
}

#ifdef POSTGRES
inline void
set_raw_tlp_trace_finished(struct RawTLP *out)
{
	set_raw_tlp_invalid(out);
	out->data_length = -2;
}

inline bool
is_raw_tlp_trace_finished(struct RawTLP *tlp)
{
	return !is_raw_tlp_valid(tlp) && (tlp->data_length == -2);
}
#endif

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

inline bool
tlp_fmt_has_data(enum tlp_fmt fmt)
{
	return fmt & TLPFMT_WITHDATA;
}

inline bool
tlp_fmt_is_4dw(enum tlp_fmt fmt)
{
	return fmt & TLPFMT_4DW;
}

typedef union {
	struct {
		uint64_t endofpacketEE:8;
		uint64_t startofpacket55:8;
		uint64_t pad2:22;
		uint64_t endofpacket:1;
		uint64_t startofpacket:1;
		uint64_t byteenable:8;
		uint64_t pad1:16;
	} bits;
	uint64_t word;
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
	enum tlp_fmt fmt:3;
	enum tlp_type type:5;
	uint32_t reserved0:1;
	uint32_t tc:3;
	uint32_t reserved1:3;
	uint32_t th:1;
	uint32_t td:1;
	uint32_t ep:1;
	uint32_t attr:2;
	uint32_t at:2;
	uint32_t length:10;
};

union TLP64DWord0Int {
        struct TLP64DWord0 bits;
        uint32_t word;
};

struct TLP64RequestDWord1 {
	uint32_t requester_id:16;
	uint32_t tag:8;
	uint32_t lastbe:4;
	uint32_t firstbe:4;
};

union TLP64RequestDWord1Int {
        struct TLP64RequestDWord1 bits;
        uint32_t word;
};

struct TLP64MessageRequestDWord1 {
	uint32_t requester_id:16;
	uint32_t tag:8;
	uint32_t message_code:8;
};

struct TLP64CompletionDWord1 {
	uint32_t	completer_id:16;
	uint32_t	status:3;
	uint32_t	bcm:1;
	uint32_t	bytecount:12;
};

union TLP64CompletionDWord1Int {
	struct TLP64CompletionDWord1 bits;
	uint32_t word;
};

struct TLP64CompletionDWord2 {
	uint32_t	requester_id:16;
	uint32_t	tag:8;
	uint32_t	reserved:1;
	uint32_t	loweraddress:7; // byte 0 L
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
	uint32_t device_id:16;
	uint32_t reserved0:4;
	uint32_t ext_reg_num:4;
	uint32_t reg_num:8;
};

struct TLP64ConfigReq {
	struct TLP64DWord0 header0;
	struct TLP64RequestDWord1 req_header;
	struct TLP64ConfigRequestDWord2 dword2;
};

void
create_completion_header(struct RawTLP *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress);

void
create_memory_read_header(struct RawTLP *tlp, uint16_t length,
	uint16_t requester_id, uint8_t tag, uint8_t lastbe, uint8_t firstbe,
	uint64_t address);


#endif
