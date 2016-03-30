#ifndef PCIE_H
#define PCIE_H

typedef enum {
	MemoryReq=0, MemoryReqLocked=1, IOReq=2, Conf0=4, Conf1=5,
	TConf=0x1B, Message=0x10, Completion=0xA, CompletionLock=0x0B
} TLPType;

typedef enum {
	Read=0, Write=1
} TLPDirection;

enum TLPFmt {
	TLPFMT_3DW_NODATA	= 0,
	TLPFMT_4DW_NODATA	= 1,
	TLPFMT_3DW_DATA		= 2,
	TLPFMT_4DW_DATA		= 3,
	TLPFMT_PREFIX		= 4
};

#define TLPFMT_PREFIX		0x4
#define TLPFMT_WITHDATA		0x2
#define TLPFMT_4DW			0x1

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

struct TLP64Header0Bits {
	uint32_t fmt:3;
	TLPType type:5;
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

typedef union {
        struct TLP64Header0Bits bits;
        uint32_t word;
} TLP64Header0;

struct TLP64HeaderReqBits {
	uint32_t requester_id:16;
	uint32_t tag:8;
	uint32_t lastbe:4;
	uint32_t firstbe:4;
};

typedef union {
        struct TLP64HeaderReqBits bits;
        uint32_t word;
} TLP64HeaderReq;


struct TLP64HeaderCompl0Bits {
	uint32_t	completer_id:16;
	uint32_t	status:3;
	uint32_t	bcm:1;
	uint32_t	bytecount:12;
};

typedef union {
	struct TLP64HeaderCompl0Bits bits;
	uint32_t word;
} TLP64HeaderCompl0;

struct TLP64HeaderCompl1Bits {
	uint32_t	requester_id:16;
	uint32_t	tag:8;
	uint32_t	reserved:1;
	uint32_t	loweraddress:7; // byte 0 L
};

typedef union {
	struct TLP64HeaderCompl1Bits bits;
	uint32_t word;
} TLP64HeaderCompl1;

typedef union {
	TLP64HeaderReq req;
	TLP64HeaderCompl0 compl0;
	TLP64HeaderCompl1 compl1;
} TLP64Header1;

union TLP64HeaderWord0 {					// big endian
	struct TLP64Header0Bits bits;
	uint32_t word;
};

typedef union {					// big endian
	struct {
		uint32_t requester_id:16;
		uint32_t tag:8;
		uint32_t lastbe:4;
		uint32_t firstbe:4;
	} bits;
	uint32_t word;
} TLPHeaderReq;

typedef union {					// big endian
	struct {
		uint32_t completer_id:16;
		uint32_t status:3;
		uint32_t bcm:1;
		uint32_t bytecount:12;
	} bits;
	uint32_t word;
} TLPHeaderCompl0;

typedef union {					// big endian
	struct {
		uint32_t requester_id:16;
		uint32_t tag:8;
		uint32_t seven:1;
		uint32_t loweraddress:7;
	} bits;
	uint32_t word;
} TLPHeaderCompl1;

enum TLPCompletionStatus {
	TLPCS_SUCCESSFUL_COMPLETION	= 0,
	TLPCS_UNSUPPORTED_REQUEST		= 1,
	TLPCS_CONFIGURATION_REQUEST_RETRY = 2,
	TLPCS_RESERVED_LITERAL_3		= 3,
	TLPCS_COMPLETER_ABORT			= 4,
	TLPCS_RESERVED_LITERAL_5		= 5,
	TLPCS_REQUEST_TIMEOUT			= -1
} ;

typedef uint64_t TLPDoubleWord;

typedef uint32_t TLPWord;

typedef uint32_t TLPAddress32;

typedef uint32_t MemoryWord;

typedef struct {
	TLPAddress32 addressH;
	TLPAddress32 addressL;
} TLP64Address64;

typedef union {
	struct {
		TLP64Header0 header0;
		TLP64Header1 header1;
	} bits;
	uint64_t word;
} TLP64Header01;

typedef struct {
	union TLP64HeaderWord0 header0;
	TLPHeaderReq      id;
	TLPAddress32 addressH;
	TLPAddress32 addressL;
	TLPWord	   data[];
} TLP64bit;

struct TLP64ConfigReq {
	struct TLP64Header0Bits header0;
	struct TLP64HeaderReqBits req;
	uint32_t completer_id:16;
	uint32_t reserved0:4;
	uint32_t ext_reg_num:4;
	uint32_t reg_num:6;
	uint32_t reserved1:2;
};

typedef struct {
	TLP64Header01	header;
	TLP64Address64	address;
	TLPWord		data[];
} TLP6464bit;

typedef struct {
	/// XXX: CR I BROKEN THIS
	//union TLP64HeaderWord0Union header0;
	TLPHeaderReq      id;
	TLPAddress32 addressL;
	TLPWord	   data[];
} TLP32bit;

typedef struct {
	TLP64Header01	header;
	TLPAddress32	addressL;
	TLPWord		data[];	// first word could either be pad, or the first data word if a 3 D-word TLP with non-Qword aligned address
//	TLPWord		data[];
} TLP6432bit;

typedef struct {			// big endian
	TLPWord		h0;
	TLPWord		h1;
	TLPWord		h2;
	TLPWord		h3;
} TLP64HeaderRaw;

typedef struct {
	enum TLPCompletionStatus status;
//	uint32_t			length;
	MemoryWord			data32;
} MemoryResponse;

typedef uint64_t Address;

#endif
