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
		uint64_t pad:48;
		uint8_t startofpacket:8;
		uint8_t endofpacket:8;
	} bits;
	uint64_t word;
} PCIeStatus;

struct TLP64Header0Bits {
	uint8_t lengthL:8; // LSbyte 0 HL
	uint8_t td:1;      // byte 1 H
	uint8_t ep:1;
	uint8_t attr:2;
	uint8_t at:2;
	uint8_t lengthH:2; // byte 1 L
	uint8_t twentythree:1; // byte 2 H
	uint8_t tc:3;
	uint8_t sixteen:4; // byte 2 L
	uint8_t fmt:3;     // MSbyte 3 H
	uint8_t type:5;    // MSbyte 3 L
};

typedef union {
        struct TLP64Header0Bits bits;
        uint32_t word;
} TLP64Header0;

struct TLP64HeaderReqBits {
	uint8_t lastbe:4; //XXX CR: Think last and first be might be in the wrong order?
	uint8_t firstbe:4;
	uint8_t tag:8; // XXX: CR: If not, tag will be manged in the middle
	uint8_t requesteridL:8;
	uint8_t requesteridH:8;
};

typedef union {
        struct TLP64HeaderReqBits bits;
        uint32_t word;
} TLP64HeaderReq;


typedef union {
	struct {
		uint8_t		bytecountL:8;	// byte 0
		uint8_t		status:3;	// byte 1 H
		uint8_t		bcm:1;
		uint8_t		bytecountH:4;	// byte 1 L
		uint8_t		completeridL:8;	// byte 2
		uint8_t		completeridH:8;	// byte 3
	} bits;
	uint32_t word;
} TLP64HeaderCompl0;


typedef union {
	struct {
		uint8_t		seven:1;	// byte 0 H
		uint8_t		loweraddress:7; // byte 0 L
		uint8_t		tag:8;		// byte 1
		uint8_t		requestedidL:8; // byte 2
		uint8_t		requesteridH:8;	// byte 3
	} bits;
	uint32_t word;
} TLP64HeaderCompl1;

typedef union {
	TLP64HeaderReq req;
	TLP64HeaderCompl0 compl0;
	TLP64HeaderCompl1 compl1;
} TLP64Header1;

struct TLP64HeaderWord0 {
	unsigned int fmt:3; // XXX CR: This was 2, but seems to be wrong
	TLPType      type:5;
	unsigned int twentythree:1;
	unsigned int tc:3;
	unsigned int sixteen:4;
	unsigned int td:1;
	unsigned int ep:1;
	unsigned int attr:2;
	unsigned int at:2;
	unsigned int length:10;
};

union TLP64HeaderWord0Union {					// big endian
	struct TLP64HeaderWord0 bits;
	uint32_t word;
};

typedef union {					// big endian
	struct {
		unsigned int requesterid:16;
		unsigned int tag:8;
		unsigned int lastbe:4;
		unsigned int firstbe:4;
	} bits;
	uint32_t word;
} TLPHeaderReq;

typedef union {					// big endian
	struct {
		unsigned int completerid:16;
		unsigned int status:3;
		unsigned int bcm:1;
		unsigned int bytecount:12;
	} bits;
	uint32_t word;
} TLPHeaderCompl0;

typedef union {					// big endian
	struct {
		unsigned int requesterid:16;
		unsigned int tag:8;
		unsigned int seven:1;
		unsigned int loweraddress:7;
	} bits;
	uint32_t word;
} TLPHeaderCompl1;

typedef enum {
	SC=0,
	UR=1,
	CRS=2,
	Reserved3=3,
	CA=4,
	Reserved5=5,
	RequestTimeout=-1
} TLPCompletionStatus;

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
	union TLP64HeaderWord0Union header0;
	TLPHeaderReq      id;
	TLPAddress32 addressH;
	TLPAddress32 addressL;
	TLPWord	   data[];
} TLP64bit;

struct TLP64ConfigReq {
	struct TLP64HeaderWord0 header0;
	struct TLP64HeaderReqBits req;
	uint8_t reserved:2;
	uint8_t reg_num:6;
	uint8_t ext_reg_num:4;
	uint8_t reserved2:4;
	uint8_t func_num:3;
	uint8_t device_num:5;
	uint8_t bus_num:8;
}

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
	TLPCompletionStatus status;
//	uint32_t			length;
	MemoryWord			data32;
} MemoryResponse;

typedef uint64_t Address;

#endif
