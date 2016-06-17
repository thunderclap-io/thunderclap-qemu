typedef enum {
	MemoryReq=0, MemoryReqLocked=1, IOReq=2, Conf0=4, Conf1=5,
	TConf=0x1B, Message=0x10, Completion=0xA, CompletionLock=0x0B
} TLPType;

typedef enum {
	Read=0, Write=1
} TLPDirection;

#define TLPFMT_PREFIX		0x4
#define TLPFMT_WITHDATA		0x2
#define TLPFMT_4DW			0x1

typedef union {
	struct {
		unsigned int pad:24;
		unsigned int startofpacket:1;
		unsigned int endofpacket:1;
	} bits;
	uint32_t word;
} PCIeStatus;

typedef union {
	struct {
		unsigned int length:10;
		unsigned int at:2;
		unsigned int attr:2;
		unsigned int ep:1;
		unsigned int td:1;
		unsigned int sixteen:4;
		unsigned int tc:3;
		unsigned int twentythree:1;
		TLPType      type:5;
		unsigned int fmt:2;
	} bits;
	uint32_t word;
} TLPHeader0;

typedef union {
	struct {
		unsigned int firstbe:4;
		unsigned int lastbe:4;
		unsigned int tag:8;
		unsigned int requesterid:16;
	} bits;
	uint32_t word;
} TLPHeaderReq;

typedef union {
	struct {
		unsigned int bytecount:12;
		unsigned int bcm:1;
		unsigned int status:3;
		unsigned int completerid:16;
	} bits;
	uint32_t word;
} TLPHeaderCompl0;

typedef union {
	struct {
		unsigned int loweraddress:7;
		unsigned int seven:1;
		unsigned int tag:8;
		unsigned int requesterid:16;
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



typedef uint32_t TLPWord;

typedef uint32_t TLPAddress32;

typedef uint32_t MemoryWord;

typedef struct {
	TLPHeader0 header0;
	TLPHeaderReq      id;
	TLPAddress32 address0;
	TLPAddress32 address1;
	TLPWord	   data[];
} TLP64bit;

typedef struct {
	TLPHeader0 header0;
	TLPHeaderReq      id;
	TLPAddress32 address0;
	TLPWord	   data[];
} TLP32bit;


typedef struct {
	TLPCompletionStatus status;
//	uint32_t			length;
	MemoryWord			data32;
} MemoryResponse;

typedef uint64_t Address;