#ifndef PCIE_H
#define PCIE_H

/*
 * The backend is expected to implement 'wait_for_tlp', but this should not be
 * used by most users.
 *
 * Instead 'next_tlp' and 'next_completion_tlp' should be used. These are
 * constructed so that perform_dma_read can run while requests are being made
 * by the host to the platform. If a non-completion tlp is sent while a
 * completion is being waited for, the non-completion tlp will be added to a
 * queue and returned by the next call of the next_tlp function.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <mask.h>

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

static inline void
print_raw_tlp(struct RawTLP *tlp)
{
	printf("header_length: %d. header: %p\n", tlp->header_length, tlp->header);
	printf("data_length: %d. data: %p\n", tlp->data_length, tlp->data);
}

static inline void
print_tlp_dwords(uint64_t dwords) {
	for (int byte_num = 0; byte_num < sizeof(uint64_t); ++byte_num) {
		printf("%02"PRIx64, (dwords >> (byte_num * 8)) & 0xFF);
		putchar((byte_num % 4 == 3) ? '\n' : ' ');
	}
}


void
next_tlp(struct RawTLP *out);

void
next_completion_tlp(struct RawTLP *out);

void
free_raw_tlp_buffer(struct RawTLP *tlp);

static inline void
set_raw_tlp_invalid(struct RawTLP *out)
{
	out->header_length = -1;
	out->data_length = -1;
}

static inline bool
is_raw_tlp_valid(struct RawTLP *tlp)
{
	return tlp->header_length != -1;
}

#ifdef POSTGRES
static inline void
set_raw_tlp_trace_finished(struct RawTLP *out)
{
	set_raw_tlp_invalid(out);
	out->data_length = -2;
}

static inline bool
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

static inline const char *
tlp_type_str(enum tlp_type type)
{
	switch (type) {
	case M:
		return "M";
	case M_LK:
		return "M_LK";
	case IO:
		return "IO";
	case CFG_0:
		return "CFG_0";
	case CFG_1:
		return "CFG_1";
	case CPL:
		return "CPL";
	case CPL_LK:
		return "CPL_LK";
	case MSG:
		return "MSG";
	case T_CFG:
		return "T_CFG";
	default:
		return "[unrecognised]";
	}
}

enum tlp_direction {
	TLPD_READ = 0, TLPD_WRITE = 1
};

static inline const char *
tlp_direction_str(enum tlp_direction direction) {
	switch (direction) {
	case TLPD_READ:
		return "READ";
	case TLPD_WRITE:
		return "WRITE";
	default:
		return "[oh no. this shouldn't happen.]";
	}
}

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

static inline bool
tlp_fmt_has_data(enum tlp_fmt fmt)
{
	return fmt & TLPFMT_WITHDATA;
}

static inline bool
tlp_fmt_is_4dw(enum tlp_fmt fmt)
{
	return fmt & TLPFMT_4DW;
}

static inline bool
status_get_start_of_packet(uint64_t status) {
	return ((status >> 24LL) & 1LL) == 1LL;
}

static inline bool
status_get_end_of_packet(uint64_t status) {
	return ((status >> 25LL) & 1LL) == 1LL;
}

static inline uint64_t
status_set_start_of_packet(uint64_t status) {
	return status | (1LL << 24LL);
}

static inline uint64_t
status_set_end_of_packet(uint64_t status) {
	return status | (1LL << 25LL);
}

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

enum tlp_at {
	TLP_AT_UNTRANSLATED,
	TLP_AT_TRANSLATION_REQUEST,
	TLP_AT_TRANSLATED,
	TLP_AT_RESERVED
};

#ifdef HOST_WORDS_BIGENDIAN
struct TLP64DWord0 {
	uint8_t fmt_and_type;
	uint8_t byte1;
	uint8_t byte2;
	uint8_t low_length;
};
#else
struct TLP64DWord0 {
	uint8_t low_length;
	uint8_t byte2;
	uint8_t byte1;
	uint8_t fmt_and_type;
};
#endif

static inline enum tlp_fmt
tlp_get_fmt(const struct TLP64DWord0 *dword)
{
	return (dword->fmt_and_type >> 5) & 3;
}

static inline void
tlp_set_fmt(struct TLP64DWord0 *dword, enum tlp_fmt fmt)
{
	uint8_t fmt_and_type = dword->fmt_and_type;
	fmt_and_type &= MASK(uint8_t, 5);
	fmt_and_type |= fmt << 5;
	dword->fmt_and_type = fmt_and_type;
}

static inline enum tlp_type
tlp_get_type(const struct TLP64DWord0 *dword)
{
	return dword->fmt_and_type & 31;
}

static inline void
tlp_set_type(struct TLP64DWord0 *dword, enum tlp_type type)
{
	uint8_t fmt_and_type = dword->fmt_and_type;
	fmt_and_type &= ~MASK(uint8_t, 5);
	fmt_and_type |= type;
	dword->fmt_and_type = type;
}

static inline void
tlp_set_at(struct TLP64DWord0 *dword, enum tlp_at at) {
	dword->byte2 = uint8_t_set_bits(dword->byte2, 3, 2, at);
}

static inline uint16_t
tlp_get_length(struct TLP64DWord0 *dword) {
	uint16_t length = dword->low_length;
	return (dword->byte2 & MASK(uint8_t, 2) << 8) | length;
}

static inline void
tlp_set_length(struct TLP64DWord0 *dword, uint16_t length) {
	dword->low_length = length;
	dword->byte2 = uint8_t_set_bits(dword->byte2, 1, 0, length >> 8);
}



#define BYTE_FIELD(field_name, dword_type, field_container, high, low)		\
static inline uint8_t 														\
tlp_get_ ## field_name(struct dword_type *dword)	{							\
	return uint8_t_get_bits(dword -> field_container, high, low);			\
}																			\
static inline void															\
tlp_set_ ## field_name(struct dword_type *dword, uint8_t new_value) {			\
	dword -> field_container = 												\
		uint8_t_set_bits(dword -> field_container, high, low, new_value);	\
}

#ifdef HOST_WORDS_BIGENDIAN
struct TLP64RequestDWord1 {
	uint8_t requester_idH;
	uint8_t requester_idL;
	uint8_t tag;
	uint8_t bes;
};
#else
struct TLP64RequestDWord1 {
	uint8_t bes;
	uint8_t tag;
	uint8_t requester_idL;
	uint8_t requester_idH;
};
#endif

BYTE_FIELD(firstbe, TLP64RequestDWord1, bes, 3, 0);
BYTE_FIELD(lastbe, TLP64RequestDWord1, bes, 7, 4);


#ifdef HOST_WORDS_BIGENDIAN
struct TLP64MessageRequestDWord1 {
	uint8_t requester_idH;
	uint8_t requester_idL;
	uint8_t tag;
	uint8_t message_code;
};

struct TLP64CompletionDWord1 {
	uint8_t completer_idH;
	uint8_t completer_idL;
	uint8_t byte2;
	uint8_t byte3;
};

struct TLP64CompletionDWord2 {
	uint8_t requester_idH;
	uint8_t requester_idL;
	uint8_t tag;
	uint8_t loweraddress;
};

struct TLP64ConfigRequestDWord2 {
	uint8_t device_idH;
	uint8_t device_idL;
	uint8_t ext_reg_num;
	uint8_t reg_num;
};

struct TLP64DataWord32 {
	uint32_t second;
	uint32_t first;
};
#else
struct TLP64MessageRequestDWord1 {
	uint8_t message_code;
	uint8_t tag;
	uint8_t requester_idL;
	uint8_t requester_idH;
};

struct TLP64CompletionDWord1 {
	uint8_t byte3;
	uint8_t byte2;
	uint8_t completer_idL;
	uint8_t completer_idH;
};

struct TLP64CompletionDWord2 {
	uint8_t loweraddress;
	uint8_t tag;
	uint8_t requester_idL;
	uint8_t requester_idH;
};

struct TLP64ConfigRequestDWord2 {
	uint8_t reg_num;
	uint8_t ext_reg_num;
	uint8_t device_idL;
	uint8_t device_idH;
};

struct TLP64DataWord32 {
	uint32_t first;
	uint32_t second;
};
#endif

union TLP64CompletionDWord1Int {
	struct TLP64CompletionDWord1 bits;
	uint32_t word;
};


union TLP64DataWord {
	uint64_t	d64;
	struct TLP64DataWord32	d32;
};

BYTE_FIELD(status, TLP64CompletionDWord1, byte2, 7, 5);
BYTE_FIELD(bcm, TLP64CompletionDWord1, byte2, 4, 4);

static inline uint16_t
tlp_get_bytecount(struct TLP64CompletionDWord1 *dword) {
	return (uint8_t_get_bits(dword->byte2, 3, 0) << 8) | dword->byte3;
}

static inline void
tlp_set_bytecount(struct TLP64CompletionDWord1 *dword, uint16_t value) {
	dword->byte2 = uint8_t_set_bits(dword->byte2, 3, 0, 
		uint16_t_get_bits(value, 11, 8));
	dword->byte3 = uint16_t_get_bits(value, 7, 0);
}

#define ID_FIELD(field_name, dword_type, field_container)		\
static inline uint16_t 														\
tlp_get_ ## field_name(struct dword_type *dword)	{							\
	return (dword -> field_container##H << 8) | (dword -> field_container##L);			\
}																			\
static inline void															\
tlp_set_ ## field_name(struct dword_type *dword, uint16_t new_value) {			\
	dword -> field_container##H = 												\
		(new_value & 0xFF00) >> 8;	\
	dword -> field_container##L = 												\
		(new_value & 0xFF);	\
}

ID_FIELD(requester_id, TLP64RequestDWord1, requester_id);
ID_FIELD(requester_id_msg, TLP64MessageRequestDWord1, requester_id);
ID_FIELD(completer_id, TLP64CompletionDWord1, completer_id);
ID_FIELD(requester_id_cpl, TLP64CompletionDWord2, requester_id);
ID_FIELD(device_id,    TLP64ConfigRequestDWord2, device_id);


static inline uint32_t
data64_get_first32(TLPQuadWord data) {
	uint32_t result;
#ifdef NOST_WORDS_BIGENDIAN
	result = (data & 0xffffffff00000000LL)>>32LL;
#else
	result = (data & 0xffffffffLL);
#endif
	return result;
}

static inline uint32_t
data64_get_second32(TLPQuadWord data) {
	uint32_t result;
#ifdef NOST_WORDS_BIGENDIAN
	result = (data & 0xffffffffLL);
#else
	result = (data & 0xffffffff00000000LL)>>32LL;
#endif
	return result;
}


static inline uint64_t
data32_to_64(TLPDoubleWord first, TLPDoubleWord second) {
	uint64_t result;
	uint64_t first64, second64;
	// explicit cast
	first64 = first;
	second64 = second;
#ifdef HOST_WORDS_BIGENDIAN
	result = (first64 << 32LL) | (second64);
#else
	result = (second64 << 32LL) | (first64);
#endif
	return result;
}



enum tlp_completion_status {
	TLPCS_SUCCESSFUL_COMPLETION	= 0,
	TLPCS_UNSUPPORTED_REQUEST		= 1,
	TLPCS_CONFIGURATION_REQUEST_RETRY = 2,
	TLPCS_RESERVED_LITERAL_3		= 3,
	TLPCS_COMPLETER_ABORT			= 4,
	TLPCS_RESERVED_LITERAL_5		= 5,
	TLPCS_REQUEST_TIMEOUT			= -1
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
create_memory_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	enum tlp_at at, uint16_t length, uint16_t requester_id, uint8_t tag,
	uint8_t lastbe, uint8_t firstbe, uint64_t address);

void
create_config_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	uint16_t requester_id, uint8_t tag, uint8_t firstbe, uint16_t device_id,
	uint16_t address);

enum dma_read_response {
	DRR_SUCCESS = 0,
	DRR_UNSUPPORTED_REQUEST,
	DRR_NO_RESPONSE,
	DRR_CHEWED
};

enum dma_read_response
perform_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address);

enum dma_read_response
perform_translated_dma_read(uint8_t* buf, uint16_t length,
	uint16_t requester_id, uint8_t tag, uint64_t address);

enum dma_read_response
perform_dma_long_read(uint8_t* buf, uint64_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address);

/* length is in bytes */
int
perform_dma_write(const uint8_t* buf, int16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address);

void
print_tlp(struct RawTLP *tlp);

static inline enum tlp_type
get_tlp_type(const struct RawTLP *tlp)
{
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)(tlp->header);
	assert(dword0 != NULL);
	return tlp_get_type(dword0);
}

static inline uint64_t
get_config_req_addr(const struct RawTLP *tlp)
{
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(tlp->header + 2);
	return (config_request_dword2->ext_reg_num << 8) |
		config_request_dword2->reg_num;
}

static enum tlp_direction
get_tlp_direction(const struct RawTLP *tlp)
{
	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp->header;
	return ((tlp_get_fmt(dword0) & 2) >> 1);
}

static inline uint16_t
bdf_to_uint(uint8_t bus_num, uint8_t dev_num, uint8_t fn_num)
{
	assert((dev_num & ~uint32_mask(5)) == 0);
	assert((fn_num & ~uint32_mask(3)) == 0);
	return ((uint16_t)bus_num) << 8 | (dev_num << 3) | fn_num;
}

#define WARN_ON_CHEW(a)	if (a == DRR_CHEWED) { PDBG("chewed!"); }

#endif
