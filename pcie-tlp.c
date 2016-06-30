#include <stdint.h>
#include <stdbool.h>
#include "pcie.h"

inline void
create_memory_request(volatile TLPDoubleWord *tlp, uint32_t buffer_length,
	enum tlp_direction direction, uint16_t completer_id,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress,
	uint64_t memory_address, uint32_t memory_length)
{
	assert( buffer_length>=16 );

	uint32_t tlp_len;
	// Clear buffer before we start filling bits in
	tlp[0] = 0;
	tlp[1] = 0;
	tlp[2] = 0;
	tlp[3] = 0;

	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)(tlp);
	header0->type = M;
	// Round up number of bytes into number of DWords
	header0->length = (memory_length+3)/4;
	header0->at = 0;

	struct TLP64RequestDWord1 *header1 = (struct TLP64RequestDWord1 *)(tlp) + 1;
	header1->requester_id = completer_id;
	header1->tag = tag;
	// only support word accesses currently
	header1->firstbe = 0xf;
	header1->lastbe = 0;
	
	if (direction == TLPD_READ)	{

		if (memory_address >= (1LL<<32)) {
			header0->fmt = TLPFMT_4DW_NODATA;
			tlp[2] = (memory_address>>32);
			tlp[3] = (memory_address & 0xFFFFFFFF);
			tlp_len = 4*4;
		} else {
			header0->fmt = TLPFMT_3DW_NODATA;
			tlp[2] = (memory_address & 0xFFFFFFFF);
			tlp_len = 3*4;
		}
	} else {
		// build a write
		if (memory_address >= (1LL<<32)) {
			header0->fmt = TLPFMT_4DW_DATA;
			tlp[2] = (memory_address>>32);
			tlp[3] = (memory_address & 0xFFFFFFFF);
			tlp_len = 4*4;
			memcpy(tlp+4, memory_address, (memory_length+3)/4);
			tlp_len += memory_length;
		} else {
			header0->fmt = TLPFMT_3DW_DATA;
			tlp[2] = (memory_address & 0xFFFFFFFF);
			tlp_len = 3*4;
			memcpy(tlp+3, memory_address, (memory_length+3)/4);
			tlp_len += memory_length;
		}
	}
}

// Interpret a memory response we already received as a packet
// Returns:
// negative: error in TLP
// positive: completion status
// 0: successful completion

int
parse_memory_response(volatile TLPDoubleWord *tlp, uint32_t tlp_length,
	uint32_t *response_buffer, uint32_t response_buffer_length,
	enum tlp_completion_status *completion_status,
	uint16_t *completer_id,
	uint16_t *requester_id, uint8_t *tag, uint32_t *returned_length)
{
	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)(tlp);
	struct TLP64CompletionDWord1 *header1 = (struct TLP64CompletionDWord1 *)(tlp) + 1;
	struct TLP64CompletionDWord2 *header2 = (struct TLP64CompletionDWord2 *)(tlp) + 2;
	uint32_t *payload = (uint32_t *) tlp+3;

	if (header0->type != CPL)
	{
		puts("Parsing memory response that isn't a completion");
		return -100;
	}
	if ((header0->fmt !=TLPFMT_3DW_NODATA) || (header0->fmt != TLPFMT_3DW_DATA))
	{
		puts("Invalid TLP format for parse_memory_response");
		return -101;
	}

	if (completion_status)
		*completion_status = header1->status;
	if (tag)
		*tag = header2->tag;
	if (completer_id)
		*completer_id = header1->completer_id;
	if (requester_id)
		*requester_id = header2->requester_id;

	if (header1->status != TLPCS_SUCCESSFUL_COMPLETION)
		return (int) header1->status;

	// we know it's a successful completion

	// XXX: handle Byte Count and Lower Address for unaligned accesses

	if (header0->fmt == TLPFMT_3DW_DATA)
	{
		uint32_t i = 0;
		uint32_t response_length = header0->length;
		uint32_t worst_buffer_length = 0;

		worst_buffer_length = tlp_length-12;
		if (response_buffer_length < worst_buffer_length) {
			worst_buffer_length = response_buffer_length;
		}
		if (response_length < worst_buffer_length) {
			worst_buffer_length = response_length;
		}

		memcpy(response_buffer, payload, worst_buffer_length);
		return 0;
	}

	// should never reach here
	return -102;
}