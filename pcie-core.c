#include "pcie.h"
#include "pcie-debug.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

/* length is used as the PCIe field, so is in DWords i.e. units of 32 bits. */
void
create_completion_header(struct RawTLP *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress)
{
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp->header[0] = 0;
	tlp->header[1] = 0;
	tlp->header[2] = 0;

	struct TLP64DWord0 *header0 = (struct TLP64DWord0 *)(tlp->header);
	if (direction == TLPD_READ
		&& completion_status == TLPCS_SUCCESSFUL_COMPLETION) {
		header0->fmt = TLPFMT_3DW_DATA;
		header0->length = 1;
	} else {
		header0->fmt = TLPFMT_3DW_NODATA;
		header0->length = 0;
	}
	header0->type = CPL;

	struct TLP64CompletionDWord1 *header1 =
		(struct TLP64CompletionDWord1 *)(tlp->header) + 1;
	header1->completer_id = completer_id;
	header1->status = completion_status;
	header1->bytecount = bytecount;

	struct TLP64CompletionDWord2 *header2 =
		(struct TLP64CompletionDWord2 *)(tlp->header) + 2;
	header2->requester_id = requester_id;
	header2->tag = tag;
	header2->loweraddress = loweraddress;
}

void
create_memory_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	enum tlp_at at, uint16_t length, uint16_t requester_id, uint8_t tag,
	uint8_t lastbe, uint8_t firstbe, uint64_t address)
{
	bool large_address = (address >= (1LL << 32));

	int i;

	for (i = 0; i < 4; ++i) {
		tlp->header[i] = 0;
	}
	if (large_address) {
		tlp->header_length = 16;
	} else {
		tlp->header_length = 12;
	}
	if (direction == TLPD_READ) {
		tlp->data_length = 0;
	} else {
		tlp->data_length = length * sizeof(TLPDoubleWord);
	}

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp->header;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(tlp->header + 1);
	TLPDoubleWord *address_dword2 = (tlp->header + 2);
	TLPDoubleWord *address_dword3 = (tlp->header + 3);

	dword0->fmt = 0;
	if (tlp->header_length == 16) {
		dword0->fmt |= TLPFMT_4DW;
	}
	if (direction == TLPD_WRITE) {
		dword0->fmt |= TLPFMT_WITHDATA;
	}
	dword0->at = at;
	dword0->length = length;
	dword0->type = M;

	request_dword1->requester_id = requester_id;
	request_dword1->tag = tag;
	request_dword1->lastbe = lastbe;
	request_dword1->firstbe = firstbe;

	if (large_address) {
		*address_dword2 = (TLPDoubleWord)(address >> 32);
		*address_dword3 = (TLPDoubleWord)address;
	} else {
		*address_dword2 = (TLPDoubleWord)address;
	}
}
