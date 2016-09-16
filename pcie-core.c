#include "pcie.h"

#include <stdbool.h>
#include <stddef.h>

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
