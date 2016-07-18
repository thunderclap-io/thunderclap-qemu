#include "pcie.h"

extern volatile uint8_t *physmem;

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem);

unsigned long
read_hw_counter();

int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len);

enum tlp_data_alignment { TDA_ALIGNED, TDA_UNALIGNED };

int
send_tlp(TLPQuadWord *header, int header_len, TLPQuadWord *data, int data_len,
	enum tlp_data_alignment data_alignment);

void
close_connections();

void
drain_pcie_core();

#ifdef POSTGRES
#define TRACE_COMPLETE	-2
extern int TLPS_CHECKED;
#endif
