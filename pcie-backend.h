#include "pcie.h"

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem);

unsigned long
read_hw_counter();

int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len);

int
send_tlp(volatile TLPQuadWord *tlp, int tlp_len);

void
close_connections();
