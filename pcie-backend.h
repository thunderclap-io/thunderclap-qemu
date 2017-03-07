#include "pcie.h"

extern volatile uint8_t *physmem;
extern volatile uint8_t *led_phys_mem;

static inline void
write_leds(uint32_t data)
{
#ifdef BERI
	*led_phys_mem = ~data;
#endif
}

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem);

unsigned long
read_hw_counter();

void
wait_for_tlp(volatile TLPQuadWord *buffer, int buffer_len, struct RawTLP *tlp);

enum tlp_data_alignment { TDA_ALIGNED, TDA_UNALIGNED };

int
send_tlp(struct RawTLP *tlp);

void
close_connections();

void
drain_pcie_core();

#ifdef POSTGRES
extern int TLPS_CHECKED;
#endif
