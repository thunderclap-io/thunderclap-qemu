#include "pcie.h"

extern volatile uint8_t *physmem;
extern volatile uint8_t *led_phys_mem;

static inline void
write_leds(uint32_t data)
{
#ifdef PLATFORM_BERI
	*led_phys_mem = ~data;
#endif
}

int
pcie_hardware_init(int argc, char **argv, volatile uint8_t **physmem);

unsigned long
read_hw_counter();

void
wait_for_tlp(TLPQuadWord *buffer, int buffer_len, struct RawTLP *tlp);

// don't get confused when we print 'aligned' and get zero
// - should only ever use as an enum and compared
enum tlp_data_alignment { TDA_ALIGNED=0xA1, TDA_UNALIGNED=0x20 };

int
send_tlp(struct RawTLP *tlp);

void
close_connections();

void
drain_pcie_core();

#ifdef POSTGRES
extern int TLPS_CHECKED;
#endif
