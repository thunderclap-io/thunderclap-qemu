#ifndef MACOS_MBUF_MANIPULATION
#define MACOS_MBUF_MANIPULATION

#ifdef VICTIM_MACOS_EL_CAPITAN
#include "macos-stub-mbuf-el-capitan.h"
#elif defined(VICTIM_MACOS_HIGH_SIERRA)
#include "macos-stub-mbuf-high-sierra.h"
#endif

void
endianness_swap_mac_mbuf_header(struct mbuf *mbuf);

void
print_macos_mbuf_header(const struct mbuf *mbuf);

#endif
