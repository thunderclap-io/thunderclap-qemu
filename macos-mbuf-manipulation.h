#ifndef MACOS_MBUF_MANIPULATION
#define MACOS_MBUF_MANIPULATION

#include "macos-stub-mbuf.h"

void
endianness_swap_mac_mbuf_header(struct mbuf *mbuf);

void
print_macos_mbuf_header(const struct mbuf *mbuf);

#endif
