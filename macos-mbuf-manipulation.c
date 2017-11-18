#include <stdint.h>
#include <stdio.h>

#include "macos-stub-mbuf.h"
#include "qemu/bswap.h"

void
endianness_swap_mac_mbuf_header(struct mbuf *mbuf)
{
	mbuf->m_next = bswap64(mbuf->m_next);
	mbuf->m_nextpkt = bswap64(mbuf->m_nextpkt);
	mbuf->m_data = bswap64(mbuf->m_data);
	mbuf->m_len = bswap32(mbuf->m_len);
	mbuf->m_type = bswap16(mbuf->m_type);
	mbuf->m_flags = bswap16(mbuf->m_flags);
}

void
print_macos_mbuf_header(const struct mbuf *mbuf)
{
	printf("m_next: 0x%lx. mh_nextpkt 0x%lx.\n",
		mbuf->m_next, mbuf->m_nextpkt);
	printf("m_data: 0x%lx. m_len: %d.\n", mbuf->m_data, mbuf->m_len);
	printf("m_type: %x. m_flags: %x.\n", (uint32_t)mbuf->m_type, (uint32_t)mbuf->m_flags);
}
