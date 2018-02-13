#include <stdint.h>
#include <stdio.h>

#include "macos-mbuf-manipulation.h"
#include "qemu/bswap.h"

void
endianness_swap_mac_mbuf_header(struct mbuf *mbuf)
{
#define MBUF_FIELD_BSWAP(bswap_fn, field_name)								\
	field_name = bswap_fn(field_name)

	mbuf->m_hdr.mh_next = bswap64(mbuf->m_hdr.mh_next);
	mbuf->m_hdr.mh_nextpkt = bswap64(mbuf->m_hdr.mh_nextpkt);
	mbuf->m_hdr.mh_data = bswap64(mbuf->m_hdr.mh_data);
	mbuf->m_hdr.mh_len = bswap32(mbuf->m_hdr.mh_len);
	mbuf->m_hdr.mh_type = bswap16(mbuf->m_hdr.mh_type);
	mbuf->m_hdr.mh_flags = bswap16(mbuf->m_hdr.mh_flags);
	MBUF_FIELD_BSWAP(bswap64, mbuf->MM_EXT.ext_buf);
	MBUF_FIELD_BSWAP(bswap64, mbuf->MM_EXT.ext_free);
	MBUF_FIELD_BSWAP(bswap32, mbuf->MM_EXT.ext_size);

#undef MBUF_FIELD_BSWAP
}

void
print_macos_mbuf_header(const struct mbuf *mbuf)
{
	printf("m_hdr.mh_next: 0x%lx. mh_nextpkt 0x%lx.\n",
		mbuf->m_hdr.mh_next, mbuf->m_hdr.mh_nextpkt);
	printf("m_hdr.mh_data: 0x%lx. m_hdr.mh_len: %d.\n", mbuf->m_hdr.mh_data, mbuf->m_hdr.mh_len);
	printf("m_hdr.mh_type: %d. m_hdr.mh_flags: 0x%x.\n", (uint32_t)mbuf->m_hdr.mh_type, (uint32_t)mbuf->m_hdr.mh_flags);
	printf("ext_buf: 0x%lx. ext_free: 0x%lx.\n", mbuf->MM_EXT.ext_buf,
		mbuf->MM_EXT.ext_free);
	printf("ext_size: %u.\n", mbuf->MM_EXT.ext_size);
}
