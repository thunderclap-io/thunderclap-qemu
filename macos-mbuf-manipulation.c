#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "macos-mbuf-manipulation.h"
#include "qemu/bswap.h"

void
endianness_swap_mac_mbuf_header(struct mbuf *mbuf)
{
#define FIX_FIELD(size, field)												\
	mbuf->field = (typeof(mbuf->field))le ## size ## _to_cpu(				\
		(int ## size ## _t)mbuf->field)

	FIX_FIELD(64, MM_NEXT);
	FIX_FIELD(64, MM_NEXTPKT);
	FIX_FIELD(64, MM_DATA);
	FIX_FIELD(32, MM_LEN);
	FIX_FIELD(16, MM_TYPE);
	FIX_FIELD(16, MM_FLAGS);

	FIX_FIELD(64, MM_EXT.ext_buf);
	FIX_FIELD(64, MM_EXT.ext_free);
	FIX_FIELD(32, MM_EXT.ext_size);
	FIX_FIELD(64, MM_EXT.ext_arg);
	FIX_FIELD(64, MM_EXT.ext_refflags);


#undef FIX_FIELD
}

void
print_macos_mbuf_header(const struct mbuf *mbuf)
{
	printf("m_hdr.mh_next: 0x%"PRIx64". mh_nextpkt 0x%"PRIx64".\n",
		mbuf->m_hdr.mh_next, mbuf->m_hdr.mh_nextpkt);
	printf("m_hdr.mh_data: 0x%"PRIx64". m_hdr.mh_len: %d.\n", mbuf->m_hdr.mh_data, mbuf->m_hdr.mh_len);
	printf("m_hdr.mh_type: %d. m_hdr.mh_flags: 0x%x.\n", (uint32_t)mbuf->m_hdr.mh_type, (uint32_t)mbuf->m_hdr.mh_flags);
	printf("ext_buf: 0x%"PRIx64". ext_free: 0x%"PRIx64".\n", mbuf->MM_EXT.ext_buf,
		mbuf->MM_EXT.ext_free);
	printf("ext_size: %u.\n", mbuf->MM_EXT.ext_size);
}
