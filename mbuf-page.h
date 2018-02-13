#ifndef MBUF_PAGE_H
#define MBUF_PAGE_H

#include <stdint.h>

#include "exec/hwaddr.h"
#include "macos-stub-mbuf-high-sierra.h"

#define MBUFS_PER_PAGE (4096 / sizeof(struct mbuf))

struct mbuf_page {
	hwaddr iovaddr;
	struct mbuf contents[MBUFS_PER_PAGE];
};

#endif
