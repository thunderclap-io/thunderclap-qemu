#ifndef DEBUG_H
#define DEBUG_H

#ifdef PCIE_DEBUG

#include <stdio.h>

#define PDBG(...)				do {									\
	fprintf(stderr, "%s(%s:%d): ", __func__, __FILE__, __LINE__);		\
	fprintf(stderr, __VA_ARGS__);										\
	fprintf(stderr, "\n");												\
} while (0)

#define DEBUG_PRINTF(...)		do {									\
	fprintf(stderr, __VA_ARGS__);										\
} while (0)
#else
//#error "No PCIE DEBUG :'("
#define PDBG(...)
#define DEBUG_PRINTF(...)
#endif

#endif
