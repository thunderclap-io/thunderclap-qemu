//#ifndef DEBUG_H
//#define DEBUG_H

#include <stdio.h>

//#ifdef PCIE_DEBUG
//#define PDBG(...)				do {									\
	//fprintf(stderr, "%s(%s:%d): ", __func__, __FILE__, __LINE__);		\
	//fprintf(stderr, __VA_ARGS__);										\
	//fprintf(stderr, "\n");												\
//} while (0)

//#define DEBUG_PRINTF(...)		do {									\
	//fprintf(stderr, __VA_ARGS__);										\
//} while (0)
//#else
#define PDBG(...)
#define DBG_PRINTF(...)
//#endif

//#endif
