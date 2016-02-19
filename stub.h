#ifndef STUB_H
#define STUB_H

#include <stdio.h>
#include <execinfo.h>
#include <stdlib.h>

/* Obtain a backtrace and print it to stdout. */
void stub_print_trace (void);

#define STUB_WARN()														\
	fprintf(stderr, "WARNING: STUB %s (%s:%d) called!\n",				\
	   	__func__, __FILE__, __LINE__);									\
	//stub_print_trace();													\
	printf("-------------------------\n");

#define DBG(...)	do {													\
	printf("%s(%s:%d): ", __func__, __FILE__, __LINE__);					\
	printf(__VA_ARGS__);													\
	printf("\n");															\
} while (0)

#endif
