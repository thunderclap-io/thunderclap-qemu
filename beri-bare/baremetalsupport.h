#ifndef BAREMETALSUPPORT_H
#define BAREMETALSUPPORT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef BAREMETAL
#include "parameters.h"

static inline void
assert(bool predicate)
{
}

#define IO_RD_BYTE(x) (*(volatile unsigned char*)(x))
#define IO_RD(x) (*(volatile unsigned long long*)(x))
#define IO_RD32(x) (*(volatile int*)(x))
#define IO_WR(x, y) (*(volatile unsigned long long*)(x) = y)
#define IO_WR_BYTE(x, y) (*(volatile unsigned char*)(x) = y)
#endif

void writeUARTChar(char c);
void writeString(char* s);
void writeHex(unsigned long long n);
char readUARTChar();

void write_uint_32(uint32_t n, char pad);
void write_uint_32_hex(uint32_t n, char pad);
void write_uint_64(uint64_t n, char pad);
void write_uint_64_hex(uint64_t n, char pad);
void write_int_32(int32_t n, char pad);
void write_int_64(uint64_t n, char pad);

#endif