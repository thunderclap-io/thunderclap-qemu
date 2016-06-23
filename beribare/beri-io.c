#ifdef BAREMETAL
#include "parameters.h"
#else
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#include <stdint.h>
#include "beri-io.h"

volatile uint8_t *physmem = 0;

volatile uint8_t *open_io_region(uint64_t address, uint64_t length)
{
#ifdef BAREMETAL
	return (uint8_t *)(MIPS_XKPHYS_UNCACHED_BASE + address);
#else
    int fd = 0;
    volatile uint8_t *mapped = 0;

    fd = open("/dev/mem", O_RDWR|O_SYNC);
    if (fd == -1) {
        perror("open /dev/mem failed");
        exit(1);
    }
    mapped = (uint8_t *)mmap(0, length, PROT_READ|PROT_WRITE, MAP_SHARED, fd, address);
    if (mapped == MAP_FAILED) {
        perror("mmap failed");
        exit(2);
    }
    return mapped;
#endif
}
