/*-
 * Copyright (c) 2016 Brett F. Gutstein
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/** PCI host read/write functionality */


#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "pcie.h"
#include "pcietlp.h"
#include "pcie-backend.h"


//XXX: find completer id programmatically
#ifndef COMPLETER_ID
//#define COMPLETER_ID 0x8200
#define COMPLETER_ID 0xC500
#endif


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

  do {
    int32_t received_count = wait_for_tlp((TLPQuadWord *) tlp, sizeof(tlp),
        start_time + timeout_cycles);
    // valid TLPs are >= 12 bytes - wait_for_tlp should also return -1 on timeout
    if (received_count < 12) {
      continue;
    }

    enum tlp_completion_status completion_status = 0;
    uint16_t completer_id = 0, requester_id = 0;
    uint8_t response_tag = 0;
    int32_t parse_status = parse_memory_response(tlp, received_count, data_buffer, read_length,
        &completion_status, &completer_id, &requester_id, &response_tag, returned_length);

    if ((parse_status == 0) && (completion_status == TLPCS_SUCCESSFUL_COMPLETION) &&
        (response_tag == tag_sent)) {
      return 0;
    } else if ((response_tag == tag_sent)) {
      // tag was correct but completion was not successful
      return 1;
    }
  } while (read_hw_counter() < start_time + timeout_cycles);

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
 * at a time will work. Reads should be 8 byte aligned and will be automatically aligned
 * by the stack.
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
 * will work. There is no way to guarantee reliability. Writes should be
 * 8 byte aligned and will not go through otherwise.
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
