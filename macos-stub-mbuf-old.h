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

#ifndef MACOS_STUB_MBUF
#define MACOS_STUB_MBUF

/* mbuf header */
struct m_hdr {
  uint64_t mh_next; /*struct mbuf * */
  uint64_t mh_nextpkt; /*struct mbuf * */
  uint64_t mh_data; /* caddr_t */
  int32_t mh_len;
  uint16_t mh_type;
  uint16_t mh_flags;
}; // 32 bytes


/*
 * record/packet header in first mbuf of chain if M_PKTHDR set 
 *
 * this is 136 bytes in Darwin 15.2.0 and 128 in 14.5.0
 */
#define DARWIN_15_2_0
struct pkthdr {
#ifdef DARWIN_15_2_0
  char opaque[136];
#endif

#ifdef DARWIN_14_5_0
  char opaque[128];
#endif
};


/* external storage if M_EXT set */
typedef struct m_ext {
  uint64_t ext_buf; /* caddr_t */
  uint64_t ext_free; /* void *()(caddr_t, u_int, caddr_t) */
  uint64_t ext_size; /* XXX: source says uint32_t but seems 8 byte in practice */
  uint64_t ext_arg;
  struct ext_refsq {
    uint64_t forward; /* struct ext_refsq * */
    uint64_t backward; /* struct ext_refsq * */
  } ext_refs;
  uint64_t ext_refflags; /* struct ext_ref * */
} m_ext_t; // 56 bytes

struct ext_ref {
  uint32_t refcnt;
  uint32_t flags;
};


struct mbuf {
  struct m_hdr m_hdr;
  union {
    struct {
      struct pkthdr MH_pkthdr; /* M_PKTHDR set */
      union {
        struct m_ext MH_ext; /* M_EXT set */
        char MH_databuf[256 - sizeof(struct pkthdr) - sizeof(struct m_hdr)];
      } MH_dat;
    } MH;
    char MH_databuf[256 - sizeof(struct m_hdr)];
  } M_dat;
}; //256 bytes


#define m_next    m_hdr.mh_next
#define m_len   m_hdr.mh_len
#define m_data    m_hdr.mh_data
#define m_type    m_hdr.mh_type
#define m_flags   m_hdr.mh_flags
#define m_nextpkt m_hdr.mh_nextpkt
#define m_act   m_nextpkt
#define m_pkthdr  M_dat.MH.MH_pkthdr
#define m_ext   M_dat.MH.MH_dat.MH_ext
#define m_pktdat  M_dat.MH.MH_dat.MH_databuf
#define m_dat   M_dat.M_databuf
#define m_pktlen(_m)  ((_m)->m_pkthdr.len)
#define m_pftag(_m) (&(_m)->m_pkthdr.pf_mtag)

/* mbuf flags (private) */
#define M_EXT   0x0001  /* has associated external storage */
#define M_PKTHDR  0x0002  /* start of record */
#define M_EOR   0x0004  /* end of record */
#define M_PROTO1  0x0008  /* protocol-specific */
#define M_PROTO2  0x0010  /* protocol-specific */
#define M_PROTO3  0x0020  /* protocol-specific */
#define M_LOOP    0x0040  /* packet is looped back (also see PKTF_LOOP) */
#define M_PROTO5  0x0080  /* protocol-specific */

/* mbuf pkthdr flags, also in m_flags (private) */
#define M_BCAST   0x0100  /* send/received as link-level broadcast */
#define M_MCAST   0x0200  /* send/received as link-level multicast */
#define M_FRAG    0x0400  /* packet is a fragment of a larger packet */
#define M_FIRSTFRAG 0x0800  /* packet is first fragment */
#define M_LASTFRAG  0x1000  /* packet is last fragment */
#define M_PROMISC 0x2000  /* packet is promiscuous (shouldn't go to stack) */
#define M_HASFCS  0x4000  /* packet has FCS */
#define M_TAGHDR  0x8000  /* m_tag hdr structure at top of mbuf data */

/* mbuf types */
#define MT_FREE   0 /* should be on free list */
#define MT_DATA   1 /* dynamic (data) allocation */
#define MT_HEADER 2 /* packet header */
#define MT_SOCKET 3 /* socket structure */
#define MT_PCB    4 /* protocol control block */
#define MT_RTABLE 5 /* routing tables */
#define MT_HTABLE 6 /* IMP host tables */
#define MT_ATABLE 7 /* address resolution tables */
#define MT_SONAME 8 /* socket name */
#define MT_SOOPTS 10  /* socket options */
#define MT_FTABLE 11  /* fragment reassembly header */
#define MT_RIGHTS 12  /* access rights */
#define MT_IFADDR 13  /* interface address */
#define MT_CONTROL  14  /* extra-data protocol message */
#define MT_OOBDATA  15  /* expedited data  */
#define MT_TAG    16  /* volatile metadata associated to pkts */
#define MT_MAX    32  /* enough? */

#endif
