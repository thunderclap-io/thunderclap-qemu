/*
 * Copyright (c) 1999-2015 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * Copyright (c) 1994 NeXT Computer, Inc. All rights reserved.
 *
 * Copyright (c) 1982, 1986, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)mbuf.h	8.3 (Berkeley) 1/21/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#ifndef	MACOS_MM_EL_CAPITAN
#define	MACOS_MM_EL_CAPITAN

#include <stdint.h>
#include "freebsd-queue.h"

/*
 * From bsd/i386/params.h
 */

/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than CLBYTES (the software page size), and,
 * on machines that exchange pages of input or output buffers with mbuf
 * clusters (MAPPED_MMS), MCLBYTES must also be an integral multiple
 * of the hardware page size.
 */
#define	MSIZESHIFT	8			/* 256 */
#define	MSIZE		(1 << MSIZESHIFT)	/* size of an mbuf */
#define	MCLSHIFT	11			/* 2048 */
#define	MCLBYTES	(1 << MCLSHIFT)		/* size of an mbuf cluster */
#define	MBIGCLSHIFT	12			/* 4096 */
#define	MBIGCLBYTES	(1 << MBIGCLSHIFT)	/* size of a big cluster */
#define	M16KCLSHIFT	14			/* 16384 */
#define	M16KCLBYTES	(1 << M16KCLSHIFT)	/* size of a jumbo cluster */

/*
 * The following _MLEN and _MHLEN macros are private to xnu.  Private code
 * that are outside of xnu must use the mbuf_get_{mlen,mhlen} routines since
 * the sizes of the structures are dependent upon specific xnu configs.
 */
#define	_MLEN		(MSIZE - sizeof(struct m_hdr))	/* normal data len */
#define	_MHLEN		(_MLEN - sizeof(struct pkthdr))	/* data len w/pkthdr */

#define	NMBPGSHIFT	(PAGE_SHIFT - MSIZESHIFT)
#define	NMBPG		(1 << NMBPGSHIFT)	/* # of mbufs per page */

#define	NCLPGSHIFT	(PAGE_SHIFT - MCLSHIFT)
#define	NCLPG		(1 << NCLPGSHIFT)	/* # of cl per page */

#define	NBCLPGSHIFT	(PAGE_SHIFT - MBIGCLSHIFT)
#define NBCLPG		(1 << NBCLPGSHIFT)	/* # of big cl per page */

#define	NMBPCLSHIFT	(MCLSHIFT - MSIZESHIFT)
#define	NMBPCL		(1 << NMBPCLSHIFT)	/* # of mbufs per cl */

#define	NCLPJCLSHIFT	(M16KCLSHIFT - MCLSHIFT)
#define	NCLPJCL		(1 << NCLPJCLSHIFT)	/* # of cl per jumbo cl */

#define	NCLPBGSHIFT	(MBIGCLSHIFT - MCLSHIFT)
#define	NCLPBG		(1 << NCLPBGSHIFT)	/* # of cl per big cl */

#define	NMBPBGSHIFT	(MBIGCLSHIFT - MSIZESHIFT)
#define	NMBPBG		(1 << NMBPBGSHIFT)	/* # of mbufs per big cl */

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef int kern_return_t;
typedef unsigned int u_int;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
typedef uint64_t MM_caddr_t; /* Actual definition is char * */
typedef uint64_t MM_struct_mbuf_p;

/* header at beginning of each mbuf: */
struct m_hdr {
	MM_struct_mbuf_p mh_next;	/* next buffer in chain */
	MM_struct_mbuf_p mh_nextpkt;	/* next chain in queue/record */
	MM_caddr_t		mh_data;	/* location of data */
	int32_t		mh_len;		/* amount of data in this mbuf */
	u_int16_t	mh_type;	/* type of data in this mbuf */
	u_int16_t	mh_flags;	/* flags; see below */
};

/*
 * Packet tag structure (see below for details).
 */
struct m_tag {
	u_int64_t		m_tag_cookie;	/* Error checking */
#ifndef __LP64__
	u_int32_t		pad;		/* For structure alignment */
#endif /* !__LP64__ */
	SLIST_ENTRY(m_tag)	m_tag_link;	/* List of packet tags */
	u_int16_t		m_tag_type;	/* Module specific type */
	u_int16_t		m_tag_len;	/* Length of data */
	u_int32_t		m_tag_id;	/* Module ID */
};

#define	M_TAG_ALIGN(len) \
	(P2ROUNDUP(len, sizeof (u_int64_t)) + sizeof (struct m_tag))

#define	M_TAG_VALID_PATTERN	0xfeedfacefeedfaceULL
#define	M_TAG_FREE_PATTERN	0xdeadbeefdeadbeefULL

/*
 * Packet tag header structure (at the top of mbuf).  Pointers are
 * 32-bit in ILP32; m_tag needs 64-bit alignment, hence padded.
 */
struct m_taghdr {
#ifndef __LP64__
	u_int32_t		pad;		/* For structure alignment */
#endif /* !__LP64__ */
	u_int64_t		refcnt;		/* Number of tags in this mbuf */
};

/*
 * Driver auxiliary metadata tag (KERNEL_TAG_TYPE_DRVAUX).
 */
struct m_drvaux_tag {
	u_int32_t	da_family;	/* IFNET_FAMILY values */
	u_int32_t	da_subfamily;	/* IFNET_SUBFAMILY values */
	u_int32_t	da_reserved;	/* for future */
	u_int32_t	da_length;	/* length of following data */
};

/* Values for pftag_flags (16-bit wide) */
#define	PF_TAG_GENERATED		0x1	/* pkt generated by PF */
#define	PF_TAG_FRAGCACHE		0x2
#define	PF_TAG_TRANSLATE_LOCALHOST	0x4
#if PF_ECN
#define	PF_TAG_HDR_INET			0x8	/* hdr points to IPv4 */
#define	PF_TAG_HDR_INET6		0x10	/* hdr points to IPv6 */
#endif /* PF_ECN */
/*
 * PF mbuf tag
 */
struct pf_mtag {
	u_int16_t	pftag_flags;	/* PF_TAG flags */
	u_int16_t	pftag_rtableid;	/* alternate routing table id */
	u_int16_t	pftag_tag;
	u_int16_t	pftag_routed;
#if PF_ALTQ
	u_int32_t	pftag_qid;
#endif /* PF_ALTQ */
#if PF_ECN
	void		*pftag_hdr;	/* saved hdr pos in mbuf, for ECN */
#endif /* PF_ECN */
};

/*
 * TCP mbuf tag
 */
struct tcp_pktinfo {
	union {
		struct {
			u_int32_t segsz;	/* segment size (actual MSS) */
		} __tx;
		struct {
			u_int16_t lro_pktlen;	/* max seg size encountered */
			u_int8_t  lro_npkts;	/* # of coalesced TCP pkts */
			u_int8_t  lro_timediff;	/* time spent in LRO */
		} __rx;
	} __offload;
	union {
		u_int32_t	pri;		/* send msg priority */
		u_int32_t	seq;		/* recv msg sequence # */
	} __msgattr;
#define tso_segsz	proto_mtag.__pr_u.tcp.tm_tcp.__offload.__tx.segsz
#define lro_pktlen	proto_mtag.__pr_u.tcp.tm_tcp.__offload.__rx.lro_pktlen
#define lro_npkts	proto_mtag.__pr_u.tcp.tm_tcp.__offload.__rx.lro_npkts
#define lro_elapsed	proto_mtag.__pr_u.tcp.tm_tcp.__offload.__rx.lro_timediff
#define msg_pri		proto_mtag.__pr_u.tcp.tm_tcp.__msgattr.pri
#define msg_seq		proto_mtag.__pr_u.tcp.tm_tcp.__msgattr.seq
};

/*
 * MPTCP mbuf tag
 */
struct mptcp_pktinfo {
	u_int64_t	mtpi_dsn;	/* MPTCP Data Sequence Number */
	union {
		u_int64_t	mtpi_dan;	/* MPTCP Data Ack Number */
		struct {
			u_int32_t mtpi_rel_seq;	/* Relative Seq Number */
			u_int32_t mtpi_length;	/* Length of mapping */
		} mtpi_subf;
	};
#define	mp_dsn		proto_mtag.__pr_u.tcp.tm_mptcp.mtpi_dsn
#define	mp_rseq		proto_mtag.__pr_u.tcp.tm_mptcp.mtpi_subf.mtpi_rel_seq
#define	mp_rlen		proto_mtag.__pr_u.tcp.tm_mptcp.mtpi_subf.mtpi_length
#define	mp_dack		proto_mtag.__pr_u.tcp.tm_mptcp.mtpi_subf.mtpi_dan
};

/*
 * TCP specific mbuf tag.  Note that the current implementation uses
 * MPTCP metadata strictly between MPTCP and the TCP subflow layers,
 * hence tm_tcp and tm_mptcp are mutually exclusive.  This also means
 * that TCP messages functionality is currently incompatible with MPTCP.
 */
struct tcp_mtag {
	union {
		struct tcp_pktinfo	tm_tcp;		/* TCP and below */
		struct mptcp_pktinfo	tm_mptcp;	/* MPTCP-TCP only */
	};
};

/*
 * Protocol specific mbuf tag (at most one protocol metadata per mbuf).
 *
 * Care must be taken to ensure that they are mutually exclusive, e.g.
 * IPSec policy ID implies no TCP segment offload (which is fine given
 * that the former is used on the virtual ipsec interface that does
 * not advertise the TSO capability.)
 */
struct proto_mtag {
	union {
		struct tcp_mtag	tcp;		/* TCP specific */
	} __pr_u;
};

/*
 * NECP specific mbuf tag.
 */
struct necp_mtag {
	u_int32_t	necp_policy_id;
	u_int32_t	necp_last_interface_index;
	u_int32_t	necp_route_rule_id;
};

/*
 * Record/packet header in first mbuf of chain; valid only if M_PKTHDR set.
 */
struct pkthdr {
	uint64_t rcvif_p;		/* rcv interface */
	/* variables for ip and tcp reassembly */
	uint64_t	pkt_hdr_p;		/* pointer to packet header */
	int32_t	len;			/* total packet length */
	/* variables for hardware checksum */
	/* Note: csum_flags is used for hardware checksum and VLAN */
	u_int32_t csum_flags;		/* flags regarding checksum */
	union {
		struct {
			u_int16_t val;	 /* checksum value */
			u_int16_t start; /* checksum start offset */
		} _csum_rx;
#define	csum_rx_val	_csum_rx.val
#define	csum_rx_start	_csum_rx.start
		struct {
			u_int16_t start; /* checksum start offset */
			u_int16_t stuff; /* checksum stuff offset */
		} _csum_tx;
#define	csum_tx_start	_csum_tx.start
#define	csum_tx_stuff	_csum_tx.stuff
		u_int32_t csum_data;	/* data field used by csum routines */
	};
	u_int16_t vlan_tag;		/* VLAN tag, host byte order */
	/*
	 * Packet classifier info
	 *
	 * PKTF_FLOW_ID set means valid flow ID.  A non-zero flow ID value
	 * means the packet has been classified by one of the flow sources.
	 * It is also a prerequisite for flow control advisory, which is
	 * enabled by additionally setting PKTF_FLOW_ADV.
	 *
	 * The protocol value is a best-effort representation of the payload.
	 * It is opportunistically updated and used only for optimization.
	 * It is not a substitute for parsing the protocol header(s); use it
	 * only as a hint.
	 *
	 * If PKTF_IFAINFO is set, pkt_ifainfo contains one or both of the
	 * indices of interfaces which own the source and/or destination
	 * addresses of the packet.  For the local/loopback case (PKTF_LOOP),
	 * both should be valid, and thus allows for the receiving end to
	 * quickly determine the actual interfaces used by the the addresses;
	 * they may not necessarily be the same or refer to the loopback
	 * interface.  Otherwise, in the non-local/loopback case, the indices
	 * are opportunistically set, and because of that only one may be set
	 * (0 means the index has not been determined.)  In addition, the
	 * interface address flags are also recorded.  This allows us to avoid
	 * storing the corresponding {in,in6}_ifaddr in an mbuf tag.  Ideally
	 * this would be a superset of {ia,ia6}_flags, but the namespaces are
	 * overlapping at present, so we'll need a new set of values in future
	 * to achieve this.  For now, we will just rely on the address family
	 * related code paths examining this mbuf to interpret the flags.
	 */
	u_int8_t pkt_proto;		/* IPPROTO value */
	u_int8_t pkt_flowsrc;		/* FLOWSRC values */
	u_int32_t pkt_flowid;		/* flow ID */
	u_int32_t pkt_flags;		/* PKTF flags (see below) */
	u_int32_t pkt_svc;		/* MBUF_SVC value */
	union {
		struct {
			u_int16_t src;		/* ifindex of src addr i/f */
			u_int16_t src_flags;	/* src PKT_IFAIFF flags */
			u_int16_t dst;		/* ifindex of dst addr i/f */
			u_int16_t dst_flags;	/* dst PKT_IFAIFF flags */
		} _pkt_iaif;
#define	src_ifindex	_pkt_iaif.src
#define	src_iff		_pkt_iaif.src_flags
#define	dst_ifindex	_pkt_iaif.dst
#define	dst_iff		_pkt_iaif.dst_flags
		u_int64_t pkt_ifainfo;	/* data field used by ifainfo */
		u_int32_t pkt_unsent_databytes; /* unsent data */
	};
#if MEASURE_BW
	u_int64_t pkt_bwseq;		/* sequence # */
#endif /* MEASURE_BW */
	u_int64_t pkt_enqueue_ts;	/* enqueue time */

	/*
	 * Tags (external and built-in)
	 */
	SLIST_HEAD(packet_tags, m_tag) tags; /* list of external tags */
	struct proto_mtag proto_mtag;	/* built-in protocol-specific tag */
	struct pf_mtag	pf_mtag;	/* built-in PF tag */
	struct necp_mtag necp_mtag; /* built-in NECP tag */
	/*
	 * Module private scratch space (32-bit aligned), currently 16-bytes
	 * large.  Anything stored here is not guaranteed to survive across
	 * modules.  This should be the penultimate structure right before
	 * the red zone.  Add new fields above this.
	 */
	struct {
		union {
			u_int8_t	__mpriv8[16];
			u_int16_t	__mpriv16[8];
			struct {
				union {
					u_int8_t	__val8[4];
					u_int16_t	__val16[2];
					u_int32_t	__val32;
				} __mpriv32_u;
			}		__mpriv32[4];
			u_int64_t	__mpriv64[2];
		} __mpriv_u;
	} pkt_mpriv __attribute__((aligned(4)));
	u_int32_t redzone;		/* red zone */
};

/*
 * Flow data source type.  A data source module is responsible for generating
 * a unique flow ID and associating it to each data flow as pkt_flowid.
 * This is required for flow control/advisory, as it allows the output queue
 * to identify the data source object and inform that it can resume its
 * transmission (in the event it was flow controlled.)
 */
#define	FLOWSRC_INPCB		1	/* flow ID generated by INPCB */
#define	FLOWSRC_IFNET		2	/* flow ID generated by interface */
#define	FLOWSRC_PF		3	/* flow ID generated by PF */

/*
 * Packet flags.  Unlike m_flags, all packet flags are copied along when
 * copying m_pkthdr, i.e. no equivalent of M_COPYFLAGS here.  These flags
 * (and other classifier info) will be cleared during DLIL input.
 *
 * Some notes about M_LOOP and PKTF_LOOP:
 *
 *    - M_LOOP flag is overloaded, and its use is discouraged.  Historically,
 *	that flag was used by the KAME implementation for allowing certain
 *	certain exceptions to be made in the IP6_EXTHDR_CHECK() logic; this
 *	was originally meant to be set as the packet is looped back to the
 *	system, and in some circumstances temporarily set in ip6_output().
 *	Over time, this flag was used by the pre-output routines to indicate
 *	to the DLIL frameout and output routines, that the packet may be
 *	looped back to the system under the right conditions.  In addition,
 *	this is an mbuf flag rather than an mbuf packet header flag.
 *
 *    - PKTF_LOOP is an mbuf packet header flag, which is set if and only
 *	if the packet was looped back to the system.  This flag should be
 *	used instead for newer code.
 */
#define	PKTF_FLOW_ID		0x1	/* pkt has valid flowid value */
#define	PKTF_FLOW_ADV		0x2	/* pkt triggers local flow advisory */
#define	PKTF_FLOW_LOCALSRC	0x4	/* pkt is locally originated  */
#define	PKTF_FLOW_RAWSOCK	0x8	/* pkt locally generated by raw sock */
#define	PKTF_PRIO_PRIVILEGED	0x10	/* packet priority is privileged */
#define	PKTF_PROXY_DST		0x20	/* processed but not locally destined */
#define	PKTF_INET_RESOLVE	0x40	/* IPv4 resolver packet */
#define	PKTF_INET6_RESOLVE	0x80	/* IPv6 resolver packet */
#define	PKTF_RESOLVE_RTR	0x100	/* pkt is for resolving router */
#define	PKTF_SW_LRO_PKT		0x200	/* pkt is a large coalesced pkt */
#define	PKTF_SW_LRO_DID_CSUM	0x400	/* IP and TCP checksums done by LRO */
#define	PKTF_MPTCP		0x800	/* TCP with MPTCP metadata */
#define	PKTF_MPSO		0x1000	/* MPTCP socket meta data */
#define	PKTF_LOOP		0x2000	/* loopbacked packet */
#define	PKTF_IFAINFO		0x4000	/* pkt has valid interface addr info */
#define	PKTF_SO_BACKGROUND	0x8000	/* data is from background source */
#define	PKTF_FORWARDED		0x10000	/* pkt was forwarded from another i/f */
#define	PKTF_PRIV_GUARDED	0x20000	/* pkt_mpriv area guard enabled */
#define	PKTF_KEEPALIVE		0x40000	/* pkt is kernel-generated keepalive */
#define	PKTF_SO_REALTIME	0x80000	/* data is realtime traffic */
#define	PKTF_VALID_UNSENT_DATA	0x100000 /* unsent data is valid */
#define	PKTF_TCP_REXMT		0x200000 /* packet is TCP retransmission */

/* flags related to flow control/advisory and identification */
#define	PKTF_FLOW_MASK	\
	(PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC | PKTF_FLOW_RAWSOCK)

/*
 * Description of external storage mapped into mbuf, valid only if M_EXT set.
 */
typedef uint64_t m_ext_free_func_t;
struct m_ext {
	MM_caddr_t	ext_buf;		/* start of buffer */
	m_ext_free_func_t ext_free;	/* free routine if not the usual */
	u_int	ext_size;		/* size of buffer, for ext_free */
	MM_caddr_t	ext_arg;		/* additional ext_free argument */
	struct	ext_refsq {		/* references held */
		struct ext_refsq *forward, *backward;
	} ext_refs;
	struct ext_ref {
		u_int32_t refcnt;
		u_int32_t flags;
	} *ext_refflags;
};

/* define m_ext to a type since it gets redefined below */
typedef struct m_ext _m_ext_t;

/*
 * The mbuf object
 */
struct mbuf {
	struct	m_hdr m_hdr;
	union {
		struct {
			struct	pkthdr MH_pkthdr;	/* M_PKTHDR set */
			union {
				struct	m_ext MH_ext;	/* M_EXT set */
				char	MH_databuf[_MHLEN];
			} MH_dat;
		} MH;
		char	M_databuf[_MLEN];		/* !M_PKTHDR, !M_EXT */
	} M_dat;
};

/* MM is MacOS Mbuf */
#define MM_NEXT		m_hdr.mh_next
#define MM_NEXTPKT	m_hdr.mh_nextpkt
#define MM_DATA		m_hdr.mh_data
#define MM_LEN		m_hdr.mh_len
#define MM_TYPE		m_hdr.mh_type
#define MM_FLAGS	m_hdr.mh_flags
#define	MM_ACT		m_nextpkt
#define	MM_PKTHDR	M_dat.MH.MH_pkthdr
#define	MM_EXT		M_dat.MH.MH_dat.MH_ext
#define	MM_PKTDAT	M_dat.MH.MH_dat.MH_databuf
#define	MM_DAT		M_dat.M_databuf
#define	MM_PKTLEN(_m)	((_m)->m_pkthdr.len)
#define	MM_PFTAG(_m)	(&(_m)->m_pkthdr.pf_mtag)

/* mbuf flags (private) */
#define	M_EXT		0x0001	/* has associated external storage */
#define	M_PKTHDR	0x0002	/* start of record */
#define	M_EOR		0x0004	/* end of record */
#define	M_PROTO1	0x0008	/* protocol-specific */
#define	M_PROTO2	0x0010	/* protocol-specific */
#define	M_PROTO3	0x0020	/* protocol-specific */
#define	M_LOOP		0x0040	/* packet is looped back (also see PKTF_LOOP) */
#define	M_PROTO5	0x0080	/* protocol-specific */

/* mbuf pkthdr flags, also in m_flags (private) */
#define	M_BCAST		0x0100	/* send/received as link-level broadcast */
#define	M_MCAST		0x0200	/* send/received as link-level multicast */
#define	M_FRAG		0x0400	/* packet is a fragment of a larger packet */
#define	M_FIRSTFRAG	0x0800	/* packet is first fragment */
#define	M_LASTFRAG	0x1000	/* packet is last fragment */
#define	M_PROMISC	0x2000	/* packet is promiscuous (shouldn't go to stack) */
#define	M_HASFCS	0x4000	/* packet has FCS */
#define	M_TAGHDR	0x8000	/* m_tag hdr structure at top of mbuf data */

/* mbuf types */
#define	MT_FREE		0	/* should be on free list */
#define	MT_DATA		1	/* dynamic (data) allocation */
#define	MT_HEADER	2	/* packet header */
#define	MT_SOCKET	3	/* socket structure */
#define	MT_PCB		4	/* protocol control block */
#define	MT_RTABLE	5	/* routing tables */
#define	MT_HTABLE	6	/* IMP host tables */
#define	MT_ATABLE	7	/* address resolution tables */
#define	MT_SONAME	8	/* socket name */
#define	MT_SOOPTS	10	/* socket options */
#define	MT_FTABLE	11	/* fragment reassembly header */
#define	MT_RIGHTS	12	/* access rights */
#define	MT_IFADDR	13	/* interface address */
#define	MT_CONTROL	14	/* extra-data protocol message */
#define	MT_OOBDATA	15	/* expedited data  */
#define	MT_TAG		16	/* volatile metadata associated to pkts */
#define	MT_MAX		32	/* enough? */

/*
 * mbuf allocation/deallocation macros:
 *
 *	MGET(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain internal data.
 *
 *	MGETHDR(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain a packet header
 * and internal data.
 */

#if 1
#define	MCHECK(m) m_mcheck(m)
#else
#define	MCHECK(m)
#endif

#define	MGET(m, how, type) ((m) = m_get((how), (type)))

#define	MGETHDR(m, how, type)	((m) = m_gethdr((how), (type)))

/*
 * Mbuf cluster macros.
 * MCLALLOC(caddr_t p, int how) allocates an mbuf cluster.
 * MCLGET adds such clusters to a normal mbuf;
 * the flag M_EXT is set upon success.
 * MCLFREE releases a reference to a cluster allocated by MCLALLOC,
 * freeing the cluster if the reference count has reached 0.
 *
 * Normal mbuf clusters are normally treated as character arrays
 * after allocation, but use the first word of the buffer as a free list
 * pointer while on the free list.
 */
union mcluster {
	union	mcluster *mcl_next;
	char	mcl_buf[MCLBYTES];
};

#define	MCLALLOC(p, how)	((p) = m_mclalloc(how))

#define	MCLFREE(p)		m_mclfree(p)

#define	MCLGET(m, how)		((m) = m_mclget(m, how))

/*
 * Mbuf big cluster
 */
union mbigcluster {
	union mbigcluster	*mbc_next;
	char			mbc_buf[MBIGCLBYTES];
};

/*
 * Mbuf jumbo cluster
 */
union m16kcluster {
	union m16kcluster	*m16kcl_next;
	char			m16kcl_buf[M16KCLBYTES];
};

#endif	/* !_SYS_MBUF_H_ */
