/*
* Core code for QEMU e1000e emulation
*
* Software developer's manuals:
* http://www.intel.com/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf
*
* Copyright (c) 2015 Ravello Systems LTD (http://ravellosystems.com)
* Developed by Daynix Computing LTD (http://www.daynix.com)
*
* Authors:
* Dmitry Fleytman <dmitry@daynix.com>
* Leonid Bloch <leonid@daynix.com>
* Yan Vugenfirer <yan@daynix.com>
*
* Based on work done by:
* Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
* Copyright (c) 2008 Qumranet
* Based on work done by:
* Copyright (c) 2007 Dan Aloni
* Copyright (c) 2004 Antony T Curtis
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#define E1000E_PHY_PAGE_SIZE    (0x20)
#define E1000E_PHY_PAGES        (0x07)
#define E1000E_MAC_SIZE         (0x8000)
#define E1000E_EEPROM_SIZE      (64)
#define E1000E_MSIX_VEC_NUM     (5)
#define E1000E_NUM_QUEUES       (2)

typedef struct E1000Core_st E1000ECore;

enum { PHY_R = BIT(0),
       PHY_W = BIT(1),
       PHY_RW = PHY_R | PHY_W,
       PHY_ANYPAGE = BIT(2) };

typedef struct E1000IntrDelayTimer_st {
    QEMUTimer *timer;
    bool running;
    uint32_t delay_reg;
    uint32_t delay_resolution_ns;
    E1000ECore *core;
} E1000IntrDelayTimer;

#define VMSTATE_E1000_INTR_DELAY_TIMER(_f, _s) \
    VMSTATE_TIMER_PTR(_f.timer, _s),           \
    VMSTATE_BOOL(_f.running, _s)               \

struct E1000Core_st {
    uint32_t mac[E1000E_MAC_SIZE];
    uint16_t phy[E1000E_PHY_PAGES][E1000E_PHY_PAGE_SIZE];
    uint16_t eeprom[E1000E_EEPROM_SIZE];

    uint32_t rxbuf_sizes[E1000_PSRCTL_BUFFS_PER_DESC];
    uint32_t rx_desc_buf_size;
    uint32_t rxbuf_min_shift;
    uint8_t rx_desc_len;

    QEMUTimer *autoneg_timer;

    struct e1000_tx {
        unsigned char sum_needed;
        uint8_t ipcss;
        uint8_t ipcso;
        uint16_t ipcse;
        uint8_t tucss;
        uint8_t tucso;
        uint16_t tucse;
        uint8_t hdr_len;
        uint16_t mss;
        uint32_t paylen;
        int8_t ip;
        int8_t tcp;
        bool tse;
        bool cptse;

        struct NetTxPkt *tx_pkt;
        bool skip_cp;
    } tx[E1000E_NUM_QUEUES];

    struct NetRxPkt *rx_pkt;

    bool has_vnet;
    int max_queue_num;

    /* Interrupt moderation management */
    uint32_t delayed_causes;

    E1000IntrDelayTimer radv;
    E1000IntrDelayTimer rdtr;
    E1000IntrDelayTimer raid;

    E1000IntrDelayTimer tadv;
    E1000IntrDelayTimer tidv;

    E1000IntrDelayTimer itr;
    bool itr_intr_pending;

    E1000IntrDelayTimer eitr[E1000E_MSIX_VEC_NUM];
    bool eitr_intr_pending[E1000E_MSIX_VEC_NUM];

    uint32_t itr_guest_value;
    uint32_t eitr_guest_value[E1000E_MSIX_VEC_NUM];

    uint16_t vet;

    uint8_t permanent_mac[ETH_ALEN];

    NICState *owner_nic;
    PCIDevice *owner;
    void (*owner_start_recv)(PCIDevice *d);
};

#define defreg(x)   x = (E1000_##x>>2)
enum {
    defreg(CTRL),    defreg(EECD),    defreg(EERD),    defreg(GPRC),
    defreg(GPTC),    defreg(ICR),     defreg(ICS),     defreg(IMC),
    defreg(IMS),     defreg(LEDCTL),  defreg(MANC),    defreg(MDIC),
    defreg(MPC),     defreg(PBA),     defreg(RCTL),    defreg(RDBAH0),
    defreg(RDBAL0),  defreg(RDH0),    defreg(RDLEN0),  defreg(RDT0),
    defreg(STATUS),  defreg(SWSM),    defreg(TCTL),    defreg(TDBAH),
    defreg(TDBAL),   defreg(TDH),     defreg(TDLEN),   defreg(TDT),
    defreg(TDLEN1),  defreg(TDBAL1),  defreg(TDBAH1),  defreg(TDH1),
    defreg(TDT1),    defreg(TORH),    defreg(TORL),    defreg(TOTH),
    defreg(TOTL),    defreg(TPR),     defreg(TPT),     defreg(TXDCTL),
    defreg(WUFC),    defreg(RA),      defreg(MTA),     defreg(CRCERRS),
    defreg(VFTA),    defreg(VET),     defreg(RDTR),    defreg(RADV),
    defreg(TADV),    defreg(ITR),     defreg(SCC),     defreg(ECOL),
    defreg(MCC),     defreg(LATECOL), defreg(COLC),    defreg(DC),
    defreg(TNCRS),   defreg(SEC),     defreg(CEXTERR), defreg(RLEC),
    defreg(XONRXC),  defreg(XONTXC),  defreg(XOFFRXC), defreg(XOFFTXC),
    defreg(FCRUC),   defreg(AIT),     defreg(TDFH),    defreg(TDFT),
    defreg(TDFHS),   defreg(TDFTS),   defreg(TDFPC),   defreg(WUC),
    defreg(WUS),     defreg(POEMB),   defreg(PBS),     defreg(RDFH),
    defreg(RDFT),    defreg(RDFHS),   defreg(RDFTS),   defreg(RDFPC),
    defreg(PBM),     defreg(IPAV),    defreg(IP4AT),   defreg(IP6AT),
    defreg(WUPM),    defreg(FFLT),    defreg(FFMT),    defreg(FFVT),
    defreg(TARC0),   defreg(TARC1),   defreg(IAM),     defreg(EXTCNF_CTRL),
    defreg(GCR),     defreg(TIMINCA), defreg(EIAC),    defreg(CTRL_EXT),
    defreg(IVAR),    defreg(MFUTP01), defreg(MFUTP23), defreg(MANC2H),
    defreg(MFVAL),   defreg(MDEF),    defreg(FACTPS),  defreg(FTFT),
    defreg(RUC),     defreg(ROC),     defreg(RFC),     defreg(RJC),
    defreg(PRC64),   defreg(PRC127),  defreg(PRC255),  defreg(PRC511),
    defreg(PRC1023), defreg(PRC1522), defreg(PTC64),   defreg(PTC127),
    defreg(PTC255),  defreg(PTC511),  defreg(PTC1023), defreg(PTC1522),
    defreg(GORCL),   defreg(GORCH),   defreg(GOTCL),   defreg(GOTCH),
    defreg(RNBC),    defreg(BPRC),    defreg(MPRC),    defreg(RFCTL),
    defreg(PSRCTL),  defreg(MPTC),    defreg(BPTC),    defreg(TSCTFC),
    defreg(IAC),     defreg(MGTPRC),  defreg(MGTPDC),  defreg(MGTPTC),
    defreg(TSCTC),   defreg(RXCSUM),  defreg(FUNCTAG), defreg(GSCL_1),
    defreg(GSCL_2),  defreg(GSCL_3),  defreg(GSCL_4),  defreg(GSCN_0),
    defreg(GSCN_1),  defreg(GSCN_2),  defreg(GSCN_3),  defreg(GCR2),
    defreg(RAID),    defreg(RSRPD),   defreg(TIDV),    defreg(EITR),
    defreg(MRQC),    defreg(RETA),    defreg(RSSRK),   defreg(RDBAH1),
    defreg(RDBAL1),  defreg(RDLEN1),  defreg(RDH1),    defreg(RDT1),
    defreg(PBACLR),  defreg(FCAL),    defreg(FCAH),    defreg(FCT),
    defreg(FCRTH),   defreg(FCRTL),   defreg(FCTTV),   defreg(FCRTV),
    defreg(FLA),     defreg(EEWR),    defreg(FLOP),    defreg(FLOL),
    defreg(FLSWCTL), defreg(FLSWCNT), defreg(RXDCTL),  defreg(RXDCTL1),
    defreg(MAVTV0),  defreg(MAVTV1),  defreg(MAVTV2),  defreg(MAVTV3),
    defreg(TXSTMPL), defreg(TXSTMPH), defreg(SYSTIML), defreg(SYSTIMH),
    defreg(RXCFGL),  defreg(RXUDP),   defreg(TIMADJL), defreg(TIMADJH),
    defreg(RXSTMPH), defreg(RXSTMPL), defreg(RXSATRL), defreg(RXSATRH),
    defreg(FLASHT),  defreg(TIPG),    defreg(TXDCTL1), defreg(FLSWDATA),
    defreg(CTRL_DUP),
    defreg(EXTCNF_SIZE),
    defreg(EEMNGCTL),
    defreg(EEMNGDATA),
    defreg(FLMNGCTL),
    defreg(FLMNGDATA),
    defreg(FLMNGCNT),
    defreg(TSYNCRXCTL),
    defreg(TSYNCTXCTL),

    /* Aliases */
    defreg(RDH0_A),  defreg(RDT0_A),  defreg(RDTR_A),  defreg(RDFH_A),
    defreg(RDFT_A),  defreg(TDH_A),   defreg(TDT_A),   defreg(TIDV_A),
    defreg(TDFH_A),  defreg(TDFT_A),  defreg(RA_A),    defreg(RDBAL0_A),
    defreg(TDBAL_A), defreg(TDLEN_A), defreg(VFTA_A),  defreg(RDLEN0_A),
    defreg(FCRTL_A), defreg(FCRTH_A)
};

void
e1000e_core_write(E1000ECore *core, hwaddr addr, uint64_t val, unsigned size);

uint64_t
e1000e_core_read(E1000ECore *core, hwaddr addr, unsigned size);

void
e1000e_core_pci_realize(E1000ECore      *regs,
                       const uint16_t *eeprom_templ,
                       uint32_t        eeprom_size,
                       const uint8_t  *macaddr);

void
e1000e_core_reset(E1000ECore *core);

void
e1000e_core_pre_save(E1000ECore *core);

int
e1000e_core_post_load(E1000ECore *core);

void
e1000e_core_set_link_status(E1000ECore *core);

void
e1000e_core_pci_uninit(E1000ECore *core);

int
e1000e_can_receive(E1000ECore *core);

ssize_t
e1000e_receive(E1000ECore *core, const uint8_t *buf, size_t size);

ssize_t
e1000e_receive_iov(E1000ECore *core, const struct iovec *iov, int iovcnt);
