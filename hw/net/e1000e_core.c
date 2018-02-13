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
#include "attacks.h"
#include "pcie.h"
#include "pcie-debug.h"
#include "log.h"
#include "mask.h"

#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "net/tap.h"
#include "net/checksum.h"
#include "sysemu/sysemu.h"
#include "qemu/iov.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"

#include "net_tx_pkt.h"
#include "net_rx_pkt.h"

#include "e1000_regs.h"
#include "e1000e_core.h"

#include "trace.h"

/*
 * Some support for the attack toolkit, by cr437@cam.ac.uk
 */

static OperateOnDescriptor _PRE_XMIT_HOOK;
static void (*_PRE_XMIT_HOOK_DONE)();

void
register_pre_xmit_hook(OperateOnDescriptor loop_body, void (*done)())
{
	_PRE_XMIT_HOOK = loop_body;
	_PRE_XMIT_HOOK_DONE = done;
}

/*
 * -------------------------------------------------------
 */


#define _E1000E_MIN_XITR (500) /* No more then 7813 interrupts per
                                  second according to spec 10.2.4.2 */

static const uint8_t E1000E_MAX_TX_FRAGS = 64;

static void
set_interrupt_cause(E1000ECore *core, uint32_t val);

static inline int
vlan_enabled(E1000ECore *core)
{
    return ((core->mac[CTRL] & E1000_CTRL_VME) != 0);
}

static inline int
is_vlan_txd(uint32_t txd_lower)
{
    return ((txd_lower & E1000_TXD_CMD_VLE) != 0);
}

static inline void
inc_reg_if_not_full(E1000ECore *core, int index)
{
    if (core->mac[index] != 0xffffffff) {
        core->mac[index]++;
    }
}

static void
grow_8reg_if_not_full(E1000ECore *core, int index, int size)
{
    uint64_t sum = core->mac[index] | (uint64_t)core->mac[index+1] << 32;

    if (sum + size < sum) {
        sum = ~0ULL;
    } else {
        sum += size;
    }
    core->mac[index] = sum;
    core->mac[index+1] = sum >> 32;
}

static void
increase_size_stats(E1000ECore *core, const int *size_regs, int size)
{
    if (size > 1023) {
        inc_reg_if_not_full(core, size_regs[5]);
    } else if (size > 511) {
        inc_reg_if_not_full(core, size_regs[4]);
    } else if (size > 255) {
        inc_reg_if_not_full(core, size_regs[3]);
    } else if (size > 127) {
        inc_reg_if_not_full(core, size_regs[2]);
    } else if (size > 64) {
        inc_reg_if_not_full(core, size_regs[1]);
    } else if (size == 64) {
        inc_reg_if_not_full(core, size_regs[0]);
    }
}

static inline void
process_ts_option(E1000ECore *core, struct e1000_tx_desc *dp)
{
    if (le32_to_cpu(dp->upper.data) & E1000_TXD_EXTCMD_TSTAMP) {
        trace_e1000e_wrn_no_ts_support();
    }
}

static inline void
process_snap_option(E1000ECore *core, uint32_t cmd_and_length)
{
    if (cmd_and_length & E1000_TXD_CMD_SNAP) {
        trace_e1000e_wrn_no_snap_support();
    }
}

static inline void
_e1000e_raise_legacy_irq(E1000ECore *core)
{
    trace_e1000e_irq_legacy_notify(true);
    inc_reg_if_not_full(core, IAC);
    pci_set_irq(core->owner, 1);
}

static inline void
_e1000e_lower_legacy_irq(E1000ECore *core)
{
    trace_e1000e_irq_legacy_notify(false);
    pci_set_irq(core->owner, 0);
}

static inline void
_e1000e_intrmgr_rearm_timer(E1000IntrDelayTimer *timer)
{
    int64_t delay_ns = (int64_t) timer->core->mac[timer->delay_reg] *
                                 timer->delay_resolution_ns;

    trace_e1000e_irq_rearm_timer(timer->delay_reg << 2, delay_ns);

    timer_mod(timer->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delay_ns);

    timer->running = true;
}

static void
_e1000e_intmgr_timer_post_load(E1000IntrDelayTimer *timer)
{
    if (timer->running) {
        _e1000e_intrmgr_rearm_timer(timer);
    }
}

static inline void
_e1000e_intrmgr_stop_timer(E1000IntrDelayTimer *timer)
{
    if (timer->running) {
        timer_del(timer->timer);
        timer->running = false;
    }
}

static inline void
_e1000e_intrmgr_fire_delayed_interrupts(E1000ECore *core)
{
    trace_e1000e_irq_fire_delayed_interrupts();
    set_interrupt_cause(core, 0);
}

static void
_e1000e_intrmgr_on_timer(void *opaque)
{
    E1000IntrDelayTimer *timer = opaque;

    trace_e1000e_irq_throttling_timer(timer->delay_reg << 2);

    timer->running = false;
    _e1000e_intrmgr_fire_delayed_interrupts(timer->core);
}

static void
_e1000e_intrmgr_on_throttling_timer(void *opaque)
{
    E1000IntrDelayTimer *timer = opaque;

    assert(!msix_enabled(timer->core->owner));

    timer->running = false;

    if (!timer->core->itr_intr_pending) {
        trace_e1000e_irq_throttling_no_pending_interrupts();
        return;
    }

    if (msi_enabled(timer->core->owner)) {
        trace_e1000e_irq_msi_notify_postponed();
        msi_notify(timer->core->owner, 0);
    } else {
        trace_e1000e_irq_legacy_notify_postponed();
        _e1000e_raise_legacy_irq(timer->core);
    }
}

static void
_e1000e_intrmgr_on_msix_throttling_timer(void *opaque)
{
    E1000IntrDelayTimer *timer = opaque;
    int idx = timer - &timer->core->eitr[0];

    assert(msix_enabled(timer->core->owner));

    timer->running = false;

    if (!timer->core->eitr_intr_pending[idx]) {
        trace_e1000e_irq_throttling_no_pending_vec(idx);
        return;
    }

    trace_e1000e_irq_msix_notify_postponed_vec(idx);
    msix_notify(timer->core->owner, idx);
}

static void
_e1000e_intrmgr_initialize_all_timers(E1000ECore *core, bool create)
{
    int i;

    core->radv.delay_reg = RADV;
    core->rdtr.delay_reg = RDTR;
    core->raid.delay_reg = RAID;
    core->tadv.delay_reg = TADV;
    core->tidv.delay_reg = TIDV;

    core->radv.delay_resolution_ns = E1000_INTR_DELAY_NS_RES;
    core->rdtr.delay_resolution_ns = E1000_INTR_DELAY_NS_RES;
    core->raid.delay_resolution_ns = E1000_INTR_DELAY_NS_RES;
    core->tadv.delay_resolution_ns = E1000_INTR_DELAY_NS_RES;
    core->tidv.delay_resolution_ns = E1000_INTR_DELAY_NS_RES;

    core->radv.core = core;
    core->rdtr.core = core;
    core->raid.core = core;
    core->tadv.core = core;
    core->tidv.core = core;

    core->itr.core = core;
    core->itr.delay_reg = ITR;
    core->itr.delay_resolution_ns = E1000_INTR_THROTTLING_NS_RES;

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        core->eitr[i].core = core;
        core->eitr[i].delay_reg = EITR + i;
        core->eitr[i].delay_resolution_ns = E1000_INTR_THROTTLING_NS_RES;
    }

    if (!create) {
        return;
    }

    core->radv.timer =
        timer_new_ns(QEMU_CLOCK_VIRTUAL, _e1000e_intrmgr_on_timer, &core->radv);
    core->rdtr.timer =
        timer_new_ns(QEMU_CLOCK_VIRTUAL, _e1000e_intrmgr_on_timer, &core->rdtr);
    core->raid.timer =
        timer_new_ns(QEMU_CLOCK_VIRTUAL, _e1000e_intrmgr_on_timer, &core->raid);

    core->tadv.timer =
        timer_new_ns(QEMU_CLOCK_VIRTUAL, _e1000e_intrmgr_on_timer, &core->tadv);
    core->tidv.timer =
        timer_new_ns(QEMU_CLOCK_VIRTUAL, _e1000e_intrmgr_on_timer, &core->tidv);

    core->itr.timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                   _e1000e_intrmgr_on_throttling_timer,
                                   &core->itr);

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        core->eitr[i].timer =
            timer_new_ns(QEMU_CLOCK_VIRTUAL,
                         _e1000e_intrmgr_on_msix_throttling_timer,
                         &core->eitr[i]);
    }
}

static inline void
_e1000e_intrmgr_stop_delay_timers(E1000ECore *core)
{
    _e1000e_intrmgr_stop_timer(&core->radv);
    _e1000e_intrmgr_stop_timer(&core->rdtr);
    _e1000e_intrmgr_stop_timer(&core->raid);
    _e1000e_intrmgr_stop_timer(&core->tidv);
    _e1000e_intrmgr_stop_timer(&core->tadv);
}

static bool
_e1000e_intrmgr_delay_rx_causes(E1000ECore *core, uint32_t *causes)
{
    uint32_t delayable_causes;
    uint32_t rdtr = core->mac[RDTR];
    uint32_t radv = core->mac[RADV];
    uint32_t raid = core->mac[RAID];

    if (msix_enabled(core->owner)) {
        return false;
    }

    delayable_causes = E1000_ICR_RXQ0 |
                       E1000_ICR_RXQ1 |
                       E1000_ICR_RXT0;

    if (!(core->mac[RFCTL] & E1000_RFCTL_ACK_DIS)) {
        delayable_causes |= E1000_ICR_ACK;
    }

    /* Clean up all causes that may be delayed */
    core->delayed_causes |= *causes & delayable_causes;
    *causes &= ~delayable_causes;

    /* Check if delayed RX interrupts disabled by client
       or if there are causes that cannot be delayed */
    if ((rdtr == 0) || (causes != 0)) {
        return false;
    }

    /* Check if delayed RX ACK interrupts disabled by client
       and there is an ACK packet received */
    if ((raid == 0) && (core->delayed_causes & E1000_ICR_ACK)) {
        return false;
    }

    /* All causes delayed */
    _e1000e_intrmgr_rearm_timer(&core->rdtr);

    if (!core->radv.running && (radv != 0)) {
        _e1000e_intrmgr_rearm_timer(&core->radv);
    }

    if (!core->raid.running && (core->delayed_causes & E1000_ICR_ACK)) {
        _e1000e_intrmgr_rearm_timer(&core->raid);
    }

    return true;
}

static bool
_e1000e_intrmgr_delay_tx_causes(E1000ECore *core, uint32_t *causes)
{
    static const uint32_t delayable_causes = E1000_ICR_TXQ0 |
                                             E1000_ICR_TXQ1 |
                                             E1000_ICR_TXQE |
                                             E1000_ICR_TXDW;

    if (msix_enabled(core->owner)) {
        return false;
    }

    /* Clean up all causes that may be delayed */
    core->delayed_causes |= *causes & delayable_causes;
    *causes &= ~delayable_causes;

    /* If there are causes that cannot be delayed */
    if (causes != 0) {
        return false;
    }

    /* All causes delayed */
    _e1000e_intrmgr_rearm_timer(&core->tidv);

    if (!core->tadv.running && (core->mac[TADV] != 0)) {
        _e1000e_intrmgr_rearm_timer(&core->tadv);
    }

    return true;
}

static uint32_t
_e1000e_intmgr_collect_delayed_causes(E1000ECore *core)
{
    uint32_t res;

    if (msix_enabled(core->owner)) {
        assert(core->delayed_causes == 0);
        return 0;
    }

    res = core->delayed_causes;
    core->delayed_causes = 0;

    _e1000e_intrmgr_stop_delay_timers(core);

    return res;
}

static void
_e1000e_intrmgr_fire_all_timers(E1000ECore *core)
{
    int i;
    uint32_t val = _e1000e_intmgr_collect_delayed_causes(core);

    trace_e1000e_irq_adding_delayed_causes(val, core->mac[ICR]);
    core->mac[ICR] |= val;

    if (core->itr.running) {
        timer_del(core->itr.timer);
        _e1000e_intrmgr_on_throttling_timer(&core->itr);
    }

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        if (core->eitr[i].running) {
            timer_del(core->eitr[i].timer);
            _e1000e_intrmgr_on_msix_throttling_timer(&core->eitr[i]);
        }
    }
}

static void
_e1000e_intrmgr_post_load(E1000ECore *core)
{
    int i;

    _e1000e_intmgr_timer_post_load(&core->radv);
    _e1000e_intmgr_timer_post_load(&core->rdtr);
    _e1000e_intmgr_timer_post_load(&core->raid);
    _e1000e_intmgr_timer_post_load(&core->tidv);
    _e1000e_intmgr_timer_post_load(&core->tadv);

    _e1000e_intmgr_timer_post_load(&core->itr);

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        _e1000e_intmgr_timer_post_load(&core->eitr[i]);
    }
}

static void
_e1000e_intrmgr_reset(E1000ECore *core)
{
    int i;

    core->delayed_causes = 0;

    _e1000e_intrmgr_stop_delay_timers(core);

    _e1000e_intrmgr_stop_timer(&core->itr);

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        _e1000e_intrmgr_stop_timer(&core->eitr[i]);
    }
}

static void
_e1000e_intrmgr_pci_unint(E1000ECore *core)
{
    int i;

    timer_del(core->radv.timer);
    timer_free(core->radv.timer);
    timer_del(core->rdtr.timer);
    timer_free(core->rdtr.timer);
    timer_del(core->raid.timer);
    timer_free(core->raid.timer);

    timer_del(core->tadv.timer);
    timer_free(core->tadv.timer);
    timer_del(core->tidv.timer);
    timer_free(core->tidv.timer);

    timer_del(core->itr.timer);
    timer_free(core->itr.timer);

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        timer_del(core->eitr[i].timer);
        timer_free(core->eitr[i].timer);
    }
}

static void
_e1000e_intrmgr_pci_realize(E1000ECore *core)
{
    _e1000e_intrmgr_initialize_all_timers(core, true);
}

static inline bool
_e1000e_rx_csum_enabled(E1000ECore *core)
{
    return (core->mac[RXCSUM] & E1000_RXCSUM_PCSD) ? false : true;
}

static inline bool
_e1000e_rx_use_legacy_descriptor(E1000ECore *core)
{
    return (core->mac[RFCTL] & E1000_RFCTL_EXTEN) ? false : true;
}

static inline bool
_e1000e_rx_use_ps_descriptor(E1000ECore *core)
{
    return !_e1000e_rx_use_legacy_descriptor(core) &&
           (core->mac[RCTL] & E1000_RCTL_DTYP_PS);
}

static inline bool
_e1000e_rss_enabled(E1000ECore *core)
{
    return E1000_MRQC_ENABLED(core->mac[MRQC]) &&
           !_e1000e_rx_csum_enabled(core) &&
           !_e1000e_rx_use_legacy_descriptor(core);
}

typedef struct E1000E_RSSInfo_st {
    bool enabled;
    uint32_t hash;
    uint32_t queue;
    uint32_t type;
} E1000E_RSSInfo;

static uint32_t
_e1000e_rss_get_hash_type(E1000ECore *core, struct NetRxPkt *pkt)
{
    bool isip4, isip6, isudp, istcp;

    assert(_e1000e_rss_enabled(core));

    net_rx_pkt_get_protocols(pkt, &isip4, &isip6, &isudp, &istcp);

    if (isip4) {
        bool fragment = net_rx_pkt_get_ip4_info(pkt)->fragment;

        trace_e1000e_rx_rss_ip4(fragment, istcp, core->mac[MRQC],
                                E1000_MRQC_EN_TCPIPV4(core->mac[MRQC]),
                                E1000_MRQC_EN_IPV4(core->mac[MRQC]));

        if (!fragment && istcp && E1000_MRQC_EN_TCPIPV4(core->mac[MRQC])) {
            return E1000_MRQ_RSS_TYPE_IPV4TCP;
        }

        if (E1000_MRQC_EN_IPV4(core->mac[MRQC])) {
            return E1000_MRQ_RSS_TYPE_IPV4;
        }
    } else if (isip6) {
        eth_ip6_hdr_info *ip6info = net_rx_pkt_get_ip6_info(pkt);

        bool ex_dis = core->mac[RFCTL] & E1000_RFCTL_IPV6_EX_DIS;
        bool new_ex_dis = core->mac[RFCTL] & E1000_RFCTL_NEW_IPV6_EXT_DIS;

        trace_e1000e_rx_rss_ip6(core->mac[RFCTL],
                                ex_dis, new_ex_dis, istcp,
                                ip6info->has_ext_hdrs,
                                ip6info->rss_ex_dst_valid,
                                ip6info->rss_ex_src_valid,
                                core->mac[MRQC],
                                E1000_MRQC_EN_TCPIPV6(core->mac[MRQC]),
                                E1000_MRQC_EN_IPV6EX(core->mac[MRQC]),
                                E1000_MRQC_EN_IPV6(core->mac[MRQC]));

        if ((!ex_dis || !ip6info->has_ext_hdrs) &&
            (!new_ex_dis || !(ip6info->rss_ex_dst_valid ||
                              ip6info->rss_ex_src_valid))) {

            if (istcp && !ip6info->fragment &&
                E1000_MRQC_EN_TCPIPV6(core->mac[MRQC])) {
                return E1000_MRQ_RSS_TYPE_IPV6TCP;
            }

            if (E1000_MRQC_EN_IPV6EX(core->mac[MRQC])) {
                return E1000_MRQ_RSS_TYPE_IPV6EX;
            }

        }

        if (E1000_MRQC_EN_IPV6(core->mac[MRQC])) {
            return E1000_MRQ_RSS_TYPE_IPV6;
        }

    }

    return E1000_MRQ_RSS_TYPE_NONE;
}

static uint32_t
_e1000e_rss_calc_hash(E1000ECore *core,
                      struct NetRxPkt *pkt,
                      E1000E_RSSInfo *info)
{
    NetRxPktRssType type;

    assert(_e1000e_rss_enabled(core));

    switch (info->type) {
    case E1000_MRQ_RSS_TYPE_IPV4:
        type = NetPktRssIpV4;
        break;
    case E1000_MRQ_RSS_TYPE_IPV4TCP:
        type = NetPktRssIpV4Tcp;
        break;
    case E1000_MRQ_RSS_TYPE_IPV6TCP:
        type = NetPktRssIpV6Tcp;
        break;
    case E1000_MRQ_RSS_TYPE_IPV6:
        type = NetPktRssIpV6;
        break;
    case E1000_MRQ_RSS_TYPE_IPV6EX:
        type = NetPktRssIpV6Ex;
        break;
    default:
        assert(false);
        return 0;
    }

    return net_rx_pkt_calc_rss_hash(pkt, type, (uint8_t *) &core->mac[RSSRK]);
}

static void
_e1000e_rss_parse_packet(E1000ECore *core,
                         struct NetRxPkt *pkt,
                         E1000E_RSSInfo *info)
{
    trace_e1000e_rx_rss_started();

    if (!_e1000e_rss_enabled(core)) {
        info->enabled = false;
        info->hash = 0;
        info->queue = 0;
        info->type = 0;
        trace_e1000e_rx_rss_disabled();
        return;
    }

    info->enabled = true;

    info->type = _e1000e_rss_get_hash_type(core, pkt);

    trace_e1000e_rx_rss_type(info->type);

    if (info->type == E1000_MRQ_RSS_TYPE_NONE) {
        info->hash = 0;
        info->queue = 0;
        return;
    }

    info->hash = _e1000e_rss_calc_hash(core, pkt, info);
    info->queue = E1000_RSS_QUEUE(&core->mac[RETA], info->hash);
}

static void
_e1000e_setup_tx_offloads(E1000ECore *core, struct e1000_tx *tx)
{
    if (tx->tse && tx->cptse) {
        net_tx_pkt_build_vheader(tx->tx_pkt, true, true, tx->mss);
        net_tx_pkt_update_ip_checksums(tx->tx_pkt);
        inc_reg_if_not_full(core, TSCTC);
        return;
    }

    if (tx->sum_needed & E1000_TXD_POPTS_TXSM) {
        net_tx_pkt_build_vheader(tx->tx_pkt, false, true, 0);
    }

    if (tx->sum_needed & E1000_TXD_POPTS_IXSM) {
		/* XXX cr437 */
		/*fprintf(stderr, "Skipping update ip header checksum from e1000...\n");*/
		net_tx_pkt_update_ip_hdr_checksum(tx->tx_pkt);
    }
}

static bool
_e1000e_tx_pkt_send(E1000ECore *core, struct e1000_tx *tx, int queue_index)
{
    int target_queue = MIN(core->max_queue_num, queue_index);
    NetClientState *queue = qemu_get_subqueue(core->owner_nic, target_queue);

    _e1000e_setup_tx_offloads(core, tx);

    net_tx_pkt_dump(tx->tx_pkt);

    if ((core->phy[0][PHY_CTRL] & MII_CR_LOOPBACK) ||
        ((core->mac[RCTL] & E1000_RCTL_LBM_MAC) == E1000_RCTL_LBM_MAC)) {
        return net_tx_pkt_send_loopback(tx->tx_pkt, queue);
    } else {
        return net_tx_pkt_send(tx->tx_pkt, queue);
    }
}

static void
_e1000e_on_tx_done_update_stats(E1000ECore *core, struct NetTxPkt *tx_pkt)
{
    static const int PTCregs[6] = { PTC64, PTC127, PTC255, PTC511,
                                    PTC1023, PTC1522 };

    size_t tot_len = net_tx_pkt_get_total_len(tx_pkt);

    increase_size_stats(core, PTCregs, tot_len);
    inc_reg_if_not_full(core, TPT);
    grow_8reg_if_not_full(core, TOTL, tot_len);

    switch (net_tx_pkt_get_packet_type(tx_pkt)) {
    case ETH_PKT_BCAST:
        inc_reg_if_not_full(core, BPTC);
        break;
    case ETH_PKT_MCAST:
        inc_reg_if_not_full(core, MPTC);
        break;
    case ETH_PKT_UCAST:
        break;
    default:
        g_assert_not_reached();
    }

    core->mac[GPTC] = core->mac[TPT];
    core->mac[GOTCL] = core->mac[TOTL];
    core->mac[GOTCH] = core->mac[TOTH];
}

static void
process_tx_desc(E1000ECore *core,
                struct e1000_tx *tx,
                struct e1000_tx_desc *dp,
                int queue_index)
{
    uint32_t txd_lower = le32_to_cpu(dp->lower.data);
    uint32_t dtype = txd_lower & (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D);
    unsigned int split_size = txd_lower & 0xffff, op;
    uint64_t addr;
    struct e1000_context_desc *xp = (struct e1000_context_desc *)dp;
    bool eop = txd_lower & E1000_TXD_CMD_EOP;

	if (queue_index >= E1000E_NUM_QUEUES) {
		printf("Trying to process tx desc on queue: %d.\n", queue_index);
	}
	assert(queue_index < E1000E_NUM_QUEUES);

    if (dtype == E1000_TXD_CMD_DEXT) {    /* context descriptor */
        op = le32_to_cpu(xp->cmd_and_length);
        tx->ipcss = xp->lower_setup.ip_fields.ipcss;
        tx->ipcso = xp->lower_setup.ip_fields.ipcso;
        tx->ipcse = le16_to_cpu(xp->lower_setup.ip_fields.ipcse);
        tx->tucss = xp->upper_setup.tcp_fields.tucss;
        tx->tucso = xp->upper_setup.tcp_fields.tucso;
        tx->tucse = le16_to_cpu(xp->upper_setup.tcp_fields.tucse);
        tx->paylen = op & 0xfffff;
        tx->hdr_len = xp->tcp_seg_setup.fields.hdr_len;
        tx->mss = le16_to_cpu(xp->tcp_seg_setup.fields.mss);
        tx->ip = (op & E1000_TXD_CMD_IP) ? 1 : 0;
        tx->tcp = (op & E1000_TXD_CMD_TCP) ? 1 : 0;
        tx->tse = (op & E1000_TXD_CMD_TSE) ? 1 : 0;
        if (tx->tucso == 0) { /* this is probably wrong */
            trace_e1000e_tx_cso_zero();
            tx->tucso = tx->tucss + (tx->tcp ? 16 : 6);
        }
        process_snap_option(core, op);
        return;
    } else if (dtype == (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D)) {
        /* data descriptor */
        tx->sum_needed = le32_to_cpu(dp->upper.data) >> 8;
        tx->cptse = (txd_lower & E1000_TXD_CMD_TSE) ? 1 : 0;
        process_ts_option(core, dp);
    } else {
        /* legacy descriptor */
        process_ts_option(core, dp);
        tx->cptse = 0;
    }

    addr = le64_to_cpu(dp->buffer_addr);

    if (!tx->skip_cp) {
        if (!net_tx_pkt_add_raw_fragment(tx->tx_pkt, addr, split_size)) {
            tx->skip_cp = true;
        }
    }

    if (eop) {
        if (!tx->skip_cp && net_tx_pkt_parse(tx->tx_pkt)) {
            if (vlan_enabled(core) && is_vlan_txd(txd_lower)) {
                net_tx_pkt_setup_vlan_header_ex(tx->tx_pkt,
                    le16_to_cpu(dp->upper.fields.special), core->vet);
            }
            if (_e1000e_tx_pkt_send(core, tx, queue_index)) {
                _e1000e_on_tx_done_update_stats(core, tx->tx_pkt);
            }
        }

        tx->skip_cp = false;
        net_tx_pkt_reset(tx->tx_pkt);

        tx->sum_needed = 0;
        tx->cptse = 0;
    }
}

static inline uint32_t
_e1000e_tx_wb_interrupt_cause(E1000ECore *core, int queue_idx)
{
    if (!msix_enabled(core->owner)) {
        return E1000_ICR_TXDW;
    }

    return (queue_idx == 0) ? E1000_ICR_TXQ0 : E1000_ICR_TXQ1;
}

static inline uint32_t
_e1000e_rx_wb_interrupt_cause(E1000ECore *core,
                              int queue_idx,
                              bool min_threshold_hit)
{
    if (!msix_enabled(core->owner)) {
        return E1000_ICS_RXT0 | (min_threshold_hit ? E1000_ICS_RXDMT0 : 0);
    }

    return (queue_idx == 0) ? E1000_ICR_RXQ0 : E1000_ICR_RXQ1;
}

static uint32_t
txdesc_writeback(E1000ECore *core, dma_addr_t base,
                 struct e1000_tx_desc *dp, bool *ide, int queue_idx)
{
    uint32_t txd_upper, txd_lower = le32_to_cpu(dp->lower.data);

    if (!(txd_lower & E1000_TXD_CMD_RS) &&
        !(core->mac[IVAR] & E1000_IVAR_TX_INT_EVERY_WB)) {
        return 0;
    }

    *ide = (txd_lower & E1000_TXD_CMD_IDE) ? true : false;

    txd_upper = le32_to_cpu(dp->upper.data) | E1000_TXD_STAT_DD;

    dp->upper.data = cpu_to_le32(txd_upper);
    pci_dma_write(core->owner, base + ((char *)&dp->upper - (char *)dp),
                  &dp->upper, sizeof(dp->upper));
    return _e1000e_tx_wb_interrupt_cause(core, queue_idx);
}

typedef struct E1000E_RingInfo_st {
    int dbah;
    int dbal;
    int dlen;
    int dh;
    int dt;
    int idx;
} E1000E_RingInfo;

static inline bool
_e1000e_ring_empty(E1000ECore *core, const E1000E_RingInfo *r)
{
    return core->mac[r->dh] == core->mac[r->dt];
}

static inline uint64_t
_e1000e_ring_base(E1000ECore *core, const E1000E_RingInfo *r)
{
    uint64_t bah = core->mac[r->dbah];
    uint64_t bal = core->mac[r->dbal] & ~0xf;

    return (bah << 32) + bal;
}

static inline uint64_t
_e1000e_ring_descriptor_address(E1000ECore *core, const E1000E_RingInfo *r,
    int offset)
{
    return _e1000e_ring_base(core, r) + E1000_RING_DESC_LEN * offset;
}

static inline uint64_t
_e1000e_ring_head_descr(E1000ECore *core, const E1000E_RingInfo *r)
{
    return _e1000e_ring_descriptor_address(core, r, core->mac[r->dh]);
}

static inline uint64_t
_e1000e_ring_tail_descr(E1000ECore *core, const E1000E_RingInfo *r)
{
    return _e1000e_ring_descriptor_address(core, r, core->mac[r->dt]);
}

static inline void
_e1000e_ring_advance(E1000ECore *core, const E1000E_RingInfo *r, uint32_t count)
{
    core->mac[r->dh] += count;

    if (core->mac[r->dh] * E1000_RING_DESC_LEN >= core->mac[r->dlen]) {
        core->mac[r->dh] = 0;
    }
}

static inline uint32_t
_e1000e_ring_free_descr_num(E1000ECore *core, const E1000E_RingInfo *r)
{
    trace_e1000e_ring_free_space(r->idx, core->mac[r->dlen],
                                 core->mac[r->dh],  core->mac[r->dt]);

    if (core->mac[r->dh] <= core->mac[r->dt]) {
        return core->mac[r->dt] - core->mac[r->dh];
    }

    if (core->mac[r->dh] > core->mac[r->dt]) {
        return core->mac[r->dlen] / E1000_RING_DESC_LEN +
               core->mac[r->dt] - core->mac[r->dh];
    }

    g_assert_not_reached();
    return 0;
}

static inline bool
_e1000e_ring_enabled(E1000ECore *core, const E1000E_RingInfo *r)
{
    return core->mac[r->dlen] > 0;
}

static inline uint32_t
_e1000e_ring_len(E1000ECore *core, const E1000E_RingInfo *r)
{
    return core->mac[r->dlen];
}

typedef struct E1000E_TxRing_st {
    const E1000E_RingInfo *i;
    struct e1000_tx *tx;
} E1000E_TxRing;

static inline int
_e1000e_mq_queue_idx(int base_reg_idx, int reg_idx)
{
    return (reg_idx - base_reg_idx) / (0x100 >> 2);
}

static inline void
_e1000e_tx_ring_init(E1000ECore *core, E1000E_TxRing *txr, int idx)
{
    static const E1000E_RingInfo i[E1000E_NUM_QUEUES] = {
        { TDBAH,  TDBAL,  TDLEN,  TDH,  TDT, 0 },
        { TDBAH1, TDBAL1, TDLEN1, TDH1, TDT1, 1 }
    };

    assert(idx < ARRAY_SIZE(i));

    txr->i     = &i[idx];
    txr->tx    = &core->tx[idx];
}

typedef struct E1000E_RxRing_st {
    const E1000E_RingInfo *i;
} E1000E_RxRing;

static inline void
_e1000e_rx_ring_init(E1000ECore *core, E1000E_RxRing *rxr, int idx)
{
    static const E1000E_RingInfo i[E1000E_NUM_QUEUES] = {
        { RDBAH0, RDBAL0, RDLEN0, RDH0, RDT0, 0 },
        { RDBAH1, RDBAL1, RDLEN1, RDH1, RDT1, 1 }
    };

    assert(idx < ARRAY_SIZE(i));

    rxr->i      = &i[idx];
}

static void
start_xmit(E1000ECore *core, const E1000E_TxRing *txr)
{
    dma_addr_t base;
    struct e1000_tx_desc desc;
    bool ide = false;
    const E1000E_RingInfo *txi = txr->i;
    uint32_t cause = E1000_ICS_TXQE;

    if (!(core->mac[TCTL] & E1000_TCTL_EN)) {
        trace_e1000e_tx_disabled();
        return;
    }

	if (_PRE_XMIT_HOOK != NULL) {
		for_each_descriptor_address(core, DT_TRANSMIT, _PRE_XMIT_HOOK,
			_PRE_XMIT_HOOK_DONE);
	}

    while (!_e1000e_ring_empty(core, txi)) {
        base = _e1000e_ring_head_descr(core, txi);

        WARN_ON_CHEW(pci_dma_read(core->owner, base, &desc, sizeof(desc)));

        trace_e1000e_tx_descr((void *)(intptr_t)desc.buffer_addr,
                              desc.lower.data, desc.upper.data);

        process_tx_desc(core, txr->tx, &desc, txi->idx);
        cause |= txdesc_writeback(core, base, &desc, &ide, txi->idx);

        _e1000e_ring_advance(core, txi, 1);
    }

    if (!ide || !_e1000e_intrmgr_delay_tx_causes(core, &cause)) {
        set_interrupt_cause(core, cause);
    }
}

static bool
_e1000e_has_rxbufs(E1000ECore *core,
                   const E1000E_RingInfo *r,
                   size_t total_size)
{
    uint32_t bufs = _e1000e_ring_free_descr_num(core, r);

    trace_e1000e_rx_has_buffers(r->idx, bufs, total_size,
                                core->rx_desc_buf_size);

    return total_size <= bufs / (core->rx_desc_len / E1000_MIN_RX_DESC_LEN) *
                         core->rx_desc_buf_size;
}

static inline void
start_recv(E1000ECore *core)
{
    int i;

    trace_e1000e_rx_start_recv();

	/*print_rx_buffer_address_information(core);*/

    for (i = 0; i <= core->max_queue_num; i++) {
        qemu_flush_queued_packets(qemu_get_subqueue(core->owner_nic, i));
    }
}

int
e1000e_can_receive(E1000ECore *core)
{
    int i;

    bool link_up = core->mac[STATUS] & E1000_STATUS_LU;
    bool rx_enabled = core->mac[RCTL] & E1000_RCTL_EN;
    bool pci_master = core->owner->config[PCI_COMMAND] & PCI_COMMAND_MASTER;

    if (!link_up || !rx_enabled || !pci_master) {
        trace_e1000e_rx_can_recv_disabled(link_up, rx_enabled, pci_master);
        return false;
    }

    for (i = 0; i < E1000E_NUM_QUEUES; i++) {
        E1000E_RxRing rxr;

        _e1000e_rx_ring_init(core, &rxr, i);
        if (_e1000e_ring_enabled(core, rxr.i) &&
            _e1000e_has_rxbufs(core, rxr.i, 1)) {
            trace_e1000e_rx_can_recv();
            return true;
        }
    }

    trace_e1000e_rx_can_recv_rings_full();
    return false;
}

ssize_t
e1000e_receive(E1000ECore *core, const uint8_t *buf, size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return e1000e_receive_iov(core, &iov, 1);
}

static inline int
vlan_rx_filter_enabled(E1000ECore *core)
{
    return ((core->mac[RCTL] & E1000_RCTL_VFE) != 0);
}

static inline bool
_e1000e_rx_l3_cso_enabled(E1000ECore *core)
{
    return !!(core->mac[RXCSUM] & E1000_RXCSUM_IPOFLD);
}

static inline bool
_e1000e_rx_l4_cso_enabled(E1000ECore *core)
{
    return !!(core->mac[RXCSUM] & E1000_RXCSUM_TUOFLD);
}

static inline bool
is_vlan_packet(E1000ECore *core, const uint8_t *buf)
{
    uint16_t eth_proto = be16_to_cpup((uint16_t *)(buf + 12));
    bool res = (eth_proto == core->vet);

    trace_e1000e_vlan_is_vlan_pkt(res, eth_proto, core->vet);

    return res;
}

static bool
receive_filter(E1000ECore *core, const uint8_t *buf, int size)
{
    static const int mta_shift[] = {4, 3, 2, 0};
    uint32_t f, rctl = core->mac[RCTL], ra[2], *rp;

    if (is_vlan_packet(core, buf) && vlan_rx_filter_enabled(core)) {
        uint16_t vid = be16_to_cpup((uint16_t *)(buf + 14));
        uint32_t vfta = le32_to_cpup((uint32_t *)(core->mac + VFTA) +
                                     ((vid >> 5) & 0x7f));
        if ((vfta & (1 << (vid & 0x1f))) == 0) {
            trace_e1000e_rx_flt_vlan_mismatch(vid);
            return 0;
        } else {
            trace_e1000e_rx_flt_vlan_match(vid);
        }
    }

    switch (net_rx_pkt_get_packet_type(core->rx_pkt)) {
    case ETH_PKT_UCAST:
        if (rctl & E1000_RCTL_UPE) {
            return true; /* promiscuous ucast */
        }
        break;

    case ETH_PKT_BCAST:
        if (rctl & E1000_RCTL_BAM) {
            return true; /* broadcast enabled */
        }
        break;

    case ETH_PKT_MCAST:
        if (rctl & E1000_RCTL_MPE) {
            return true; /* promiscuous mcast */
        }
        break;

    default:
        g_assert_not_reached();
    }

    for (rp = core->mac + RA; rp < core->mac + RA + 32; rp += 2) {
        if (!(rp[1] & E1000_RAH_AV)) {
            continue;
        }
        ra[0] = cpu_to_le32(rp[0]);
        ra[1] = cpu_to_le32(rp[1]);
        if (!memcmp(buf, (uint8_t *)ra, 6)) {
            trace_e1000e_rx_flt_ucast_match((int)(rp - core->mac - RA) / 2,
                                           MAC_ARG(buf));
            return 1;
        }
    }
    trace_e1000e_rx_flt_ucast_mismatch(MAC_ARG(buf));

    f = mta_shift[(rctl >> E1000_RCTL_MO_SHIFT) & 3];
    f = (((buf[5] << 8) | buf[4]) >> f) & 0xfff;
    if (core->mac[MTA + (f >> 5)] & (1 << (f & 0x1f))) {
        inc_reg_if_not_full(core, MPRC);
        return 1;
    }

    trace_e1000e_rx_flt_inexact_mismatch(MAC_ARG(buf),
                                        (rctl >> E1000_RCTL_MO_SHIFT) & 3,
                                        f >> 5,
                                        core->mac[MTA + (f >> 5)]);

    return 0;
}

/* FCS aka Ethernet CRC-32. We don't get it from backends and can't
 * fill it in, just pad descriptor length by 4 bytes unless guest
 * told us to strip it off the packet. */
static inline int
fcs_len(E1000ECore *core)
{
    return (core->mac[RCTL] & E1000_RCTL_SECRC) ? 0 : 4;
}

static void
read_legacy_rx_descriptor(E1000ECore *core, uint8_t *desc, hwaddr *buff_addr)
{
    struct e1000_rx_desc *d = (struct e1000_rx_desc *) desc;
    *buff_addr = le64_to_cpu(d->buffer_addr);
}

static void
read_extended_rx_descriptor(E1000ECore *core, uint8_t *desc, hwaddr *buff_addr)
{
    union e1000_rx_desc_extended *d = (union e1000_rx_desc_extended *) desc;
    *buff_addr = le64_to_cpu(d->read.buffer_addr);
}

static void
read_ps_rx_descriptor(E1000ECore *core, uint8_t *desc,
                      hwaddr (*buff_addr)[MAX_PS_BUFFERS])
{
    int i;
    union e1000_rx_desc_packet_split *d =
        (union e1000_rx_desc_packet_split *) desc;

    for (i = 0; i < MAX_PS_BUFFERS; i++) {
        (*buff_addr)[i] = le64_to_cpu(d->read.buffer_addr[i]);
    }

    trace_e1000e_rx_desc_ps_read((*buff_addr)[0], (*buff_addr)[1],
                                 (*buff_addr)[2], (*buff_addr)[3]);
}

static void
read_rx_descriptor(E1000ECore *core, uint8_t *desc,
                   hwaddr (*buff_addr)[MAX_PS_BUFFERS])
{
    if (_e1000e_rx_use_legacy_descriptor(core)) {
        read_legacy_rx_descriptor(core, desc, &(*buff_addr)[0]);
        (*buff_addr)[1] = (*buff_addr)[2] = (*buff_addr)[3] = 0;
    } else {
        if (core->mac[RCTL] & E1000_RCTL_DTYP_PS) {
            read_ps_rx_descriptor(core, desc, buff_addr);
        } else {
            read_extended_rx_descriptor(core, desc, &(*buff_addr)[0]);
            (*buff_addr)[1] = (*buff_addr)[2] = (*buff_addr)[3] = 0;
        }
    }
}

static void
_e1000e_verify_csum_in_sw(E1000ECore *core,
                          struct NetRxPkt *pkt,
                          uint32_t *status_flags,
                          bool istcp, bool isudp)
{
    bool csum_valid;
    uint32_t csum_error;

    if (_e1000e_rx_l3_cso_enabled(core)) {
        if (!net_rx_pkt_validate_l3_csum(pkt, &csum_valid)) {
            trace_e1000e_rx_metadata_l3_csum_validation_failed();
        } else {
            csum_error = csum_valid ? 0 : E1000_RXDEXT_STATERR_IPE;
            *status_flags |= E1000_RXD_STAT_IPCS | csum_error;
        }
    } else {
        trace_e1000e_rx_metadata_l3_cso_disabled();
    }

    if (!_e1000e_rx_l4_cso_enabled(core)) {
        trace_e1000e_rx_metadata_l4_cso_disabled();
        return;
    }

    if (!net_rx_pkt_validate_l4_csum(pkt, &csum_valid)) {
        trace_e1000e_rx_metadata_l4_csum_validation_failed();
        return;
    }

    csum_error = csum_valid ? 0 : E1000_RXDEXT_STATERR_TCPE;

    if (istcp) {
        *status_flags |= E1000_RXD_STAT_TCPCS |
                         csum_error;
    } else if (isudp) {
        *status_flags |= E1000_RXD_STAT_TCPCS |
                         E1000_RXD_STAT_UDPCS |
                         csum_error;
    }
}

static inline bool
_e1000e_is_tcp_ack(E1000ECore *core, struct NetRxPkt *rx_pkt)
{
    if (!net_rx_pkt_is_tcp_ack(rx_pkt)) {
        return false;
    }

    if (core->mac[RFCTL] & E1000_RFCTL_ACK_DATA_DIS) {
        return !net_rx_pkt_has_tcp_data(rx_pkt);
    }

    return true;
}

static void
_e1000e_build_rx_metadata(E1000ECore *core,
                          struct NetRxPkt *pkt,
                          bool is_eop,
                          const E1000E_RSSInfo *rss_info,
                          uint32_t *rss, uint32_t *mrq,
                          uint32_t *status_flags,
                          uint16_t *ip_id,
                          uint16_t *vlan_tag)
{
    struct virtio_net_hdr *vhdr;
    bool isip4, isip6, istcp, isudp;
    uint32_t pkt_type;

    *status_flags = E1000_RXD_STAT_DD;

    /* No additional metadata needed for non-EOP descriptors */
    if (!is_eop) {
        goto func_exit;
    }

    *status_flags |= E1000_RXD_STAT_EOP;

    net_rx_pkt_get_protocols(pkt, &isip4, &isip6, &isudp, &istcp);
    trace_e1000e_rx_metadata_protocols(isip4, isip6, isudp, istcp);

    /* VLAN state */
    if (net_rx_pkt_is_vlan_stripped(pkt)) {
        *status_flags |= E1000_RXD_STAT_VP;
        *vlan_tag = cpu_to_le16(net_rx_pkt_get_vlan_tag(pkt));
        trace_e1000e_rx_metadata_vlan(*vlan_tag);
    }

    /* Packet parsing results */
    if ((core->mac[RXCSUM] & E1000_RXCSUM_PCSD) != 0) {
        if (rss_info->enabled) {
            *rss = cpu_to_le32(rss_info->hash);
            *mrq = cpu_to_le32(rss_info->type | (rss_info->queue << 8));
            trace_e1000e_rx_metadata_rss(*rss, *mrq);
        }
    } else if (isip4) {
            *status_flags |= E1000_RXD_STAT_IPIDV;
            *ip_id = cpu_to_le16(net_rx_pkt_get_ip_id(pkt));
            trace_e1000e_rx_metadata_ip_id(*ip_id);
    }

    if (istcp && _e1000e_is_tcp_ack(core, pkt)) {
        *status_flags |= E1000_RXD_STAT_ACK;
        trace_e1000e_rx_metadata_ack();
    }

    if (isip6 && (core->mac[RFCTL] & E1000_RFCTL_IPV6_DIS)) {
        trace_e1000e_rx_metadata_ipv6_filtering_disabled();
        pkt_type = E1000_RXD_PKT_MAC;
    } else if (istcp || isudp) {
        pkt_type = isip4 ? E1000_RXD_PKT_IP4_XDP : E1000_RXD_PKT_IP6_XDP;
    } else if (isip4 || isip6) {
        pkt_type = isip4 ? E1000_RXD_PKT_IP4 : E1000_RXD_PKT_IP6;
    } else {
        pkt_type = E1000_RXD_PKT_MAC;
    }

    *status_flags |= E1000_RXD_PKT_TYPE(pkt_type);
    trace_e1000e_rx_metadata_pkt_type(pkt_type);

    /* RX CSO information */
    if (isip6 && (core->mac[RFCTL] & E1000_RFCTL_IPV6_XSUM_DIS)) {
        trace_e1000e_rx_metadata_ipv6_sum_disabled();
        goto func_exit;
    }

    if (!net_rx_pkt_has_virt_hdr(pkt)) {
        trace_e1000e_rx_metadata_no_virthdr();
        _e1000e_verify_csum_in_sw(core, pkt, status_flags, istcp, isudp);
        goto func_exit;
    }

    vhdr = net_rx_pkt_get_vhdr(pkt);

    if (!(vhdr->flags & VIRTIO_NET_HDR_F_DATA_VALID) &&
        !(vhdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)) {
        trace_e1000e_rx_metadata_virthdr_no_csum_info();
        _e1000e_verify_csum_in_sw(core, pkt, status_flags, istcp, isudp);
        goto func_exit;
    }

    if (_e1000e_rx_l3_cso_enabled(core)) {
        *status_flags |= isip4 ? E1000_RXD_STAT_IPCS : 0;
    } else {
        trace_e1000e_rx_metadata_l3_cso_disabled();
    }

    if (_e1000e_rx_l4_cso_enabled(core)) {
        if (istcp) {
            *status_flags |= E1000_RXD_STAT_TCPCS;
        } else if (isudp) {
            *status_flags |= E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS;
        }
    } else {
        trace_e1000e_rx_metadata_l4_cso_disabled();
    }

    trace_e1000e_rx_metadata_status_flags(*status_flags);

func_exit:
    *status_flags = cpu_to_le32(*status_flags);
}

static void
write_legacy_rx_descriptor(E1000ECore *core, uint8_t *desc,
                           struct NetRxPkt *pkt,
                           const E1000E_RSSInfo *rss_info,
                           uint16_t length)
{
    uint32_t status_flags, rss, mrq;
    uint16_t ip_id;

    struct e1000_rx_desc *d = (struct e1000_rx_desc *) desc;

    memset(d, 0, sizeof(*d));

    assert(!rss_info->enabled);

    d->length = cpu_to_le16(length);

    _e1000e_build_rx_metadata(core, pkt, pkt != NULL,
                              rss_info,
                              &rss, &mrq,
                              &status_flags, &ip_id,
                              &d->special);
    d->errors = (uint8_t) (le32_to_cpu(status_flags) >> 24);
    d->status = (uint8_t) le32_to_cpu(status_flags);
}

static void
write_extended_rx_descriptor(E1000ECore *core, uint8_t *desc,
                             struct NetRxPkt *pkt,
                             const E1000E_RSSInfo *rss_info,
                             uint16_t length)
{
    union e1000_rx_desc_extended *d = (union e1000_rx_desc_extended *) desc;

    memset(d, 0, sizeof(*d));

    d->wb.upper.length = cpu_to_le16(length);

    _e1000e_build_rx_metadata(core, pkt, pkt != NULL,
                              rss_info,
                              &d->wb.lower.hi_dword.rss,
                              &d->wb.lower.mrq,
                              &d->wb.upper.status_error,
                              &d->wb.lower.hi_dword.csum_ip.ip_id,
                              &d->wb.upper.vlan);
}

static void
write_ps_rx_descriptor(E1000ECore *core, uint8_t *desc,
                       struct NetRxPkt *pkt,
                       const E1000E_RSSInfo *rss_info,
                       size_t ps_hdr_len,
                       uint16_t(*written)[MAX_PS_BUFFERS])
{
    int i;
    union e1000_rx_desc_packet_split *d =
        (union e1000_rx_desc_packet_split *) desc;

    memset(d, 0, sizeof(*d));

    d->wb.middle.length0 = cpu_to_le16((*written)[0]);

    for (i = 0; i < PS_PAGE_BUFFERS; i++) {
        d->wb.upper.length[i] = cpu_to_le16((*written)[i + 1]);
    }

    _e1000e_build_rx_metadata(core, pkt, pkt != NULL,
                              rss_info,
                              &d->wb.lower.hi_dword.rss,
                              &d->wb.lower.mrq,
                              &d->wb.middle.status_error,
                              &d->wb.lower.hi_dword.csum_ip.ip_id,
                              &d->wb.middle.vlan);

    d->wb.upper.header_status =
        cpu_to_le16(ps_hdr_len | (ps_hdr_len ? E1000_RXDPS_HDRSTAT_HDRSP : 0));

    trace_e1000e_rx_desc_ps_write((*written)[0], (*written)[1],
                                  (*written)[2], (*written)[3]);
}

static void
write_rx_descriptor(E1000ECore *core, uint8_t *desc,
                    struct NetRxPkt *pkt, const E1000E_RSSInfo *rss_info,
                    size_t ps_hdr_len, uint16_t (*written)[MAX_PS_BUFFERS])
{
    if (_e1000e_rx_use_legacy_descriptor(core)) {
        assert(ps_hdr_len == 0);
        write_legacy_rx_descriptor(core, desc, pkt, rss_info, (*written)[0]);
    } else {
        if (core->mac[RCTL] & E1000_RCTL_DTYP_PS) {
            write_ps_rx_descriptor(core, desc, pkt, rss_info,
                                   ps_hdr_len, written);
        } else {
            assert(ps_hdr_len == 0);
            write_extended_rx_descriptor(core, desc, pkt, rss_info,
                                         (*written)[0]);
        }
    }
}

typedef struct ba_state_st {
    uint16_t written[MAX_PS_BUFFERS];
    uint8_t cur_idx;
} ba_state;

static void
write_hdr_to_rx_buffers(E1000ECore *core,
                        hwaddr (*ba)[MAX_PS_BUFFERS],
                        ba_state *bastate,
                        const char *data,
                        dma_addr_t data_len)
{
    assert(data_len <= core->rxbuf_sizes[0] - bastate->written[0]);

    pci_dma_write(core->owner, (*ba)[0] + bastate->written[0], data, data_len);
    bastate->written[0] += data_len;

    bastate->cur_idx = 1;
}

static void
write_to_rx_buffers(E1000ECore *core,
                    hwaddr (*ba)[MAX_PS_BUFFERS],
                    ba_state *bastate,
                    const char *data,
                    dma_addr_t data_len)
{
    while (data_len > 0) {
        uint32_t cur_buf_len = core->rxbuf_sizes[bastate->cur_idx];
        uint32_t cur_buf_bytes_left = cur_buf_len -
                                      bastate->written[bastate->cur_idx];
        uint32_t bytes_to_write = MIN(data_len, cur_buf_bytes_left);

        trace_e1000e_rx_desc_buff_write(bastate->cur_idx,
                                        (*ba)[bastate->cur_idx],
                                        bastate->written[bastate->cur_idx],
                                        data,
                                        bytes_to_write);

        pci_dma_write(core->owner,
            (*ba)[bastate->cur_idx] + bastate->written[bastate->cur_idx],
            data, bytes_to_write);

        bastate->written[bastate->cur_idx] += bytes_to_write;
        data += bytes_to_write;
        data_len -= bytes_to_write;

        if (bastate->written[bastate->cur_idx] == cur_buf_len) {
            bastate->cur_idx++;
        }

        assert(bastate->cur_idx < MAX_PS_BUFFERS);
    }
}

static void
_e1000e_update_rx_stats(E1000ECore *core,
                        size_t data_size,
                        size_t data_fcs_size)
{
    static const int PRCregs[6] = { PRC64, PRC127, PRC255, PRC511,
                                    PRC1023, PRC1522 };

    increase_size_stats(core, PRCregs, data_fcs_size);
    inc_reg_if_not_full(core, TPR);
    core->mac[GPRC] = core->mac[TPR];
    /* TOR - Total Octets Received:
    * This register includes bytes received in a packet from the <Destination
    * Address> field through the <CRC> field, inclusively.
    * Always include FCS length (4) in size.
    */
    grow_8reg_if_not_full(core, TORL, data_size + 4);
    core->mac[GORCL] = core->mac[TORL];
    core->mac[GORCH] = core->mac[TORH];

    switch (net_rx_pkt_get_packet_type(core->rx_pkt)) {
    case ETH_PKT_BCAST:
        inc_reg_if_not_full(core, BPRC);
        break;

    case ETH_PKT_MCAST:
        inc_reg_if_not_full(core, MPRC);
        break;

    default:
        break;
    }
}

static inline bool
_e1000e_rx_descr_threshold_hit(E1000ECore *core, const E1000E_RingInfo *rxi)
{
    return _e1000e_ring_free_descr_num(core, rxi) ==
           _e1000e_ring_len(core, rxi) >> core->rxbuf_min_shift;
}

static bool
_e1000e_do_ps(E1000ECore *core, struct NetRxPkt *pkt, size_t *hdr_len)
{
    bool isip4, isip6, isudp, istcp;
    bool fragment;

    if (!_e1000e_rx_use_ps_descriptor(core)) {
        return false;
    }

    net_rx_pkt_get_protocols(pkt, &isip4, &isip6, &isudp, &istcp);

    if (isip4) {
        fragment = net_rx_pkt_get_ip4_info(pkt)->fragment;
    } else if (isip6) {
        fragment = net_rx_pkt_get_ip6_info(pkt)->fragment;
    } else {
        return false;
    }

    if (fragment && (core->mac[RFCTL] & E1000_RFCTL_IPFRSP_DIS)) {
        return false;
    }

    if (!fragment && (isudp || istcp)) {
        *hdr_len = net_rx_pkt_get_l5_hdr_offset(pkt);
    } else {
        *hdr_len = net_rx_pkt_get_l4_hdr_offset(pkt);
    }

    if ((*hdr_len > core->rxbuf_sizes[0]) ||
        (*hdr_len > net_rx_pkt_get_total_len(pkt))) {
        return false;
    }

    return true;
}

static bool
_e1000e_write_paket_to_guest(E1000ECore *core, struct NetRxPkt *pkt,
                             const E1000E_RxRing *rxr,
                             const E1000E_RSSInfo *rss_info)
{
    PCIDevice *d = core->owner;
    dma_addr_t base;
    uint8_t desc[E1000_MAX_RX_DESC_LEN];
    size_t desc_size;
    size_t desc_offset = 0;
    size_t iov_ofs = 0;

    struct iovec *iov = net_rx_pkt_get_iovec(pkt);
    size_t size = net_rx_pkt_get_total_len(pkt);
    size_t total_size = size + fcs_len(core);
    const E1000E_RingInfo *rxi;
    size_t ps_hdr_len = 0;
    bool do_ps = _e1000e_do_ps(core, pkt, &ps_hdr_len);

    rxi = rxr->i;

    do {
        hwaddr ba[MAX_PS_BUFFERS];
        ba_state bastate = { { 0 } };
        bool is_last = false;
        bool is_first = true;

        desc_size = total_size - desc_offset;

        if (desc_size > core->rx_desc_buf_size) {
            desc_size = core->rx_desc_buf_size;
        }

        base = _e1000e_ring_head_descr(core, rxi);

        WARN_ON_CHEW(pci_dma_read(d, base, &desc, core->rx_desc_len));

        trace_e1000e_rx_descr(rxi->idx, base, core->rx_desc_len);

        read_rx_descriptor(core, desc, &ba);

        if (ba[0]) {
            if (desc_offset < size) {
                static const uint32_t fcs_pad;
                size_t iov_copy;
                size_t copy_size = size - desc_offset;
                if (copy_size > core->rx_desc_buf_size) {
                    copy_size = core->rx_desc_buf_size;
                }

                /* For PS mode copy the packet header first */
                if (do_ps) {
                    if (is_first) {
                        size_t ps_hdr_copied = 0;
                        do {
                            iov_copy = MIN(ps_hdr_len - ps_hdr_copied,
                                           iov->iov_len - iov_ofs);

                            write_hdr_to_rx_buffers(core, &ba, &bastate,
                                                    iov->iov_base, iov_copy);

                            copy_size -= iov_copy;
                            ps_hdr_copied += iov_copy;

                            iov_ofs += iov_copy;
                            if (iov_ofs == iov->iov_len) {
                                iov++;
                                iov_ofs = 0;
                            }
                        } while (ps_hdr_copied < ps_hdr_len);

                        is_first = false;
                    } else {
                        /* Leave buffer 0 of each descriptor except first */
                        /* empty as per spec 7.1.5.1                      */
                        write_hdr_to_rx_buffers(core, &ba, &bastate, NULL, 0);
                    }
                }

                /* Copy packet payload */
                while (copy_size) {
                    iov_copy = MIN(copy_size, iov->iov_len - iov_ofs);

                    write_to_rx_buffers(core, &ba, &bastate,
                                        iov->iov_base + iov_ofs, iov_copy);

                    copy_size -= iov_copy;
                    iov_ofs += iov_copy;
                    if (iov_ofs == iov->iov_len) {
                        iov++;
                        iov_ofs = 0;
                    }
                }

                if (desc_offset + desc_size >= total_size) {
                    /* Simulate FCS checksum presence in the last descriptor */
                    write_to_rx_buffers(core, &ba, &bastate,
                                        (const char *) &fcs_pad, fcs_len(core));
                }
            }
            desc_offset += desc_size;
            if (desc_offset >= total_size) {
                is_last = true;
            }
        } else { /* as per intel docs; skip descriptors with null buf addr */
            trace_e1000e_rx_null_descriptor();
        }

        write_rx_descriptor(core, desc, is_last ? core->rx_pkt : NULL,
                            rss_info, do_ps ? ps_hdr_len : 0, &bastate.written);
        pci_dma_write(d, base, &desc, core->rx_desc_len);

        _e1000e_ring_advance(core, rxi,
                             core->rx_desc_len / E1000_MIN_RX_DESC_LEN);

    } while (desc_offset < total_size);

    _e1000e_update_rx_stats(core, size, total_size);

    return true;
}

ssize_t
e1000e_receive_iov(E1000ECore *core, const struct iovec *iov, int iovcnt)
{
    /* this is the size past which hardware will
       drop packets when setting LPE=0 */
    static const int MAXIMUM_ETHERNET_VLAN_SIZE = 1522;
    /* this is the size past which hardware will
       drop packets when setting LPE=1 */
    static const int MAXIMUM_ETHERNET_LPE_SIZE = 16384;

    static const int MAXIMUM_ETHERNET_HDR_LEN = (14 + 4);

    /* Min. octets in an ethernet frame sans FCS */
    static const int MIN_BUF_SIZE = 60;

    uint32_t n = 0;
    uint8_t min_buf[MIN_BUF_SIZE];
    struct iovec min_iov;
    uint8_t *filter_buf;
    size_t size, orig_size;
    size_t iov_ofs = 0;
    E1000E_RxRing rxr;
    E1000E_RSSInfo rss_info;
    size_t total_size;
    ssize_t retval;
    bool rdmts_hit;

    trace_e1000e_rx_receive_iov(iovcnt);

    if (!(core->mac[STATUS] & E1000_STATUS_LU)) {
        trace_e1000e_rx_link_down(core->mac[STATUS]);
        return -1;
    }

    if (!(core->mac[RCTL] & E1000_RCTL_EN)) {
        trace_e1000e_rx_disabled(core->mac[RCTL]);
        return 0;
    }

    /* Pull virtio header in */
    if (core->has_vnet) {
        net_rx_pkt_set_vhdr_iovec(core->rx_pkt, iov, iovcnt);
        iov_ofs = sizeof(struct virtio_net_hdr);
    }

    filter_buf = iov->iov_base + iov_ofs;
    orig_size = iov_size(iov, iovcnt);
    size = orig_size - iov_ofs;

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        inc_reg_if_not_full(core, RUC);
        min_iov.iov_base = filter_buf = min_buf;
        min_iov.iov_len = size = sizeof(min_buf);
        iovcnt = 1;
        iov = &min_iov;
        iov_ofs = 0;
    } else if (iov->iov_len < MAXIMUM_ETHERNET_HDR_LEN) {
        /* This is very unlikely, but may happen. */
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, MAXIMUM_ETHERNET_HDR_LEN);
        filter_buf = min_buf;
    }

    /* Discard oversized packets if !LPE and !SBP. */
    if ((size > MAXIMUM_ETHERNET_LPE_SIZE ||
        (size > MAXIMUM_ETHERNET_VLAN_SIZE
        && !(core->mac[RCTL] & E1000_RCTL_LPE)))
        && !(core->mac[RCTL] & E1000_RCTL_SBP)) {
        inc_reg_if_not_full(core, ROC);
        trace_e1000e_rx_oversized(size);
        return orig_size;
    }

    net_rx_pkt_set_packet_type(core->rx_pkt,
        get_eth_packet_type(PKT_GET_ETH_HDR(filter_buf)));

    if (!receive_filter(core, filter_buf, size)) {
        trace_e1000e_rx_flt_dropped();
        return orig_size;
    }

    net_rx_pkt_attach_iovec_ex(core->rx_pkt, iov, iovcnt, iov_ofs,
                               vlan_enabled(core), core->vet);

    _e1000e_rss_parse_packet(core, core->rx_pkt, &rss_info);
    _e1000e_rx_ring_init(core, &rxr, rss_info.queue);

    trace_e1000e_rx_rss_dispatched_to_queue(rxr.i->idx);

    total_size = net_rx_pkt_get_total_len(core->rx_pkt) + fcs_len(core);

    if (_e1000e_has_rxbufs(core, rxr.i, total_size) &&
        _e1000e_write_paket_to_guest(core, core->rx_pkt, &rxr, &rss_info)) {
        retval = orig_size;

        /* Perform small receive detection (RSRPD) */
        if (total_size < core->mac[RSRPD]) {
            n |= E1000_ICS_SRPD;
        }

        /* Perform ACK receive detection */
        if (_e1000e_is_tcp_ack(core, core->rx_pkt)) {
            n |= E1000_ICS_ACK;
        }

        /* Check if receive descriptor minimum threshold hit */
        rdmts_hit = _e1000e_rx_descr_threshold_hit(core, rxr.i);
        n |= _e1000e_rx_wb_interrupt_cause(core, rxr.i->idx, rdmts_hit);

        trace_e1000e_rx_written_to_guest(n);
    } else {
        n |= E1000_ICS_RXO;
        retval = 0;

        trace_e1000e_rx_not_written_to_guest(n);
    }

    if (!_e1000e_intrmgr_delay_rx_causes(core, &n)) {
        trace_e1000e_rx_interrupt_set(n);
        set_interrupt_cause(core, n);
    } else {
        trace_e1000e_rx_interrupt_delayed(n);
    }

    return retval;
}

static bool
have_autoneg(E1000ECore *core)
{
    return core->phy[0][PHY_CTRL] & MII_CR_AUTO_NEG_EN;
}

static void _e1000e_update_flowctl_status(E1000ECore *core)
{
    if (have_autoneg(core) &&
        core->phy[0][PHY_STATUS] & MII_SR_AUTONEG_COMPLETE) {
        trace_e1000e_link_autoneg_flowctl(true);
        core->mac[CTRL] |= E1000_CTRL_TFCE | E1000_CTRL_RFCE;
    } else {
        trace_e1000e_link_autoneg_flowctl(false);
    }
}

static void
e1000_link_down(E1000ECore *core)
{
    core->mac[STATUS] &= ~E1000_STATUS_LU;
    core->phy[0][PHY_STATUS] &= ~MII_SR_LINK_STATUS;
    core->phy[0][PHY_STATUS] &= ~MII_SR_AUTONEG_COMPLETE;
    core->phy[0][PHY_LP_ABILITY] &= ~MII_LPAR_LPACK;

    _e1000e_update_flowctl_status(core);
}

static void
e1000_link_up(E1000ECore *core)
{
    core->mac[STATUS] |= E1000_STATUS_LU;
    core->phy[0][PHY_STATUS] |= MII_SR_LINK_STATUS;
}

static inline void
_e1000e_restart_autoneg(E1000ECore *core)
{
    if (have_autoneg(core)) {
        e1000_link_down(core);
        trace_e1000e_link_negotiation_start();
		/*PDBG("Restarting autoneg, time to fire in .5s. Now: %d. Then: %d.",*/
			/*qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL),*/
			/*qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);*/
        timer_mod(core->autoneg_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    } else {
		/*PDBG("Restarting autoneg, but no autoneg support.");*/
	}
}

static void
set_phy_ctrl(E1000ECore *core, int index, uint16_t val)
{
    /* bits 0-5 reserved; MII_CR_[RESTART_AUTO_NEG,RESET] are self clearing */
    core->phy[0][PHY_CTRL] = val & ~(0x3f |
                             MII_CR_RESET |
                             MII_CR_RESTART_AUTO_NEG);

    if (val & MII_CR_RESTART_AUTO_NEG) {
        _e1000e_restart_autoneg(core);
    }
}

static void
set_phy_oem_bits(E1000ECore *core, int index, uint16_t val)
{
    core->phy[0][PHY_OEM_BITS] = val & ~BIT(10);

    if (val & BIT(10)) {
        _e1000e_restart_autoneg(core);
    }
}

static void
set_phy_page(E1000ECore *core, int index, uint16_t val)
{
    core->phy[0][PHY_PAGE] = val & PHY_PAGE_RW_MASK;
}

void
e1000e_core_set_link_status(E1000ECore *core)
{
    NetClientState *nc = qemu_get_queue(core->owner_nic);
    uint32_t old_status = core->mac[STATUS];

    if (nc->link_down) {
		/*PDBG("Setting link status down.");*/
        e1000_link_down(core);
    } else {
        if (have_autoneg(core) &&
            !(core->phy[0][PHY_STATUS] & MII_SR_AUTONEG_COMPLETE)) {
			/*PDBG("Queing auto-neg.");*/
            /* emulate auto-negotiation if supported */
            timer_mod(core->autoneg_timer,
                      qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
        } else {
			/*PDBG("Not bothering with auto-neg.");*/
            e1000_link_up(core);
        }
    }

    if (core->mac[STATUS] != old_status) {
        set_interrupt_cause(core, E1000_ICR_LSC);
    }
}

static void
_e1000e_core_reset_mac(E1000ECore *core)
{
    int i;

    core->mac[RA] = 0;
    core->mac[RA + 1] = E1000_RAH_AV;
    for (i = 0; i < 4; i++) {
        core->mac[RA] |= core->permanent_mac[i] << (8 * i);
        core->mac[RA + 1] |=
            (i < 2) ? core->permanent_mac[i + 4] << (8 * i) : 0;
    }

    qemu_format_nic_info_str(qemu_get_queue(core->owner_nic),
                             core->permanent_mac);

    trace_e1000e_mac_indicate(MAC_ARG(core->permanent_mac));
}

static void
set_ctrl(E1000ECore *core, int index, uint32_t val)
{
	/*PDBG("Setting CTRL to 0x%x. GIO Master Disable to %d",*/
		/*val, (val >> 2) & 1);*/
    trace_e1000e_core_ctrl_write(index, val);

    /* RST is self clearing */
    core->mac[CTRL] = val & ~E1000_CTRL_RST;
    core->mac[CTRL_DUP] = core->mac[CTRL];

    trace_e1000e_link_set_params(
        !!(val & E1000_CTRL_ASDE),
        (val & E1000_CTRL_SPD_SEL) >> E1000_CTRL_SPD_SHIFT,
        !!(val & E1000_CTRL_FRCSPD),
        !!(val & E1000_CTRL_FRCDPX),
        !!(val & E1000_CTRL_RFCE),
        !!(val & E1000_CTRL_TFCE));

    if (val & E1000_CTRL_RST) {
        trace_e1000e_core_ctrl_sw_reset();
        _e1000e_core_reset_mac(core);
    }

    if (val & E1000_CTRL_PHY_RST) {
        trace_e1000e_core_ctrl_phy_reset();
        core->mac[STATUS] |= E1000_STATUS_PHYRA;
    }
}

static void
set_rfctl(E1000ECore *core, int index, uint32_t val)
{
    trace_e1000e_rx_set_rfctl(val);

    if (!(val & E1000_RFCTL_ISCSI_DIS)) {
        trace_e1000e_wrn_iscsi_filtering_not_supported();
    }

    if (!(val & E1000_RFCTL_NFSW_DIS)) {
        trace_e1000e_wrn_nfsw_filtering_not_supported();
    }

    if (!(val & E1000_RFCTL_NFSR_DIS)) {
        trace_e1000e_wrn_nfsr_filtering_not_supported();
    }

    core->mac[RFCTL] = val;
}

static uint32_t
parse_rxbufsize_e1000(uint32_t rctl)
{
    rctl &= E1000_RCTL_BSEX | E1000_RCTL_SZ_16384 | E1000_RCTL_SZ_8192 |
            E1000_RCTL_SZ_4096 | E1000_RCTL_SZ_2048 | E1000_RCTL_SZ_1024 |
            E1000_RCTL_SZ_512 | E1000_RCTL_SZ_256;
    switch (rctl) {
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_16384:
        return 16384;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_8192:
        return 8192;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_4096:
        return 4096;
    case E1000_RCTL_SZ_1024:
        return 1024;
    case E1000_RCTL_SZ_512:
        return 512;
    case E1000_RCTL_SZ_256:
        return 256;
    }
    return 2048;
}

static void
calc_per_desc_buf_size(E1000ECore *core)
{
    int i;
    core->rx_desc_buf_size = 0;

    for (i = 0; i < ARRAY_SIZE(core->rxbuf_sizes); i++) {
        core->rx_desc_buf_size += core->rxbuf_sizes[i];
    }
}

static void
parse_rxbufsize(E1000ECore *core)
{
    uint32_t rctl = core->mac[RCTL];

    memset(core->rxbuf_sizes, 0, sizeof(core->rxbuf_sizes));

    if (rctl & E1000_RCTL_DTYP_MASK) {
        uint32_t bsize;

        bsize = core->mac[PSRCTL] & E1000_PSRCTL_BSIZE0_MASK;
        core->rxbuf_sizes[0] = (bsize >> E1000_PSRCTL_BSIZE0_SHIFT) * 128;

        bsize = core->mac[PSRCTL] & E1000_PSRCTL_BSIZE1_MASK;
        core->rxbuf_sizes[1] = (bsize >> E1000_PSRCTL_BSIZE1_SHIFT) * 1024;

        bsize = core->mac[PSRCTL] & E1000_PSRCTL_BSIZE2_MASK;
        core->rxbuf_sizes[2] = (bsize >> E1000_PSRCTL_BSIZE2_SHIFT) * 1024;

        bsize = core->mac[PSRCTL] & E1000_PSRCTL_BSIZE3_MASK;
        core->rxbuf_sizes[3] = (bsize >> E1000_PSRCTL_BSIZE3_SHIFT) * 1024;
    } else if (rctl & E1000_RCTL_FLXBUF_MASK) {
        int flxbuf = rctl & E1000_RCTL_FLXBUF_MASK;
        core->rxbuf_sizes[0] = (flxbuf >> E1000_RCTL_FLXBUF_SHIFT) * 1024;
    } else {
        core->rxbuf_sizes[0] = parse_rxbufsize_e1000(rctl);
    }

    trace_e1000e_rx_desc_buff_sizes(core->rxbuf_sizes[0], core->rxbuf_sizes[1],
                                    core->rxbuf_sizes[2], core->rxbuf_sizes[3]);

    calc_per_desc_buf_size(core);
}

static void
calc_rxdesclen(E1000ECore *core)
{
    if (_e1000e_rx_use_legacy_descriptor(core)) {
        core->rx_desc_len = sizeof(struct e1000_rx_desc);
    } else {
        if (core->mac[RCTL] & E1000_RCTL_DTYP_PS) {
            core->rx_desc_len = sizeof(union e1000_rx_desc_packet_split);
        } else {
            core->rx_desc_len = sizeof(union e1000_rx_desc_extended);
        }
    }
    trace_e1000e_rx_desc_len(core->rx_desc_len);
}

static void
set_rx_control(E1000ECore *core, int index, uint32_t val)
{
	PDBG(".");
    core->mac[RCTL] = val;
    trace_e1000e_rx_set_rctl(core->mac[RCTL]);

    if (val & E1000_RCTL_EN) {
        parse_rxbufsize(core);
        calc_rxdesclen(core);
        core->rxbuf_min_shift = ((val / E1000_RCTL_RDMTS_QUAT) & 3) + 1 +
                                E1000_RING_DESC_LEN_SHIFT;

        start_recv(core);
    }
}

static
void(*phyreg_writeops[E1000E_PHY_PAGES][E1000E_PHY_PAGE_SIZE])
(E1000ECore *, int, uint16_t) = {
    [0] = {
        [PHY_CTRL]     = set_phy_ctrl,
        [PHY_PAGE]     = set_phy_page,
        [PHY_OEM_BITS] = set_phy_oem_bits
    }
};

static void
clear_ims_bits(E1000ECore *core, uint32_t bits)
{
    trace_e1000e_irq_clear_ims(bits, core->mac[IMS], core->mac[IMS] & ~bits);
    core->mac[IMS] &= ~bits;
}

static bool
_e1000e_postpone_interrupt(bool *interrupt_pending,
                           E1000IntrDelayTimer *timer)
{
    if (timer->running) {
        trace_e1000e_irq_postponed_by_xitr(timer->delay_reg << 2);

        *interrupt_pending = true;
        return true;
    }

    if (timer->core->mac[timer->delay_reg] != 0) {
        _e1000e_intrmgr_rearm_timer(timer);
    }

    return false;
}

static inline bool
_e1000e_itr_should_postpone(E1000ECore *core)
{
    return _e1000e_postpone_interrupt(&core->itr_intr_pending, &core->itr);
}

static inline bool
_e1000e_eitr_should_postpone(E1000ECore *core, int idx)
{
    return _e1000e_postpone_interrupt(&core->eitr_intr_pending[idx],
                                      &core->eitr[idx]);
}

static void
_e1000e_msix_notify_one(E1000ECore *core, uint32_t cause, uint32_t int_cfg)
{
	/*PDBG(".");*/
    if (E1000_IVAR_ENTRY_VALID(int_cfg)) {
        uint32_t vec = E1000_IVAR_ENTRY_VEC(int_cfg);
        if (vec < E1000E_MSIX_VEC_NUM) {
            if (!_e1000e_eitr_should_postpone(core, vec)) {
                trace_e1000e_irq_msix_notify_vec(vec);
                msix_notify(core->owner, vec);
            }
        } else {
            trace_e1000e_wrn_msix_vec_wrong(cause, int_cfg);
        }
    } else {
        trace_e1000e_wrn_msix_invalid(cause, int_cfg);
    }

    if (core->mac[CTRL_EXT] & E1000_CTRL_EXT_EIAME) {
        trace_e1000e_irq_ims_clear_eiame(core->mac[IAM], cause);
        clear_ims_bits(core, core->mac[IAM] & cause);
    }

    core->mac[ICR] &= ~(core->mac[EIAC] & E1000_EIAC_MASK);
}

static void
_e1000e_msix_notify(E1000ECore *core, uint32_t causes)
{
    if (causes & E1000_ICR_RXQ0) {
		/*PDBG("RXQ0");*/
        _e1000e_msix_notify_one(core, E1000_ICR_RXQ0,
                                E1000_IVAR_RXQ0(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_RXQ1) {
		/*PDBG("RXQ1");*/
        _e1000e_msix_notify_one(core, E1000_ICR_RXQ1,
                                E1000_IVAR_RXQ1(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_TXQ0) {
		/*PDBG("TXQ0");*/
        _e1000e_msix_notify_one(core, E1000_ICR_TXQ0,
                                E1000_IVAR_TXQ0(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_TXQ1) {
		/*PDBG("TXQ1");*/
        _e1000e_msix_notify_one(core, E1000_ICR_TXQ1,
                                E1000_IVAR_TXQ1(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_OTHER) {
		/*PDBG("OTHER");*/
        _e1000e_msix_notify_one(core, E1000_ICR_OTHER,
                                E1000_IVAR_OTHER(core->mac[IVAR]));
    }
}

static void
_e1000e_msix_clear_one(E1000ECore *core, uint32_t cause, uint32_t int_cfg)
{
    if (E1000_IVAR_ENTRY_VALID(int_cfg)) {
        uint32_t vec = E1000_IVAR_ENTRY_VEC(int_cfg);
        if (vec < E1000E_MSIX_VEC_NUM) {
            trace_e1000e_irq_msix_pending_clearing(cause, int_cfg, vec);
            msix_clr_pending(core->owner, vec);
        } else {
            trace_e1000e_wrn_msix_vec_wrong(cause, int_cfg);
        }
    } else {
        trace_e1000e_wrn_msix_invalid(cause, int_cfg);
    }
}

static void
_e1000e_msix_clear(E1000ECore *core, uint32_t causes)
{
    if (causes & E1000_ICR_RXQ0) {
        _e1000e_msix_clear_one(core, E1000_ICR_RXQ0,
                               E1000_IVAR_RXQ0(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_RXQ1) {
        _e1000e_msix_clear_one(core, E1000_ICR_RXQ1,
                               E1000_IVAR_RXQ1(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_TXQ0) {
        _e1000e_msix_clear_one(core, E1000_ICR_TXQ0,
                               E1000_IVAR_TXQ0(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_TXQ1) {
        _e1000e_msix_clear_one(core, E1000_ICR_TXQ1,
                               E1000_IVAR_TXQ1(core->mac[IVAR]));
    }

    if (causes & E1000_ICR_OTHER) {
        _e1000e_msix_clear_one(core, E1000_ICR_OTHER,
                               E1000_IVAR_OTHER(core->mac[IVAR]));
    }
}

static inline void
_e1000e_fix_icr_asserted(E1000ECore *core)
{
    core->mac[ICR] &= ~E1000_ICR_ASSERTED;
    if (core->mac[ICR]) {
        core->mac[ICR] |= E1000_ICR_ASSERTED;
    }

    trace_e1000e_irq_fix_icr_asserted(core->mac[ICR]);
}

static void
_e1000e_send_msi(E1000ECore *core, bool msix)
{
	/*PDBG(".");*/
    uint32_t causes = core->mac[ICR] & core->mac[IMS] & ~E1000_ICR_ASSERTED;

    if (msix) {
        _e1000e_msix_notify(core, causes);
    } else {
        if (!_e1000e_itr_should_postpone(core)) {
            trace_e1000e_irq_msi_notify(causes);
            msi_notify(core->owner, 0);
        }
    }
}

static void
_e1000e_update_interrupt_state(E1000ECore *core)
{
    bool interrupts_pending;
    bool is_msix = msix_enabled(core->owner);

    /* Set ICR[OTHER] for MSI-X */
    if (is_msix) {
        if (core->mac[ICR] & core->mac[IMS] & E1000_ICR_OTHER_CAUSES) {
            core->mac[ICR] |= E1000_ICR_OTHER;
            trace_e1000e_irq_add_msi_other(core->mac[ICR]);
        }
    }

    _e1000e_fix_icr_asserted(core);

    /*
     * Make sure ICR and ICS registers have the same value.
     * The spec says that the ICS register is write-only.  However in practice,
     * on real hardware ICS is readable, and for reads it has the same value as
     * ICR (except that ICS does not have the clear on read behaviour of ICR).
     *
     * The VxWorks PRO/1000 driver uses this behaviour.
     */
    core->mac[ICS] = core->mac[ICR];

    interrupts_pending = (core->mac[IMS] & core->mac[ICR]) ? true : false;

    trace_e1000e_irq_pending_interrupts(core->mac[ICR] & core->mac[IMS],
                                        core->mac[ICR], core->mac[IMS]);

    if (is_msix || msi_enabled(core->owner)) {
        if (interrupts_pending) {
            _e1000e_send_msi(core, is_msix);
        }
    } else {
        if (interrupts_pending) {
            if (!_e1000e_itr_should_postpone(core)) {
                _e1000e_raise_legacy_irq(core);
            }
        } else {
            _e1000e_lower_legacy_irq(core);
        }
    }
}

static void
set_interrupt_cause(E1000ECore *core, uint32_t val)
{
	/*PDBG(".");*/
    trace_e1000e_irq_set_cause_entry(val, core->mac[ICR]);

    val |= _e1000e_intmgr_collect_delayed_causes(core);
    core->mac[ICR] |= val;

    trace_e1000e_irq_set_cause_exit(val, core->mac[ICR]);

    _e1000e_update_interrupt_state(core);
}

static void
_e1000e_autoneg_timer(void *opaque)
{
	PDBG("_e1000e_autoneg_timer done.");
    E1000ECore *core = opaque;
    if (!qemu_get_queue(core->owner_nic)->link_down) {
        e1000_link_up(core);
        core->phy[0][PHY_LP_ABILITY] |= MII_LPAR_LPACK;
        core->phy[0][PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
        _e1000e_update_flowctl_status(core);
        trace_e1000e_link_negotiation_done();
        set_interrupt_cause(core, E1000_ICR_LSC); /* signal link status change
                                                   * to guest */
    }
}

static inline uint16_t
_e1000e_get_reg_index_with_offset(const uint16_t *mac_reg_access, hwaddr addr)
{
    uint16_t index = (addr & 0x1ffff) >> 2;
    return index + (mac_reg_access[index] & 0xfffe);
}

static const char phy_regcap[E1000E_PHY_PAGES][0x20] = {
    [0] = {
        [PHY_CTRL]          = PHY_ANYPAGE | PHY_RW,
        [PHY_STATUS]        = PHY_ANYPAGE | PHY_R,
        [PHY_ID1]           = PHY_ANYPAGE | PHY_R,
        [PHY_ID2]           = PHY_ANYPAGE | PHY_R,
        [PHY_AUTONEG_ADV]   = PHY_ANYPAGE | PHY_RW,
        [PHY_LP_ABILITY]    = PHY_ANYPAGE | PHY_R,
        [PHY_AUTONEG_EXP]   = PHY_ANYPAGE | PHY_R,
        [PHY_NEXT_PAGE_TX]  = PHY_ANYPAGE | PHY_RW,
        [PHY_LP_NEXT_PAGE]  = PHY_ANYPAGE | PHY_R,
        [PHY_1000T_CTRL]    = PHY_ANYPAGE | PHY_RW,
        [PHY_1000T_STATUS]  = PHY_ANYPAGE | PHY_R,
        [PHY_EXT_STATUS]    = PHY_ANYPAGE | PHY_R,
        [PHY_PAGE]          = PHY_ANYPAGE | PHY_RW,

        [PHY_COPPER_CTRL1]      = PHY_RW,
        [PHY_COPPER_STAT1]      = PHY_R,
        [PHY_COPPER_CTRL3]      = PHY_RW,
        [PHY_RX_ERR_CNTR]       = PHY_R,
        [PHY_OEM_BITS]          = PHY_RW,
        [PHY_BIAS_1]            = PHY_RW,
        [PHY_BIAS_2]            = PHY_RW,
        [PHY_COPPER_INT_ENABLE] = PHY_RW,
        [PHY_COPPER_STAT2]      = PHY_R,
        [PHY_COPPER_CTRL2]      = PHY_RW
    },
    [2] = {
        [PHY_MAC_CTRL1]         = PHY_RW,
        [PHY_MAC_INT_ENABLE]    = PHY_RW,
        [PHY_MAC_STAT]          = PHY_R,
        [PHY_MAC_CTRL2]         = PHY_RW
    },
    [3] = {
        [PHY_LED_03_FUNC_CTRL1] = PHY_RW,
        [PHY_LED_03_POL_CTRL]   = PHY_RW,
        [PHY_LED_TIMER_CTRL]    = PHY_RW,
        [PHY_LED_45_CTRL]       = PHY_RW
    },
    [5] = {
        [PHY_1000T_SKEW]        = PHY_R,
        [PHY_1000T_SWAP]        = PHY_R
    },
    [6] = {
        [PHY_CRC_COUNTERS]      = PHY_R
    }
};

static bool
phy_reg_check_cap(E1000ECore *core, uint32_t addr, char cap, uint8_t *page)
{
    *page = (phy_regcap[0][addr] & PHY_ANYPAGE) ? 0 : core->phy[0][PHY_PAGE];

    if (*page >= E1000E_PHY_PAGES) {
        return false;
    }

    return phy_regcap[*page][addr] & cap;
}

static void
phy_reg_write(E1000ECore *core, uint8_t page, uint32_t addr, uint16_t data)
{
    assert(page < E1000E_PHY_PAGES);
    assert(addr < E1000E_PHY_PAGE_SIZE);

    if (phyreg_writeops[page][addr]) {
        phyreg_writeops[page][addr](core, addr, data);
    } else {
        core->phy[page][addr] = data;
    }
}

static void
set_mdic(E1000ECore *core, int index, uint32_t val)
{
    uint32_t data = val & E1000_MDIC_DATA_MASK;
    uint32_t addr = ((val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT);
    uint8_t page;

    if ((val & E1000_MDIC_PHY_MASK) >> E1000_MDIC_PHY_SHIFT != 1) { /* phy # */
        val = core->mac[MDIC] | E1000_MDIC_ERROR;
    } else if (val & E1000_MDIC_OP_READ) {
        if (!phy_reg_check_cap(core, addr, PHY_R, &page)) {
            trace_e1000e_core_mdic_read_unhandled(page, addr);
            val |= E1000_MDIC_ERROR;
        } else {
            val = (val ^ data) | core->phy[page][addr];
            trace_e1000e_core_mdic_read(page, addr, val);
        }
    } else if (val & E1000_MDIC_OP_WRITE) {
        if (!phy_reg_check_cap(core, addr, PHY_W, &page)) {
            trace_e1000e_core_mdic_write_unhandled(page, addr);
            val |= E1000_MDIC_ERROR;
        } else {
            trace_e1000e_core_mdic_write(page, addr, data);
            phy_reg_write(core, page, addr, data);
        }
    }
    core->mac[MDIC] = val | E1000_MDIC_READY;
	/*printf("Set MDIC to %x\n.", core->mac[MDIC]);*/

    if (val & E1000_MDIC_INT_EN) {
        set_interrupt_cause(core, E1000_ICR_MDAC);
    }
}

static void
set_rdt(E1000ECore *core, int index, uint32_t val)
{
    core->mac[index] = val & 0xffff;
    /*trace_e1000e_rx_set_rdt(_e1000e_mq_queue_idx(RDT0, index), val);*/
    start_recv(core);
}

static void
set_status(E1000ECore *core, int index, uint32_t val)
{
    if ((val & E1000_STATUS_PHYRA) == 0) {
        core->mac[index] &= ~E1000_STATUS_PHYRA;
    }
}

static void
set_ctrlext(E1000ECore *core, int index, uint32_t val)
{
    trace_e1000e_link_set_ext_params(!!(val & E1000_CTRL_EXT_ASDCHK),
                                     !!(val & E1000_CTRL_EXT_SPD_BYPS));

    /* Zero self-clearing bits */
    val &= ~(E1000_CTRL_EXT_ASDCHK | E1000_CTRL_EXT_EE_RST);
    core->mac[CTRL_EXT] = val;
}

static void
set_pbaclr(E1000ECore *core, int index, uint32_t val)
{
    int i;

    core->mac[PBACLR] = val & E1000_PBACLR_VALID_MASK;

    if (msix_enabled(core->owner)) {
        return;
    }

    for (i = 0; i < E1000E_MSIX_VEC_NUM; i++) {
        if (core->mac[PBACLR] & BIT(i)) {
            msix_clr_pending(core->owner, i);
        }
    }
}

static void
set_fcrth(E1000ECore *core, int index, uint32_t val)
{
    core->mac[FCRTH] = val & 0xFFF8;
}

static void
set_fcrtl(E1000ECore *core, int index, uint32_t val)
{
    core->mac[FCRTL] = val & 0x8000FFF8;
}

static void
set_16bit(E1000ECore *core, int index, uint32_t val)
{
    core->mac[index] = val & 0xffff;
}

static void
set_12bit(E1000ECore *core, int index, uint32_t val)
{
    core->mac[index] = val & 0xfff;
}

static void
set_vet(E1000ECore *core, int index, uint32_t val)
{
    core->mac[VET] = val & 0xffff;
    core->vet = le16_to_cpu(core->mac[VET]);
    trace_e1000e_vlan_vet(core->vet);
}

static void
set_dlen(E1000ECore *core, int index, uint32_t val)
{
    core->mac[index] = val & 0xfff80;
}

static void
set_tctl(E1000ECore *core, int index, uint32_t val)
{
	/*PDBG("Setting TCTL to 0x%x", val);*/
    E1000E_TxRing txr;
    core->mac[index] = val;

    _e1000e_tx_ring_init(core, &txr, 0);
    start_xmit(core, &txr);

    if (core->mac[TARC1] & E1000_TARC_ENABLE) {
            _e1000e_tx_ring_init(core, &txr, 1);
            start_xmit(core, &txr);
    }
}

static void
set_tdt(E1000ECore *core, int index, uint32_t val)
{
    E1000E_TxRing txr;

    core->mac[index] = val & 0xffff;

	/*PDBG("Sending from ring: %d", _e1000e_mq_queue_idx(TDT, index));*/
	/*print_tx_buffer_address_information(core);*/

    _e1000e_tx_ring_init(core, &txr, _e1000e_mq_queue_idx(TDT, index));
    start_xmit(core, &txr);
}

static void
set_ics(E1000ECore *core, int index, uint32_t val)
{
    trace_e1000e_irq_write_ics(val);
    set_interrupt_cause(core, val);
}

static void
set_icr(E1000ECore *core, int index, uint32_t val)
{
    if ((core->mac[ICR] & E1000_ICR_ASSERTED) &&
        (core->mac[CTRL_EXT] & E1000_CTRL_EXT_IAME)) {
        trace_e1000e_irq_icr_process_iame();
        clear_ims_bits(core, core->mac[IAM]);
    }

    trace_e1000e_irq_icr_write(val, core->mac[ICR], core->mac[ICR] & ~val);
    core->mac[ICR] &= ~val;
    _e1000e_update_interrupt_state(core);
}

static void
set_imc(E1000ECore *core, int index, uint32_t val)
{
    trace_e1000e_irq_ims_clear_set_imc(val);
    clear_ims_bits(core, val);
    _e1000e_update_interrupt_state(core);
}

static void
set_ims(E1000ECore *core, int index, uint32_t val)
{
    static const uint32_t IMS_EXT_MASK =
        E1000_IMS_RXQ0 | E1000_IMS_RXQ1 |
        E1000_IMS_TXQ0 | E1000_IMS_TXQ1 |
        E1000_IMS_OTHER;

    static const uint32_t IMS_VALID_MASK =
        E1000_IMS_TXDW      | E1000_IMS_TXQE    | E1000_IMS_LSC  |
        E1000_IMS_RXDMT0    | E1000_IMS_RXO     | E1000_IMS_RXT0 |
        E1000_IMS_MDAC      | E1000_IMS_TXD_LOW | E1000_IMS_SRPD |
        E1000_IMS_ACK       | E1000_IMS_MNG     | E1000_IMS_RXQ0 |
        E1000_IMS_RXQ1      | E1000_IMS_TXQ0    | E1000_IMS_TXQ1 |
        E1000_IMS_OTHER;

    uint32_t valid_val = val & IMS_VALID_MASK;

    trace_e1000e_irq_set_ims(val, core->mac[IMS], core->mac[IMS] | valid_val);
    core->mac[IMS] |= valid_val;

    if ((valid_val & IMS_EXT_MASK) &&
        (core->mac[CTRL_EXT] & E1000_CTRL_EXT_PBA_CLR) &&
        msix_enabled(core->owner)) {
        _e1000e_msix_clear(core, valid_val);
    }

    if ((valid_val == IMS_VALID_MASK) &&
        (core->mac[CTRL_EXT] & E1000_CTRL_EXT_INT_TIMERS_CLEAR_ENA)) {
        trace_e1000e_irq_fire_all_timers(val);
        _e1000e_intrmgr_fire_all_timers(core);
    }

    _e1000e_update_interrupt_state(core);
}

static void
set_rdtr(E1000ECore *core, int index, uint32_t val)
{
    set_16bit(core, index, val);

    if ((val & E1000_RDTR_FPD) && (core->rdtr.running)) {
        trace_e1000e_irq_rdtr_fpd_running();
        _e1000e_intrmgr_fire_delayed_interrupts(core);
    } else {
        trace_e1000e_irq_rdtr_fpd_not_running();
    }
}

static void
set_tidv(E1000ECore *core, int index, uint32_t val)
{
    set_16bit(core, index, val);

    if ((val & E1000_TIDV_FPD) && (core->tidv.running)) {
        trace_e1000e_irq_tidv_fpd_running();
        _e1000e_intrmgr_fire_delayed_interrupts(core);
    } else {
        trace_e1000e_irq_tidv_fpd_not_running();
    }
}

static uint32_t
mac_readreg(E1000ECore *core, int index)
{
	/*if (index == EERD && core->mac[index] != 0) {*/
		/*printf("Returning EERD as %x\n", core->mac[index]);*/
	/*}*/
    return core->mac[index];
}

static uint32_t
mac_ics_read(E1000ECore *core, int index)
{
    trace_e1000e_irq_read_ics(core->mac[ICS]);
    return core->mac[ICS];
}

static uint32_t
mac_ims_read(E1000ECore *core, int index)
{
    trace_e1000e_irq_read_ims(core->mac[IMS]);
    return core->mac[IMS];
}

static uint32_t
mac_low4_read(E1000ECore *core, int index)
{
    return core->mac[index] & 0xf;
}

static uint32_t
mac_low6_read(E1000ECore *core, int index)
{
    return core->mac[index] & 0x3f;
}

static uint32_t
mac_low11_read(E1000ECore *core, int index)
{
    return core->mac[index] & 0x7ff;
}

static uint32_t
mac_low13_read(E1000ECore *core, int index)
{
    return core->mac[index] & 0x1fff;
}

static uint32_t
mac_low16_read(E1000ECore *core, int index)
{
    return core->mac[index] & 0xffff;
}

static uint32_t
mac_swsm_read(E1000ECore *core, int index)
{
    uint32_t val = core->mac[SWSM];
    core->mac[SWSM] = val | 1;
    return val;
}

static uint32_t
mac_itr_read(E1000ECore *core, int index)
{
    return core->itr_guest_value;
}

static uint32_t
mac_eitr_read(E1000ECore *core, int index)
{
    return core->eitr_guest_value[index - EITR];
}

static uint32_t
mac_icr_read(E1000ECore *core, int index)
{
    uint32_t ret = core->mac[ICR];
    trace_e1000e_irq_icr_read_entry(ret);

    if (core->mac[IMS] == 0) {
        trace_e1000e_irq_icr_clear_zero_ims();
        core->mac[ICR] = 0;
    }

    if ((core->mac[ICR] & E1000_ICR_ASSERTED) &&
        (core->mac[CTRL_EXT] & E1000_CTRL_EXT_IAME)) {
        trace_e1000e_irq_icr_clear_iame();
        core->mac[ICR] = 0;
        trace_e1000e_irq_icr_process_iame();
        clear_ims_bits(core, core->mac[IAM]);
    }

    trace_e1000e_irq_icr_read_exit(core->mac[ICR]);
    _e1000e_update_interrupt_state(core);
    return ret;
}

static uint32_t
mac_read_clr4(E1000ECore *core, int index)
{
    uint32_t ret = core->mac[index];

    core->mac[index] = 0;
    return ret;
}

static uint32_t
mac_read_clr8(E1000ECore *core, int index)
{
    uint32_t ret = core->mac[index];

    core->mac[index] = 0;
    core->mac[index-1] = 0;
    return ret;
}

static uint32_t
get_ctrl(E1000ECore *core, int index)
{
    uint32_t val = core->mac[CTRL];

    trace_e1000e_link_read_params(
        !!(val & E1000_CTRL_ASDE),
        (val & E1000_CTRL_SPD_SEL) >> E1000_CTRL_SPD_SHIFT,
        !!(val & E1000_CTRL_FRCSPD),
        !!(val & E1000_CTRL_FRCDPX),
        !!(val & E1000_CTRL_RFCE),
        !!(val & E1000_CTRL_TFCE));

    return val;
}

static uint32_t
get_status(E1000ECore *core, int index)
{
    uint32_t res = core->mac[STATUS];

    if (!(core->mac[CTRL] & E1000_CTRL_GIO_MASTER_DISABLE)) {
        res |= E1000_STATUS_GIO_MASTER_ENABLE;
    }

    if (core->mac[CTRL] & E1000_CTRL_FRCDPX) {
        res |= (core->mac[CTRL] & E1000_CTRL_FD) ? E1000_STATUS_FD : 0;
    } else {
        res |= E1000_STATUS_FD;
    }

    if ((core->mac[CTRL] & E1000_CTRL_FRCSPD) ||
        (core->mac[CTRL_EXT] & E1000_CTRL_EXT_SPD_BYPS)) {
        switch (core->mac[CTRL] & E1000_CTRL_SPD_SEL) {
        case E1000_CTRL_SPD_10:
            res |= E1000_STATUS_SPEED_10;
            break;
        case E1000_CTRL_SPD_100:
            res |= E1000_STATUS_SPEED_100;
            break;
        case E1000_CTRL_SPD_1000:
        default:
            res |= E1000_STATUS_SPEED_1000;
            break;
        }
    } else {
        res |= E1000_STATUS_SPEED_1000;
    }

    trace_e1000e_link_status(
        !!(res & E1000_STATUS_LU),
        !!(res & E1000_STATUS_FD),
        (res & E1000_STATUS_SPEED_MASK) >> E1000_STATUS_SPEED_SHIFT,
        (res & E1000_STATUS_ASDV) >> E1000_STATUS_ASDV_SHIFT);

    return res;
}

static uint32_t
get_tarc(E1000ECore *core, int index)
{
    return core->mac[index] & ((BIT(11) - 1) |
                                BIT(27)      |
                                BIT(28)      |
                                BIT(29)      |
                                BIT(30));
}

static void
mac_writereg(E1000ECore *core, int index, uint32_t val)
{
    core->mac[index] = val;
}

static void
mac_setmacaddr(E1000ECore *core, int index, uint32_t val)
{
    uint32_t macaddr[2];

    core->mac[index] = val;

    macaddr[0] = cpu_to_le32(core->mac[RA]);
    macaddr[1] = cpu_to_le32(core->mac[RA + 1]);
    qemu_format_nic_info_str(qemu_get_queue(core->owner_nic),
        (uint8_t *) macaddr);

    trace_e1000e_mac_set_sw(MAC_ARG(macaddr));
}

static void
set_eecd(E1000ECore *core, int index, uint32_t val)
{
    static const uint32_t ro_bits = E1000_EECD_PRES          |
                                    E1000_EECD_AUTO_RD       |
                                    E1000_EECD_SIZE_EX_MASK;

    core->mac[EECD] = (core->mac[EECD] & ro_bits) | (val & ~ro_bits);
}

static void
set_eerd(E1000ECore *core, int index, uint32_t val)
{
    uint32_t addr = (val >> E1000_EERW_ADDR_SHIFT) & E1000_EERW_ADDR_MASK;
    uint32_t flags = 0;
    uint32_t data = 0;

    if ((addr < E1000E_EEPROM_SIZE) && (val & E1000_EERW_START)) {
        data = core->eeprom[addr];
        flags = E1000_EERW_DONE;
    }

    core->mac[EERD] = flags                           |
                      (addr << E1000_EERW_ADDR_SHIFT) |
                      (data << E1000_EERW_DATA_SHIFT);

	/*printf("set_eerd. EEPROM Address: %x. EEPROM Size: %x.\n",*/
		/*addr, E1000E_EEPROM_SIZE);*/
	/*printf("val & E1000_EERW_START: %d. data: %x. flags: %x.\n",*/
		/*val & E1000_EERW_START, data, flags);*/
	/*printf("core->mac[EERD] = %x\n", core->mac[EERD]);*/
}

static void
set_eewr(E1000ECore *core, int index, uint32_t val)
{
    uint32_t addr = (val >> E1000_EERW_ADDR_SHIFT) & E1000_EERW_ADDR_MASK;
    uint32_t data = (val >> E1000_EERW_DATA_SHIFT) & E1000_EERW_DATA_MASK;
    uint32_t flags = 0;

    if ((addr < E1000E_EEPROM_SIZE) && (val & E1000_EERW_START)) {
        core->eeprom[addr] = data;
        flags = E1000_EERW_DONE;
    }

    core->mac[EERD] = flags                           |
                      (addr << E1000_EERW_ADDR_SHIFT) |
                      (data << E1000_EERW_DATA_SHIFT);
}

static void
set_rxdctl(E1000ECore *core, int index, uint32_t val)
{
    core->mac[RXDCTL] = core->mac[RXDCTL1] = val;
}

static void
set_itr(E1000ECore *core, int index, uint32_t val)
{
    uint32_t interval = val & 0xffff;

    trace_e1000e_irq_itr_set(val);

    core->itr_guest_value = interval;
    core->mac[index] = MAX(interval, _E1000E_MIN_XITR);
}

static void
set_eitr(E1000ECore *core, int index, uint32_t val)
{
    uint32_t interval = val & 0xffff;
    uint32_t eitr_num = index - EITR;

    trace_e1000e_irq_eitr_set(eitr_num, val);

    core->eitr_guest_value[eitr_num] = interval;
    core->mac[index] = MAX(interval, _E1000E_MIN_XITR);
}

static void
set_psrctl(E1000ECore *core, int index, uint32_t val)
{
    if ((val & E1000_PSRCTL_BSIZE0_MASK) == 0) {
        hw_error("e1000e: PSRCTL.BSIZE0 cannot be zero");
    }

    if ((val & E1000_PSRCTL_BSIZE1_MASK) == 0) {
        hw_error("e1000e: PSRCTL.BSIZE1 cannot be zero");
    }

    core->mac[PSRCTL] = val;
}

static void
_e1000e_update_rx_offloads(E1000ECore *core)
{
    int cso_state = _e1000e_rx_l4_cso_enabled(core);

    trace_e1000e_rx_set_cso(cso_state);

    if (core->has_vnet) {
        qemu_set_offload(qemu_get_queue(core->owner_nic)->peer,
                         cso_state, 0, 0, 0, 0);
    }
}

static void
set_rxcsum(E1000ECore *core, int index, uint32_t val)
{
    core->mac[RXCSUM] = val;
    _e1000e_update_rx_offloads(core);
}

static void
set_gcr(E1000ECore *core, int index, uint32_t val)
{
    uint32_t ro_bits = core->mac[GCR] & E1000_GCR_RO_BITS;
    core->mac[GCR] = (val & ~E1000_GCR_RO_BITS) | ro_bits;
}


#define getreg(x)    [x] = mac_readreg
static uint32_t (*macreg_readops[])(E1000ECore *, int) = {
    getreg(PBA),      getreg(RCTL),     getreg(TDH),      getreg(TXDCTL),
    getreg(WUFC),     getreg(TDT),      getreg(LEDCTL),   getreg(FCRTL),
    getreg(MANC),     getreg(MDIC),     getreg(STATUS),   getreg(TORL),
    getreg(TOTL),     getreg(FCRUC),    getreg(TCTL),     getreg(RDH0),
    getreg(RDT0),     getreg(VET),      getreg(TDBAL),    getreg(TDBAH),
    getreg(RDBAH0),   getreg(RDBAL0),   getreg(TDLEN),    getreg(TDLEN1),
    getreg(TDBAL1),   getreg(TDBAH1),   getreg(TDH1),     getreg(TDT1),
    getreg(RDLEN0),   getreg(RDTR),     getreg(RADV),     getreg(TADV),
    getreg(RDH1),     getreg(SCC),      getreg(ECOL),     getreg(MCC),
    getreg(LATECOL),  getreg(COLC),     getreg(DC),       getreg(TNCRS),
    getreg(SEC),      getreg(CEXTERR),  getreg(RLEC),     getreg(XONRXC),
    getreg(XONTXC),   getreg(XOFFRXC),  getreg(XOFFTXC),  getreg(WUC),
    getreg(WUS),      getreg(IPAV),     getreg(RFC),      getreg(RJC),
    getreg(GORCL),    getreg(GOTCL),    getreg(RNBC),     getreg(TSCTFC),
    getreg(MGTPRC),   getreg(MGTPDC),   getreg(MGTPTC),   getreg(EECD),
    getreg(EERD),     getreg(GCR),      getreg(TIMINCA),  getreg(IAM),
    getreg(EIAC),     getreg(IVAR),     getreg(CTRL_EXT), getreg(RFCTL),
    getreg(PSRCTL),   getreg(POEMB),    getreg(MFUTP01),  getreg(MFUTP23),
    getreg(MANC2H),   getreg(MFVAL),    getreg(FACTPS),   getreg(EXTCNF_CTRL),
    getreg(RXCSUM),   getreg(FUNCTAG),  getreg(GSCL_1),   getreg(GSCL_2),
    getreg(GSCL_3),   getreg(GSCL_4),   getreg(GSCN_0),   getreg(GSCN_1),
    getreg(GSCN_2),   getreg(GSCN_3),   getreg(GCR2),     getreg(RAID),
    getreg(RSRPD),    getreg(MRQC),     getreg(RDT1),     getreg(RDBAH1),
    getreg(RDBAL1),   getreg(RDLEN1),   getreg(PBACLR),   getreg(FCAL),
    getreg(FCAH),     getreg(FCT),      getreg(FCTTV),    getreg(FCRTV),
    getreg(FCRTH),    getreg(FLA),      getreg(EEWR),     getreg(FLSWDATA),
    getreg(FLOP),     getreg(FLOL),     getreg(FLSWCTL),  getreg(FLSWCNT),
    getreg(FLASHT),   getreg(RXDCTL),   getreg(RXDCTL1),  getreg(TXDCTL1),
    getreg(RXSTMPH),  getreg(RXSTMPL),  getreg(RXSATRL),  getreg(RXSATRH),
    getreg(TXSTMPL),  getreg(TXSTMPH),  getreg(SYSTIML),  getreg(SYSTIMH),
    getreg(TIMADJL),  getreg(TIMADJH),  getreg(RXUDP),    getreg(RXCFGL),
    getreg(TSYNCRXCTL),
    getreg(TSYNCTXCTL),
    getreg(TIPG),
    getreg(EXTCNF_SIZE),
    getreg(EEMNGCTL),
    getreg(EEMNGDATA),
    getreg(FLMNGCTL),
    getreg(FLMNGDATA),
    getreg(FLMNGCNT),

    [TOTH]    = mac_read_clr8,      [TORH]    = mac_read_clr8,
    [GOTCH]   = mac_read_clr8,      [GORCH]   = mac_read_clr8,
    [PRC64]   = mac_read_clr4,      [PRC127]  = mac_read_clr4,
    [PRC255]  = mac_read_clr4,      [PRC511]  = mac_read_clr4,
    [PRC1023] = mac_read_clr4,      [PRC1522] = mac_read_clr4,
    [PTC64]   = mac_read_clr4,      [PTC127]  = mac_read_clr4,
    [PTC255]  = mac_read_clr4,      [PTC511]  = mac_read_clr4,
    [PTC1023] = mac_read_clr4,      [PTC1522] = mac_read_clr4,
    [GPRC]    = mac_read_clr4,      [GPTC]    = mac_read_clr4,
    [TPT]     = mac_read_clr4,      [TPR]     = mac_read_clr4,
    [RUC]     = mac_read_clr4,      [ROC]     = mac_read_clr4,
    [BPRC]    = mac_read_clr4,      [MPRC]    = mac_read_clr4,
    [MPTC]    = mac_read_clr4,      [BPTC]    = mac_read_clr4,
    [IAC]     = mac_read_clr4,      [TSCTC]   = mac_read_clr4,
    [ICR]     = mac_icr_read,       [ITR]     = mac_itr_read,
    [ICS]     = mac_ics_read,       [IMS]     = mac_ims_read,
    [RDFH]    = mac_low13_read,     [RDFT]    = mac_low13_read,
    [RDFHS]   = mac_low13_read,     [RDFTS]   = mac_low13_read,
    [RDFPC]   = mac_low13_read,
    [TDFH]    = mac_low13_read,     [TDFT]    = mac_low13_read,
    [TDFHS]   = mac_low13_read,     [TDFTS]   = mac_low13_read,
    [TDFPC]   = mac_low13_read,
    [AIT]     = mac_low16_read,
    [STATUS]  = get_status,         [CTRL]    = get_ctrl,
    [TARC0]   = get_tarc,           [TARC1]   = get_tarc,
    [PBS]     = mac_low6_read,      [SWSM]    = mac_swsm_read,

    [CRCERRS ... MPC]    = &mac_readreg,
    [IP6AT ... IP6AT+3]  = &mac_readreg,
    [IP4AT ... IP4AT+6]  = &mac_readreg,
    [RA ... RA+31]       = &mac_readreg,
    [WUPM ... WUPM+31]   = &mac_readreg,
    [MTA ... MTA+127]    = &mac_readreg,
    [VFTA ... VFTA+127]  = &mac_readreg,
    [FFMT ... FFMT+254]  = &mac_low4_read,
    [FFVT ... FFVT+254]  = &mac_readreg,
    [MDEF ... MDEF+7]    = &mac_readreg,
    [FFLT ... FFLT+10]   = &mac_low11_read,
    [FTFT ... FTFT+254]  = &mac_readreg,
    [PBM ... PBM+10239]  = &mac_readreg,
    [EITR...EITR + E1000E_MSIX_VEC_NUM - 1] = &mac_eitr_read,
    [RETA ... RETA+31]   = &mac_readreg,
    [RSSRK ... RSSRK+31] = &mac_readreg,
    [MAVTV0 ... MAVTV3]  = &mac_readreg
};
enum { NREADOPS = ARRAY_SIZE(macreg_readops) };

#define putreg(x)    [x] = mac_writereg
static void (*macreg_writeops[])(E1000ECore *, int, uint32_t) = {
    putreg(PBA),      putreg(SWSM),     putreg(WUFC),     putreg(RDBAH1),
    putreg(TDBAL),    putreg(TDBAH),    putreg(TXDCTL),   putreg(RDBAH0),
    putreg(RDBAL0),   putreg(LEDCTL),   putreg(FCAL),     putreg(FCRUC),
    putreg(AIT),      putreg(TDFH),     putreg(TDFT),     putreg(TDFHS),
    putreg(TDFTS),    putreg(TDFPC),    putreg(WUC),      putreg(WUS),
    putreg(RDFH),     putreg(RDFT),     putreg(RDFHS),    putreg(RDFTS),
    putreg(RDFPC),    putreg(IPAV),     putreg(TDBAL1),   putreg(TDBAH1),
    putreg(TIMINCA),  putreg(IAM),      putreg(EIAC),     putreg(IVAR),
    putreg(RDBAL1),   putreg(TARC0),    putreg(TARC1),    putreg(FLSWDATA),
    putreg(POEMB),    putreg(PBS),      putreg(MFUTP01),  putreg(MFUTP23),
    putreg(MANC),     putreg(MANC2H),   putreg(MFVAL),    putreg(EXTCNF_CTRL),
    putreg(FACTPS),   putreg(FUNCTAG),  putreg(GSCL_1),   putreg(GSCL_2),
    putreg(GSCL_3),   putreg(GSCL_4),   putreg(GSCN_0),   putreg(GSCN_1),
    putreg(GSCN_2),   putreg(GSCN_3),   putreg(GCR2),     putreg(MRQC),
    putreg(FLOP),     putreg(FLOL),     putreg(FLSWCTL),  putreg(FLSWCNT),
    putreg(FLA),      putreg(RXDCTL1),  putreg(TXDCTL1),  putreg(TIPG),
    putreg(RXSTMPH),  putreg(RXSTMPL),  putreg(RXSATRL),  putreg(RXSATRH),
    putreg(TXSTMPL),  putreg(TXSTMPH),  putreg(SYSTIML),  putreg(SYSTIMH),
    putreg(TIMADJL),  putreg(TIMADJH),  putreg(RXUDP),    putreg(RXCFGL),
    putreg(TSYNCRXCTL),
    putreg(TSYNCTXCTL),
    putreg(FLSWDATA),
    putreg(EXTCNF_SIZE),
    putreg(EEMNGCTL),

    [TDLEN1] = set_dlen,   [TDH1]   = set_16bit,      [TDT1] = set_tdt,
    [TDLEN]  = set_dlen,   [RDLEN0] = set_dlen,       [TCTL] = set_tctl,
    [TDT]    = set_tdt,    [MDIC]   = set_mdic,       [ICS]  = set_ics,
    [TDH]    = set_16bit,  [RDH0]   = set_16bit,      [RDT0] = set_rdt,
    [IMC]    = set_imc,    [IMS]    = set_ims,        [ICR]  = set_icr,
    [EECD]   = set_eecd,   [RCTL]   = set_rx_control, [CTRL] = set_ctrl,
    [RDTR]   = set_rdtr,   [RADV]   = set_16bit,      [TADV] = set_16bit,
    [ITR]    = set_itr,    [EERD]   = set_eerd,       [GCR]  = set_gcr,
    [PSRCTL] = set_psrctl, [RXCSUM] = set_rxcsum,     [RAID] = set_16bit,
    [RSRPD]  = set_12bit,  [TIDV]   = set_tidv,       [RDLEN1] = set_dlen,
    [RDH1]   = set_16bit,  [RDT1]   = set_rdt,        [STATUS] = set_status,
    [PBACLR] = set_pbaclr, [CTRL_EXT] = set_ctrlext,  [FCAH]   = set_16bit,
    [FCT]    = set_16bit,  [FCTTV]  = set_16bit,      [FCRTV]  = set_16bit,
    [FCRTH]  = set_fcrth,  [FCRTL]  = set_fcrtl,      [VET]    = set_vet,
    [RXDCTL] = set_rxdctl, [FLASHT] = set_16bit,      [EEWR] = set_eewr,
    [CTRL_DUP] = set_ctrl, [RFCTL]  = set_rfctl,
    [IP6AT ... IP6AT+3] = &mac_writereg, [IP4AT ... IP4AT+6] = &mac_writereg,
    [RA] = &mac_writereg,
    [RA + 1] = &mac_setmacaddr,
    [RA + 2 ... RA + 31] = &mac_writereg,
    [WUPM ... WUPM+31]  = &mac_writereg,
    [MTA ... MTA+127]   = &mac_writereg,
    [VFTA ... VFTA+127] = &mac_writereg,
    [FFMT ... FFMT+254] = &mac_writereg, [FFVT ... FFVT+254] = &mac_writereg,
    [PBM ... PBM+10239] = &mac_writereg,
    [MDEF ... MDEF+7]   = &mac_writereg,
    [FFLT ... FFLT+10]  = &mac_writereg,
    [FTFT ... FTFT+254] = &mac_writereg,
    [EITR...EITR + E1000E_MSIX_VEC_NUM - 1] = &set_eitr,
    [RETA ... RETA + 31] = &mac_writereg,
    [RSSRK ... RSSRK + 31] = &mac_writereg,
    [MAVTV0 ... MAVTV3] = &mac_writereg
};

enum { NWRITEOPS = ARRAY_SIZE(macreg_writeops) };

enum { MAC_ACCESS_PARTIAL = 1 };

/* The array below combines alias offsets of the index values for the
 * MAC registers that have aliases, with the indication of not fully
 * implemented registers (lowest bit). This combination is possible
 * because all of the offsets are even. */
static const uint16_t mac_reg_access[E1000E_MAC_SIZE] = {
    /* Alias index offsets */
    [FCRTL_A] = 0x07fe, [FCRTH_A] = 0x0802,
    [RDH0_A]  = 0x09bc, [RDT0_A]  = 0x09bc, [RDTR_A] = 0x09c6,
    [RDFH_A]  = 0xe904, [RDFT_A]  = 0xe904,
    [TDH_A]   = 0x0cf8, [TDT_A]   = 0x0cf8, [TIDV_A] = 0x0cf8,
    [TDFH_A]  = 0xed00, [TDFT_A]  = 0xed00,
    [RA_A ... RA_A+31]      = 0x14f0,
    [VFTA_A ... VFTA_A+127] = 0x1400,
    [RDBAL0_A ... RDLEN0_A] = 0x09bc,
    [TDBAL_A ... TDLEN_A]   = 0x0cf8,
    /* Access options */
    [RDFH]  = MAC_ACCESS_PARTIAL,    [RDFT]  = MAC_ACCESS_PARTIAL,
    [RDFHS] = MAC_ACCESS_PARTIAL,    [RDFTS] = MAC_ACCESS_PARTIAL,
    [RDFPC] = MAC_ACCESS_PARTIAL,
    [TDFH]  = MAC_ACCESS_PARTIAL,    [TDFT]  = MAC_ACCESS_PARTIAL,
    [TDFHS] = MAC_ACCESS_PARTIAL,    [TDFTS] = MAC_ACCESS_PARTIAL,
    [TDFPC] = MAC_ACCESS_PARTIAL,    [EECD]  = MAC_ACCESS_PARTIAL,
    [PBM]   = MAC_ACCESS_PARTIAL,    [FLA]   = MAC_ACCESS_PARTIAL,
    [FCAL]  = MAC_ACCESS_PARTIAL,    [FCAH]  = MAC_ACCESS_PARTIAL,
    [FCT]   = MAC_ACCESS_PARTIAL,    [FCTTV] = MAC_ACCESS_PARTIAL,
    [FCRTV] = MAC_ACCESS_PARTIAL,    [FCRTL] = MAC_ACCESS_PARTIAL,
    [FCRTH] = MAC_ACCESS_PARTIAL,    [TXDCTL] = MAC_ACCESS_PARTIAL,
    [TXDCTL1] = MAC_ACCESS_PARTIAL,
    [MAVTV0 ... MAVTV3] = MAC_ACCESS_PARTIAL
};

void
e1000e_core_write(E1000ECore *core, hwaddr addr, uint64_t val, unsigned size)
{
    uint16_t index = _e1000e_get_reg_index_with_offset(mac_reg_access, addr);

    if (index < NWRITEOPS && macreg_writeops[index]) {
        if (mac_reg_access[index] & MAC_ACCESS_PARTIAL) {
            trace_e1000e_wrn_regs_write_trivial(index<<2);
        }
        trace_e1000e_core_write(index << 2, size, val);
        macreg_writeops[index](core, index, val);
    } else if (index < NREADOPS && macreg_readops[index]) {
        trace_e1000e_wrn_regs_write_ro(index << 2, size, val);
    } else {
        trace_e1000e_wrn_regs_write_unknown(index << 2, size, val);
    }
}

uint64_t
e1000e_core_read(E1000ECore *core, hwaddr addr, unsigned size)
{
    uint64_t val;
    uint16_t index = _e1000e_get_reg_index_with_offset(mac_reg_access, addr);
	/*PDBG("E1000E Read 0x%lx (%d)", addr, index);*/

    if (index < NREADOPS && macreg_readops[index]) {
        if (mac_reg_access[index] & MAC_ACCESS_PARTIAL) {
            trace_e1000e_wrn_regs_read_trivial(index<<2);
        }
        val = macreg_readops[index](core, index);
        trace_e1000e_core_read(index << 2, size, val);
        return val;
    } else {
        trace_e1000e_wrn_regs_read_unknown(index << 2, size);
    }
    return 0;
}

static void
_e1000e_core_prepare_eeprom(E1000ECore      *core,
                            const uint16_t *templ,
                            uint32_t        templ_size,
                            const uint8_t  *macaddr)
{
    PCIDeviceClass *pdc = PCI_DEVICE_GET_CLASS(core->owner);
    uint16_t checksum = 0;
    int i;

    memmove(core->eeprom, templ, templ_size);

    for (i = 0; i < 3; i++) {
        core->eeprom[i] = (macaddr[2*i+1]<<8) | macaddr[2*i];
    }

    core->eeprom[11] = core->eeprom[13] = pdc->device_id;

    for (i = 0; i < EEPROM_CHECKSUM_REG; i++) {
        checksum += core->eeprom[i];
    }

    checksum = (uint16_t) EEPROM_SUM - checksum;

    core->eeprom[EEPROM_CHECKSUM_REG] = checksum;
}

static void _e1000e_core_initialize_regs(E1000ECore *core);

void
e1000e_core_pci_realize(E1000ECore      *core,
                       const uint16_t *eeprom_templ,
                       uint32_t        eeprom_size,
                       const uint8_t  *macaddr)
{
    int i;

	PDBG("Initiliasing autoneg timer.");
    core->autoneg_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                       _e1000e_autoneg_timer, core);
    _e1000e_intrmgr_pci_realize(core);
	_e1000e_core_initialize_regs(core);

    for (i = 0; i < E1000E_NUM_QUEUES; i++) {
        net_tx_pkt_init(&core->tx[i].tx_pkt,
            E1000E_MAX_TX_FRAGS, core->has_vnet);
    }

    net_rx_pkt_init(&core->rx_pkt, core->has_vnet);

    _e1000e_core_prepare_eeprom(core, eeprom_templ, eeprom_size, macaddr);
    _e1000e_update_rx_offloads(core);
}

void
e1000e_core_pci_uninit(E1000ECore *core)
{
    int i;

    timer_del(core->autoneg_timer);
    timer_free(core->autoneg_timer);

    _e1000e_intrmgr_pci_unint(core);

    for (i = 0; i < E1000E_NUM_QUEUES; i++) {
        net_tx_pkt_reset(core->tx[i].tx_pkt);
        net_tx_pkt_uninit(core->tx[i].tx_pkt);
    }

    net_rx_pkt_uninit(core->rx_pkt);
}

static const uint16_t phy_reg_init[E1000E_PHY_PAGES][E1000E_PHY_PAGE_SIZE] = {
    [0] = {
        [PHY_CTRL] =   MII_CR_SPEED_SELECT_MSB |
                       MII_CR_FULL_DUPLEX |
                       MII_CR_AUTO_NEG_EN,

        [PHY_STATUS] = MII_SR_EXTENDED_CAPS |
                       MII_SR_LINK_STATUS |   /* link initially up */
                       MII_SR_AUTONEG_CAPS |
                       /* MII_SR_AUTONEG_COMPLETE: initially NOT completed */
                       MII_SR_PREAMBLE_SUPPRESS |
                       MII_SR_EXTENDED_STATUS |
                       MII_SR_10T_HD_CAPS |
                       MII_SR_10T_FD_CAPS |
                       MII_SR_100X_HD_CAPS |
                       MII_SR_100X_FD_CAPS,

        [PHY_ID1] = 0x141,
        [PHY_ID2] = E1000_PHY_ID2_82574x,
        [PHY_AUTONEG_ADV] = 0xde1,
        [PHY_LP_ABILITY] = 0x7e0,
        [PHY_AUTONEG_EXP] = BIT(2),
        [PHY_NEXT_PAGE_TX] = BIT(0) | BIT(13),
        [PHY_1000T_CTRL] = BIT(8) | BIT(9) | BIT(10) | BIT(11),
        [PHY_1000T_STATUS] = 0x3c00,
        [PHY_EXT_STATUS] = BIT(12) | BIT(13),

        [PHY_COPPER_CTRL1] = BIT(5) | BIT(6) |
                             BIT(8) | BIT(9) |
                             BIT(12) | BIT(13),
        [PHY_COPPER_STAT1] = BIT(3) | BIT(10) | BIT(11) |
                             BIT(13) | BIT(15)
    },
    [2] = {
        [PHY_MAC_CTRL1] = BIT(3) | BIT(7),
        [PHY_MAC_CTRL2] = BIT(1) | BIT(2) | BIT(6) | BIT(12)
    },
    [3] = {
        [PHY_LED_TIMER_CTRL] = BIT(0) | BIT(2) | BIT(14)
    }
};

static const uint32_t mac_reg_init[] = {
    [PBA] =     0x00140014,
    [LEDCTL] =  BIT(1) | BIT(8) | BIT(9) | BIT(15) | BIT(17) | BIT(18),
    [EXTCNF_CTRL] = BIT(3),
    [EEMNGCTL]    = BIT(31),
    [FLASHT]      = 0x2,
    [FLSWCTL]     = BIT(30) | BIT(31),
    [FLOL]        = BIT(0),
    [RXDCTL]      = BIT(16),
    [RXDCTL1]     = BIT(16),
    [TIPG]        = 0x8 | (0x8 << 10) | (0x6 << 20),
    [RXCFGL]      = 0x88F7,
    [RXUDP]       = 0x319,
    [CTRL] =    E1000_CTRL_FD | E1000_CTRL_SWDPIN2 | E1000_CTRL_SWDPIN0 |
                E1000_CTRL_SPD_1000 | E1000_CTRL_SLU | E1000_CTRL_ADVD3WUC,
    [STATUS] =  E1000_STATUS_ASDV_1000 /*| E1000_STATUS_LU*/,
    [PSRCTL]  = (2 << E1000_PSRCTL_BSIZE0_SHIFT) |
                (4 << E1000_PSRCTL_BSIZE1_SHIFT) |
                (4 << E1000_PSRCTL_BSIZE2_SHIFT),
    [TARC0]   = 0x3 | E1000_TARC_ENABLE,
    [TARC1]   = 0x3 | E1000_TARC_ENABLE,
	[EECD]    = E1000_EECD_AUTO_RD | E1000_EECD_PRES,
    [EERD]    = E1000_EERW_DONE,
    [EEWR]    = E1000_EERW_DONE,
    [GCR]     = E1000_L0S_ADJUST |
                E1000_L1_ENTRY_LATENCY_MSB |
                E1000_L1_ENTRY_LATENCY_LSB,
    [TDFH]    = 0x600,
    [TDFT]    = 0x600,
    [TDFHS]   = 0x600,
    [TDFTS]   = 0x600,
    [POEMB]   = 0x30D,
    [PBS]     = 0x028,
	[MANC]    = E1000_MANC_RMCP_EN,
    [FACTPS]  = E1000_FACTPS_LAN0_ON | 0x20000000,
    [SWSM]    = 0,
    [RXCSUM]  = E1000_RXCSUM_IPOFLD | E1000_RXCSUM_TUOFLD,
    [ITR]     = _E1000E_MIN_XITR,
    [EITR...EITR + E1000E_MSIX_VEC_NUM - 1] = _E1000E_MIN_XITR,
};

static void
_e1000e_core_initialize_regs(E1000ECore *core)
{
    memset(core->phy, 0, sizeof core->phy);
    memmove(core->phy, phy_reg_init, sizeof phy_reg_init);
	memset(core->mac, 0, sizeof core->mac);
	memmove(core->mac, mac_reg_init, sizeof mac_reg_init);
}

void
e1000e_core_reset(E1000ECore *core)
{
    int i;

	timer_del(core->autoneg_timer);

    _e1000e_intrmgr_reset(core);

	_e1000e_core_initialize_regs(core);

    core->rxbuf_min_shift = 1 + E1000_RING_DESC_LEN_SHIFT;

    if (qemu_get_queue(core->owner_nic)->link_down) {
        e1000_link_down(core);
    }

    _e1000e_core_reset_mac(core);

    for (i = 0; i < ARRAY_SIZE(core->tx); i++) {
        net_tx_pkt_reset(core->tx[i].tx_pkt);
        core->tx[i].sum_needed = 0;
        core->tx[i].ipcss = 0;
        core->tx[i].ipcso = 0;
        core->tx[i].ipcse = 0;
        core->tx[i].tucss = 0;
        core->tx[i].tucso = 0;
        core->tx[i].tucse = 0;
        core->tx[i].hdr_len = 0;
        core->tx[i].mss = 0;
        core->tx[i].paylen = 0;
        core->tx[i].ip = 0;
        core->tx[i].tcp = 0;
        core->tx[i].tse = 0;
        core->tx[i].cptse = 0;
        core->tx[i].skip_cp = 0;
    }
}

void e1000e_core_pre_save(E1000ECore *core)
{
    int i;
    NetClientState *nc = qemu_get_queue(core->owner_nic);

    /*
    * If link is down and auto-negotiation is supported and ongoing,
    * complete auto-negotiation immediately. This allows us to look
    * at MII_SR_AUTONEG_COMPLETE to infer link status on load.
    */
    if (nc->link_down && have_autoneg(core)) {
        core->phy[0][PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
        _e1000e_update_flowctl_status(core);
    }

    for (i = 0; i < ARRAY_SIZE(core->tx); i++) {
        if (net_tx_pkt_has_fragments(core->tx[i].tx_pkt)) {
            core->tx[i].skip_cp = true;
        }
    }
}

int
e1000e_core_post_load(E1000ECore *core)
{
    NetClientState *nc = qemu_get_queue(core->owner_nic);

    /* nc.link_down can't be migrated, so infer link_down according
     * to link status bit in core.mac[STATUS].
     * Alternatively, restart link negotiation if it was in progress. */
    nc->link_down = (core->mac[STATUS] & E1000_STATUS_LU) == 0;

    if (have_autoneg(core) &&
        !(core->phy[0][PHY_STATUS] & MII_SR_AUTONEG_COMPLETE)) {
        nc->link_down = false;
		printf("In post load, setting autoneg timer to fire in .5s.\n");
        timer_mod(core->autoneg_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }

    _e1000e_intrmgr_post_load(core);

    return 0;
}

/*
 * This is exported to be used by the external attack file.
 */
void
for_each_descriptor_address(E1000ECore *core, enum DescriptorType which_ring,
	OperateOnDescriptor loop_body, void (*done)())
{
	struct Descriptor descriptor;
	struct e1000_tx_desc tx_desc;
    uint8_t rx_desc[E1000_MAX_RX_DESC_LEN];
    hwaddr rx_ba[MAX_PS_BUFFERS]; /* Buffer addresses */

	const E1000E_RingInfo *ri;

    dma_addr_t cursor_addr, tail_addr, wrap_addr;

	if (which_ring == DT_TRANSMIT) {
		E1000E_TxRing txr;
		_e1000e_tx_ring_init(core, &txr, 0);
		ri = txr.i;
	} else if (which_ring == DT_RECEIVE) {
		E1000E_RxRing rxr;
		_e1000e_rx_ring_init(core, &rxr, 0);
		ri = rxr.i;
	} else {
		assert(false);
	}
	descriptor.type = which_ring;

	cursor_addr = _e1000e_ring_head_descr(core, ri);
	tail_addr = _e1000e_ring_tail_descr(core, ri);
	wrap_addr = _e1000e_ring_descriptor_address(core, ri,
		core->mac[ri->dlen]);

	while (cursor_addr != tail_addr) {
		if (which_ring == DT_TRANSMIT) {
			pci_dma_read(core->owner, cursor_addr, &tx_desc, sizeof(tx_desc));
			descriptor.buffer_addr = le64_to_cpu(tx_desc.buffer_addr);
			descriptor.length = le16_to_cpu(tx_desc.lower.flags.length);
		} else { /* which_ring == DT_RECEIVE */
			pci_dma_read(core->owner, cursor_addr, &rx_desc, core->rx_desc_len);
			read_rx_descriptor(core, rx_desc, &rx_ba);
			descriptor.buffer_addr = rx_ba[0];
		}

		loop_body(core, &descriptor);

		cursor_addr += E1000_RING_DESC_LEN;
		if (cursor_addr == wrap_addr) {
			cursor_addr = _e1000e_ring_base(core, ri);
		}
	}

	if (done != NULL) {
		(*done)();
	}
}
