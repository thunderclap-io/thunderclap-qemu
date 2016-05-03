/*
* QEMU INTEL 82574 GbE NIC emulation
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
#include "pcie-debug.h"

#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "net/tap.h"
#include "sysemu/sysemu.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"

#include "hw/net/e1000_regs.h"

#include "e1000e_core.h"

#include "trace.h"

#define TYPE_E1000E "e1000e"
#define E1000E(obj) OBJECT_CHECK(E1000EState, (obj), TYPE_E1000E)

typedef struct {
    PCIDevice parent_obj;
    NICState *nic;
    NICConf conf;

    MemoryRegion mmio;
    MemoryRegion flash;
    MemoryRegion io;
    MemoryRegion msix;

    uint32_t ioaddr;

    uint16_t subsys_ven;
    uint16_t subsys;

    uint16_t subsys_ven_used;
    uint16_t subsys_used;

    uint32_t intr_state;
    bool use_vnet;

    E1000ECore core;

} E1000EState;

#define E1000E_MMIO_IDX     0
#define E1000E_FLASH_IDX    1
#define E1000E_IO_IDX       2
#define E1000E_MSIX_IDX     3

#define E1000E_MMIO_SIZE    (128*1024)
#define E1000E_FLASH_SIZE   (128*1024)
#define E1000E_IO_SIZE      (32)
#define E1000E_MSIX_SIZE    (16*1024)

#define E1000E_MSIX_TABLE   (0x0000)
#define E1000E_MSIX_PBA     (0x2000)

#define E1000E_USE_MSI     BIT(0)
#define E1000E_USE_MSIX    BIT(1)

static uint64_t
e1000e_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    E1000EState *s = opaque;
    return e1000e_core_read(&s->core, addr, size);
}

static void
e1000e_mmio_write(void *opaque, hwaddr addr,
                  uint64_t val, unsigned size)
{
    E1000EState *s = opaque;
    e1000e_core_write(&s->core, addr, val, size);
}

static uint64_t
e1000e_flash_read(void *opaque, hwaddr addr, unsigned size)
{
    trace_e1000e_wrn_flash_read(addr);
    return 0;
}

static void
e1000e_flash_write(void *opaque, hwaddr addr,
                  uint64_t val, unsigned size)
{
    trace_e1000e_wrn_flash_write(addr, val);
}

static bool
_e1000e_io_get_reg_index(E1000EState *s, uint32_t *idx)
{
    if (s->ioaddr < 0x1FFFF) {
        *idx = s->ioaddr;
        return true;
    }

    if (s->ioaddr < 0x7FFFF) {
        trace_e1000e_wrn_io_addr_undefined(s->ioaddr);
        return false;
    }

    if (s->ioaddr < 0xFFFFF) {
        trace_e1000e_wrn_io_addr_flash(s->ioaddr);
        return false;
    }

    trace_e1000e_wrn_io_addr_unknown(s->ioaddr);
    return false;
}

static uint64_t
e1000e_io_read(void *opaque, hwaddr addr, unsigned size)
{
    E1000EState *s = opaque;
    uint32_t idx;
    uint64_t val;

    switch (addr) {
    case E1000_IOADDR:
        trace_e1000e_io_read_addr(s->ioaddr);
        return s->ioaddr;
    case E1000_IODATA:
        if (_e1000e_io_get_reg_index(s, &idx)) {
            val = e1000e_core_read(&s->core, idx, sizeof(val));
            trace_e1000e_io_read_data(idx, val);
            return val;
        }
        return 0;
    default:
        trace_e1000e_wrn_io_read_unknown(addr);
        return 0;
    }
}

static void
e1000e_io_write(void *opaque, hwaddr addr,
                uint64_t val, unsigned size)
{
    E1000EState *s = opaque;
    uint32_t idx;

    switch (addr) {
    case E1000_IOADDR:
        trace_e1000e_io_write_addr(val);
        s->ioaddr = (uint32_t) val;
        return;
    case E1000_IODATA:
        if (_e1000e_io_get_reg_index(s, &idx)) {
            trace_e1000e_io_write_data(idx, val);
            e1000e_core_write(&s->core, idx, val, sizeof(val));
        }
        return;
    default:
        trace_e1000e_wrn_io_write_unknown(addr);
        return;
    }
}

static const MemoryRegionOps mmio_ops = {
    .read = e1000e_mmio_read,
    .write = e1000e_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps flash_ops = {
    .read = e1000e_flash_read,
    .write = e1000e_flash_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps io_ops = {
    .read = e1000e_io_read,
    .write = e1000e_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static int
_e1000e_can_receive(NetClientState *nc)
{
    E1000EState *s = qemu_get_nic_opaque(nc);
    return e1000e_can_receive(&s->core);
}

static ssize_t
_e1000e_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    E1000EState *s = qemu_get_nic_opaque(nc);
    return e1000e_receive_iov(&s->core, iov, iovcnt);
}

static ssize_t
_e1000e_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    E1000EState *s = qemu_get_nic_opaque(nc);
    return e1000e_receive(&s->core, buf, size);
}

static void
e1000e_set_link_status(NetClientState *nc)
{
    E1000EState *s = qemu_get_nic_opaque(nc);
    e1000e_core_set_link_status(&s->core);
}

static NetClientInfo net_e1000e_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = _e1000e_can_receive,
    .receive = _e1000e_receive,
    .receive_iov = _e1000e_receive_iov,
    .link_status_changed = e1000e_set_link_status,
};

/*
* EEPROM (NVM) contents documented in Table 36, section 6.1.
*/
static const uint16_t e1000e_eeprom_template[64] = {
  /*        Address        |    Compat.    | ImVer |   Compat.     */
    0x0000, 0x0000, 0x0000, 0x0420, 0xf746, 0x2010, 0xffff, 0xffff,
  /*      PBA      |ICtrl1 | SSID  | SVID  | DevID |-------|ICtrl2 */
    0x0000, 0x0000, 0x026b, 0x0000, 0x8086, 0x0000, 0x0000, 0x8058,
  /*    NVM words 1,2,3    |-------------------------------|PCI-EID*/
    0x0000, 0x2001, 0x7e7c, 0xffff, 0x1000, 0x00c8, 0x0000, 0x2704,
  /* PCIe Init. Conf 1,2,3 |PCICtrl|PHY|LD1|-------| RevID | LD0,2 */
    0x6cc9, 0x3150, 0x070e, 0x460b, 0x2d84, 0x0100, 0xf000, 0x0706,
  /* FLPAR |FLANADD|LAN-PWR|FlVndr |ICtrl3 |APTSMBA|APTRxEP|APTSMBC*/
    0x6000, 0x0080, 0x0f04, 0x7fff, 0x4f01, 0xc600, 0x0000, 0x20ff,
  /* APTIF | APTMC |APTuCP |LSWFWID|MSWFWID|NC-SIMC|NC-SIC | VPDP  */
    0x0028, 0x0003, 0x0000, 0x0000, 0x0000, 0x0003, 0x0000, 0xffff,
  /*                            SW Section                         */
    0x0100, 0xc000, 0x121c, 0xc007, 0xffff, 0xffff, 0xffff, 0xffff,
  /*                      SW Section                       |CHKSUM */
    0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x0120, 0xffff, 0x0000,
};

static void _e1000e_core_reinitialize(E1000EState *s)
{
    s->core.owner = &s->parent_obj;
    s->core.owner_nic = s->nic;
}

static void
_e1000e_init_msi(E1000EState *s)
{
    int res;

    res = msi_init(PCI_DEVICE(s),
                   0xD0,   /* MSI capability offset              */
                   1,      /* MAC MSI interrupts                 */
                   true,   /* 64-bit message addresses supported */
                   false); /* Per vector mask supported          */

    if (res > 0) {
        s->intr_state |= E1000E_USE_MSI;
    } else {
        trace_e1000e_msi_init_fail(res);
    }
}

static void
_e1000e_cleanup_msi(E1000EState *s)
{
    if (s->intr_state & E1000E_USE_MSI) {
        msi_uninit(PCI_DEVICE(s));
    }
}

static void
_e1000e_unuse_msix_vectors(E1000EState *s, int num_vectors)
{
    int i;
    for (i = 0; i < num_vectors; i++) {
        msix_vector_unuse(PCI_DEVICE(s), i);
    }
}

static bool
_e1000e_use_msix_vectors(E1000EState *s, int num_vectors)
{
    int i;
    for (i = 0; i < num_vectors; i++) {
        int res = msix_vector_use(PCI_DEVICE(s), i);
        if (res < 0) {
            trace_e1000e_msix_use_vector_fail(i, res);
            _e1000e_unuse_msix_vectors(s, i);
            return false;
        }
    }
    return true;
}

static void
_e1000e_init_msix(E1000EState *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    int res = msix_init(PCI_DEVICE(s), E1000E_MSIX_VEC_NUM,
                        &s->msix,
                        E1000E_MSIX_IDX, E1000E_MSIX_TABLE,
                        &s->msix,
                        E1000E_MSIX_IDX, E1000E_MSIX_PBA,
                        0xA0);

    if (0 > res) {
        trace_e1000e_msix_init_fail(res);
    } else {
        if (!_e1000e_use_msix_vectors(s, E1000E_MSIX_VEC_NUM)) {
            msix_uninit(d, &s->msix, &s->msix);
        } else {
            s->intr_state |= E1000E_USE_MSIX;
        }
    }
}

static void
_e1000e_cleanup_msix(E1000EState *s)
{
    if (s->intr_state & E1000E_USE_MSIX) {
        _e1000e_unuse_msix_vectors(s, E1000E_MSIX_VEC_NUM);
        msix_uninit(PCI_DEVICE(s), &s->msix, &s->msix);
    }
}

static void
_e1000e_init_net_peer(E1000EState *s, PCIDevice *pci_dev, uint8_t *macaddr)
{
    DeviceState *dev = DEVICE(pci_dev);
    NetClientState *nc;
    int i;

    s->nic = qemu_new_nic(&net_e1000e_info, &s->conf,
        object_get_typename(OBJECT(s)), dev->id, s);

    if (s->conf.peers.queues != E1000E_NUM_QUEUES) {
        fprintf(stderr,
            "WARNING: e1000e: Device requires %d network backend "
            "queues for optimal performance. Current number of "
            "queues is %d.\n", E1000E_NUM_QUEUES, s->conf.peers.queues);
    }

    s->core.max_queue_num = s->conf.peers.queues - 1;

    trace_e1000e_mac_set_permanent(MAC_ARG(macaddr));
    memcpy(s->core.permanent_mac, macaddr, sizeof(s->core.permanent_mac));

    qemu_format_nic_info_str(qemu_get_queue(s->nic), macaddr);

    /* Setup virtio headers */
    if (s->use_vnet) {
        s->core.has_vnet = true;
    } else {
        s->core.has_vnet = false;
        return;
    }

    for (i = 0; i < s->conf.peers.queues; i++) {
        nc = qemu_get_subqueue(s->nic, i);
        if (!nc->peer || !qemu_has_vnet_hdr(nc->peer)) {
            s->core.has_vnet = false;
            trace_e1000e_cfg_support_virtio(false);
            return;
        }
    }

    trace_e1000e_cfg_support_virtio(true);

    for (i = 0; i < s->conf.peers.queues; i++) {
        nc = qemu_get_subqueue(s->nic, i);
        qemu_set_vnet_hdr_len(nc->peer, sizeof(struct virtio_net_hdr));
        qemu_using_vnet_hdr(nc->peer, true);
    }
}

static inline uint64_t
_e1000e_gen_dsn(uint8_t *mac)
{
    return (uint64_t)(mac[5])        |
           (uint64_t)(mac[4])  << 8  |
           (uint64_t)(mac[3])  << 16 |
           (uint64_t)(0x00FF)  << 24 |
           (uint64_t)(0x00FF)  << 32 |
           (uint64_t)(mac[2])  << 40 |
           (uint64_t)(mac[1])  << 48 |
           (uint64_t)(mac[0])  << 56;
}

static void e1000e_pci_realize(PCIDevice *pci_dev, Error **errp)
{
    static const uint16_t E1000E_PMRB_OFFSET = 0x0C8;
    static const uint16_t E1000E_PCIE_OFFSET = 0x0E0;
    static const uint16_t E1000E_AER_OFFSET =  0x100;
    static const uint16_t E1000E_DSN_OFFSET =  0x140;

	fprintf(stderr, "!!!!!!  Realising e1000e!\n");

    E1000EState *s = E1000E(pci_dev);
    uint8_t *macaddr;

    trace_e1000e_cb_pci_realize();

    pci_dev->config[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_dev->config[PCI_INTERRUPT_PIN] = 1;

    pci_set_word(pci_dev->config + PCI_SUBSYSTEM_VENDOR_ID, s->subsys_ven);
    pci_set_word(pci_dev->config + PCI_SUBSYSTEM_ID, s->subsys);

    s->subsys_ven_used = s->subsys_ven;
    s->subsys_used = s->subsys;

    /* Define IO/MMIO regions */
    memory_region_init_io(&s->mmio, OBJECT(s), &mmio_ops, s,
                          "e1000e-mmio", E1000E_MMIO_SIZE);
    pci_register_bar(pci_dev, E1000E_MMIO_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    memory_region_init_io(&s->flash, OBJECT(s), &flash_ops, s,
                          "e1000e-flash", E1000E_FLASH_SIZE);
    pci_register_bar(pci_dev, E1000E_FLASH_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->flash);

    memory_region_init_io(&s->io, OBJECT(s), &io_ops, s,
                          "e1000e-io", E1000E_IO_SIZE);
    pci_register_bar(pci_dev, E1000E_IO_IDX,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

    memory_region_init(&s->msix, OBJECT(s), "e1000e-msix",
                       E1000E_MSIX_SIZE);
    pci_register_bar(pci_dev, E1000E_MSIX_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->msix);

    /* Create networking backend */
    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    macaddr = s->conf.macaddr.a;

    _e1000e_init_msix(s);

    if (pcie_endpoint_cap_v1_init(pci_dev, E1000E_PCIE_OFFSET) < 0) {
        hw_error("Failed to initialize PCIe capability");
    }

    _e1000e_init_msi(s);

    if (pci_add_pm_capability(pci_dev, E1000E_PMRB_OFFSET,
                              PCI_PM_CAP_DSI) < 0) {
        hw_error("Failed to initialize PM capability");
    }

    if (pcie_aer_init(pci_dev, E1000E_AER_OFFSET) < 0) {
        hw_error("Failed to initialize AER capability");
    }

    pcie_dsn_init(pci_dev, E1000E_DSN_OFFSET,
                  _e1000e_gen_dsn(macaddr));

    _e1000e_init_net_peer(s, pci_dev, macaddr);

    /* Initialize core */
    _e1000e_core_reinitialize(s);

    e1000e_core_pci_realize(&s->core,
                           e1000e_eeprom_template,
                           sizeof(e1000e_eeprom_template),
                           macaddr);
}

static void e1000e_pci_uninit(PCIDevice *pci_dev)
{
    E1000EState *s = E1000E(pci_dev);

    trace_e1000e_cb_pci_uninit();

    e1000e_core_pci_uninit(&s->core);

    pcie_aer_exit(pci_dev);
    pcie_cap_exit(pci_dev);

    qemu_del_nic(s->nic);

    _e1000e_cleanup_msix(s);
    _e1000e_cleanup_msi(s);
}

static void e1000e_qdev_reset(DeviceState *dev)
{
    E1000EState *s = E1000E(dev);

    trace_e1000e_cb_qdev_reset();

    e1000e_core_reset(&s->core);
}

static void e1000e_pre_save(void *opaque)
{
    E1000EState *s = opaque;

    trace_e1000e_cb_pre_save();

    e1000e_core_pre_save(&s->core);
}

static int e1000e_post_load(void *opaque, int version_id)
{
    E1000EState *s = opaque;

    trace_e1000e_cb_post_load();

    if ((s->subsys != s->subsys_used) ||
        (s->subsys_ven != s->subsys_ven_used)) {
        fprintf(stderr,
            "ERROR: Cannot migrate while device properties "
            "(subsys/subsys_ven) differ");
        return -1;
    }

    return e1000e_core_post_load(&s->core);
}

static const VMStateDescription vmstate_e1000e = {
    .name = "e1000e",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = e1000e_pre_save,
    .post_load = e1000e_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCIE_DEVICE(parent_obj, E1000EState),
        VMSTATE_MSIX(parent_obj, E1000EState),

        VMSTATE_UINT32(ioaddr, E1000EState),
        VMSTATE_UINT32(intr_state, E1000EState),
        VMSTATE_UINT32(core.rxbuf_min_shift, E1000EState),
        VMSTATE_UINT8(core.rx_desc_len, E1000EState),
        VMSTATE_UINT32_ARRAY(core.rxbuf_sizes, E1000EState,
                             E1000_PSRCTL_BUFFS_PER_DESC),
        VMSTATE_UINT32(core.rx_desc_buf_size, E1000EState),
        VMSTATE_UINT16_ARRAY(core.eeprom, E1000EState, E1000E_EEPROM_SIZE),
        VMSTATE_UINT16_2DARRAY(core.phy, E1000EState,
                               E1000E_PHY_PAGES, E1000E_PHY_PAGE_SIZE),
        VMSTATE_UINT32_ARRAY(core.mac, E1000EState, E1000E_MAC_SIZE),
        VMSTATE_UINT8_ARRAY(core.permanent_mac, E1000EState, ETH_ALEN),

        VMSTATE_UINT32(core.delayed_causes, E1000EState),

        VMSTATE_UINT16(subsys, E1000EState),
        VMSTATE_UINT16(subsys_ven, E1000EState),

        VMSTATE_E1000_INTR_DELAY_TIMER(core.rdtr, E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.radv, E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.raid, E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.tadv, E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.tidv, E1000EState),

        VMSTATE_E1000_INTR_DELAY_TIMER(core.itr, E1000EState),
        VMSTATE_BOOL(core.itr_intr_pending, E1000EState),

        VMSTATE_E1000_INTR_DELAY_TIMER(core.eitr[0], E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.eitr[1], E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.eitr[2], E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.eitr[3], E1000EState),
        VMSTATE_E1000_INTR_DELAY_TIMER(core.eitr[4], E1000EState),
        VMSTATE_BOOL_ARRAY(core.eitr_intr_pending, E1000EState,
                           E1000E_MSIX_VEC_NUM),

        VMSTATE_UINT32(core.itr_guest_value, E1000EState),
        VMSTATE_UINT32_ARRAY(core.eitr_guest_value, E1000EState,
                             E1000E_MSIX_VEC_NUM),

        VMSTATE_UINT16(core.vet, E1000EState),

        VMSTATE_UINT8(core.tx[0].sum_needed, E1000EState),
        VMSTATE_UINT8(core.tx[0].ipcss, E1000EState),
        VMSTATE_UINT8(core.tx[0].ipcso, E1000EState),
        VMSTATE_UINT16(core.tx[0].ipcse, E1000EState),
        VMSTATE_UINT8(core.tx[0].tucss, E1000EState),
        VMSTATE_UINT8(core.tx[0].tucso, E1000EState),
        VMSTATE_UINT16(core.tx[0].tucse, E1000EState),
        VMSTATE_UINT8(core.tx[0].hdr_len, E1000EState),
        VMSTATE_UINT16(core.tx[0].mss, E1000EState),
        VMSTATE_UINT32(core.tx[0].paylen, E1000EState),
        VMSTATE_INT8(core.tx[0].ip, E1000EState),
        VMSTATE_INT8(core.tx[0].tcp, E1000EState),
        VMSTATE_BOOL(core.tx[0].tse, E1000EState),
        VMSTATE_BOOL(core.tx[0].cptse, E1000EState),
        VMSTATE_BOOL(core.tx[0].skip_cp, E1000EState),

        VMSTATE_UINT8(core.tx[1].sum_needed, E1000EState),
        VMSTATE_UINT8(core.tx[1].ipcss, E1000EState),
        VMSTATE_UINT8(core.tx[1].ipcso, E1000EState),
        VMSTATE_UINT16(core.tx[1].ipcse, E1000EState),
        VMSTATE_UINT8(core.tx[1].tucss, E1000EState),
        VMSTATE_UINT8(core.tx[1].tucso, E1000EState),
        VMSTATE_UINT16(core.tx[1].tucse, E1000EState),
        VMSTATE_UINT8(core.tx[1].hdr_len, E1000EState),
        VMSTATE_UINT16(core.tx[1].mss, E1000EState),
        VMSTATE_UINT32(core.tx[1].paylen, E1000EState),
        VMSTATE_INT8(core.tx[1].ip, E1000EState),
        VMSTATE_INT8(core.tx[1].tcp, E1000EState),
        VMSTATE_BOOL(core.tx[1].tse, E1000EState),
        VMSTATE_BOOL(core.tx[1].cptse, E1000EState),
        VMSTATE_BOOL(core.tx[1].skip_cp, E1000EState),

        VMSTATE_BOOL(core.has_vnet, E1000EState),

        VMSTATE_END_OF_LIST()
    }
};

static Property e1000e_properties[] = {
    DEFINE_NIC_PROPERTIES(E1000EState, conf),
    DEFINE_PROP_BOOL("vnet", E1000EState, use_vnet, true),
    DEFINE_PROP_UINT16("subsys_ven", E1000EState,
                       subsys_ven, PCI_VENDOR_ID_INTEL),
    DEFINE_PROP_UINT16("subsys", E1000EState, subsys, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static uint32_t e1000e_config_read(PCIDevice *d,
    uint32_t address, int len)
{
    if (address >= 0x1c && address <= 0x24) {
        PDBG("Addr 0x%x Returning 0.\n", address);
        return 0;
    }
    return pci_default_read_config(d, address, len);
}

static void e1000e_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *c = PCI_DEVICE_CLASS(class);

    c->config_read = e1000e_config_read;
    c->realize = e1000e_pci_realize;
    c->exit = e1000e_pci_uninit;
    c->vendor_id = PCI_VENDOR_ID_INTEL;
    c->device_id = E1000_DEV_ID_82574L;
    c->revision = 0;
    c->class_id = PCI_CLASS_NETWORK_ETHERNET;
    c->is_express = 1;

    dc->desc = "Intel 82574L GbE Controller";
    dc->reset = e1000e_qdev_reset;
    dc->vmsd = &vmstate_e1000e;
    dc->props = e1000e_properties;

    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static void e1000e_instance_init(Object *obj)
{
    E1000EState *s = E1000E(obj);
    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(obj), NULL);
}

static const TypeInfo e1000e_info = {
    .name = TYPE_E1000E,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000EState),
    .class_init = e1000e_class_init,
    .instance_init = e1000e_instance_init,
};

static void e1000e_register_types(void)
{
    type_register_static(&e1000e_info);
}

type_init(e1000e_register_types)
