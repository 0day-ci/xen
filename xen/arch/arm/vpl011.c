/*
 * arch/arm/vpl011.c
 *
 * Virtual PL011 UART
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/errno.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/vpl011.h>
#include <public/io/console.h>
#include <asm-arm/pl011-uart.h>

unsigned int vpl011_reg_mask[] = {0xff, 0xffff, 0xffffffff};

static void vgic_inject_vpl011_spi(struct domain *d)
{
    struct vpl011_s *vpl011 = &d->arch.vpl011;

    if ( (vpl011->uartris & vpl011->uartimsc) )
        vgic_vcpu_inject_spi(d, GUEST_VPL011_SPI);
}

static void vpl011_read_data(struct domain *d, uint8_t *data)
{
    unsigned long flags;
    struct vpl011_s *vpl011 = &d->arch.vpl011;
    struct xencons_interface *intf = vpl011->ring_buf;

    /*
     * Initialize the data so that even if there is no data in ring buffer
     * 0 is returned.
     */
    *data = 0;

    VPL011_LOCK(d, flags);

    /*
     * It is expected that there will be data in the ring buffer when this
     * function is called since the guest is expected to read the data register
     * only if the TXFE flag is not set.
     * If the guest still does read when TXFE bit is set then 0 will be returned.
     */
    if ( !VPL011_IN_RING_EMPTY(intf) )
    {
        uint32_t in_cons = intf->in_cons;
        *data = intf->in[MASK_XENCONS_IDX(in_cons, intf->in)];
        smp_mb();
        intf->in_cons = in_cons + 1;
    }

    if ( VPL011_IN_RING_EMPTY(intf) )
    {
        vpl011->uartfr |= (RXFE);
        vpl011->uartris &= ~(RXI);
    }
    vpl011->uartfr &= ~(RXFF);
    VPL011_UNLOCK(d, flags);

    notify_via_xen_event_channel(d, vpl011->evtchn);
}

static void vpl011_write_data(struct domain *d, uint8_t data)
{
    unsigned long flags;
    struct vpl011_s *vpl011 = &d->arch.vpl011;
    struct xencons_interface *intf = vpl011->ring_buf;

    VPL011_LOCK(d, flags);

    /*
     * It is expected that the ring is not full when this function is called
     * as the guest is expected to write to the data register only when the
     * TXFF flag is not set.
     * In case the guest does write even when the TXFF flag is set then the
     * data will be silently dropped.
     */
    if ( !VPL011_OUT_RING_FULL(intf) )
    {
        uint32_t out_prod = intf->out_prod;
        intf->out[MASK_XENCONS_IDX(out_prod, intf->out)] = data;
        smp_wmb();
        intf->out_prod = out_prod + 1;
    }

    if ( VPL011_OUT_RING_FULL(intf) )
    {
        vpl011->uartfr |= (TXFF);
        vpl011->uartris &= ~(TXI);
    }

    vpl011->uartfr |= (BUSY);

    vpl011->uartfr &= ~(TXFE);

    VPL011_UNLOCK(d, flags);

    notify_via_xen_event_channel(d, vpl011->evtchn);
}

static int vpl011_mmio_read(struct vcpu *v, mmio_info_t *info, register_t *r, void *priv)
{
    uint8_t ch;
    struct hsr_dabt dabt = info->dabt;
    int vpl011_reg = (int)(info->gpa - GUEST_PL011_BASE);
    struct vpl011_s *vpl011 = &v->domain->arch.vpl011;

    switch ( vpl011_reg )
    {
    case DR:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
        vpl011_read_data(v->domain, &ch);
        *r = ch;
        break;

    case RSR:
        if ( !VALID_BW_SIZE(dabt.size) ) goto bad_width;

        /* It always returns 0 as there are no physical errors. */
        *r = 0;
        break;

    case FR:
        if ( !VALID_BW_SIZE(dabt.size) ) goto bad_width;
        *r = (vpl011->uartfr & vpl011_reg_mask[dabt.size]);
        break;

    case RIS:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
        *r = (vpl011->uartris & vpl011_reg_mask[dabt.size]);
        break;

    case MIS:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
        *r = (vpl011->uartris &
                            vpl011->uartimsc & vpl011_reg_mask[dabt.size]);
        break;

    case IMSC:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
        *r = (vpl011->uartimsc & vpl011_reg_mask[dabt.size]);
        break;

    case ICR:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;

        /* Only write is valid. */
        return 0;

    default:
        gprintk(XENLOG_ERR, "vpl011: unhandled read r%d offset %#08x\n",
                               dabt.reg, vpl011_reg);
        return 0;
    }

    return 1;

bad_width:
    gprintk(XENLOG_ERR, "vpl011: bad read width %d r%d offset %#08x\n",
                       dabt.size, dabt.reg, vpl011_reg);
    domain_crash_synchronous();
    return 0;

}

static int vpl011_mmio_write(struct vcpu *v, mmio_info_t *info, register_t r, void *priv)
{
    uint8_t ch = ((struct uartdr_reg *)&r)->data;
    struct hsr_dabt dabt = info->dabt;
    int vpl011_reg = (int)(info->gpa - GUEST_PL011_BASE);
    struct vpl011_s *vpl011 = &v->domain->arch.vpl011;

    switch ( vpl011_reg )
    {
    case DR:

        if ( !VALID_BW_SIZE(dabt.size) ) goto bad_width;
        vpl011_write_data(v->domain, ch);
        break;

    case RSR: /* Nothing to clear. */
        if ( !VALID_BW_SIZE(dabt.size) ) goto bad_width;
        break;

    case FR:
        goto write_ignore;
    case RIS:
    case MIS:
        goto word_write_ignore;

    case IMSC:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
        vpl011->uartimsc = (r & vpl011_reg_mask[dabt.size]);
        vgic_inject_vpl011_spi(v->domain);
        break;

    case ICR:
        if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
        vpl011->uartris &= ~(r & vpl011_reg_mask[dabt.size]);
        vgic_inject_vpl011_spi(v->domain);
        break;

    default:
        gprintk(XENLOG_ERR, "vpl011: unhandled write r%d offset %#08x\n",
                               dabt.reg, vpl011_reg);
        return 0;
    }

    return 1;

write_ignore:
    if ( !VALID_BW_SIZE(dabt.size) ) goto bad_width;
    return 1;

word_write_ignore:
    if ( !VALID_W_SIZE(dabt.size) ) goto bad_width;
    return 1;

bad_width:
    gprintk(XENLOG_ERR, "vpl011: bad write width %d r%d offset %#08x\n",
                       dabt.size, dabt.reg, vpl011_reg);
    domain_crash_synchronous();
    return 0;

}

static const struct mmio_handler_ops vpl011_mmio_handler = {
    .read = vpl011_mmio_read,
    .write = vpl011_mmio_write,
};

int vpl011_map_guest_page(struct domain *d, unsigned long pfn)
{
    struct vpl011_s *vpl011 = &d->arch.vpl011;

    /* Map the guest PFN to Xen address space. */
    return prepare_ring_for_helper(d,
                                   pfn,
                                   &vpl011->ring_page,
                                   &vpl011->ring_buf);
}

static void vpl011_data_avail(struct domain *d)
{
    unsigned long flags;
    struct vpl011_s *vpl011 = &d->arch.vpl011;
    struct xencons_interface *intf = vpl011->ring_buf;
    uint32_t in_ring_depth, out_ring_depth;

    VPL011_LOCK(d, flags);

    in_ring_depth = intf->in_prod - intf->in_cons;
    out_ring_depth = intf->out_prod - intf->out_cons;

    /* Update the uart rx state if the buffer is not empty. */
    if ( in_ring_depth != 0 )
    {
        vpl011->uartfr &= ~(RXFE);
        if ( in_ring_depth == VPL011_RING_MAX_DEPTH(intf, in) )
            vpl011->uartfr |= (RXFF);
        vpl011->uartris |= (RXI);
    }

    /* Update the uart tx state if the buffer is not full. */
    if ( out_ring_depth != VPL011_RING_MAX_DEPTH(intf, out) )
    {
        vpl011->uartfr &= ~(TXFF);
        vpl011->uartris |= (TXI);
        if ( out_ring_depth == 0 )
        {
            vpl011->uartfr &= ~(BUSY);
            vpl011->uartfr |= (TXFE);
        }
    }

    VPL011_UNLOCK(d, flags);

    vgic_inject_vpl011_spi(d);
}


static void vpl011_notification(struct vcpu *v, unsigned int port)
{
    vpl011_data_avail(v->domain);
}

int domain_vpl011_init(struct domain *d, struct xen_arch_domainconfig *config)
{
    int rc;
    struct vpl011_s *vpl011 = &d->arch.vpl011;

    rc = alloc_unbound_xen_event_channel(d, 0, config->console_domid,
                                         vpl011_notification);
    if (rc < 0)
    {
        return rc;
    }

    vpl011->evtchn = rc;
    rc = vgic_reserve_virq(d, GUEST_VPL011_SPI);
    if ( !rc )
    {
        free_xen_event_channel(d, vpl011->evtchn);
        vpl011->evtchn = -1;
        return rc;
    }
    register_mmio_handler(d, &vpl011_mmio_handler, GUEST_PL011_BASE, GUEST_PL011_SIZE, NULL);
    spin_lock_init(&vpl011->lock);

    vpl011->initialized = true;

    return 0;
}

void domain_vpl011_deinit(struct domain *d)
{
    struct vpl011_s *vpl011 = &d->arch.vpl011;

    if ( vpl011->initialized )
    {
        free_xen_event_channel(d, vpl011->evtchn);
        destroy_ring_for_helper(&vpl011->ring_buf, vpl011->ring_page);
    }
    vpl011->initialized = false;
}
