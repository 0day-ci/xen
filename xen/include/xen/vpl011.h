/*
 * include/xen/vpl011.h
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

#ifndef _VPL011_H_

#define _VPL011_H_

/* helper macros */
#define VPL011_RING_DEPTH(intf,dir) (((intf)->dir ## _prod - (intf)->dir ## _cons))

#define VPL011_RING_MAX_DEPTH(intf,dir) (sizeof((intf)->dir)-1)

#define VPL011_IN_RING_EMPTY(intf) (VPL011_RING_DEPTH(intf, in) == 0)

#define VPL011_OUT_RING_EMPTY(intf) (VPL011_RING_DEPTH(intf, out) == 0)

#define VPL011_IN_RING_FULL(intf) (VPL011_RING_DEPTH(intf, in) == VPL011_RING_MAX_DEPTH(intf, in))

#define VPL011_OUT_RING_FULL(intf) (VPL011_RING_DEPTH(intf, out) == VPL011_RING_MAX_DEPTH(intf,out))

#define VPL011_LOCK(d,flags) spin_lock_irqsave(&(d)->arch.vpl011.lock, flags)
#define VPL011_UNLOCK(d,flags) spin_unlock_irqrestore(&(d)->arch.vpl011.lock, flags)

#define VALID_BW_SIZE(size) ( size == DABT_BYTE || size == DABT_HALF_WORD || size == DABT_WORD )
#define VALID_W_SIZE(size)  ( size == DABT_HALF_WORD || size == DABT_WORD )

struct uartdr_reg {
    uint8_t data;
    uint8_t error_status:4;
    uint8_t reserved1:4;
    uint16_t reserved2;
    uint32_t reserved3;
};

struct vpl011_s {
    void *ring_buf;
    struct page_info *ring_page;
    uint32_t    uartfr;     /* Flag register */
    uint32_t    uartcr;     /* Control register */
    uint32_t    uartimsc;   /* Interrupt mask register*/
    uint32_t    uarticr;    /* Interrupt clear register */
    uint32_t    uartris;    /* Raw interrupt status register */
    uint32_t    uartmis;    /* Masked interrupt register */
    spinlock_t  lock;
    bool        initialized; /* Flag which tells whether vpl011 is initialized */
    uint32_t    evtchn;
};

#ifdef CONFIG_VPL011_CONSOLE
int domain_vpl011_init(struct domain *d, struct xen_arch_domainconfig *config);
void domain_vpl011_deinit(struct domain *d);
int vpl011_map_guest_page(struct domain *d, unsigned long pfn);
#else
static inline int domain_vpl011_init(struct domain *d, struct xen_arch_domainconfig *config) { return -ENOSYS; }
static inline void domain_vpl011_deinit(struct domain *d) { }
static inline int vpl011_map_guest_page(struct domain *d, unsigned long pfn) { return -ENOSYS; }
#endif

#endif
