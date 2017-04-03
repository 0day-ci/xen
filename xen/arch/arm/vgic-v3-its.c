/*
 * xen/arch/arm/vgic-v3-its.c
 *
 * ARM Interrupt Translation Service (ITS) emulation
 *
 * Andre Przywara <andre.przywara@arm.com>
 * Copyright (c) 2016,2017 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/bitops.h>
#include <xen/config.h>
#include <xen/domain_page.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <asm/current.h>
#include <asm/mmio.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/vgic.h>
#include <asm/vgic-emul.h>

/* Data structure to describe a virtual ITS */
#define VIRT_ITS_ENABLED        0
#define VIRT_ITS_COLL_VALID     1
#define VIRT_ITS_DEV_VALID      2
#define VIRT_ITS_CMDBUF_VALID   3
struct virt_its {
    struct domain *d;
    paddr_t doorbell_address;
    spinlock_t vcmd_lock;       /* Protects the virtual command buffer. */
    uint64_t cbaser;
    uint64_t cwriter;
    uint64_t creadr;
    spinlock_t its_lock;        /* Protects the collection and device tables. */
    uint64_t baser_dev, baser_coll;
    unsigned int max_collections;
    unsigned int max_devices;
    unsigned int devid_bits;
    unsigned int intid_bits;
    unsigned long flags;
};

/*
 * An Interrupt Translation Table Entry: this is indexed by a
 * DeviceID/EventID pair and is located in guest memory.
 */
struct vits_itte
{
    uint32_t vlpi;
    uint16_t collection;
    uint16_t pad;
};

static bool its_is_enabled(struct virt_its *its)
{
    return test_bit(VIRT_ITS_ENABLED, &its->flags);
}

#define UNMAPPED_COLLECTION      ((uint16_t)~0)

/*
 * The physical address is encoded slightly differently depending on
 * the used page size: the highest four bits are stored in the lowest
 * four bits of the field for 64K pages.
 */
static paddr_t get_baser_phys_addr(uint64_t reg)
{
    if ( reg & BIT(9) )
        return (reg & GENMASK_ULL(47, 16)) |
                ((reg & GENMASK_ULL(15, 12)) << 36);
    else
        return reg & GENMASK_ULL(47, 12);
}

static int its_set_collection(struct virt_its *its, uint16_t collid,
                              uint16_t vcpu_id)
{
    paddr_t addr = get_baser_phys_addr(its->baser_coll);
    uint16_t *coll_table;

    if ( collid >= its->max_collections )
        return -ENOENT;

    coll_table = map_one_guest_page(its->d, addr + collid * sizeof(uint16_t));
    if ( !coll_table )
        return -EFAULT;

    *coll_table = vcpu_id;

    unmap_one_guest_page(coll_table);

    return 0;
}

/* Must be called with the ITS lock held. */
static struct vcpu *get_vcpu_from_collection(struct virt_its *its,
                                             uint16_t collid)
{
    paddr_t addr = get_baser_phys_addr(its->baser_coll);
    uint16_t *coll_table;
    uint16_t vcpu_id;

    if ( collid >= its->max_collections )
        return NULL;

    coll_table = map_one_guest_page(its->d, addr + collid * sizeof(uint16_t));
    if ( !coll_table )
        return NULL;

    vcpu_id = *coll_table;

    unmap_one_guest_page(coll_table);

    if ( vcpu_id == UNMAPPED_COLLECTION || vcpu_id >= its->d->max_vcpus )
        return NULL;

    return its->d->vcpu[vcpu_id];
}

/*
 * Our device table encodings:
 * Contains the guest physical address of the Interrupt Translation Table in
 * bits [51:8], and the size of it encoded in the lowest 8 bits.
 */
#define DEV_TABLE_ITT_ADDR(x) ((x) & GENMASK_ULL(51, 8))
#define DEV_TABLE_ITT_SIZE(x) (BIT(((x) & GENMASK_ULL(7, 0)) + 1))
#define DEV_TABLE_ENTRY(addr, bits)                     \
        (((addr) & GENMASK_ULL(51, 8)) | (((bits) - 1) & GENMASK_ULL(7, 0)))

/* Set the address of an ITT for a given device ID. */
static int its_set_itt_address(struct virt_its *its, uint32_t devid,
                               paddr_t itt_address, uint32_t nr_bits)
{
    paddr_t addr = get_baser_phys_addr(its->baser_dev);
    uint64_t *itt;

    if ( devid >= its->max_devices )
        return -ENOENT;

    itt = map_one_guest_page(its->d, addr + devid * sizeof(uint64_t));
    if ( !itt )
        return -EFAULT;

    *itt = DEV_TABLE_ENTRY(itt_address, nr_bits);

    unmap_one_guest_page(itt);

    return 0;
}

/*
 * Lookup the address of the Interrupt Translation Table associated with
 * a device ID and return the address of the ITTE belonging to the event ID
 * (which is an index into that table).
 */
static paddr_t its_get_itte_address(struct virt_its *its,
                                    uint32_t devid, uint32_t evid)
{
    paddr_t ret, addr = get_baser_phys_addr(its->baser_dev);
    uint64_t *itt_ptr;
    uint64_t itt;

    if ( devid >= its->max_devices )
        return INVALID_PADDR;

    itt_ptr = map_one_guest_page(its->d, addr + devid * sizeof(uint64_t));
    if ( !itt_ptr )
        return INVALID_PADDR;

    itt = read_u64_atomic(itt_ptr);

    if ( evid < DEV_TABLE_ITT_SIZE(itt) &&
         DEV_TABLE_ITT_ADDR(itt) != INVALID_PADDR )
        ret = DEV_TABLE_ITT_ADDR(itt) + evid * sizeof(struct vits_itte);
    else
        ret = INVALID_PADDR;

    unmap_one_guest_page(itt_ptr);

    return ret;
}

/*
 * Looks up a given deviceID/eventID pair on an ITS and returns a pointer to
 * the corresponding ITTE. This maps the respective guest page into Xen.
 * Once finished with handling the ITTE, call put_itte() to unmap
 * the page again.
 * Must be called with the ITS lock held.
 */
static struct vits_itte *get_itte(struct virt_its *its,
                                  uint32_t devid, uint32_t evid)
{
    paddr_t addr = its_get_itte_address(its, devid, evid);

    if ( addr == INVALID_PADDR )
        return NULL;

    return map_one_guest_page(its->d, addr);
}

/* Must be called with the ITS lock held. */
static void put_itte(struct virt_its *its, struct vits_itte *itte)
{
    unmap_one_guest_page(itte);
}

/*
 * Queries the collection and device tables to get the vCPU and virtual
 * LPI number for a given guest event. This takes care of mapping the
 * respective tables and validating the values, since we can't efficiently
 * protect the ITTs with their less-than-page-size granularity.
 * This function takes care of the locking by taking the its_lock itself, so
 * a caller shall not hold this. Upon returning, the lock is dropped again.
 */
static bool read_itte(struct virt_its *its, uint32_t devid, uint32_t evid,
                      struct vcpu **vcpu, uint32_t *vlpi)
{
    struct vits_itte *itte;
    uint16_t collid;
    uint32_t _vlpi;
    struct vcpu *_vcpu;

    spin_lock(&its->its_lock);
    itte = get_itte(its, devid, evid);
    if ( !itte )
    {
        spin_unlock(&its->its_lock);
        return false;
    }
    collid = itte->collection;
    _vlpi = itte->vlpi;
    put_itte(its, itte);

    _vcpu = get_vcpu_from_collection(its, collid);
    spin_unlock(&its->its_lock);

    if ( !_vcpu )
        return false;

    *vcpu = _vcpu;
    *vlpi = _vlpi;

    return true;
}

#define SKIP_LPI_UPDATE 1
/*
 * This function takes care of the locking by taking the its_lock itself, so
 * a caller shall not hold this. Upon returning, the lock is dropped again.
 */
static bool write_itte(struct virt_its *its, uint32_t devid, uint32_t evid,
                       uint32_t collid, uint32_t vlpi, struct vcpu **vcpu)
{
    struct vits_itte *itte;

    if ( collid >= its->max_collections )
        return false;

    if ( vlpi >= its->d->arch.vgic.nr_lpis )
        return false;

    spin_lock(&its->its_lock);
    itte = get_itte(its, devid, evid);
    if ( !itte )
    {
        spin_unlock(&its->its_lock);
        return false;
    }

    itte->collection = collid;
    if ( vlpi != SKIP_LPI_UPDATE )
        itte->vlpi = vlpi;

    if ( vcpu )
        *vcpu = get_vcpu_from_collection(its, collid);

    put_itte(its, itte);
    spin_unlock(&its->its_lock);

    return true;
}

/**************************************
 * Functions that handle ITS commands *
 **************************************/

static uint64_t its_cmd_mask_field(uint64_t *its_cmd, unsigned int word,
                                   unsigned int shift, unsigned int size)
{
    return (le64_to_cpu(its_cmd[word]) >> shift) & (BIT(size) - 1);
}

#define its_cmd_get_command(cmd)        its_cmd_mask_field(cmd, 0,  0,  8)
#define its_cmd_get_deviceid(cmd)       its_cmd_mask_field(cmd, 0, 32, 32)
#define its_cmd_get_size(cmd)           its_cmd_mask_field(cmd, 1,  0,  5)
#define its_cmd_get_id(cmd)             its_cmd_mask_field(cmd, 1,  0, 32)
#define its_cmd_get_physical_id(cmd)    its_cmd_mask_field(cmd, 1, 32, 32)
#define its_cmd_get_collection(cmd)     its_cmd_mask_field(cmd, 2,  0, 16)
#define its_cmd_get_target_addr(cmd)    its_cmd_mask_field(cmd, 2, 16, 32)
#define its_cmd_get_validbit(cmd)       its_cmd_mask_field(cmd, 2, 63,  1)

static int its_handle_clear(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *p;
    struct vcpu *vcpu;
    uint32_t vlpi;

    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        return -1;

    p = lpi_to_pending(its->d, vlpi);
    if ( !p )
        return -1;

    clear_bit(GIC_IRQ_GUEST_LPI_PENDING, &p->status);

    /* Remove a pending, but not yet injected guest IRQ. */
    clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
    gic_remove_from_queues(vcpu, vlpi);

    return 0;
}

static int its_handle_int(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *p;
    struct vcpu *vcpu;
    uint32_t vlpi;

    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        return -1;

    p = lpi_to_pending(its->d, vlpi);
    if ( !p )
        return -1;

    /*
     * If the LPI is enabled, inject it.
     * If not, store the pending state to inject it once it gets enabled later.
     */
    if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) )
        vgic_vcpu_inject_irq(vcpu, vlpi);
    else
        set_bit(GIC_IRQ_GUEST_LPI_PENDING, &p->status);

    return 0;
}

/*
 * For a given virtual LPI read the enabled bit and priority from the virtual
 * property table and update the virtual IRQ's state.
 * This takes care of removing or pushing of virtual LPIs to their VCPUs.
 */
static void update_lpi_enabled_status(struct virt_its* its,
                                      struct vcpu *vcpu, uint32_t vlpi)
{
    struct pending_irq *p = lpi_to_pending(its->d, vlpi);
    paddr_t proptable_addr;
    uint8_t *property;

    if ( !p )
        return;

    proptable_addr = its->d->arch.vgic.rdist_propbase & GENMASK_ULL(51, 12);
    property = map_one_guest_page(its->d, proptable_addr + vlpi - LPI_OFFSET);

    p->lpi_priority = *property & LPI_PROP_PRIO_MASK;

    if ( *property & LPI_PROP_ENABLED )
    {
        unsigned long flags;

        set_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        spin_lock_irqsave(&vcpu->arch.vgic.lock, flags);
        if ( !list_empty(&p->inflight) &&
             !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
            gic_raise_guest_irq(vcpu, vlpi, p->lpi_priority);
        spin_unlock_irqrestore(&vcpu->arch.vgic.lock, flags);

        /* Check whether the LPI has fired while the guest had it disabled. */
        if ( test_and_clear_bit(GIC_IRQ_GUEST_LPI_PENDING, &p->status) )
            vgic_vcpu_inject_irq(vcpu, vlpi);
    }
    else
    {
        clear_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
        gic_remove_from_queues(vcpu, vlpi);
    }

    unmap_one_guest_page(property);
}

static int its_handle_inv(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct vcpu *vcpu;
    uint32_t vlpi;

    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        return -1;

    update_lpi_enabled_status(its, vcpu, vlpi);

    return 0;
}

/*
 * INVALL updates the per-LPI configuration status for every LPI mapped to
 * a particular redistributor.
 * We iterate over all mapped LPIs in our radix tree and update those.
 */
static int its_handle_invall(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t collid = its_cmd_get_collection(cmdptr);
    struct vcpu *vcpu;
    struct pending_irq *pirqs[16];
    uint32_t vlpi = 0;
    int nr_lpis, i;

    /* We may want to revisit this implementation for DomUs. */
    ASSERT(is_hardware_domain(its->d));

    spin_lock(&its->its_lock);
    vcpu = get_vcpu_from_collection(its, collid);
    spin_unlock(&its->its_lock);

    read_lock(&its->d->arch.vgic.pend_lpi_tree_lock);

    do {
        nr_lpis = radix_tree_gang_lookup(&its->d->arch.vgic.pend_lpi_tree,
                                         (void **)pirqs, vlpi,
					 ARRAY_SIZE(pirqs));

        for ( i = 0; i < nr_lpis; i++ )
        {
            vlpi = pirqs[i]->irq;
            update_lpi_enabled_status(its, vcpu, vlpi);
        }

        /* Protect from overflow when incrementing 0xffffffff */
        if ( vlpi == ~0 || ++vlpi < its->d->arch.vgic.nr_lpis )
            break;
    } while ( nr_lpis == ARRAY_SIZE(pirqs));

    read_unlock(&its->d->arch.vgic.pend_lpi_tree_lock);

    return 0;
}

static int its_handle_mapc(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t collid = its_cmd_get_collection(cmdptr);
    uint64_t rdbase = its_cmd_mask_field(cmdptr, 2, 16, 44);

    if ( collid >= its->max_collections )
        return -1;

    if ( rdbase >= its->d->max_vcpus )
        return -1;

    spin_lock(&its->its_lock);

    if ( its_cmd_get_validbit(cmdptr) )
        its_set_collection(its, collid, rdbase);
    else
        its_set_collection(its, collid, UNMAPPED_COLLECTION);

    spin_unlock(&its->its_lock);

    return 0;
}

static int its_handle_mapd(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    unsigned int size = its_cmd_get_size(cmdptr) + 1;
    bool valid = its_cmd_get_validbit(cmdptr);
    paddr_t itt_addr = its_cmd_mask_field(cmdptr, 2, 0, 52) &
                           GENMASK_ULL(51, 8);
    int ret;

    /*
     * There is no easy and clean way for Xen to know the ITS device ID of a
     * particular (PCI) device, so we have to rely on the guest telling
     * us about it. For *now* we are just using the device ID *Dom0* uses,
     * because the driver there has the actual knowledge.
     * Eventually this will be replaced with a dedicated hypercall to
     * announce pass-through of devices.
     */
    if ( is_hardware_domain(its->d) )
    {
        /* Dom0's ITSes are mapped 1:1, so both address are the same. */
        ret = gicv3_its_map_guest_device(its->d, its->doorbell_address, devid,
                                         its->doorbell_address, devid,
                                         BIT(size), valid);
        if ( ret )
            return ret;
    }

    spin_lock(&its->its_lock);
    if ( valid )
        ret = its_set_itt_address(its, devid, itt_addr, size);
    else
        ret = its_set_itt_address(its, devid, INVALID_PADDR, 1);

    spin_unlock(&its->its_lock);

    return ret;
}

static int its_handle_mapti(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    uint32_t intid = its_cmd_get_physical_id(cmdptr);
    uint16_t collid = its_cmd_get_collection(cmdptr);
    struct pending_irq *pirq;
    struct vcpu *vcpu;

    if ( its_cmd_get_command(cmdptr) == GITS_CMD_MAPI )
        intid = eventid;

    pirq = gicv3_assign_guest_event(its->d, its->doorbell_address,
                                    devid, eventid, vcpu, intid);
    if ( !pirq )
        return -1;

    vgic_init_pending_irq(pirq, intid);
    write_lock(&its->d->arch.vgic.pend_lpi_tree_lock);
    radix_tree_insert(&its->d->arch.vgic.pend_lpi_tree, intid, pirq);
    write_unlock(&its->d->arch.vgic.pend_lpi_tree_lock);

    if ( !write_itte(its, devid, eventid, collid, intid, &vcpu) )
        return -1;

    return 0;
}

static int its_handle_movi(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    int collid = its_cmd_get_collection(cmdptr);
    struct vcpu *vcpu;

    if ( !write_itte(its, devid, eventid, collid, SKIP_LPI_UPDATE, &vcpu) )
        return -1;

    /* TODO: lookup currently-in-guest virtual IRQs and migrate them */

    gicv3_lpi_change_vcpu(its->d,
                          its->doorbell_address, devid, eventid, vcpu->vcpu_id);

    return 0;
}

static int its_handle_discard(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *pirq;
    struct vcpu *vcpu;
    uint32_t vlpi;

    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        return -1;

    pirq = lpi_to_pending(its->d, vlpi);
    if ( pirq )
    {
        clear_bit(GIC_IRQ_GUEST_QUEUED, &pirq->status);
        gic_remove_from_queues(vcpu, vlpi);
    }

    if ( !write_itte(its, devid, eventid, UNMAPPED_COLLECTION, INVALID_LPI, NULL) )
        return -1;

    gicv3_assign_guest_event(its->d, its->doorbell_address,
                             devid, eventid, NULL, 0);

    return 0;
}

#define ITS_CMD_BUFFER_SIZE(baser)      ((((baser) & 0xff) + 1) << 12)

static int vgic_its_handle_cmds(struct domain *d, struct virt_its *its,
                                uint32_t writer)
{
    paddr_t cmdbuf_addr = its->cbaser & GENMASK_ULL(51, 12);
    void *cmdbuf = NULL;
    uint64_t *cmdptr;

    if ( writer >= ITS_CMD_BUFFER_SIZE(its->cbaser) )
        return -1;

    spin_lock(&its->vcmd_lock);

    while ( its->creadr != writer )
    {
        int ret;

        ret = 0;

        /*
         * If this is the first command we handle or we cross a page boundary,
         * we need to (re)map the command buffer.
         */
        if ( !cmdbuf || (its->creadr & ~PAGE_MASK) == 0 )
        {
            if ( cmdbuf )
                unmap_one_guest_page(cmdbuf);
            cmdbuf = map_one_guest_page(d,
                                       (cmdbuf_addr + its->creadr) & PAGE_MASK);
            if ( !cmdbuf )
                return -EFAULT;
        }
        cmdptr = cmdbuf + (its->creadr & ~PAGE_MASK);

        switch ( its_cmd_get_command(cmdptr) )
        {
        case GITS_CMD_CLEAR:
            ret = its_handle_clear(its, cmdptr);
            break;
        case GITS_CMD_DISCARD:
            ret = its_handle_discard(its, cmdptr);
            break;
        case GITS_CMD_INT:
            ret = its_handle_int(its, cmdptr);
            break;
        case GITS_CMD_INV:
            ret = its_handle_inv(its, cmdptr);
	    break;
        case GITS_CMD_INVALL:
            ret = its_handle_invall(its, cmdptr);
	    break;
        case GITS_CMD_MAPC:
            ret = its_handle_mapc(its, cmdptr);
            break;
        case GITS_CMD_MAPD:
            ret = its_handle_mapd(its, cmdptr);
	    break;
        case GITS_CMD_MAPI:
        case GITS_CMD_MAPTI:
            ret = its_handle_mapti(its, cmdptr);
            break;
        case GITS_CMD_MOVALL:
            gdprintk(XENLOG_G_INFO, "ITS: ignoring MOVALL command\n");
            break;
        case GITS_CMD_MOVI:
            ret = its_handle_movi(its, cmdptr);
            break;
        case GITS_CMD_SYNC:
            /* We handle ITS commands synchronously, so we ignore SYNC. */
	    break;
        default:
            gdprintk(XENLOG_WARNING, "ITS: unhandled ITS command %lu\n",
                     its_cmd_get_command(cmdptr));
            break;
        }

        its->creadr += ITS_CMD_SIZE;
        if ( its->creadr == ITS_CMD_BUFFER_SIZE(its->cbaser) )
            its->creadr = 0;

        if ( ret )
            gdprintk(XENLOG_WARNING,
                     "ITS: ITS command error %d while handling command %lu\n",
                     ret, its_cmd_get_command(cmdptr));
    }
    its->cwriter = writer;

    spin_unlock(&its->vcmd_lock);

    if ( cmdbuf )
        unmap_one_guest_page(cmdbuf);

    return 0;
}

/*****************************
 * ITS registers read access *
 *****************************/

static int vgic_v3_its_mmio_read(struct vcpu *v, mmio_info_t *info,
                                 register_t *r, void *priv)
{
    struct virt_its *its = priv;
    uint64_t reg;

    switch ( info->gpa & 0xffff )
    {
    case VREG32(GITS_CTLR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        if ( its_is_enabled(its) )
            reg = GITS_CTLR_ENABLE | BIT(31);
        else
            reg = BIT(31);
        *r = vgic_reg32_extract(reg, info);
        break;
    case VREG32(GITS_IIDR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GITS_IIDR_VALUE, info);
        break;
    case VREG64(GITS_TYPER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        reg = GITS_TYPER_PHYSICAL;
        reg |= (sizeof(struct vits_itte) - 1) << GITS_TYPER_ITT_SIZE_SHIFT;
        reg |= (its->intid_bits - 1) << GITS_TYPER_IDBITS_SHIFT;
        reg |= (its->devid_bits - 1) << GITS_TYPER_DEVIDS_SHIFT;
        *r = vgic_reg64_extract(reg, info);
        break;
    case VREG64(GITS_CBASER):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(its->cbaser, info);
        break;
    case VREG64(GITS_CWRITER):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(its->cwriter, info);
        break;
    case VREG64(GITS_CREADR):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(its->creadr, info);
        break;
    case VREG64(GITS_BASER0):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(its->baser_dev, info);
        break;
    case VREG64(GITS_BASER1):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(its->baser_coll, info);
        break;
    case VRANGE64(GITS_BASER2, GITS_BASER7):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(0, info);
        break;
    case VREG32(GITS_PIDR2):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GICV3_GICD_PIDR2, info);
        break;
    }

    return 1;

bad_width:
    domain_crash_synchronous();

    return 0;
}

/******************************
 * ITS registers write access *
 ******************************/

static int its_baser_table_size(uint64_t baser)
{
    int page_size = 0;

    switch ( (baser >> 8) & 3 )
    {
    case 0: page_size = SZ_4K; break;
    case 1: page_size = SZ_16K; break;
    case 2:
    case 3: page_size = SZ_64K; break;
    }

    return page_size * ((baser & GENMASK_ULL(7, 0)) + 1);
}

static int its_baser_nr_entries(uint64_t baser)
{
    int entry_size = ((baser & GENMASK_ULL(52, 48)) >> 48) + 1;

    return its_baser_table_size(baser) / entry_size;
}

static int vgic_its_map_cmdbuf(struct virt_its *its)
{
    if ( !(its->cbaser & GITS_VALID_BIT) )
        return -EBUSY;

    return get_guest_pages(its->d, its->cbaser & GENMASK_ULL(51, 12),
                           (its->cbaser & 0xff) + 1);
}

static void vgic_its_unmap_cmdbuf(struct virt_its *its)
{
    int nr_pages = (its->cbaser & 0xff) + 1;

    put_guest_pages(its->d, its->cbaser & GENMASK_ULL(51, 12), nr_pages);
}

static int vgic_its_map_its_table(struct virt_its *its, uint64_t reg)
{
    unsigned int i, table_size = its_baser_table_size(reg);
    paddr_t guest_addr = get_baser_phys_addr(reg);

    if ( !(reg & GITS_VALID_BIT) )
        return -EINVAL;

    get_guest_pages(its->d, guest_addr, table_size >> PAGE_SHIFT);
    /* Map each page one by one to check and clear it. */
    for ( i = 0; i < table_size >> PAGE_SHIFT; i++ )
    {
        void *ptr = map_one_guest_page(its->d, guest_addr + (i << PAGE_SHIFT));

        if ( !ptr )
            return -EFAULT;

        memset(ptr, 0, table_size);
        unmap_one_guest_page(ptr);
    }

    return 0;
}

static void vgic_its_unmap_its_table(struct domain *d, uint64_t reg)
{
    put_guest_pages(d, get_baser_phys_addr(reg),
                    its_baser_table_size(reg) >> PAGE_SHIFT);
}

static bool vgic_v3_its_change_its_status(struct virt_its *its, bool status)
{
    bool ret = true;

    if ( !status )
    {
        clear_bit(VIRT_ITS_ENABLED, &its->flags);
        return false;
    }

    if ( !vgic_its_map_cmdbuf(its) )
        set_bit(VIRT_ITS_CMDBUF_VALID, &its->flags);
    else
    {
        clear_bit(VIRT_ITS_CMDBUF_VALID, &its->flags);
        ret = false;
    }

    if ( !vgic_its_map_its_table(its, its->baser_dev) )
        set_bit(VIRT_ITS_DEV_VALID, &its->flags);
    else
    {
        clear_bit(VIRT_ITS_DEV_VALID, &its->flags);
        ret = false;
    }

    if ( !vgic_its_map_its_table(its, its->baser_coll) )
        set_bit(VIRT_ITS_COLL_VALID, &its->flags);
    else
    {
        clear_bit(VIRT_ITS_COLL_VALID, &its->flags);
        ret = false;
    }

    if ( ret )
        set_bit(VIRT_ITS_ENABLED, &its->flags);
    else
        clear_bit(VIRT_ITS_ENABLED, &its->flags);

    return ret;
}

static void sanitize_its_base_reg(uint64_t *reg)
{
    uint64_t r = *reg;

    /* Avoid outer shareable. */
    switch ( (r >> GITS_BASER_SHAREABILITY_SHIFT) & 0x03 )
    {
    case GIC_BASER_OuterShareable:
        r = r & ~GITS_BASER_SHAREABILITY_MASK;
        r |= GIC_BASER_InnerShareable << GITS_BASER_SHAREABILITY_SHIFT;
        break;
    default:
        break;
    }

    /* Avoid any inner non-cacheable mapping. */
    switch ( (r >> GITS_BASER_INNER_CACHEABILITY_SHIFT) & 0x07 )
    {
    case GIC_BASER_CACHE_nCnB:
    case GIC_BASER_CACHE_nC:
        r = r & ~GITS_BASER_INNER_CACHEABILITY_MASK;
        r |= GIC_BASER_CACHE_RaWb << GITS_BASER_INNER_CACHEABILITY_SHIFT;
        break;
    default:
        break;
    }

    /* Only allow non-cacheable or same-as-inner. */
    switch ( (r >> GITS_BASER_OUTER_CACHEABILITY_SHIFT) & 0x07 )
    {
    case GIC_BASER_CACHE_SameAsInner:
    case GIC_BASER_CACHE_nC:
        break;
    default:
        r = r & ~GITS_BASER_OUTER_CACHEABILITY_MASK;
        r |= GIC_BASER_CACHE_nC << GITS_BASER_OUTER_CACHEABILITY_SHIFT;
        break;
    }

    *reg = r;
}

static int vgic_v3_its_mmio_write(struct vcpu *v, mmio_info_t *info,
                                  register_t r, void *priv)
{
    struct domain *d = v->domain;
    struct virt_its *its = priv;
    uint64_t reg;
    uint32_t reg32, ctlr;

    switch ( info->gpa & 0xffff )
    {
    case VREG32(GITS_CTLR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;

        ctlr = its_is_enabled(its) ? GITS_CTLR_ENABLE : 0;
        reg32 = ctlr;
        vgic_reg32_update(&reg32, r, info);

        if ( ctlr ^ reg32 )
            vgic_v3_its_change_its_status(its, reg32 & GITS_CTLR_ENABLE);
        return 1;

    case VREG32(GITS_IIDR):
        goto write_ignore_32;
    case VREG32(GITS_TYPER):
        goto write_ignore_32;
    case VREG64(GITS_CBASER):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;

        /* Changing base registers with the ITS enabled is UNPREDICTABLE. */
        if ( its_is_enabled(its) )
        {
            gdprintk(XENLOG_WARNING, "ITS: Domain %d tried to change CBASER with the ITS enabled.\n", d->domain_id);
            return 1;
        }

        reg = its->cbaser;
        vgic_reg64_update(&reg, r, info);
        sanitize_its_base_reg(&reg);

        vgic_its_unmap_cmdbuf(its);
        its->cbaser = reg;

	return 1;

    case VREG64(GITS_CWRITER):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
        reg = its->cwriter & 0xfffe0;
        vgic_reg64_update(&reg, r, info);
        its->cwriter = reg & 0xfffe0;

        if ( its_is_enabled(its) )
            vgic_its_handle_cmds(d, its, reg);

        return 1;

    case VREG64(GITS_CREADR):
        goto write_ignore_64;
    case VREG64(GITS_BASER0):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;

        /* Changing base registers with the ITS enabled is UNPREDICTABLE. */
        if ( its_is_enabled(its) )
        {
            gdprintk(XENLOG_WARNING, "ITS: Domain %d tried to change BASER with the ITS enabled.\n",
                     d->domain_id);

            return 1;
        }

        reg = its->baser_dev;
        vgic_reg64_update(&reg, r, info);

        reg &= ~GITS_BASER_RO_MASK;
        reg |= (sizeof(uint64_t) - 1) << GITS_BASER_ENTRY_SIZE_SHIFT;
        reg |= GITS_BASER_TYPE_DEVICE << GITS_BASER_TYPE_SHIFT;
        sanitize_its_base_reg(&reg);

        /* Has the table address been changed or invalidated? */
        if ( !(reg & GITS_VALID_BIT) ||
             get_baser_phys_addr(reg) != get_baser_phys_addr(its->baser_dev) )
        {
            vgic_its_unmap_its_table(its->d, its->baser_dev);
            clear_bit(VIRT_ITS_DEV_VALID, &its->flags);
        }

        if ( reg & GITS_VALID_BIT )
            its->max_devices = its_baser_nr_entries(reg);
        else
            its->max_devices = 0;

        its->baser_dev = reg;
        return 1;
    case VREG64(GITS_BASER1):
        if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;

        /* Changing base registers with the ITS enabled is UNPREDICTABLE. */
        if ( its_is_enabled(its) )
        {
            gdprintk(XENLOG_INFO, "ITS: Domain %d tried to change BASER with the ITS enabled.\n",
                     d->domain_id);
            return 1;
        }

        reg = its->baser_coll;
        vgic_reg64_update(&reg, r, info);
        reg &= ~GITS_BASER_RO_MASK;
        reg |= (sizeof(uint16_t) - 1) << GITS_BASER_ENTRY_SIZE_SHIFT;
        reg |= GITS_BASER_TYPE_COLLECTION << GITS_BASER_TYPE_SHIFT;
        sanitize_its_base_reg(&reg);

        if ( !(reg & GITS_VALID_BIT) ||
             get_baser_phys_addr(reg) != get_baser_phys_addr(its->baser_coll) )
        {
            vgic_its_unmap_its_table(its->d, its->baser_coll);
            clear_bit(VIRT_ITS_COLL_VALID, &its->flags);
        }

        if ( reg & GITS_VALID_BIT )
            its->max_collections = its_baser_nr_entries(reg);
        else
            its->max_collections = 0;
        its->baser_coll = reg;
        return 1;
    case VRANGE64(GITS_BASER2, GITS_BASER7):
        goto write_ignore_64;
    default:
        gdprintk(XENLOG_G_WARNING, "ITS: unhandled ITS register 0x%lx\n",
                 info->gpa & 0xffff);
        return 0;
    }

    return 1;

write_ignore_64:
    if ( ! vgic_reg64_check_access(info->dabt) ) goto bad_width;
    return 1;

write_ignore_32:
    if ( info->dabt.size != DABT_WORD ) goto bad_width;
    return 1;

bad_width:
    printk(XENLOG_G_ERR "%pv vGICR: bad read width %d r%d offset %#08lx\n",
           v, info->dabt.size, info->dabt.reg, info->gpa & 0xffff);

    domain_crash_synchronous();

    return 0;
}

static const struct mmio_handler_ops vgic_its_mmio_handler = {
    .read  = vgic_v3_its_mmio_read,
    .write = vgic_v3_its_mmio_write,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
