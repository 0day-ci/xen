/*
 * vvtd.c
 *
 * virtualize VTD for HVM.
 *
 * Copyright (C) 2017 Chao Gao, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/viommu.h>
#include <xen/xmalloc.h>
#include <asm/apic.h>
#include <asm/current.h>
#include <asm/event.h>
#include <asm/hvm/domain.h>
#include <asm/io_apic.h>
#include <asm/page.h>
#include <asm/p2m.h>
#include <asm/system.h>
#include <public/viommu.h>

#include "../../../drivers/passthrough/vtd/iommu.h"

struct hvm_hw_vvtd_regs {
    uint8_t data[1024];
};

/* Status field of struct vvtd */
#define VIOMMU_STATUS_IRQ_REMAPPING_ENABLED     (1 << 0)
#define VIOMMU_STATUS_DMA_REMAPPING_ENABLED     (1 << 1)

#define vvtd_irq_remapping_enabled(vvtd) \
            (vvtd->status & VIOMMU_STATUS_IRQ_REMAPPING_ENABLED)

struct vvtd {
    /* VIOMMU_STATUS_XXX_REMAPPING_ENABLED */
    int status;
    /* Base address of remapping hardware register-set */
    uint64_t base_addr;
    /* Point back to the owner domain */
    struct domain *domain;
    int frcd_idx;
    /* Is in Extended Interrupt Mode */
    bool eim;
    /* Interrupt remapping table base gfn */
    uint64_t irt;
    /* Max remapping entries in IRT */
    int irt_max_entry;

    struct hvm_hw_vvtd_regs *regs;
    struct page_info *regs_page;
};

#define __DEBUG_VVTD__
#ifdef __DEBUG_VVTD__
extern unsigned int vvtd_debug_level;
#define VVTD_DBG_INFO     1
#define VVTD_DBG_TRANS    (1<<1)
#define VVTD_DBG_RW       (1<<2)
#define VVTD_DBG_FAULT    (1<<3)
#define VVTD_DBG_EOI      (1<<4)
#define VVTD_DEBUG(lvl, _f, _a...) do { \
    if ( vvtd_debug_level & lvl ) \
    printk("VVTD %s:" _f "\n", __func__, ## _a);    \
} while(0)
#else
#define VVTD_DEBUG(fmt...) do {} while(0)
#endif

unsigned int vvtd_debug_level __read_mostly;
integer_param("vvtd_debug", vvtd_debug_level);

struct vvtd *domain_vvtd(struct domain *d)
{
    struct viommu_info *info = &d->viommu;

    BUILD_BUG_ON(NR_VIOMMU_PER_DOMAIN != 1);
    return (info && info->viommu[0]) ? info->viommu[0]->priv : NULL;
}

static inline struct vvtd *vcpu_vvtd(struct vcpu *v)
{
    return domain_vvtd(v->domain);
}

static inline int vvtd_test_and_set_bit(struct vvtd *vvtd, uint32_t reg,
                                        int nr)
{
    return test_and_set_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
}

static inline int vvtd_test_and_clear_bit(struct vvtd *vvtd, uint32_t reg,
                                          int nr)
{
    return test_and_clear_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
}

static inline int vvtd_test_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return test_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
}

static inline void __vvtd_set_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return __set_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
}

static inline void __vvtd_clear_bit(struct vvtd *vvtd, uint32_t reg, int nr)
{
    return __clear_bit(nr, (uint32_t *)&vvtd->regs->data[reg]);
}

static inline void vvtd_set_reg(struct vvtd *vtd, uint32_t reg,
                                uint32_t value)
{
    *((uint32_t *)(&vtd->regs->data[reg])) = value;
}

static inline uint32_t vvtd_get_reg(struct vvtd *vtd, uint32_t reg)
{
    return *((uint32_t *)(&vtd->regs->data[reg]));
}

static inline uint8_t vvtd_get_reg_byte(struct vvtd *vtd, uint32_t reg)
{
    return *((uint8_t *)(&vtd->regs->data[reg]));
}

#define vvtd_get_reg_quad(vvtd, reg, val) do { \
    (val) = vvtd_get_reg(vvtd, (reg) + 4 ); \
    (val) = (val) << 32; \
    (val) += vvtd_get_reg(vvtd, reg); \
} while(0)
#define vvtd_set_reg_quad(vvtd, reg, val) do { \
    vvtd_set_reg(vvtd, reg, (uint32_t)((val) & 0xffffffff)); \
    vvtd_set_reg(vvtd, (reg) + 4, (uint32_t)((val) >> 32)); \
} while(0)

static int map_guest_page(struct domain *d, uint64_t gfn, void **virt)
{
    struct page_info *p;

    p = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !p )
        return -EINVAL;

    if ( !get_page_type(p, PGT_writable_page) )
    {
        put_page(p);
        return -EINVAL;
    }

    *virt = __map_domain_page_global(p);
    if ( !*virt )
    {
        put_page_and_type(p);
        return -ENOMEM;
    }
    return 0;
}

static void unmap_guest_page(void *virt)
{
    struct page_info *page;

    if ( !virt )
        return;

    virt = (void *)((unsigned long)virt & PAGE_MASK);
    page = mfn_to_page(domain_page_map_to_mfn(virt));

    unmap_domain_page_global(virt);
    put_page_and_type(page);
}

static void vvtd_inj_irq(
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    VVTD_DEBUG(VVTD_DBG_INFO, "dest=v%d, delivery_mode=%x vector=%d "
               "trig_mode=%d.",
               vlapic_vcpu(target)->vcpu_id, delivery_mode,
               vector, trig_mode);

    ASSERT((delivery_mode == dest_Fixed) ||
           (delivery_mode == dest_LowestPrio));

    vlapic_set_irq(target, vector, trig_mode);
}

static int vvtd_delivery(
    struct domain *d, int vector,
    uint32_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode)
{
    struct vlapic *target;
    struct vcpu *v;

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
        target = vlapic_lowest_prio(d, NULL, 0, dest, dest_mode);
        if ( target != NULL )
        {
            vvtd_inj_irq(target, vector, trig_mode, delivery_mode);
            break;
        }
        VVTD_DEBUG(VVTD_DBG_INFO, "null round robin: vector=%02x\n", vector);
        break;

    case dest_Fixed:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest,
                                   dest_mode) )
                vvtd_inj_irq(vcpu_vlapic(v), vector,
                             trig_mode, delivery_mode);
        break;

    case dest_NMI:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest, dest_mode)
                 && !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
        break;

    default:
        printk(XENLOG_G_WARNING
               "%pv: Unsupported VTD delivery mode %d for Dom%d\n",
               current, delivery_mode, d->domain_id);
        return -EINVAL;
    }

    return 0;
}

void vvtd_generate_interrupt(struct vvtd *vvtd,
                             uint32_t addr,
                             uint32_t data)
{
    uint8_t dest, dm, dlm, tm, vector;

    VVTD_DEBUG(VVTD_DBG_FAULT, "Sending interrupt %x %x to d%d",
               addr, data, vvtd->domain->domain_id);

    dest = (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
    dm = !!(addr & MSI_ADDR_DESTMODE_MASK);
    dlm = (data & MSI_DATA_DELIVERY_MODE_MASK) >> MSI_DATA_DELIVERY_MODE_SHIFT;
    tm = (data & MSI_DATA_TRIGGER_MASK) >> MSI_DATA_TRIGGER_SHIFT;
    vector = data & MSI_DATA_VECTOR_MASK;

    vvtd_delivery(vvtd->domain, vector, dest, dm, dlm, tm);
}

static uint32_t irq_remapping_request_index(struct irq_remapping_request *irq)
{
    switch ( irq->type )
    {
    case VIOMMU_REQUEST_IRQ_MSI:
        return IR_MSI_INDEX(irq->msg.msi.data, irq->msg.msi.addr);

    case VIOMMU_REQUEST_IRQ_APIC:
        return IR_IOAPIC_RTE_INDEX((struct ir_ioapic_rte *)&irq->msg.rte);

    default:
        break;
    }
    BUG();
    return 0;
}

static inline uint32_t irte_dest(struct vvtd *vvtd,
                                 struct iremap_entry *irte)
{
    uint64_t irta;

    /* In xAPIC mode, only 8-bits([15:8]) are valid*/
    vvtd_get_reg_quad(vvtd, DMAR_IRTA_REG, irta);
    return (irta & IRTA_EIME) ? irte->remap.dst : (irte->remap.dst) >> 8 & 0xff;
}

static void vvtd_report_non_recoverable_fault(struct vvtd *vvtd, int reason)
{
    uint32_t fsts;

    ASSERT(reason & DMA_FSTS_FAULTS);
    fsts = vvtd_get_reg(vvtd, DMAR_FSTS_REG);
    __vvtd_set_bit(vvtd, DMAR_FSTS_REG, reason);

    /*
     * Accoroding to VT-d spec "Non-Recoverable Fault Event" chapter, if
     * there are any previously reported interrupt conditions that are yet to
     * be sevices by software, the Fault Event interrrupt is not generated.
     */
    if ( fsts & DMA_FSTS_FAULTS )
        return;

    __vvtd_set_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_BIT);
    if ( !vvtd_test_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IM_BIT) )
    {
        uint32_t fe_data, fe_addr;
        fe_data = vvtd_get_reg(vvtd, DMAR_FEDATA_REG);
        fe_addr = vvtd_get_reg(vvtd, DMAR_FEADDR_REG);
        vvtd_generate_interrupt(vvtd, fe_addr, fe_data);
        __vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_BIT);
    }
}

static void vvtd_recomputing_ppf(struct vvtd *vvtd)
{
    int i;

    for ( i = 0; i < DMAR_FRCD_REG_NR; i++ )
    {
        if ( vvtd_test_bit(vvtd, DMA_FRCD(i, DMA_FRCD3_OFFSET),
                           DMA_FRCD_F_BIT) )
        {
            vvtd_report_non_recoverable_fault(vvtd, DMA_FSTS_PPF_BIT);
            return;
        }
    }
    /*
     * No Primary Fault is in Fault Record Registers, thus clear PPF bit in
     * FSTS.
     */
    __vvtd_clear_bit(vvtd, DMAR_FSTS_REG, DMA_FSTS_PPF_BIT);

    /* If no fault is in FSTS, clear pending bit in FECTL. */
    if ( !(vvtd_get_reg(vvtd, DMAR_FSTS_REG) & DMA_FSTS_FAULTS) )
        __vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_BIT);
}

/*
 * Commit a frcd to emulated Fault Record Registers.
 */
static void vvtd_commit_frcd(struct vvtd *vvtd, int idx,
                             struct vtd_fault_record_register *frcd)
{
    vvtd_set_reg_quad(vvtd, DMA_FRCD(idx, DMA_FRCD0_OFFSET), frcd->bits.lo);
    vvtd_set_reg_quad(vvtd, DMA_FRCD(idx, DMA_FRCD2_OFFSET), frcd->bits.hi);
    vvtd_recomputing_ppf(vvtd);
}

/*
 * Allocate a FRCD for the caller. If success, return the FRI. Or, return -1
 * when failure.
 */
static int vvtd_alloc_frcd(struct vvtd *vvtd)
{
    int prev;
    /* Set the F bit to indicate the FRCD is in use. */
    if ( vvtd_test_and_set_bit(vvtd, DMA_FRCD(vvtd->frcd_idx, DMA_FRCD3_OFFSET),
                               DMA_FRCD_F_BIT) )
    {
        prev = vvtd->frcd_idx;
        vvtd->frcd_idx = (prev + 1) % DMAR_FRCD_REG_NR;
        return vvtd->frcd_idx;
    }
    return -1;
}

static void vvtd_free_frcd(struct vvtd *vvtd, int i)
{
    __vvtd_clear_bit(vvtd, DMA_FRCD(i, DMA_FRCD3_OFFSET), DMA_FRCD_F_BIT);
}

static int vvtd_log_fault(struct vvtd *vvtd,
                          struct irq_remapping_request *request,
                          int reason)
{
    struct vtd_fault_record_register frcd;
    int frcd_idx;

    switch(reason)
    {
    case VTD_FR_IR_REQ_RSVD:
    case VTD_FR_IR_INDEX_OVER:
    case VTD_FR_IR_ENTRY_P:
    case VTD_FR_IR_ROOT_INVAL:
    case VTD_FR_IR_IRTE_RSVD:
    case VTD_FR_IR_REQ_COMPAT:
    case VTD_FR_IR_SID_ERR:
        if ( vvtd_test_bit(vvtd, DMAR_FSTS_REG, DMA_FSTS_PFO_BIT) )
            return X86EMUL_OKAY;

        /* No available Fault Record means Fault overflowed */
        frcd_idx = vvtd_alloc_frcd(vvtd);
        if ( frcd_idx == -1 )
        {
            vvtd_report_non_recoverable_fault(vvtd, DMA_FSTS_PFO_BIT);
            return X86EMUL_OKAY;
        }
        memset(&frcd, 0, sizeof(frcd));
        frcd.fields.FR = (u8)reason;
        frcd.fields.FI = ((u64)irq_remapping_request_index(request)) << 36;
        frcd.fields.SID = (u16)request->source_id;
        frcd.fields.F = 1;
        vvtd_commit_frcd(vvtd, frcd_idx, &frcd);
        return X86EMUL_OKAY;

    default:
        break;
    }

    gdprintk(XENLOG_ERR, "Can't handle vVTD Fault (reason 0x%x).", reason);
    domain_crash(vvtd->domain);
    return X86EMUL_OKAY;
}

/*
 * Process a invalidation descriptor. Currently, only Two types descriptors,
 * Interrupt Entry Cache invalidation descritor and Invalidation Wait
 * Descriptor are handled.
 * @vvtd: the virtual vtd instance
 * @i: the index of the invalidation descriptor to be processed
 *
 * If success return 0, or return -1 when failure.
 */
static int process_iqe(struct vvtd *vvtd, int i)
{
    uint64_t iqa, addr;
    struct qinval_entry *qinval_page;
    void *pg;
    int ret;

    vvtd_get_reg_quad(vvtd, DMAR_IQA_REG, iqa);
    ret = map_guest_page(vvtd->domain, DMA_IQA_ADDR(iqa)>>PAGE_SHIFT,
                         (void**)&qinval_page);
    if ( ret )
    {
        gdprintk(XENLOG_ERR, "Can't map guest IRT (rc %d)", ret);
        return -1;
    }

    switch ( qinval_page[i].q.inv_wait_dsc.lo.type )
    {
    case TYPE_INVAL_WAIT:
        if ( qinval_page[i].q.inv_wait_dsc.lo.sw )
        {
            addr = (qinval_page[i].q.inv_wait_dsc.hi.saddr << 2);
            ret = map_guest_page(vvtd->domain, addr >> PAGE_SHIFT, &pg);
            if ( ret )
            {
                gdprintk(XENLOG_ERR, "Can't map guest memory to inform guest "
                         "IWC completion (rc %d)", ret);
                goto error;
            }
            *(uint32_t *)((uint64_t)pg + (addr & ~PAGE_MASK)) =
                qinval_page[i].q.inv_wait_dsc.lo.sdata;
            unmap_guest_page(pg);
        }

        /*
         * The following code generates an invalidation completion event
         * indicating the invalidation wait descriptor completion. Note that
         * the following code fragment is not tested properly.
         */
        if ( qinval_page[i].q.inv_wait_dsc.lo.iflag )
        {
            uint32_t ie_data, ie_addr;
            if ( !vvtd_test_and_set_bit(vvtd, DMAR_ICS_REG, DMA_ICS_IWC_BIT) )
            {
                __vvtd_set_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IP_BIT);
                if ( !vvtd_test_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IM_BIT) )
                {
                    ie_data = vvtd_get_reg(vvtd, DMAR_IEDATA_REG);
                    ie_addr = vvtd_get_reg(vvtd, DMAR_IEADDR_REG);
                    vvtd_generate_interrupt(vvtd, ie_addr, ie_data);
                    __vvtd_clear_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IP_BIT);
                }
            }
        }
        break;

    case TYPE_INVAL_IEC:
        /*
         * Currently, no cache is preserved in hypervisor. Only need to update
         * pIRTEs which are modified in binding process.
         */
        break;

    default:
        goto error;
    }

    unmap_guest_page((void*)qinval_page);
    return 0;

error:
    unmap_guest_page((void*)qinval_page);
    gdprintk(XENLOG_ERR, "Internal error in Queue Invalidation.\n");
    domain_crash(vvtd->domain);
    return -1;
}

/*
 * Invalidate all the descriptors in Invalidation Queue.
 */
static void vvtd_process_iq(struct vvtd *vvtd)
{
    uint64_t iqh, iqt, iqa, max_entry, i;
    int ret = 0;

    /*
     * No new descriptor is fetched from the Invalidation Queue until
     * software clears the IQE field in the Fault Status Register
     */
    if ( vvtd_test_bit(vvtd, DMAR_FSTS_REG, DMA_FSTS_IQE_BIT) )
        return;

    vvtd_get_reg_quad(vvtd, DMAR_IQH_REG, iqh);
    vvtd_get_reg_quad(vvtd, DMAR_IQT_REG, iqt);
    vvtd_get_reg_quad(vvtd, DMAR_IQA_REG, iqa);

    max_entry = DMA_IQA_ENTRY_PER_PAGE << DMA_IQA_QS(iqa);
    iqh = DMA_IQH_QH(iqh);
    iqt = DMA_IQT_QT(iqt);

    ASSERT(iqt < max_entry);
    if ( iqh == iqt )
        return;

    i = iqh;
    while ( i != iqt )
    {
        ret = process_iqe(vvtd, i);
        if ( ret )
            break;
        else
            i = (i + 1) % max_entry;
        vvtd_set_reg_quad(vvtd, DMAR_IQH_REG, i << DMA_IQH_QH_SHIFT);
    }

    /*
     * When IQE set, IQH references the desriptor associated with the error.
     */
    if ( ret )
        vvtd_report_non_recoverable_fault(vvtd, DMA_FSTS_IQE_BIT);
}

static int vvtd_write_iqt(struct vvtd *vvtd, unsigned long val)
{
    uint64_t iqa;

    if ( val & DMA_IQT_RSVD )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Attempt to set reserved bits in "
                   "Invalidation Queue Tail.");
        return X86EMUL_OKAY;
    }

    vvtd_get_reg_quad(vvtd, DMAR_IQA_REG, iqa);
    if ( DMA_IQT_QT(val) >= DMA_IQA_ENTRY_PER_PAGE << DMA_IQA_QS(iqa) )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "IQT: Value %lx exceeded supported max "
                   "index.", val);
        return X86EMUL_OKAY;
    }

    vvtd_set_reg_quad(vvtd, DMAR_IQT_REG, val);
    vvtd_process_iq(vvtd);
    return X86EMUL_OKAY;
}

static int vvtd_write_iqa(struct vvtd *vvtd, unsigned long val)
{
    if ( val & DMA_IQA_RSVD )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Attempt to set reserved bits in "
                   "Invalidation Queue Address.");
        return X86EMUL_OKAY;
    }

    vvtd_set_reg_quad(vvtd, DMAR_IQA_REG, val);
    return X86EMUL_OKAY;
}

static int vvtd_write_ics(struct vvtd *vvtd, unsigned long val)
{
    if ( val & DMA_ICS_IWC )
    {
        __vvtd_clear_bit(vvtd, DMAR_ICS_REG, DMA_ICS_IWC_BIT);
        /*When IWC field is cleared, the IP field needs to be cleared */
        __vvtd_clear_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IP_BIT);
    }
    return X86EMUL_OKAY;
}

static int vvtd_write_frcd3(struct vvtd *vvtd, unsigned long val)
{
    /* Writing a 1 means clear fault */
    if ( val & DMA_FRCD_F )
    {
        vvtd_free_frcd(vvtd, 0);
        vvtd_recomputing_ppf(vvtd);
    }
    return X86EMUL_OKAY;
}

static int vvtd_write_iectl(struct vvtd *vvtd, unsigned long val)
{
    /*
     * Only DMA_IECTL_IM bit is writable. Generate pending event when unmask.
     */
    if ( !(val & DMA_IECTL_IM) )
    {
        /* Clear IM and clear IP */
        __vvtd_clear_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IM_BIT);
        if ( vvtd_test_and_clear_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IP_BIT) )
        {
            uint32_t ie_data, ie_addr;
            ie_data = vvtd_get_reg(vvtd, DMAR_IEDATA_REG);
            ie_addr = vvtd_get_reg(vvtd, DMAR_IEADDR_REG);
            vvtd_generate_interrupt(vvtd, ie_addr, ie_data);
        }
    }
    else
        __vvtd_set_bit(vvtd, DMAR_IECTL_REG, DMA_IECTL_IM_BIT);

    return X86EMUL_OKAY;
}

static int vvtd_write_fectl(struct vvtd *vvtd, unsigned long val)
{
    /*
     * Only DMA_FECTL_IM bit is writable. Generate pending event when unmask.
     */
    if ( !(val & DMA_FECTL_IM) )
    {
        /* Clear IM */
        __vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IM_BIT);
        if ( vvtd_test_and_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_BIT) )
        {
            uint32_t fe_data, fe_addr;
            fe_data = vvtd_get_reg(vvtd, DMAR_FEDATA_REG);
            fe_addr = vvtd_get_reg(vvtd, DMAR_FEADDR_REG);
            vvtd_generate_interrupt(vvtd, fe_addr, fe_data);
        }
    }
    else
        __vvtd_set_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IM_BIT);

    return X86EMUL_OKAY;
}

static int vvtd_write_fsts(struct vvtd *vvtd, unsigned long val)
{
    int i, max_fault_index = DMA_FSTS_PRO_BIT + 1;

    val = val & DMA_FSTS_RW1CS;
    i = find_first_bit(&val, max_fault_index);
    while ( i < max_fault_index )
    {
        __vvtd_clear_bit(vvtd, DMAR_FSTS_REG, i);
        i = find_next_bit(&val, max_fault_index, i + 1);
    }

    /*
     * Clear IP field when all status fields in the Fault Status Register
     * being clear.
     */
    if ( !((vvtd_get_reg(vvtd, DMAR_FSTS_REG) & DMA_FSTS_FAULTS)) )
        __vvtd_clear_bit(vvtd, DMAR_FECTL_REG, DMA_FECTL_IP_BIT);

    /* Continue to deal invalidation when IQE is clear */
    if ( !vvtd_test_bit(vvtd, DMAR_FSTS_REG, DMA_FSTS_IQE_BIT) )
        vvtd_process_iq(vvtd);

    return X86EMUL_OKAY;
}

static int vvtd_handle_gcmd_qie(struct vvtd *vvtd, unsigned long val)
{
    VVTD_DEBUG(VVTD_DBG_RW, "Enable Queue Invalidation.");

    if ( val & DMA_GCMD_QIE )
        __vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_QIES_BIT);
    else
        __vvtd_clear_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_QIES_BIT);
    return X86EMUL_OKAY;
}

static int vvtd_handle_gcmd_ire(struct vvtd *vvtd, unsigned long val)
{
    VVTD_DEBUG(VVTD_DBG_RW, "Enable Interrupt Remapping.");

    if ( val & DMA_GCMD_IRE )
    {
        vvtd->status |= VIOMMU_STATUS_IRQ_REMAPPING_ENABLED;
        __vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_IRES_BIT);
    }
    else
    {
        vvtd->status |= ~VIOMMU_STATUS_IRQ_REMAPPING_ENABLED;
        __vvtd_clear_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_IRES_BIT);
    }

    return X86EMUL_OKAY;
}

static int vvtd_handle_gcmd_sirtp(struct vvtd *vvtd, unsigned long val)
{
    uint64_t irta;

    if ( !(val & DMA_GCMD_SIRTP) )
        return X86EMUL_OKAY;

    if ( vvtd_irq_remapping_enabled(vvtd) )
        VVTD_DEBUG(VVTD_DBG_RW, "Update Interrupt Remapping Table when "
                   "active." );

    vvtd_get_reg_quad(vvtd, DMAR_IRTA_REG, irta);
    vvtd->irt = DMA_IRTA_ADDR(irta) >> PAGE_SHIFT;
    vvtd->irt_max_entry = DMA_IRTA_SIZE(irta);
    vvtd->eim = !!(irta & IRTA_EIME);
    VVTD_DEBUG(VVTD_DBG_RW, "Update IR info (addr=%lx eim=%d size=%d).",
               vvtd->irt, vvtd->eim, vvtd->irt_max_entry);
    __vvtd_set_bit(vvtd, DMAR_GSTS_REG, DMA_GSTS_SIRTPS_BIT);

    return X86EMUL_OKAY;
}

static int vvtd_write_gcmd(struct vvtd *vvtd, unsigned long val)
{
    uint32_t orig = vvtd_get_reg(vvtd, DMAR_GSTS_REG);
    uint32_t changed = orig ^ val;

    if ( !changed )
        return X86EMUL_OKAY;
    if ( (changed & (changed - 1)) )
        VVTD_DEBUG(VVTD_DBG_RW, "Guest attempts to update multiple fields "
                     "of GCMD_REG in one write transation.");

    if ( changed & DMA_GCMD_SIRTP )
        vvtd_handle_gcmd_sirtp(vvtd, val);
    if ( changed & DMA_GCMD_QIE )
        vvtd_handle_gcmd_qie(vvtd, val);
    if ( changed & DMA_GCMD_IRE )
        vvtd_handle_gcmd_ire(vvtd, val);
    if ( changed & ~(DMA_GCMD_QIE | DMA_GCMD_SIRTP | DMA_GCMD_IRE) )
        gdprintk(XENLOG_INFO, "Only QIE,SIRTP,IRE in GCMD_REG are handled.\n");

    return X86EMUL_OKAY;
}

static int vvtd_range(struct vcpu *v, unsigned long addr)
{
    struct vvtd *vvtd = vcpu_vvtd(v);

    if ( vvtd )
        return (addr >= vvtd->base_addr) &&
               (addr < vvtd->base_addr + PAGE_SIZE);
    return 0;
}

static int vvtd_read(struct vcpu *v, unsigned long addr,
                     unsigned int len, unsigned long *pval)
{
    struct vvtd *vvtd = vcpu_vvtd(v);
    unsigned int offset = addr - vvtd->base_addr;
    unsigned int offset_aligned = offset & ~3;

    if ( !pval )
        return X86EMUL_OKAY;

    VVTD_DEBUG(VVTD_DBG_RW, "READ INFO: offset %x len %d.", offset, len);

    if ( len != 1 && (offset & 3) != 0 )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Alignment is not canonical.");
        return X86EMUL_OKAY;
    }

    switch( len )
    {
    case 1:
        *pval = vvtd_get_reg_byte(vvtd, offset);
        break;

    case 4:
        *pval = vvtd_get_reg(vvtd, offset_aligned);
        break;

    case 8:
        vvtd_get_reg_quad(vvtd, offset_aligned, *pval);
        break;

    default:
        break;
    }

    return X86EMUL_OKAY;
}

static int vvtd_write(struct vcpu *v, unsigned long addr,
                      unsigned int len, unsigned long val)
{
    struct vvtd *vvtd = vcpu_vvtd(v);
    unsigned int offset = addr - vvtd->base_addr;
    unsigned int offset_aligned = offset & ~0x3;
    unsigned long val_lo = (val & ((1ULL << 32) - 1));
    unsigned long val_hi = (val >> 32);
    int ret;

    VVTD_DEBUG(VVTD_DBG_RW, "WRITE INFO: offset %x len %d val %lx.",
               offset, len, val);

    if ( offset & 3 )
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Alignment is not canonical");
        goto error;
    }

    if ( len != 4 && len != 8)
    {
        VVTD_DEBUG(VVTD_DBG_RW, "Len is not canonical");
        goto error;
    }

    ret = X86EMUL_UNHANDLEABLE;
    switch ( offset_aligned  )
    {
    case DMAR_GCMD_REG:
        if ( len == 8 )
            goto error;
        ret = vvtd_write_gcmd(vvtd, val_lo);
        break;

    case DMAR_IQT_REG:
        if ( len == 8 )
            ret = vvtd_write_iqt(vvtd, val);
        else
            ret = vvtd_write_iqt(vvtd, val_lo);
        break;

    case DMAR_IQA_REG:
        if ( len == 8 )
            ret = vvtd_write_iqa(vvtd, val);
        else
        {
            unsigned long iqa_hi;

            iqa_hi = vvtd_get_reg(vvtd, DMAR_IQA_REG_HI);
            ret = vvtd_write_iqa(vvtd, val_lo | (iqa_hi << 32));
        }
        break;

    case DMAR_IQA_REG_HI:
    {
        unsigned long iqa_lo;

        if ( len == 8 )
            goto error;
        iqa_lo = vvtd_get_reg(vvtd, DMAR_IQA_REG);
        ret = vvtd_write_iqa(vvtd, (val_lo << 32) | iqa_lo);
        break;
    }

    case DMAR_ICS_REG:
        if ( len == 8 )
            goto error;
        ret = vvtd_write_ics(vvtd, val_lo);
        break;

    case DMAR_IECTL_REG:
        if ( len == 8 )
            goto error;
        ret = vvtd_write_iectl(vvtd, val_lo);
        break;

    case DMAR_IRTA_REG:
        if ( len == 8 )
            vvtd_set_reg_quad(vvtd, DMAR_IRTA_REG, val);
        else
            vvtd_set_reg(vvtd, DMAR_IRTA_REG, val_lo);
        break;

    case DMAR_IRTA_REG_HI:
        if ( len == 8 )
            goto error;
        vvtd_set_reg(vvtd, DMAR_IRTA_REG_HI, val_lo);
        ret = X86EMUL_OKAY;
        break;

    case DMAR_IEDATA_REG:
    case DMAR_IEADDR_REG:
    case DMAR_IEUADDR_REG:
    case DMAR_FEDATA_REG:
    case DMAR_FEADDR_REG:
    case DMAR_FEUADDR_REG:
        if ( len == 8 )
            goto error;
        vvtd_set_reg(vvtd, offset_aligned, val_lo);
        ret = X86EMUL_OKAY;

    case DMAR_FSTS_REG:
        if ( len == 8 )
            goto error;
        vvtd_write_fsts(vvtd, val_lo);
        break;

    case DMAR_FECTL_REG:
        if ( len == 8 )
            goto error;
        ret = vvtd_write_fectl(vvtd, val_lo);
        break;

    case DMA_CAP_FRO_OFFSET + DMA_FRCD0_OFFSET:
    case DMA_CAP_FRO_OFFSET + DMA_FRCD1_OFFSET:
        break;

    case DMA_CAP_FRO_OFFSET + DMA_FRCD2_OFFSET:
        if ( len == 4 ) {
            break;
        }
        vvtd_write_frcd3(vvtd, val_hi);
        break;

    case DMA_CAP_FRO_OFFSET + DMA_FRCD3_OFFSET:
        if ( len == 8 )
            goto error;
        vvtd_write_frcd3(vvtd, val_lo);
        break;

    default:
        break;
    }

error:
    return X86EMUL_OKAY;
}

static const struct hvm_mmio_ops vvtd_mmio_ops = {
    .check = vvtd_range,
    .read = vvtd_read,
    .write = vvtd_write
};

static bool ir_sid_valid(struct iremap_entry *irte, uint32_t source_id)
{
    return TRUE;
}

/* @log_fault: a flag to indicate whether we need log a fault when checking
 * vIRTE. (1 means logging it, 0 means ignoring the fault). log_fault = 0 is
 * used in parse process in which only the encoded attributes is cared.
 */
static int vvtd_get_entry(struct vvtd *vvtd,
                          struct irq_remapping_request *irq,
                          struct iremap_entry *dest,
                          bool log_fault)
{
    int ret;
    uint32_t entry = irq_remapping_request_index(irq);
    struct iremap_entry  *irte, *irt_page;

    ASSERT(entry < IREMAP_ENTRY_NR);

    if ( entry > vvtd->irt_max_entry )
    {
        ret = VTD_FR_IR_INDEX_OVER;
        goto handle_fault;
    }

    ret = map_guest_page(vvtd->domain, vvtd->irt + (entry >> IREMAP_ENTRY_ORDER),
                         (void**)&irt_page);
    if ( ret )
    {
        ret = VTD_FR_IR_ROOT_INVAL;
        goto handle_fault;
    }

    irte = irt_page + (entry % (1 << IREMAP_ENTRY_ORDER));
    dest->val = irte->val;
    if ( !qinval_present(*irte) )
    {
        ret = VTD_FR_IR_ENTRY_P;
        goto unmap_handle_fault;
    }

    /* Check reserved bits */
    if ( (irte->remap.res_1 || irte->remap.res_2 || irte->remap.res_3 ||
          irte->remap.res_4) )
    {
        ret = VTD_FR_IR_IRTE_RSVD;
        goto unmap_handle_fault;
    }

    /* TODO:Intel64 platforms block compatibility format interrupt request */

    if (!ir_sid_valid(irte, irq->source_id))
    {
        ret = VTD_FR_IR_SID_ERR;
        goto unmap_handle_fault;
    }
    unmap_guest_page(irt_page);
    return 0;

unmap_handle_fault:
    unmap_guest_page(irt_page);
handle_fault:
    if ( !log_fault )
        goto out;

    switch ( ret )
    {
    case VTD_FR_IR_SID_ERR:
    case VTD_FR_IR_IRTE_RSVD:
    case VTD_FR_IR_ENTRY_P:
        if ( qinval_fault_disable(*irte) )
            break;
    /* fall through */
    case VTD_FR_IR_INDEX_OVER:
    case VTD_FR_IR_ROOT_INVAL:
        vvtd_log_fault(vvtd, irq, ret);
        break;

    default:
        gdprintk(XENLOG_G_INFO, "Can't handle VT-d fault %x\n", ret);
        goto out;
    }
out:
    return ret;
}

static int vvtd_ioapic_check(struct vvtd *vvtd,
                             struct ir_ioapic_rte rte)
{
    VVTD_DEBUG(VVTD_DBG_INFO, "IOAPIC (%lx)", *(uint64_t *)&(rte));
    ASSERT(rte.format);

    if ( rte.reserved || rte.reserved1 || rte.reserved2[0] ||
         rte.reserved2[1] || rte.reserved2[2] )
        return VTD_FR_IR_REQ_RSVD;
    return 0;
}

static int vvtd_msi_check(struct vvtd *vvtd,
                          uint32_t data,
                          uint64_t addr)
{
    ASSERT((addr >> 20) == 0xfee);
    return 0;
}

static int vvtd_irq_request_sanity_check(struct vvtd *vvtd,
                                         struct irq_remapping_request *irq)
{
    switch ( irq->type )
    {
    case VIOMMU_REQUEST_IRQ_MSI:
        return vvtd_msi_check(vvtd, irq->msg.msi.data, irq->msg.msi.addr);

    case VIOMMU_REQUEST_IRQ_APIC:
        return vvtd_ioapic_check(vvtd, *(struct ir_ioapic_rte *)&irq->msg.rte);

    default:
        break;
    }

    BUG();
    return 0;
}

static int vvtd_handle_irq_request(struct domain *d,
                                   struct irq_remapping_request *irq)
{
    struct iremap_entry irte;
    int ret;
    struct vvtd *vvtd = domain_vvtd(d);

    if ( !vvtd || !vvtd_irq_remapping_enabled(vvtd) )
        return -EINVAL;

    ret = vvtd_irq_request_sanity_check(vvtd, irq);
    if ( ret )
    {
        vvtd_log_fault(vvtd, irq, ret);
        return ret;
    }

    if ( !vvtd_get_entry(vvtd, irq, &irte, 1) )
    {
        vvtd_delivery(vvtd->domain, irte.remap.vector,
                      irte_dest(vvtd, &irte), irte.remap.dm,
                      irte.remap.dlm, irte.remap.tm);
        return 0;
    }
    return -EFAULT;
}

static int vvtd_get_irq_info(struct domain *d,
                             struct irq_remapping_request *irq,
                             struct irq_remapping_info *info)
{
    int ret;
    struct iremap_entry irte;
    struct vvtd *vvtd = domain_vvtd(d);

    ret = vvtd_get_entry(vvtd, irq, &irte, 0);
    if ( ret )
        return -ret;

    info->vector = irte.remap.vector;
    info->dest = irte_dest(vvtd, &irte);
    info->dest_mode = irte.remap.dm;
    info->delivery_mode = irte.remap.dlm;
    return 0;
}

static void vvtd_reset(struct vvtd *vvtd, uint64_t capability)
{
    uint64_t cap, ecap;

    cap = DMA_CAP_NFR | DMA_CAP_SLLPS | DMA_CAP_FRO | \
          DMA_CAP_MGAW | DMA_CAP_SAGAW | DMA_CAP_ND;
    ecap = DMA_ECAP_IR | DMA_ECAP_EIM | DMA_ECAP_QI;
    vvtd_set_reg(vvtd, DMAR_VER_REG, 0x10UL);
    vvtd_set_reg_quad(vvtd, DMAR_CAP_REG, cap);
    vvtd_set_reg_quad(vvtd, DMAR_ECAP_REG, ecap);
    vvtd_set_reg(vvtd, DMAR_GCMD_REG, 0);
    vvtd_set_reg(vvtd, DMAR_GSTS_REG, 0);
    vvtd_set_reg(vvtd, DMAR_RTADDR_REG, 0);
    vvtd_set_reg_quad(vvtd, DMAR_CCMD_REG, 0x0ULL);
    vvtd_set_reg(vvtd, DMAR_FSTS_REG, 0);
    vvtd_set_reg(vvtd, DMAR_FECTL_REG, 0x80000000UL);
    vvtd_set_reg(vvtd, DMAR_FEDATA_REG, 0);
    vvtd_set_reg(vvtd, DMAR_FEADDR_REG, 0);
    vvtd_set_reg(vvtd, DMAR_FEUADDR_REG, 0);
    vvtd_set_reg(vvtd, DMAR_PMEN_REG, 0);
    vvtd_set_reg_quad(vvtd, DMAR_IQH_REG, 0x0ULL);
    vvtd_set_reg_quad(vvtd, DMAR_IQT_REG, 0x0ULL);
    vvtd_set_reg_quad(vvtd, DMAR_IQA_REG, 0x0ULL);
    vvtd_set_reg(vvtd, DMAR_ICS_REG, 0);
    vvtd_set_reg(vvtd, DMAR_IECTL_REG, 0x80000000UL);
    vvtd_set_reg(vvtd, DMAR_IEDATA_REG, 0);
    vvtd_set_reg(vvtd, DMAR_IEADDR_REG, 0);
    vvtd_set_reg(vvtd, DMAR_IEUADDR_REG, 0);
    vvtd_set_reg(vvtd, DMAR_IRTA_REG, 0);
}

static struct vvtd *__vvtd_create(struct domain *d,
                                  uint64_t base_addr,
                                  uint64_t cap)
{
    struct vvtd *vvtd;

    if ( !is_hvm_domain(d) )
        return 0;

    vvtd = xmalloc_bytes(sizeof(struct vvtd));
    if ( vvtd == NULL )
        return NULL;

    vvtd->regs_page = alloc_domheap_page(d, MEMF_no_owner);
    if ( vvtd->regs_page == NULL )
        goto out1;

    vvtd->regs = __map_domain_page_global(vvtd->regs_page);
    if ( vvtd->regs == NULL )
        goto out2;
    clear_page(vvtd->regs);

    vvtd_reset(vvtd, cap);
    vvtd->base_addr = base_addr;
    vvtd->domain = d;
    vvtd->status = 0;
    vvtd->eim = 0;
    vvtd->irt = 0;
    vvtd->irt_max_entry = 0;
    vvtd->frcd_idx = 0;
    register_mmio_handler(d, &vvtd_mmio_ops);
    return vvtd;

out2:
    free_domheap_page(vvtd->regs_page);
out1:
    xfree(vvtd);
    return NULL;
}

static void __vvtd_destroy(struct vvtd *vvtd)
{
    unmap_domain_page_global(vvtd->regs);
    free_domheap_page(vvtd->regs_page);
    xfree(vvtd);
}

static u64 vvtd_query_caps(struct domain *d)
{
    return VIOMMU_CAP_IRQ_REMAPPING;
}

static int vvtd_create(struct domain *d, struct viommu *viommu)
{
    viommu->priv = (void *)__vvtd_create(d, viommu->base_address, viommu->caps);
    return viommu->priv ? 0 : -ENOMEM;
}

static int vvtd_destroy(struct viommu *viommu)
{
    if ( viommu->priv )
        __vvtd_destroy(viommu->priv);
    return 0;
}

struct viommu_ops vvtd_hvm_vmx_ops = {
    .query_caps = vvtd_query_caps,
    .create = vvtd_create,
    .destroy = vvtd_destroy,
    .handle_irq_request = vvtd_handle_irq_request,
    .get_irq_info = vvtd_get_irq_info
};
