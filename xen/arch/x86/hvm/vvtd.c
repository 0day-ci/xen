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
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/viommu.h>
#include <xen/xmalloc.h>
#include <asm/current.h>
#include <asm/hvm/domain.h>
#include <asm/page.h>
#include <public/viommu.h>

#include "../../../drivers/passthrough/vtd/iommu.h"

struct hvm_hw_vvtd_regs {
    uint8_t data[1024];
};

/* Status field of struct vvtd */
#define VIOMMU_STATUS_IRQ_REMAPPING_ENABLED     (1 << 0)
#define VIOMMU_STATUS_DMA_REMAPPING_ENABLED     (1 << 1)

struct vvtd {
    /* VIOMMU_STATUS_XXX_REMAPPING_ENABLED */
    int status;
    /* Base address of remapping hardware register-set */
    uint64_t base_addr;
    /* Point back to the owner domain */
    struct domain *domain;
    struct hvm_hw_vvtd_regs *regs;
    struct page_info *regs_page;
};

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
    .destroy = vvtd_destroy
};
