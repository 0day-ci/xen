/*
 * include/asm-arm/viommu.h
 *
 * Copyright (c) 2017 Intel Corporation.
 * Author: Lan Tianyu <tianyu.lan@intel.com> 
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
 *
 */
#ifndef __ARCH_X86_VIOMMU_H__
#define __ARCH_X86_VIOMMU_H__

#include <xen/viommu.h>
#include <asm/types.h>
#include <asm/processor.h>

extern struct viommu_ops vvtd_hvm_vmx_ops;

struct irq_remapping_info
{
    u8  vector;
    u32 dest;
    u32 dest_mode:1;
    u32 delivery_mode:3;
};

struct irq_remapping_request
{
    u8 type;
    u16 source_id;
    union {
        /* MSI */
        struct {
            u64 addr;
            u32 data;
        } msi;
        /* Redirection Entry in IOAPIC */
        u64 rte;
    } msg;
};

void irq_request_ioapic_fill(struct irq_remapping_request *req,
                             uint32_t ioapic_id, uint64_t rte);

static inline const struct viommu_ops *viommu_get_ops(void)
{
    /*
     * Don't mean that viommu relies on hardward cpu vendor, but just
     * limit the usage to minimize the impact to existing code.
     */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        return &vvtd_hvm_vmx_ops;
    return NULL;
}

#endif /* __ARCH_X86_VIOMMU_H__ */
