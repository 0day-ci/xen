/*
 * include/asm-arm/viommu.h
 *
 * Copyright (c) 2017 Intel Corporation
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
#ifndef __ARCH_ARM_VIOMMU_H__
#define __ARCH_ARM_VIOMMU_H__

#include <xen/viommu.h>

struct irq_remapping_info
{
};

struct irq_remapping_request
{
};

static inline const struct viommu_ops *viommu_get_ops(void)
{
    return NULL;
}

#endif /* __ARCH_ARM_VIOMMU_H__ */
