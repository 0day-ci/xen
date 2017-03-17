/*
 * viommu.c
 *
 * virtualize IOMMU.
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

#include <xen/viommu.h>

void irq_request_ioapic_fill(struct irq_remapping_request *req,
                             uint32_t ioapic_id, uint64_t rte)
{
    ASSERT(req);
    req->type = VIOMMU_REQUEST_IRQ_APIC;
    req->source_id = ioapic_id;
    req->msg.rte = rte;
}
