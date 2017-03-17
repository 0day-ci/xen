/*
 * common/viommu.c
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

#include <xen/types.h>
#include <xen/sched.h>

int viommu_init_domain(struct domain *d)
{
    d->viommu.nr_viommu = 0;
    d->viommu.ops = viommu_get_ops();

    return 0;
}

int viommu_create(struct domain *d, u64 base_address, u64 length, u64 caps)
{
    struct viommu_info *info = &d->viommu;
    struct viommu *viommu;
    int rc;

    if ( !info || !info->ops || !info->ops->create
	        || info->nr_viommu >= NR_VIOMMU_PER_DOMAIN )
        return -EINVAL;

    viommu = xzalloc(struct viommu);
    if ( !viommu )
        return -EFAULT;

    viommu->base_address = base_address;
    viommu->length = length;
    viommu->caps = caps;
    viommu->viommu_id = info->nr_viommu;

    info->viommu[info->nr_viommu] = viommu;
    info->nr_viommu++;

    rc = info->ops->create(d, viommu);
    if ( rc < 0 ) {
        xfree(viommu);
        return rc;
    }

    return viommu->viommu_id;
}

int viommu_destroy(struct domain *d, u32 viommu_id)
{
    struct viommu_info *info = &d->viommu;

    if ( !info || !info->ops || !info->ops->destroy)
        return -EINVAL;

    if ( viommu_id > info->nr_viommu || !info->viommu[viommu_id] )
        return -EINVAL;

    if ( info->ops->destroy(info->viommu[viommu_id]) )
        return -EFAULT;

    info->viommu[viommu_id] = NULL;
    return 0;
}

u64 viommu_query_caps(struct domain *d)
{
    struct viommu_info *info = &d->viommu;

    if ( !info || !info->ops || !info->ops->query_caps)
        return -EINVAL;

    return info->ops->query_caps(d);
}

int viommu_handle_irq_request(struct domain *d,
        struct irq_remapping_request *request)
{
    struct viommu_info *info = &d->viommu;

    if ( !info || !info->ops || !info->ops->handle_irq_request)
        return -EINVAL;

    return info->ops->handle_irq_request(d, request);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
