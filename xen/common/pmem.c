/*
 * xen/common/pmem.c
 *
 * Copyright (C) 2017, Intel Corporation.
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

#include <xen/errno.h>
#include <xen/list.h>
#include <xen/pmem.h>
#include <xen/spinlock.h>

/*
 * All pmem regions probed via SPA range structures of ACPI NFIT are
 * linked in pmem_regions.
 */
static DEFINE_SPINLOCK(pmem_regions_lock);
static LIST_HEAD(pmem_regions);

struct pmem {
    struct list_head link;      /* link to pmem_list */
    unsigned long smfn;         /* start MFN of the whole pmem region */
    unsigned long emfn;         /* end MFN of the whole pmem region */
};

static bool check_overlap(unsigned long smfn1, unsigned long emfn1,
                          unsigned long smfn2, unsigned long emfn2)
{
    return smfn1 < emfn2 && smfn2 < emfn1;
}

static struct pmem *alloc_pmem_struct(unsigned long smfn, unsigned long emfn)
{
    struct pmem *pmem = xzalloc(struct pmem);

    if ( !pmem )
        return NULL;

    pmem->smfn = smfn;
    pmem->emfn = emfn;

    return pmem;
}

static int pmem_list_add(struct list_head *list, struct pmem *entry)
{
    struct list_head *cur;
    unsigned long smfn = entry->smfn, emfn = entry->emfn;

    list_for_each_prev(cur, list)
    {
        struct pmem *cur_pmem = list_entry(cur, struct pmem, link);
        unsigned long cur_smfn = cur_pmem->smfn;
        unsigned long cur_emfn = cur_pmem->emfn;

        if ( check_overlap(smfn, emfn, cur_smfn, cur_emfn) )
            return -EINVAL;

        if ( cur_smfn < smfn )
            break;
    }

    list_add(&entry->link, cur);

    return 0;
}

/**
 * Register a pmem region to Xen. It's used by Xen hypervisor to collect
 * all pmem regions can be used later.
 *
 * Parameters:
 *  smfn, emfn: start and end MFNs of the pmem region
 *
 * Return:
 *  On success, return 0. Otherwise, an error number is returned.
 */
int pmem_register(unsigned long smfn, unsigned long emfn)
{
    int rc;
    struct pmem *pmem;

    if ( smfn >= emfn )
        return -EINVAL;

    pmem = alloc_pmem_struct(smfn, emfn);
    if ( !pmem )
        return -ENOMEM;

    spin_lock(&pmem_regions_lock);
    rc = pmem_list_add(&pmem_regions, pmem);
    spin_unlock(&pmem_regions_lock);

    return rc;
}
