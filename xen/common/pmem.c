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
#include <xen/event.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/paging.h>
#include <xen/pmem.h>
#include <xen/sched.h>
#include <xen/spinlock.h>

/*
 * All pmem regions probed via SPA range structures of ACPI NFIT are
 * linked in pmem_regions.
 */
static DEFINE_SPINLOCK(pmem_regions_lock);
static LIST_HEAD(pmem_regions);

/*
 * Two types of pmem regions are linked in this list and are
 * distinguished by their ready flags.
 * - Data pmem regions that can be mapped to guest, and their ready
 *   flags are true.
 * - Management pmem regions that are used to management data regions
 *   and never mapped to guest, and their ready flags are false.
 *
 * All regions linked in this list must be covered by one or multiple
 * regions in list pmem_regions as well.
 */
static DEFINE_SPINLOCK(pmem_gregions_lock);
static LIST_HEAD(pmem_gregions);

struct pmem {
    struct list_head link;      /* link to pmem_list */
    unsigned long smfn;         /* start MFN of the whole pmem region */
    unsigned long emfn;         /* end MFN of the whole pmem region */

    /*
     * If frametable and M2P of this pmem region is stored in the
     * regular RAM, mgmt will be NULL. Otherwise, it refers to another
     * pmem region used for those management structures.
     */
    struct pmem *mgmt;

    bool ready;                 /* indicate whether it can be mapped to guest */
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

static void pmem_list_remove(struct pmem *entry)
{
    list_del(&entry->link);
}

static struct pmem *get_first_overlap(const struct list_head *list,
                                      unsigned long smfn, unsigned emfn)
{
    struct list_head *cur;
    struct pmem *overlap = NULL;

    list_for_each(cur, list)
    {
        struct pmem *cur_pmem = list_entry(cur, struct pmem, link);
        unsigned long cur_smfn = cur_pmem->smfn;
        unsigned long cur_emfn = cur_pmem->emfn;

        if ( emfn <= cur_smfn )
            break;

        if ( check_overlap(smfn, emfn, cur_smfn, cur_emfn) )
        {
            overlap = cur_pmem;
            break;
        }
    }

    return overlap;
}

static bool pmem_list_covered_ready(const struct list_head *list,
                                    unsigned long smfn, unsigned emfn,
                                    bool check_ready)
{
    struct pmem *overlap;
    bool covered = false;

    do {
        overlap = get_first_overlap(list, smfn, emfn);

        if ( !overlap || smfn < overlap->smfn ||
             (check_ready && !overlap->ready) )
            break;

        if ( emfn <= overlap->emfn )
        {
            covered = true;
            break;
        }

        smfn = overlap->emfn;
        list = &overlap->link;
    } while ( list );

    return covered;
}

static bool pmem_list_covered(const struct list_head *list,
                              unsigned long smfn, unsigned emfn)
{
    return pmem_list_covered_ready(list, smfn, emfn, false);
}

static bool check_mgmt_size(unsigned long mgmt_mfns, unsigned long total_mfns)
{
    return mgmt_mfns >=
        ((sizeof(struct page_info) * total_mfns) >> PAGE_SHIFT) +
        ((sizeof(*machine_to_phys_mapping) * total_mfns) >> PAGE_SHIFT);
}

static bool check_region(unsigned long smfn, unsigned long emfn)
{
    bool rc;

    if ( smfn >= emfn )
        return false;

    spin_lock(&pmem_regions_lock);
    rc = pmem_list_covered(&pmem_regions, smfn, emfn);
    spin_unlock(&pmem_regions_lock);

    return rc;
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

/**
 * Setup a data pmem region that can be used by guest later. A
 * separate pmem region, or the management region, can be specified to
 * store the frametable and M2P tables of the data pmem region.
 *
 * Parameters:
 *  data_smfn/_emfn: start and end MFNs of the data pmem region
 *  mgmt_emfn/_emfn: If not mfn_x(INVALID_MFN), then the pmem region from
 *                   mgmt_smfn to mgmt_emfn will be used for the frametable
 *                   M2P of itself and the data pmem region. Otherwise, the
 *                   regular RAM will be used.
 *
 * Return:
 *  On success, return 0. Otherwise, an error number will be returned.
 */
int pmem_setup(unsigned long data_smfn, unsigned long data_emfn,
               unsigned long mgmt_smfn, unsigned long mgmt_emfn)
{
    int rc = 0;
    bool mgmt_in_pmem = mgmt_smfn != mfn_x(INVALID_MFN) &&
                        mgmt_emfn != mfn_x(INVALID_MFN);
    struct pmem *pmem, *mgmt = NULL;
    unsigned long mgmt_mfns = mgmt_emfn - mgmt_smfn;
    unsigned long total_mfns = data_emfn - data_smfn + mgmt_mfns;
    unsigned long i;
    struct page_info *pg;

    if ( !check_region(data_smfn, data_emfn) )
        return -EINVAL;

    if ( mgmt_in_pmem &&
         (!check_region(mgmt_smfn, mgmt_emfn) ||
          !check_mgmt_size(mgmt_mfns, total_mfns)) )
        return -EINVAL;

    pmem = alloc_pmem_struct(data_smfn, data_emfn);
    if ( !pmem )
        return -ENOMEM;
    if ( mgmt_in_pmem )
    {
        mgmt = alloc_pmem_struct(mgmt_smfn, mgmt_emfn);
        if ( !mgmt )
            return -ENOMEM;
    }

    spin_lock(&pmem_gregions_lock);
    rc = pmem_list_add(&pmem_gregions, pmem);
    if ( rc )
    {
        spin_unlock(&pmem_gregions_lock);
        goto out;
    }
    if ( mgmt_in_pmem )
    {
        rc = pmem_list_add(&pmem_gregions, mgmt);
        if ( rc )
        {
            spin_unlock(&pmem_gregions_lock);
            goto out_remove_pmem;
        }
    }
    spin_unlock(&pmem_gregions_lock);

    rc = pmem_arch_setup(data_smfn, data_emfn, mgmt_smfn, mgmt_emfn);
    if ( rc )
        goto out_remove_mgmt;

    for ( i = data_smfn; i < data_emfn; i++ )
    {
        pg = mfn_to_page(i);
        pg->count_info = PGC_state_free;
    }

    if ( mgmt_in_pmem )
        pmem->mgmt = mgmt->mgmt = mgmt;
    /* As mgmt is never mapped to guest, we do not set its ready flag. */
    pmem->ready = true;

    return 0;

 out_remove_mgmt:
    if ( mgmt )
    {
        spin_lock(&pmem_gregions_lock);
        pmem_list_remove(mgmt);
        spin_unlock(&pmem_gregions_lock);
        xfree(mgmt);
    }
 out_remove_pmem:
    spin_lock(&pmem_gregions_lock);
    pmem_list_remove(pmem);
    spin_unlock(&pmem_gregions_lock);
    xfree(pmem);
 out:
    return rc;
}

#ifdef CONFIG_X86

static void pmem_assign_page(struct domain *d, struct page_info *pg,
                             unsigned long gfn)
{
    pg->u.inuse.type_info = 0;
    page_set_owner(pg, d);
    guest_physmap_add_page(d, _gfn(gfn), _mfn(page_to_mfn(pg)), 0);

    spin_lock(&d->pmem_lock);
    page_list_add_tail(pg, &d->pmem_page_list);
    spin_unlock(&d->pmem_lock);
}

static void pmem_unassign_page(struct domain *d, struct page_info *pg,
                               unsigned long gfn)
{
    spin_lock(&d->pmem_lock);
    page_list_del(pg, &d->pmem_page_list);
    spin_unlock(&d->pmem_lock);

    guest_physmap_remove_page(d, _gfn(gfn), _mfn(page_to_mfn(pg)), 0);
    page_set_owner(pg, NULL);
    pg->count_info = (pg->count_info & ~PGC_count_mask) | PGC_state_free;
}

static void pmem_unassign_pages(struct domain *d, unsigned long mfn,
                                unsigned long gfn, unsigned long nr_mfns)
{
    unsigned long emfn = mfn + nr_mfns;

    for ( ; mfn < emfn; mfn++, gfn++ )
        pmem_unassign_page(d, mfn_to_page(mfn), gfn);
}

/**
 * Map host pmem pages to a domain. Currently only HVM domain is
 * supported.
 *
 * Parameters:
 *  args: please refer to comments of struct xen_pmemmap_args in xen/pmem.h
 *
 * Return:
 *  0 on success; non-zero error code on failures.
 */
int pmem_populate(struct xen_pmem_map_args *args)
{
    struct domain *d = args->domain;
    unsigned long i = args->nr_done;
    unsigned long mfn = args->mfn + i;
    unsigned long emfn = args->mfn + args->nr_mfns;
    unsigned long gfn;
    struct page_info *page;
    int rc = 0;

    if ( unlikely(d->is_dying) )
        return -EINVAL;

    if ( !has_hvm_container_domain(d) || !paging_mode_translate(d) )
        return -EINVAL;

    spin_lock(&pmem_gregions_lock);
    if ( !pmem_list_covered_ready(&pmem_gregions, mfn, emfn, true) )
    {
        spin_unlock(&pmem_regions_lock);
        return -EINVAL;
    }
    spin_unlock(&pmem_gregions_lock);

    for ( gfn = args->gfn + i; mfn < emfn; i++, mfn++, gfn++ )
    {
        if ( i != args->nr_done && hypercall_preempt_check() )
        {
            args->preempted = 1;
            rc = -ERESTART;
            break;
        }

        page = mfn_to_page(mfn);

        spin_lock(&pmem_gregions_lock);
        if ( !page_state_is(page, free) )
        {
            dprintk(XENLOG_DEBUG, "pmem: mfn 0x%lx not in free state\n", mfn);
            spin_unlock(&pmem_gregions_lock);
            rc = -EINVAL;
            break;
        }
        page->count_info = PGC_state_inuse | 1;
        spin_unlock(&pmem_gregions_lock);

        pmem_assign_page(d, page, gfn);
    }

    if ( rc && rc != -ERESTART )
        pmem_unassign_pages(d, args->mfn, args->gfn, i);

    args->nr_done = i;
    return rc;
}

int pmem_teardown(struct domain *d)
{
    struct page_info *pg, *next;
    int rc = 0;

    ASSERT(d->is_dying);
    ASSERT(d != current->domain);

    spin_lock(&d->pmem_lock);

    page_list_for_each_safe (pg, next, &d->pmem_page_list )
    {
        BUG_ON(page_get_owner(pg) != d);
        BUG_ON(page_state_is(pg, free));

        page_list_del(pg, &d->pmem_page_list);
        page_set_owner(pg, NULL);
        pg->count_info = (pg->count_info & ~PGC_count_mask) | PGC_state_free;

        if ( hypercall_preempt_check() )
        {
            rc = -ERESTART;
            break;
        }
    }

    spin_unlock(&d->pmem_lock);

    return rc;
}

#endif /* CONFIG_X86 */
