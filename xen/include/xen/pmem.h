/*
 * xen/include/xen/pmem.h
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

#ifndef __XEN_PMEM_H__
#define __XEN_PMEM_H__
#ifdef CONFIG_PMEM

#include <xen/types.h>

int pmem_register(unsigned long smfn, unsigned long emfn);
int pmem_setup(unsigned long data_spfn, unsigned long data_emfn,
               unsigned long mgmt_smfn, unsigned long mgmt_emfn);

struct xen_pmem_map_args {
    struct domain *domain;

    unsigned long mfn;     /* start MFN of pmems page to be mapped */
    unsigned long gfn;     /* start GFN of target domain */
    unsigned long nr_mfns; /* number of pmem pages to be mapped */

    /* For preemption ... */
    unsigned long nr_done; /* number of pmem pages processed so far */
    int preempted;         /* Is the operation preempted? */
};

#ifdef CONFIG_X86
int pmem_arch_setup(unsigned long data_smfn, unsigned long data_emfn,
                    unsigned long mgmt_smfn, unsigned long mgmt_emfn);
int pmem_populate(struct xen_pmem_map_args *args);
int pmem_teardown(struct domain *d);
#else /* !CONFIG_X86 */
static inline int
pmem_arch_setup(unsigned long data_smfn, unsigned long data_emfn,
                unsigned mgmt_smfn, unsigned long mgmt_emfn)
{
    return -ENOSYS;
}

static inline int pmem_populate(struct xen_pmem_map_args *args)
{
    return -ENOSYS;
}

static inline int pmem_teardown(struct domain *d)
{
    return -ENOSYS;
}
#endif /* CONFIG_X86 */

#endif /* CONFIG_PMEM */
#endif /* __XEN_PMEM_H__ */
