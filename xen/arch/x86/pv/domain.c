/******************************************************************************
 * arch/x86/pv/domain.c
 *
 * PV-specific domain handling
 */

/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */


#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/sched.h>

static void noreturn continue_nonidle_domain(struct vcpu *v)
{
    check_wakeup_from_wait();
    mark_regs_dirty(guest_cpu_user_regs());
    reset_stack_and_jump(ret_from_intr);
}

static int setup_compat_l4(struct vcpu *v)
{
    struct page_info *pg;
    l4_pgentry_t *l4tab;

    pg = alloc_domheap_page(v->domain, MEMF_no_owner);
    if ( pg == NULL )
        return -ENOMEM;

    /* This page needs to look like a pagetable so that it can be shadowed */
    pg->u.inuse.type_info = PGT_l4_page_table|PGT_validated|1;

    l4tab = __map_domain_page(pg);
    clear_page(l4tab);
    init_guest_l4_table(l4tab, v->domain, 1);
    unmap_domain_page(l4tab);

    v->arch.guest_table = pagetable_from_page(pg);
    v->arch.guest_table_user = v->arch.guest_table;

    return 0;
}

static void release_compat_l4(struct vcpu *v)
{
    free_domheap_page(pagetable_get_page(v->arch.guest_table));
    v->arch.guest_table = pagetable_null();
    v->arch.guest_table_user = pagetable_null();
}

int switch_compat(struct domain *d)
{
    struct vcpu *v;
    int rc;

    if ( is_hvm_domain(d) || d->tot_pages != 0 )
        return -EACCES;
    if ( is_pv_32bit_domain(d) )
        return 0;

    d->arch.has_32bit_shinfo = 1;
    if ( is_pv_domain(d) )
        d->arch.is_32bit_pv = 1;

    for_each_vcpu( d, v )
    {
        rc = setup_compat_arg_xlat(v);
        if ( !rc )
            rc = setup_compat_l4(v);

        if ( rc )
            goto undo_and_fail;
    }

    domain_set_alloc_bitsize(d);
    recalculate_cpuid_policy(d);

    d->arch.x87_fip_width = 4;

    return 0;

 undo_and_fail:
    d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 0;
    for_each_vcpu( d, v )
    {
        free_compat_arg_xlat(v);

        if ( !pagetable_is_null(v->arch.guest_table) )
            release_compat_l4(v);
    }

    return rc;
}

int pv_vcpu_initialise(struct vcpu *v)
{
    struct domain *d = v->domain;
    int rc = 0;

    spin_lock_init(&v->arch.pv_vcpu.shadow_ldt_lock);

    if ( !is_idle_domain(d) )
    {
        rc = create_perdomain_mapping(d, GDT_VIRT_START(v),
                                      1 << GDT_LDT_VCPU_SHIFT,
                                      d->arch.pv_domain.gdt_ldt_l1tab, NULL);
        if ( rc )
            goto done;

        BUILD_BUG_ON(NR_VECTORS * sizeof(*v->arch.pv_vcpu.trap_ctxt) >
                     PAGE_SIZE);
        v->arch.pv_vcpu.trap_ctxt = xzalloc_array(struct trap_info,
                                                  NR_VECTORS);
        if ( !v->arch.pv_vcpu.trap_ctxt )
        {
            rc = -ENOMEM;
            goto done;
        }

        /* PV guests by default have a 100Hz ticker. */
        v->periodic_period = MILLISECS(10);
    }
    else
        v->arch.cr3 = __pa(idle_pg_table);

    v->arch.pv_vcpu.ctrlreg[4] = real_cr4_to_pv_guest_cr4(mmu_cr4_features);

    if ( is_pv_32bit_domain(d) )
    {
        if ( (rc = setup_compat_arg_xlat(v)) )
            goto done;

        if ( (rc = setup_compat_l4(v)) )
        {
            free_compat_arg_xlat(v);
            goto done;
        }
    }

 done:
    return rc;
}

void pv_vcpu_destroy(struct vcpu *v)
{
    if ( is_pv_32bit_vcpu(v) )
    {
        free_compat_arg_xlat(v);
        release_compat_l4(v);
    }

    xfree(v->arch.pv_vcpu.trap_ctxt);
}

void pv_domain_destroy(struct domain *d)
{
    xfree(d->arch.pv_domain.cpuidmasks);
    free_xenheap_page(d->arch.pv_domain.gdt_ldt_l1tab);
}

int pv_domain_initialise(struct domain *d, unsigned int domcr_flags)
{
    static const struct arch_csw pv_csw = {
        .from = paravirt_ctxt_switch_from,
        .to   = paravirt_ctxt_switch_to,
        .tail = continue_nonidle_domain,
    };
    int rc = -ENOMEM;

    d->arch.pv_domain.gdt_ldt_l1tab =
        alloc_xenheap_pages(0, MEMF_node(domain_to_node(d)));
    if ( !d->arch.pv_domain.gdt_ldt_l1tab )
        goto fail;
    clear_page(d->arch.pv_domain.gdt_ldt_l1tab);

    if ( levelling_caps & ~LCAP_faulting )
    {
        d->arch.pv_domain.cpuidmasks = xmalloc(struct cpuidmasks);
        if ( !d->arch.pv_domain.cpuidmasks )
            goto fail;
        *d->arch.pv_domain.cpuidmasks = cpuidmask_defaults;
    }

    rc = create_perdomain_mapping(d, GDT_LDT_VIRT_START,
                                  GDT_LDT_MBYTES << (20 - PAGE_SHIFT),
                                  NULL, NULL);
    if ( rc )
        goto fail;

    d->arch.ctxt_switch = &pv_csw;

    /* 64-bit PV guest by default. */
    d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 0;

    return 0;

fail:
    if ( d->arch.pv_domain.gdt_ldt_l1tab )
    {
        free_xenheap_page(d->arch.pv_domain.gdt_ldt_l1tab);
        d->arch.pv_domain.gdt_ldt_l1tab = NULL;
    }

    if ( d->arch.pv_domain.cpuidmasks )
    {
        xfree(d->arch.pv_domain.cpuidmasks);
        d->arch.pv_domain.cpuidmasks = NULL;
    }

    return rc;
}

/*
 * These are the masks of CR4 bits (subject to hardware availability) which a
 * PV guest may not legitimiately attempt to modify.
 */
static unsigned long __read_mostly pv_cr4_mask, compat_pv_cr4_mask;

static int __init init_pv_cr4_masks(void)
{
    unsigned long common_mask = ~X86_CR4_TSD;

    /*
     * All PV guests may attempt to modify TSD, DE and OSXSAVE.
     */
    if ( cpu_has_de )
        common_mask &= ~X86_CR4_DE;
    if ( cpu_has_xsave )
        common_mask &= ~X86_CR4_OSXSAVE;

    pv_cr4_mask = compat_pv_cr4_mask = common_mask;

    /*
     * 64bit PV guests may attempt to modify FSGSBASE.
     */
    if ( cpu_has_fsgsbase )
        pv_cr4_mask &= ~X86_CR4_FSGSBASE;

    return 0;
}
__initcall(init_pv_cr4_masks);

unsigned long pv_guest_cr4_fixup(const struct vcpu *v, unsigned long guest_cr4)
{
    unsigned long hv_cr4 = real_cr4_to_pv_guest_cr4(read_cr4());
    unsigned long mask = is_pv_32bit_vcpu(v) ? compat_pv_cr4_mask : pv_cr4_mask;

    if ( (guest_cr4 & mask) != (hv_cr4 & mask) )
        printk(XENLOG_G_WARNING
               "d%d attempted to change %pv's CR4 flags %08lx -> %08lx\n",
               current->domain->domain_id, v, hv_cr4, guest_cr4);

    return (hv_cr4 & mask) | (guest_cr4 & ~mask);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
