/**
 * @file tests/pagetable-emulation/main.c
 * @ref test-pagetable-emulation - TODO.
 *
 * @page test-pagetable-emulation TODO
 *
 * @sa tests/pagetable-emulation/main.c
 */
#include <xtf.h>

#include <arch/decode.h>
#include <arch/exinfo.h>
#include <arch/idt.h>
#include <arch/msr-index.h>
#include <arch/pagetable.h>
#include <arch/processor.h>
#include <arch/symbolic-const.h>

#include "stubs.h"

const char test_title[] = "Test pagetable-emulation";

intpte_t l1t[PAGE_SIZE / sizeof(intpte_t)] __aligned(PAGE_SIZE);
intpte_t l2t[PAGE_SIZE / sizeof(intpte_t)] __aligned(PAGE_SIZE);

#if CONFIG_PAGING_LEVELS > 3
intpte_t l3t[PAGE_SIZE / sizeof(intpte_t)] __aligned(PAGE_SIZE);
#else
extern intpte_t l3t[PAGE_SIZE / sizeof(intpte_t)];
#endif

#define LDT_SEL 0x000F /* Entry 0x8, LDT, RPL3 */

#define PFEC_P X86_PFEC_PRESENT
#define PFEC_W X86_PFEC_WRITE
#define PFEC_U X86_PFEC_USER
#define PFEC_R X86_PFEC_RSVD
#define PFEC_I X86_PFEC_INSN
#define PFEC(...) TOK_OR(PFEC_, ##__VA_ARGS__)

uint64_t efer;
unsigned long cr0, cr4;
bool host_nx_leaked;
bool amd_fam10_erratum;
bool shadow_paging;

static struct {
    unsigned long va;
    bool active;
    bool user;
    const char *desc;

    intpte_t pteval;
    bool pte_printed;
} under_test;

static const struct stubs
{
    unsigned long (*read)          (unsigned long va);
    unsigned long (*implicit)      (unsigned long va);
    unsigned long (*write)         (unsigned long va);
    unsigned long (*exec)          (unsigned long va);
    unsigned long (*read_user)     (unsigned long va);
    unsigned long (*implicit_user) (unsigned long va);
    unsigned long (*write_user)    (unsigned long va);
    unsigned long (*exec_user)     (unsigned long va);
} regular_stubs = {
    .read          = stub_read,
    .implicit      = stub_implicit,
    .write         = stub_write,
    .exec          = stub_exec,
    .read_user     = stub_read_user,
    .implicit_user = stub_implicit_user,
    .write_user    = stub_write_user,
    .exec_user     = stub_exec_user,
}, force_stubs = {
    .read          = stub_force_read,
    .implicit      = stub_force_implicit,
    .write         = stub_force_write,
    .exec          = stub_force_exec,
    .read_user     = stub_force_read_user,
    .implicit_user = stub_force_implicit_user,
    .write_user    = stub_force_write_user,
    .exec_user     = stub_force_exec_user,
};

struct mapping_info
{
    unsigned int level, order;
    void *va;
    intpte_t *pte, *fe_pte;
    uint64_t paddr;

    union
    {
        intpte_t *ptes[4];
        struct
        {
            intpte_t *l1e, *l2e, *l3e, *l4e;
        };
    };
};

void flush_tlb(bool global)
{
    write_cr3(read_cr3());

    if ( global && (cr4 & X86_CR4_PGE) )
    {
        write_cr4(cr4 & ~X86_CR4_PGE);
        write_cr4(cr4);
    }
}

bool ex_check_pf(struct cpu_regs *regs,
                 const struct extable_entry *ex)
{
    if ( regs->entry_vector == X86_EXC_PF )
    {
        unsigned long cr2 = read_cr2();

        if ( (cr2 != under_test.va) &&
             (cr2 != under_test.va + (LDT_SEL & ~7)) )
            xtf_failure("Bad %%cr2: expected %p, got %p\n",
                        _p(under_test.va), _p(cr2));

        regs->ax = EXINFO_SYM(PF, regs->error_code);

        if ( ex->fixup )
            regs->ip = ex->fixup;
        else
            regs->ip = *(unsigned long *)cpu_regs_sp(regs);

        return true;
    }

    return false;
}

void __printf(1, 2) fail(const char *fmt, ...)
{
    va_list args;

    if ( !under_test.active )
        return;

    if ( !under_test.pte_printed )
    {
        intpte_t pte = under_test.pteval;
        printk("  PTE %"PRIpte":%s%s%s%s%s%s%s%s\n", pte,
               pte & _PAGE_NX ? " Nx" : "",
               pte & 0x7ff0000000000000ULL ? " Av" : "",
               pte & ((1ULL << 52) - 1) & ~((1ULL << maxphysaddr) - 1) ? " Rs" : "",
               pte & _PAGE_GLOBAL ? " G" : "",
               pte & _PAGE_PSE ? " +" : "",
               pte & _PAGE_USER ? " U" : "",
               pte & _PAGE_RW ? " W" : "",
               pte & _PAGE_PRESENT ? " P" : ""
            );

        under_test.pte_printed = true;
    }

    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);
    xtf_failure(NULL);
}

bool unhandled_exception(struct cpu_regs *regs)
{
    fail("ERROR: Unhandled exception during %s %s\n",
         under_test.user ? "User" : "Supervisor",
         under_test.desc);
    return false;
}

static void prepare_mappings(struct mapping_info *m, unsigned int level, bool super, paddr_t paddr)
{
    bool pse36 = CONFIG_PAGING_LEVELS == 2 && paddr != (uint32_t)paddr;

    memset(m, 0, sizeof(*m));

#define PAGE_COMMON PF_SYM(AD, U, RW, P)
    /*
     * For 4-level paging, we use l4[1/2].
     */
    if ( CONFIG_PAGING_LEVELS == 4 )
    {

        pae_l4_identmap[1] = (unsigned long)l3t | PAGE_COMMON;
        pae_l4_identmap[2] = (unsigned long)l3t | PAGE_COMMON;

        l3t[0]   = (unsigned long)l2t | PAGE_COMMON;
        l3t[511] = (unsigned long)l2t | PAGE_COMMON;

        l2t[0]   = (unsigned long)l1t | PAGE_COMMON;
        l2t[511] = (unsigned long)l1t | PAGE_COMMON;

        l1t[0]   = paddr | PAGE_COMMON;
        l1t[511] = ((paddr - 1) & ~0xfff) | PAGE_COMMON;

        m->va     = _p(2ULL << PAE_L4_PT_SHIFT);
        m->l1e    = &l1t[0];
        m->l2e    = &l2t[0];
        m->l3e    = &l3t[0];
        m->l4e    = _p(&pae_l4_identmap[2]);
        m->fe_pte = &l1t[511];

        asm(_ASM_EXTABLE_HANDLER(2 << PAE_L4_PT_SHIFT, 0, ex_check_pf));
        under_test.va = (unsigned long)m->va;
    }
    else if ( CONFIG_PAGING_LEVELS == 3 )
    {
        pae32_l3_identmap[1] = (unsigned long)l2t | _PAGE_PRESENT;
        pae32_l3_identmap[2] = (unsigned long)l2t | _PAGE_PRESENT;

        l2t[0]   = (unsigned long)l1t | PAGE_COMMON;
        l2t[511] = (unsigned long)l1t | PAGE_COMMON;

        l1t[0]   = paddr | PAGE_COMMON;
        l1t[511] = ((paddr - 1) & ~0xfff) | PAGE_COMMON;

        m->va     = _p(2ULL << PAE_L3_PT_SHIFT);
        m->l1e    = &l1t[0];
        m->l2e    = &l2t[0];
        m->l3e    = _p(&pae32_l3_identmap[2]);
        m->l4e    = NULL;
        m->fe_pte = &l1t[511];

        asm(_ASM_EXTABLE_HANDLER(2 << PAE_L3_PT_SHIFT, 0, ex_check_pf));
        under_test.va = (unsigned long)m->va;
    }
    else if ( CONFIG_PAGING_LEVELS == 2 )
    {
        if ( pse36 )
        {
            ASSERT(super);
            ASSERT(IS_ALIGNED(paddr, MB(4)));

            pse_l2_identmap[511] = fold_pse36((paddr - MB(4)) | PAGE_COMMON | _PAGE_PSE);
            pse_l2_identmap[512] = fold_pse36(paddr | PAGE_COMMON | _PAGE_PSE);
        }
        else
        {
            pse_l2_identmap[511] = (unsigned long)l1t | PAGE_COMMON;
            pse_l2_identmap[512] = (unsigned long)l1t | PAGE_COMMON;

            l1t[0]    = paddr | PAGE_COMMON;
            l1t[1023] = ((paddr - 1) & ~0xfff) | PAGE_COMMON;
        }

        m->va     = _p(2ULL << PAE_L3_PT_SHIFT);
        m->l1e    = pse36 ? NULL : &l1t[0];
        m->l2e    = _p(&pse_l2_identmap[512]);
        m->l3e    = NULL;
        m->l4e    = NULL;
        m->fe_pte = pse36 ? _p(&pse_l2_identmap[511]) : &l1t[1023];

        asm(_ASM_EXTABLE_HANDLER(2 << PAE_L3_PT_SHIFT, 0, ex_check_pf));
        under_test.va = (unsigned long)m->va;
    }
    else
        panic("%s() PAGING_LEVELS %u not implemented yet\n",
              __func__, CONFIG_PAGING_LEVELS);

#undef PAGE_COMMON

    /* Flush the TLB before trying to use the new mappings. */
    flush_tlb(false);

    /* Put FEP immediately before va, and a ret instruction at va. */
    memcpy(m->va - 5, "\x0f\x0bxen\xc3", 6);
    barrier();

    /* Read them back, to confirm that RAM is properly in place. */
    if ( memcmp(m->va - 5, "\x0f\x0bxen\xc3", 6) )
        panic("Bad phys or virtual setup\n");

    /* Construct the LDT at va. */
    user_desc *ldt = m->va;

    ldt[LDT_SEL >> 3] = (typeof(*ldt))INIT_GDTE_SYM(0, 0xfffff, COMMON, DATA, DPL3, B, W);
    gdt[GDTE_AVAIL0]  = (typeof(*gdt))INIT_GDTE((unsigned long)m->va, PAGE_SIZE, 0x82);
#if __x86_64__
    /* For 64bit, put the upper 32 bits of base into the adjacent entry. */
    gdt[GDTE_AVAIL0 + 1] =
        (user_desc){{{ .lo = ((unsigned long)m->va) >> 32, .hi = 0 }}};
#endif
    lldt(GDTE_AVAIL0 << 3);
    write_fs(LDT_SEL);

    m->level = level;
    m->pte = m->ptes[level - 1];

    if ( pse36 )
    {
        /* No l1e at all. */
        m->order = PT_ORDER + PAGE_SHIFT;
        m->paddr = *m->pte & ~0xfff;
    }
    else if ( super && (cr4 & (X86_CR4_PAE|X86_CR4_PSE)) )
    {
        /* Superpage in effect. */
        m->order = ((level - 1) * PT_ORDER) + PAGE_SHIFT;
        m->paddr =  *m->l1e & ~0xfff;
    }
    else
    {
        /* Small page, or superpage not in effect. */
        m->order = 0;
        m->paddr = *m->pte & ~0xfff;
    }
}

void clear_ad(struct mapping_info *m)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(m->ptes); ++i )
        if ( m->ptes[i] )
            *m->ptes[i] &= ~_PAGE_AD;

    invlpg(m->va);
}

enum modifier
{
    /* Calc. */
    WP       = 1 << 0,
    NX       = 1 << 1,
    SMEP     = 1 << 2,
    SMAP     = 1 << 3,
    AC       = 1 << 4,
    IMP      = 1 << 5,

    /* Check only. */
    WRITE    = 1 << 6,
};

void check(struct mapping_info *m, exinfo_t actual, exinfo_t expected, enum modifier mod)
{
    /* Check that the actual pagefault matched our expectation. */
    if ( actual != expected )
    {
        const char *user_sup = under_test.user ? "User" : "Supervisor";
        bool ac_fault = !!actual, ex_fault = !!expected;
        char ac_ec[16], ex_ec[16];

        if ( ac_fault )
            x86_exc_decode_ec(ac_ec, ARRAY_SIZE(ac_ec),
                              X86_EXC_PF, (uint16_t)actual);
        if ( ex_fault )
            x86_exc_decode_ec(ex_ec, ARRAY_SIZE(ex_ec),
                              X86_EXC_PF, (uint16_t)expected);

        if ( ac_fault && !ex_fault )
            fail("    Fail: expected no fault, got #PF[%s] for %s %s\n",
                 ac_ec, user_sup, under_test.desc);
        else if ( !ac_fault && ex_fault )
            fail("    Fail: expected #PF[%s], got no fault for %s %s\n",
                 ex_ec, user_sup, under_test.desc);
        else
            fail("    Fail: expected #PF[%s], got #PF[%s] for %s %s\n",
                 ex_ec, ac_ec,  user_sup, under_test.desc);
    }

    /* Check that A/D bits got updated as expected. */
    unsigned int leaf_level =
        m->order ? ((m->order - PAGE_SHIFT) / PT_ORDER) : 0;
    unsigned int i; /* NB - Levels are 0-indexed. */

    if ( amd_fam10_erratum )
    {
        /*
         * AMD Fam10 appears to defer the setting of access bits for implicit
         * loads.  As a result, the implicit tests (which load %fs) don't
         * necessarily observe the access bits being set on the pagewalk to
         * the LDT.
         *
         * Experimentally, a serialising instruction fixes things, or a loop
         * of 1000 nops, but so does forcing the use of the loaded segment.
         *
         * If this is an implicit load which didn't fault, read through %fs to
         * force it to be loaded into the segment cache.
         */
        if ( (mod & IMP) && !actual )
            asm volatile ("mov %%fs:0x1000, %0" : "=r" (i));
    }

    for ( i = 0; i < ARRAY_SIZE(m->ptes); ++i )
    {
        int exp_a, exp_d;

        if ( !m->ptes[i] )
            continue;

        if ( CONFIG_PAGING_LEVELS == 3 && i == 2 )
        {
            /*
             * 32bit PAE paging is special.  The 4 PDPTE's are read from
             * memory, cached in the processor and don't strictly count as
             * pagetables. The A/D bits are not updated.
             */
            exp_a = 0;
            exp_d = 0;
        }
        else if ( leaf_level > i )
        {
            /*
             * Logically below a superpage.  Nothing should consider this part
             * of the pagetable structure, and neither A or D should be set.
             */
            exp_a = 0;
            exp_d = 0;
        }
        else if ( leaf_level == i )
        {
            /*
             * At a leaf page.  If there was no fault, we expect A to be set,
             * optionally D if a write occurred.
             */
            exp_a = (actual == 0);
            exp_d = exp_a && (mod & WRITE);
        }
        else
        {
            /*
             * Higher level translation structure.  A processor is free to
             * cache the partial translation or not, at its discretion, but
             * they will never be dirty.
             */
            exp_a = -1;
            exp_d = 0;
        }

        bool act_a = *m->ptes[i] & _PAGE_ACCESSED;
        bool act_d = *m->ptes[i] & _PAGE_DIRTY;

        if ( (exp_a >= 0 && exp_a != act_a) || (exp_d != act_d) )
            fail("    Fail: expected L%u AD = %c%u, got %u%u for %s %s\n",
                 i + 1, exp_a == 1 ? '1' : exp_a == 0 ? '0' : 'x', exp_d,
                 act_a, act_d,
                 under_test.user ? "User" : "Supervisor", under_test.desc);
    }

    clear_ad(m);
    write_fs(0);
}

exinfo_t calc(struct mapping_info *m, uint64_t new, unsigned int walk, enum modifier mod)
{
    bool nx_valid   = CONFIG_PAGING_LEVELS >= 3 && (host_nx_leaked || (mod & NX));
    bool insn_valid = nx_valid || (mod & SMEP);
    uint64_t rsvd = ((1ULL << 52) - 1) & ~((1ULL << maxphysaddr) - 1);

    /* Accumulate additional bits which are reserved. */
    if ( !nx_valid )
        rsvd |= _PAGE_NX;

    if ( m->level == 4 )
        rsvd |= _PAGE_PSE | (vendor_is_amd ? _PAGE_GLOBAL : 0);
    else if ( m->level == 3 && !cpu_has_page1gb )
        rsvd |= _PAGE_PSE;

    if ( m->order )
    {
        if ( CONFIG_PAGING_LEVELS > 2 || !cpu_has_pse36 )
            rsvd |= ((1ULL << m->order) - 1) & ~(_PAGE_PSE_PAT | (_PAGE_PSE_PAT - 1));
        else
            rsvd |= (1ULL << 21) | fold_pse36(rsvd);
    }

    if ( CONFIG_PAGING_LEVELS == 3 )
        rsvd |= 0x7ff0000000000000ULL;


    if ( !insn_valid )
        walk &= ~PFEC(I);

    exinfo_t base = EXINFO_SYM(PF, walk & PFEC(I, U, W));

    /* Check whether a translation exists. */
    if ( !(new & _PAGE_PRESENT) )
        return base;
    base |= PFEC(P);

    if ( new & rsvd )
        return base | PFEC(R);

    /* Check access rights. */

    if ( (walk & PFEC(I)) && (new & _PAGE_NX) )
        /* Insn fetch of NX page? Always fail. */
        return base;

    if ( walk & PFEC(U) )
    {
        /* User walk. */

        if ( !(new & _PAGE_USER) )
            /* Supervisor page? Always fail. */
            return base;

        if ( (walk & PFEC(W)) && !(new & _PAGE_RW) )
            /* Write to a read-only page? */
            return base;
    }
    else
    {
        /* Supervisor Walk. */

        if ( new & _PAGE_USER )
        {
            /* User page. */

            if ( (walk & PFEC(I)) && (mod & SMEP) )
                /* Insn fetch with SMEP? */
                return base;

            if ( !(walk & PFEC(I)) && (mod & SMAP) &&
                 ((mod & IMP) || !(mod & AC)) )
                /* data fetch with SMAP and (Implicit or !AC)? */
                return base;
        }

        if ( (walk & PFEC(W)) && !(new & _PAGE_RW) && (mod & WP) )
            /* Write to a read-only page with WP active? */
            return base;
    }

    /* Should succeed. */
    return 0;
}

void test_pte(const struct stubs *stubs, struct mapping_info *m, uint64_t overlay)
{
    uint64_t new = m->paddr | overlay;
    bool user = false;

    under_test.pteval = *m->pte = new;
    under_test.pte_printed = false;
    clear_ad(m);

    under_test.active = true;

    for ( ; ; user = true )
    {
        unsigned int base = user ? PFEC(U) : 0;

#define CALL(fn, va)                                                    \
        (user ? exec_user_param(fn ## _user, (unsigned long)(va))       \
              : fn((unsigned long)(va)))

        under_test.user = user;

        /* Map the exec FEP stub with suitable permissions. */
        if ( stubs == &force_stubs )
        {
            *m->fe_pte &= ~_PAGE_USER;
            if ( user )
                *m->fe_pte |= _PAGE_USER;
            invlpg(m->va - 5);
        }

        /* Basic read. */
        under_test.desc = "Read";
        check(m, CALL(stubs->read, m->va),
              calc(m, new, base | PFEC(), 0),
              0);

        /* Implicit read (always supervisor).  `mov $LDT_SEL, %fs`. */
        under_test.desc = "Read, Implicit";
        check(m, CALL(stubs->implicit, _p(LDT_SEL)),
              calc(m, new, PFEC(), IMP),
              IMP);

        /* Read, SMAP. */
        if ( cpu_has_smap )
        {
            write_cr4(cr4 | X86_CR4_SMAP);

            asm volatile ("clac");

            under_test.desc = "Read, SMAP AC0";
            check(m, CALL(stubs->read, m->va),
                  calc(m, new, base | PFEC(), SMAP),
                  0);

            under_test.desc = "Read, Implicit, SMAP AC0";
            check(m, CALL(stubs->implicit, _p(LDT_SEL)),
                  calc(m, new, PFEC(), SMAP | IMP),
                  IMP);

            asm volatile ("stac");

            under_test.desc = "Read, SMAP AC1";
            check(m, CALL(stubs->read, m->va),
                  calc(m, new, base | PFEC(), SMAP | AC),
                  0);

            if ( !user && !shadow_paging )
            {
                /*
                 * This corner case loses information in the pagefault error
                 * code, which the shadow pagetable logic in the hypervisor
                 * can't account for.
                 *
                 * Executing this test in supervisor mode with shadow paging
                 * will livelock with no further progress made.
                 */
                under_test.desc = "Read, Implicit, SMAP AC1";
                check(m, CALL(stubs->implicit, _p(LDT_SEL)),
                      calc(m, new, PFEC(), SMAP | AC | IMP),
                      IMP);
            }

            asm volatile ("clac");

            write_cr4(cr4);
        }

        /* Basic write. */
        under_test.desc = "Write";
        check(m, CALL(stubs->write, m->va),
              calc(m, new, base | PFEC(W), 0),
              WRITE);

        /* Write, WP. */
        write_cr0(cr0 | X86_CR0_WP);

        under_test.desc = "Write, WP";
        check(m, CALL(stubs->write, m->va),
              calc(m, new, base | PFEC(W), WP),
              WRITE);

        write_cr0(cr0);

        /* Write, SMAP. */
        if ( cpu_has_smap )
        {
            write_cr4(cr4 | X86_CR4_SMAP);

            asm volatile ("clac");

            under_test.desc = "Write, SMAP AC0";
            check(m, CALL(stubs->write, m->va),
                  calc(m, new, base | PFEC(W), SMAP),
                  WRITE);

            asm volatile ("stac");

            under_test.desc = "Write, SMAP AC1";
            check(m, CALL(stubs->write, m->va),
                  calc(m, new, base | PFEC(W), SMAP | AC),
                  WRITE);

            asm volatile ("clac");


            /* Write, SMAP + WP. */
            write_cr0(cr0 | X86_CR0_WP);

            under_test.desc = "Write, SMAP AC0, WP";
            check(m, CALL(stubs->write, m->va),
                  calc(m, new, base | PFEC(W), SMAP | WP),
                  WRITE);

            asm volatile ("stac");

            under_test.desc = "Write, SMAP AC1, WP";
            check(m, CALL(stubs->write, m->va),
                  calc(m, new, base | PFEC(W), SMAP | AC | WP),
                  WRITE);

            asm volatile ("clac");

            write_cr0(cr0);
            write_cr4(cr4);
        }


        /* Basic exec. */
        under_test.desc = "Exec";
        check(m, CALL(stubs->exec, m->va),
              calc(m, new, base | PFEC(I), 0),
              0);

        /* Exec, SMEP. */
        if ( cpu_has_smep )
        {
            write_cr4(cr4 | X86_CR4_SMEP);

            under_test.desc = "Exec, SMEP";
            check(m, CALL(stubs->exec, m->va),
                  calc(m, new, base | PFEC(I), SMEP),
                  0);

            write_cr4(cr4);
        }

        /* Exec, NX. */
        if ( cpu_has_nx )
        {
            wrmsr(MSR_EFER, efer | EFER_NXE);

            under_test.desc = "Exec, NX";
            check(m, CALL(stubs->exec, m->va),
                  calc(m, new, base | PFEC(I), NX),
                  0);

            /* Exec, NX and SMEP. */
            if ( cpu_has_smep )
            {
                write_cr4(cr4 | X86_CR4_SMEP);

                under_test.desc = "Exec, NX, SMEP";
                check(m, CALL(stubs->exec, m->va),
                      calc(m, new, base | PFEC(I), NX | SMEP),
                      0);

                write_cr4(cr4);
            }

            wrmsr(MSR_EFER, efer);
        }

        if ( user )
            break;
    }

#undef CALL

    under_test.active = false;
}

void run_test(const struct stubs *stubs, unsigned int level, bool super, paddr_t paddr)
{
    const uint64_t base = super ? _PAGE_PSE : 0;
    struct mapping_info m;
    struct
    {
        bool cond;
        uint64_t bit;
    } trans_bits[] =
        {
            { 1, 0 },
            { 1, _PAGE_GLOBAL },

#if CONFIG_PAGING_LEVELS == 2

            { super && (cr4 & X86_CR4_PSE) && !cpu_has_pse36, 1ULL << 13 },
            { super && (cr4 & X86_CR4_PSE) && !cpu_has_pse36, 1ULL << 21 },

            { super && paddr != (uint32_t)paddr, 1ULL << 21 },

            { super && paddr != (uint32_t)paddr && maxphysaddr < 39,
              fold_pse36(1ULL << 39) },
            { super && paddr != (uint32_t)paddr && maxphysaddr < 38,
              fold_pse36(1ULL << maxphysaddr) },

#else

            { super, 1ULL << 13 },
            { super, PAGE_SIZE << (((level - 1) * PT_ORDER) - 1) },

            { maxphysaddr < 50, 1ULL << maxphysaddr },
            { maxphysaddr < 51, 1ULL << 51 },
            { 1, 1ULL << 52 },
            { 1, _PAGE_NX },

#endif
        };
    uint32_t ar_bits[] =
    {
        0,
        PF_SYM(P),
        PF_SYM(RW, P),
        PF_SYM(U, P),
        PF_SYM(U, RW, P),
    };
    unsigned int trans, ar;

    printk("Test%s L%ue%s%s\n",
           (stubs == &force_stubs) ? " emulated" : "",
           level, super ? " Superpage" : "",
           CONFIG_PAGING_LEVELS == 2 && !(cr4 & X86_CR4_PSE) ? " (No PSE)" : ""
        );

    prepare_mappings(&m, level, super, paddr);

    for ( ar = 0; ar < ARRAY_SIZE(ar_bits); ++ar )
    {
        for ( trans = 0; trans < ARRAY_SIZE(trans_bits); ++trans )
        {
            if ( trans_bits[trans].cond )
                test_pte(stubs, &m, base | trans_bits[trans].bit | ar_bits[ar]);
        }
    }
}

static void shatter_console_superpage(void)
{
    /*
     * Shatter the superpage mapping the PV console. We want to test with
     * CR4.PSE disabled, at which point superpages stop working.
     */
    uint64_t raw_pfn;

    if ( hvm_get_param(HVM_PARAM_CONSOLE_PFN, &raw_pfn) == 0 )
    {
        unsigned int l2o = l2_table_offset(raw_pfn << PAGE_SHIFT);

        if ( (l2_identmap[l2o] & PF_SYM(PSE, P)) == PF_SYM(PSE, P) )
        {
            static intpte_t conl1t[L1_PT_ENTRIES] __aligned(PAGE_SIZE);
            paddr_t base_gfn = l2_identmap[l2o] >> PAGE_SHIFT;
            unsigned int i;

            for ( i = 0; i < ARRAY_SIZE(conl1t); ++i )
                conl1t[i] = pte_from_gfn(base_gfn + i, PF_SYM(AD, RW, P));

            l2_identmap[l2o] = pte_from_virt(conl1t, PF_SYM(AD, U, RW, P));
        }
    }

    flush_tlb(true);
}

static void populate_physmap_around(paddr_t paddr)
{
    unsigned long extents[] =
        {
            (paddr >> PAGE_SHIFT) - 1,
            paddr >> PAGE_SHIFT,
        };
    struct xen_memory_reservation mr =
        {
            .extent_start = extents,
            .nr_extents = ARRAY_SIZE(extents),
            .domid = DOMID_SELF,
        };
    int rc = hypercall_memory_op(XENMEM_populate_physmap, &mr);

    if ( rc != ARRAY_SIZE(extents) )
        panic("Failed populate_physmap: %d\n", rc);
}

static void nx_leak_check(const struct stubs *stubs)
{
    struct mapping_info m;

    /*
     * Always use RAM at 12k, which is present and encodable even in 2level
     * paging.
     */
    prepare_mappings(&m, 1, false, 0x3000);

    *m.pte &= ~_PAGE_PRESENT;
    invlpg(m.va);

    exinfo_t res = stubs->exec((unsigned long)m.va);

    if ( !res || exinfo_vec(res) != X86_EXC_PF )
        panic("Testing for NX leak didn't generate #PF\n");

    host_nx_leaked = exinfo_ec(res) & PFEC(I);

    printk("Host NX %sleaked%s\n",
           host_nx_leaked    ? ""              : "not ",
           stubs == &force_stubs ? " in emulation" : "");
}

void run_tests(const struct stubs *stubs, paddr_t paddr)
{
    nx_leak_check(stubs);

    if ( CONFIG_PAGING_LEVELS == 2 )
    {
        if ( paddr == (uint32_t)paddr )
        {
            /*
             * If paddr fits within 32bits, run all the tests.
             */
            run_test(stubs, 1, false, paddr);

            cr4 &= ~X86_CR4_PSE;
            write_cr4(cr4);

            run_test(stubs, 2, false, paddr);
            run_test(stubs, 2, true,  paddr);

            cr4 |= X86_CR4_PSE;
            write_cr4(cr4);

            run_test(stubs, 2, false, paddr);
            run_test(stubs, 2, true,  paddr);
        }
        else if ( cpu_has_pse36 )
            /*
             * Otherwise, paddrs above 32bits can only be encoded with pse36
             * superpages.
             */
            run_test(stubs, 2, true, paddr);
        else
            printk("No applicable tests\n");
    }
    else
    {
        run_test(stubs, 1, false, paddr);
        run_test(stubs, 2, false, paddr);
        run_test(stubs, 2, true,  paddr);

        if ( CONFIG_PAGING_LEVELS > 3 )
        {
            run_test(stubs, 3, false, paddr);
            run_test(stubs, 3, true,  paddr);
            run_test(stubs, 4, false, paddr);
            run_test(stubs, 4, true,  paddr);
        }
    }
}

static void probe_shadow_paging(void)
{
    /*
     * Shadow paging vs hap should be indistinguishable to guests.
     *
     * Shadow paging doesn't support PSE36, so this feature is nominally
     * hidden from guests.
     *
     * Luckily(?), because old versions of HyperV refuse to boot if they don't
     * see PSE36, it is purposefully leaked once PAE is enabled to keep HyperV
     * happy.
     *
     * As a result, our shadow paging heuristic is that the visibility of the
     * PSE36 feature changes as we flip in and out of PAE paging mode.
     */
    unsigned long tmp;
    unsigned int _1d;

    switch ( CONFIG_PAGING_LEVELS )
    {
    case 2:
        write_cr0(cr0 & ~X86_CR0_PG);

        write_cr3((unsigned long)pae32_l3_identmap);

        write_cr4(cr4 | X86_CR4_PAE);
        write_cr0(cr0);

        _1d = cpuid_edx(1);

        write_cr0(cr0 & ~X86_CR0_PG);
        write_cr4(cr4 & ~X86_CR4_PAE);

        write_cr3((unsigned long)cr3_target);

        write_cr0(cr0);
        break;

    case 3:
        write_cr0(cr0 & ~X86_CR0_PG);
        write_cr4(cr4 & ~X86_CR4_PAE);

        write_cr3((unsigned long)pse_l2_identmap);

        write_cr0(cr0);

        _1d = cpuid_edx(1);

        write_cr0(cr0 & ~X86_CR0_PG);

        write_cr3((unsigned long)cr3_target);

        write_cr4(cr4);
        write_cr0(cr0);
        break;

    case 4:
        asm volatile (/* Drop into a 32bit compat code segment. */
                      "push $%c[cs32];"
                      "push $1f;"
                      "lretq; 1:"

                      ".code32;"
                      "start_32bit:;"

                      /* Flip %CR4.PAE */
                      "mov %k[cr0], %%cr0;"
                      "mov %k[cr4], %%cr4;"
                      "mov $pse_l2_identmap, %k[cr3];"
                      "mov %k[cr3], %%cr3;"
                      "rdmsr;"
                      "and $~" STR(EFER_LME) ", %k[a];"
                      "wrmsr;"
                      "or $" STR(X86_CR0_PG) ", %k[cr0];"
                      "mov %k[cr0], %%cr0;"

                      "mov $1, %k[a];"
                      "cpuid;"
                      "mov %k[d], %k[b];"

                      /* Flip %CR4.PAE back. */
                      "and $~" STR(X86_CR0_PG) ", %k[cr0];"
                      "mov %k[cr0], %%cr0;"
                      "mov $" STR(MSR_EFER) ", %k[c];"
                      "rdmsr;"
                      "or $" STR(EFER_LME) ", %k[a];"
                      "wrmsr;"
                      "or $" STR(X86_CR4_PAE) ", %k[cr4];"
                      "mov %k[cr4], %%cr4;"
                      "mov $pae_l4_identmap, %k[cr3];"
                      "mov %k[cr3], %%cr3;"
                      "or $" STR(X86_CR0_PG) ", %k[cr0];"
                      "mov %k[cr0], %%cr0;"

                      /* Return to 64bit. */
                      "ljmpl $%c[cs], $1f;"
                      "end_32bit:;"
                      ".code64; 1:"
                      : [a] "=&a" (tmp),
                        [b] "=&b" (_1d),
                        [c] "=&c" (tmp),
                        [d] "=&d" (tmp),
                        [cr3] "=&r" (tmp)
                      : "c" (MSR_EFER),
                        [cr0]  "R" (cr0 & ~X86_CR0_PG),
                        [cr4]  "R" (cr4 & ~X86_CR4_PAE),
                        [cs32] "i" (GDTE_CS32_DPL0 * 8),
                        [cs]   "i" (__KERN_CS));
        break;
    }

    shadow_paging = cpu_has_pse36 ^ !!(_1d & cpufeat_mask(X86_FEATURE_PSE36));

    printk("  Paging mode heuristic: %s\n", shadow_paging ? "Shadow" : "Hap");
}

void test_main(void)
{
    xtf_unhandled_exception_hook = unhandled_exception;

    printk("  Info: Vendor %s, Family %u, Model %u, Stepping %u, paddr %u, vaddr %u\n"
           "  Features:%s%s%s%s%s%s%s%s%s%s%s\n",
           x86_vendor_name(x86_vendor),
           x86_family, x86_model, x86_stepping, maxphysaddr, maxvirtaddr,
           cpu_has_pse     ? " PSE"    : "",
           cpu_has_pae     ? " PAE"    : "",
           cpu_has_pge     ? " PGE"    : "",
           cpu_has_pat     ? " PAT"    : "",
           cpu_has_pse36   ? " PSE36"  : "",
           cpu_has_pcid    ? " PCID"   : "",
           cpu_has_nx      ? " NX"     : "",
           cpu_has_page1gb ? " PAGE1G" : "",
           cpu_has_smep    ? " SMEP"   : "",
           cpu_has_smap    ? " SMAP"   : "",
           cpu_has_pku     ? " PKU"    : ""
        );

    if ( CONFIG_PAGING_LEVELS == 2 )
        shatter_console_superpage();

    if ( !vendor_is_intel && !vendor_is_amd )
        xtf_warning("Unknown CPU vendor.  Something might go wrong\n");
    if ( !xtf_has_fep )
        xtf_skip("FEP support not detected - some tests will be skipped\n");

    if ( vendor_is_amd && x86_family == 0x10 )
    {
        amd_fam10_erratum = true;
        printk("  Working around suspected AMD Fam10h erratum\n");
    }

    /* Sanitise environment. */
    efer = rdmsr(MSR_EFER) & ~EFER_NXE;
    wrmsr(MSR_EFER, efer);
    cr0 = read_cr0() & ~X86_CR0_WP;
    write_cr0(cr0);
    cr4 = read_cr4() & ~(X86_CR4_SMEP | X86_CR4_SMAP);
    write_cr4(cr4);

    probe_shadow_paging();

    unsigned int i;
    paddr_t paddrs[] =
    {
        GB(1),
        1ULL << (min(maxphysaddr,
                     CONFIG_PAGING_LEVELS == 2
                     ? 40U
                     : (BITS_PER_LONG + PAGE_SHIFT)) - 1),
    };

    for ( i = 0; i < ARRAY_SIZE(paddrs); ++i )
    {
        paddr_t paddr = paddrs[i];

        printk("Using paddr 0x%"PRIpaddr"\n", paddr);
        populate_physmap_around(paddr);

        run_tests(&regular_stubs, paddr);

        if ( xtf_has_fep )
            run_tests(&force_stubs, paddr);
    }

    xtf_success(NULL);
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
