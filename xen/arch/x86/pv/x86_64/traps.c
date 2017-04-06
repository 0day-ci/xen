
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/nmi.h>
#include <xen/types.h>

#include <asm/current.h>
#include <asm/event.h>
#include <asm/msr.h>
#include <asm/traps.h>

#include <public/callback.h>

void toggle_guest_mode(struct vcpu *v)
{
    if ( is_pv_32bit_vcpu(v) )
        return;
    if ( cpu_has_fsgsbase )
    {
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv_vcpu.gs_base_kernel = __rdgsbase();
        else
            v->arch.pv_vcpu.gs_base_user = __rdgsbase();
    }
    v->arch.flags ^= TF_kernel_mode;
    asm volatile ( "swapgs" );
    update_cr3(v);
    /* Don't flush user global mappings from the TLB. Don't tick TLB clock. */
    asm volatile ( "mov %0, %%cr3" : : "r" (v->arch.cr3) : "memory" );
    if ( !(v->arch.flags & TF_kernel_mode) )
        return;

    if ( v->arch.pv_vcpu.need_update_runstate_area &&
         update_runstate_area(v) )
        v->arch.pv_vcpu.need_update_runstate_area = 0;

    if ( v->arch.pv_vcpu.pending_system_time.version &&
         update_secondary_system_time(v,
                                      &v->arch.pv_vcpu.pending_system_time) )
        v->arch.pv_vcpu.pending_system_time.version = 0;
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp,
                                 sizeof(iret_saved))) )
    {
        gprintk(XENLOG_ERR,
                "Fault while reading IRET context from guest stack\n");
        goto exit_and_crash;
    }

    /* Returning to user mode? */
    if ( (iret_saved.cs & 3) == 3 )
    {
        if ( unlikely(pagetable_is_null(v->arch.guest_table_user)) )
        {
            gprintk(XENLOG_ERR,
                    "Guest switching to user mode with no user page tables\n");
            goto exit_and_crash;
        }
        toggle_guest_mode(v);
    }

    if ( VM_ASSIST(v->domain, architectural_iopl) )
        v->arch.pv_vcpu.iopl = iret_saved.rflags & X86_EFLAGS_IOPL;

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = ((iret_saved.rflags & ~(X86_EFLAGS_IOPL|X86_EFLAGS_VM))
                    | X86_EFLAGS_IF);
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_in_syscall) )
    {
        regs->entry_vector &= ~TRAP_syscall;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(iret_saved.rflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
}

static unsigned int write_stub_trampoline(
    unsigned char *stub, unsigned long stub_va,
    unsigned long stack_bottom, unsigned long target_va)
{
    /* movabsq %rax, stack_bottom - 8 */
    stub[0] = 0x48;
    stub[1] = 0xa3;
    *(uint64_t *)&stub[2] = stack_bottom - 8;

    /* movq %rsp, %rax */
    stub[10] = 0x48;
    stub[11] = 0x89;
    stub[12] = 0xe0;

    /* movabsq $stack_bottom - 8, %rsp */
    stub[13] = 0x48;
    stub[14] = 0xbc;
    *(uint64_t *)&stub[15] = stack_bottom - 8;

    /* pushq %rax */
    stub[23] = 0x50;

    /* jmp target_va */
    stub[24] = 0xe9;
    *(int32_t *)&stub[25] = target_va - (stub_va + 29);

    /* Round up to a multiple of 16 bytes. */
    return 32;
}

DEFINE_PER_CPU(struct stubs, stubs);
void lstar_enter(void);
void cstar_enter(void);

void subarch_percpu_traps_init(void)
{
    unsigned long stack_bottom = get_stack_bottom();
    unsigned long stub_va = this_cpu(stubs.addr);
    unsigned char *stub_page;
    unsigned int offset;

    /* IST_MAX IST pages + 1 syscall page + 1 guard page + primary stack. */
    BUILD_BUG_ON((IST_MAX + 2) * PAGE_SIZE + PRIMARY_STACK_SIZE > STACK_SIZE);

    stub_page = map_domain_page(_mfn(this_cpu(stubs.mfn)));

    /*
     * Trampoline for SYSCALL entry from 64-bit mode.  The VT-x HVM vcpu
     * context switch logic relies on the SYSCALL trampoline being at the
     * start of the stubs.
     */
    wrmsrl(MSR_LSTAR, stub_va);
    offset = write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                   stub_va, stack_bottom,
                                   (unsigned long)lstar_enter);
    stub_va += offset;

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
         boot_cpu_data.x86_vendor == X86_VENDOR_CENTAUR )
    {
        /* SYSENTER entry. */
        wrmsrl(MSR_IA32_SYSENTER_ESP, stack_bottom);
        wrmsrl(MSR_IA32_SYSENTER_EIP, (unsigned long)sysenter_entry);
        wrmsr(MSR_IA32_SYSENTER_CS, __HYPERVISOR_CS, 0);
    }

    /* Trampoline for SYSCALL entry from compatibility mode. */
    wrmsrl(MSR_CSTAR, stub_va);
    offset += write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                    stub_va, stack_bottom,
                                    (unsigned long)cstar_enter);

    /* Don't consume more than half of the stub space here. */
    ASSERT(offset <= STUB_BUF_SIZE / 2);

    unmap_domain_page(stub_page);

    /* Common SYSCALL parameters. */
    wrmsrl(MSR_STAR, XEN_MSR_STAR);
    wrmsrl(MSR_SYSCALL_MASK, XEN_SYSCALL_MASK);
}

void init_int80_direct_trap(struct vcpu *v)
{
    struct trap_info *ti = &v->arch.pv_vcpu.trap_ctxt[0x80];
    struct trap_bounce *tb = &v->arch.pv_vcpu.int80_bounce;

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( null_trap_bounce(v, tb) )
        tb->flags = 0;
}

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    if ( !is_canonical_address(reg->address) )
        return -EINVAL;

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.pv_vcpu.event_callback_eip    = reg->address;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.pv_vcpu.failsafe_callback_eip = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall:
        v->arch.pv_vcpu.syscall_callback_eip  = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_syscall_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_syscall_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall32:
        v->arch.pv_vcpu.syscall32_callback_eip = reg->address;
        v->arch.pv_vcpu.syscall32_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_sysenter:
        v->arch.pv_vcpu.sysenter_callback_eip = reg->address;
        v->arch.pv_vcpu.sysenter_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long unregister_guest_callback(struct callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
    case CALLBACKTYPE_syscall:
    case CALLBACKTYPE_syscall32:
    case CALLBACKTYPE_sysenter:
        ret = -EINVAL;
        break;

    case CALLBACKTYPE_nmi:
        ret = unregister_guest_nmi_callback();
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}


long do_callback_op(int cmd, XEN_GUEST_HANDLE_PARAM(const_void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = event_address,
    };
    struct callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = failsafe_address,
    };
    struct callback_register syscall = {
        .type = CALLBACKTYPE_syscall,
        .address = syscall_address,
    };

    register_guest_callback(&event);
    register_guest_callback(&failsafe);
    register_guest_callback(&syscall);

    return 0;
}

static void hypercall_page_initialise_ring3_kernel(void *hypercall_page)
{
    char *p;
    int i;

    /* Fill in all the transfer points with template machine code. */
    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        if ( i == __HYPERVISOR_iret )
            continue;

        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
        *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
        *(u8  *)(p+ 3) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 4) = i;
        *(u16 *)(p+ 8) = 0x050f;  /* syscall */
        *(u16 *)(p+10) = 0x5b41;  /* pop  %r11 */
        *(u8  *)(p+12) = 0x59;    /* pop  %rcx */
        *(u8  *)(p+13) = 0xc3;    /* ret */
    }

    /*
     * HYPERVISOR_iret is special because it doesn't return and expects a
     * special stack frame. Guests jump at this transfer point instead of
     * calling it.
     */
    p = (char *)(hypercall_page + (__HYPERVISOR_iret * 32));
    *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
    *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
    *(u8  *)(p+ 3) = 0x50;    /* push %rax */
    *(u8  *)(p+ 4) = 0xb8;    /* mov  $__HYPERVISOR_iret,%eax */
    *(u32 *)(p+ 5) = __HYPERVISOR_iret;
    *(u16 *)(p+ 9) = 0x050f;  /* syscall */
}

#include "compat/traps.c"

void hypercall_page_initialise(struct domain *d, void *hypercall_page)
{
    memset(hypercall_page, 0xCC, PAGE_SIZE);
    if ( is_hvm_domain(d) )
        hvm_hypercall_page_initialise(d, hypercall_page);
    else if ( !is_pv_32bit_domain(d) )
        hypercall_page_initialise_ring3_kernel(hypercall_page);
    else
        hypercall_page_initialise_ring1_kernel(hypercall_page);
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
