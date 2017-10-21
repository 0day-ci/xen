/*
 * intel_pt.c: Support Intel Processor Trace Virtualization.
 *
 * Copyright (c) 2017, Intel Corporation.
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
 * Author: Luwei Kang <luwei.kang@intel.com>
 */

#include <xen/types.h>
#include <xen/cache.h>
#include <xen/init.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/intel_pt.h>

/* intel_pt: Flag to enable Intel Processor Trace (default on). */
bool_t __read_mostly opt_intel_pt = 1;
boolean_param("intel_pt", opt_intel_pt);

static inline void pt_load_msr(struct pt_ctx *ctx, u32 addr_num)
{
    u32 i;
    wrmsrl(MSR_IA32_RTIT_STATUS, ctx->status);
    wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, ctx->output_base);
    wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, ctx->output_mask_ptrs);
    wrmsrl(MSR_IA32_RTIT_CR3_MATCH, ctx->cr3_match);
    for ( i = 0; i < addr_num; i++ )
        wrmsrl(MSR_IA32_RTIT_ADDR0_A + i, ctx->addr[i]);
}

static inline void pt_save_msr(struct pt_ctx *ctx, u32 addr_num)
{
    u32 i;
    rdmsrl(MSR_IA32_RTIT_STATUS, ctx->status);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_BASE, ctx->output_base);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, ctx->output_mask_ptrs);
    rdmsrl(MSR_IA32_RTIT_CR3_MATCH, ctx->cr3_match);
    for ( i = 0; i < addr_num; i++ )
        rdmsrl(MSR_IA32_RTIT_ADDR0_A + i, ctx->addr[i]);
}

void pt_guest_enter(struct vcpu *v)
{
    struct pt_desc *pt = &v->arch.hvm_vmx.pt_desc;

    if ( pt->intel_pt_enabled )
    {
        vmx_vmcs_enter(v);
        __vmwrite(GUEST_IA32_RTIT_CTL, pt->guest_pt_ctx.ctl);
        vmx_vmcs_exit(v);

        pt_load_msr(&pt->guest_pt_ctx, pt->addr_num);
    }
}

void pt_guest_exit(struct vcpu *v)
{
    struct pt_desc *pt = &v->arch.hvm_vmx.pt_desc;

    if ( pt->intel_pt_enabled )
    {
        vmx_vmcs_enter(v);
        __vmread(GUEST_IA32_RTIT_CTL, &pt->guest_pt_ctx.ctl);
        vmx_vmcs_exit(v);

        pt_save_msr(&pt->guest_pt_ctx, pt->addr_num);
    }
}

void pt_vcpu_init(struct vcpu *v)
{
    struct pt_desc *pt = &v->arch.hvm_vmx.pt_desc;
    unsigned int eax, ebx, ecx, edx;
    int i;

    memset(pt, 0, sizeof(struct pt_desc));
    pt->intel_pt_enabled = false;

    if ( !cpu_has_intel_pt || !opt_intel_pt ||
         !(v->arch.hvm_vmx.secondary_exec_control & SECONDARY_EXEC_PT_USE_GPA) )
        return;

    /* get the number of address ranges */
    if ( cpuid_eax(0x14) == 1 )
        cpuid_count(0x14, 1, &eax, &ebx, &ecx, &edx);
    else
        return;

    pt->addr_num = eax & 0x7;
    pt->guest_pt_ctx.output_mask_ptrs = 0x7F;
    pt->intel_pt_enabled = true;

    vmx_vmcs_enter(v);
    __vmwrite(GUEST_IA32_RTIT_CTL, 0);
    vmx_clear_msr_intercept(v, MSR_IA32_RTIT_CTL, VMX_MSR_RW);
    vmx_clear_msr_intercept(v, MSR_IA32_RTIT_STATUS, VMX_MSR_RW);
    vmx_clear_msr_intercept(v, MSR_IA32_RTIT_OUTPUT_BASE, VMX_MSR_RW);
    vmx_clear_msr_intercept(v, MSR_IA32_RTIT_OUTPUT_MASK_PTRS, VMX_MSR_RW);
    vmx_clear_msr_intercept(v, MSR_IA32_RTIT_CR3_MATCH, VMX_MSR_RW);
    for ( i = 0; i < pt->addr_num; i++ )
        vmx_clear_msr_intercept(v, MSR_IA32_RTIT_ADDR0_A + i, VMX_MSR_RW);
    vmx_vmcs_exit(v);
}
