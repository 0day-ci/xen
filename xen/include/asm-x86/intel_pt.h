/*
 * intel_pt.h: Intel Processor Trace virtualization for HVM domain.
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

#ifndef __ASM_X86_HVM_INTEL_PT_H_
#define __ASM_X86_HVM_INTEL_PT_H_

#include <asm/msr-index.h>

struct pt_ctx {
    u64 ctl;
    u64 status;
    u64 output_base;
    u64 output_mask_ptrs;
    u64 cr3_match;
    u64 addr[NUM_MSR_IA32_RTIT_ADDR];
};

struct pt_desc {
    bool intel_pt_enabled;
    unsigned int addr_num;
    struct pt_ctx guest_pt_ctx;
};

extern bool_t opt_intel_pt;

void pt_vcpu_init(struct vcpu *v);
void pt_guest_enter(struct vcpu *v);
void pt_guest_exit(struct vcpu *v);

#endif /* __ASM_X86_HVM_INTEL_PT_H_ */
