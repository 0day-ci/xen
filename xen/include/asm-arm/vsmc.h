/*
 * Copyright (c) 2017, EPAM Systems
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __ASM_ARM_VSMC_H__
#define __ASM_ARM_VSMC_H__

#include <xen/types.h>

/*
 * This file provides common defines for ARM SMC Calling Convention as
 * specified in
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 */

#define ARM_SMCCC_STD_CALL		0
#define ARM_SMCCC_FAST_CALL		1
#define ARM_SMCCC_TYPE_SHIFT		31

#define ARM_SMCCC_SMC_32		0
#define ARM_SMCCC_SMC_64		1
#define ARM_SMCCC_CALL_CONV_SHIFT	30

#define ARM_SMCCC_OWNER_MASK		0x3F
#define ARM_SMCCC_OWNER_SHIFT		24

#define ARM_SMCCC_FUNC_MASK		0xFFFF

/* Check if this is fast call */
#define ARM_SMCCC_IS_FAST_CALL(smc_val)                         \
    ((smc_val) & (ARM_SMCCC_FAST_CALL << ARM_SMCCC_TYPE_SHIFT))

/* Check if this is 64 bit call  */
#define ARM_SMCCC_IS_64(smc_val)                                        \
    ((smc_val) & (ARM_SMCCC_SMC_64 << ARM_SMCCC_CALL_CONV_SHIFT))

/* Get function number from function identifier */
#define ARM_SMCCC_FUNC_NUM(smc_val)	((smc_val) & ARM_SMCCC_FUNC_MASK)

/* Get service owner number from function identifier */
#define ARM_SMCCC_OWNER_NUM(smc_val)                                    \
    (((smc_val) >> ARM_SMCCC_OWNER_SHIFT) & ARM_SMCCC_OWNER_MASK)

/*
 * Construct function identifier from call type (fast or standard),
 * calling convention (32 or 64 bit), service owner and function number
 */
#define ARM_SMCCC_CALL_VAL(type, calling_convention, owner, func_num)   \
    (((type) << ARM_SMCCC_TYPE_SHIFT) |                                 \
     ((calling_convention) << ARM_SMCCC_CALL_CONV_SHIFT) |              \
     (((owner) & ARM_SMCCC_OWNER_MASK) << ARM_SMCCC_OWNER_SHIFT) |      \
     ((func_num) & ARM_SMCCC_FUNC_MASK))

/* List of know service owners */
#define ARM_SMCCC_OWNER_ARCH		0
#define ARM_SMCCC_OWNER_CPU		1
#define ARM_SMCCC_OWNER_SIP		2
#define ARM_SMCCC_OWNER_OEM		3
#define ARM_SMCCC_OWNER_STANDARD	4
#define ARM_SMCCC_OWNER_HYPERVISOR	5
#define ARM_SMCCC_OWNER_TRUSTED_APP	48
#define ARM_SMCCC_OWNER_TRUSTED_APP_END	49
#define ARM_SMCCC_OWNER_TRUSTED_OS	50
#define ARM_SMCCC_OWNER_TRUSTED_OS_END	63

/* List of generic function numbers */
#define ARM_SMCCC_FUNC_CALL_COUNT	0xFF00
#define ARM_SMCCC_FUNC_CALL_UID		0xFF01
#define ARM_SMCCC_FUNC_CALL_REVISION	0xFF03

/* Only one error code defined in SMCCC */
#define ARM_SMCCC_ERR_UNKNOWN_FUNCTION	(-1)

int vsmc_handle_call(struct cpu_user_regs *regs);

#endif  /* __ASM_ARM_VSMC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:b
 */
