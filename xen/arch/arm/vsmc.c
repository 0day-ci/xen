/*
 * xen/arch/arm/vsmc.c
 *
 * Generic handler for SMC and HVC calls according to
 * ARM SMC calling convention
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <xen/config.h>
#include <xen/lib.h>
/* Need to include xen/sched.h before asm/domain.h or it breaks build*/
#include <xen/sched.h>
#include <xen/stdbool.h>
#include <xen/types.h>
#include <public/arch-arm/smc.h>
#include <asm/psci.h>
#include <asm/vsmc.h>
#include <asm/regs.h>

/*
 * Hypervisor Service version
 *
 * We can't use XEN version here, because of SMCCC requirements:
 * Major revision should change every time SMC/HVC function is removed.
 * Minor revision should change every time SMC/HVC function is added.
 * So, it is SMCCC protocol revision code, not XEN version.
 *
 * Those values are subjected to change, when interface will be extended.
 * They should not be stored in public/asm-arm/smc.h because they should
 * be queried by guest using SMC/HVC interface.
 */
#define XEN_SMCCC_MAJOR_REVISION 0
#define XEN_SMCCC_MINOR_REVISION 1

/* Number of functions currently supported by Hypervisor Service. */
#define XEN_SMCCC_FUNCTION_COUNT 3

/* Standard Service version. Check comment for Hypervisor Service for rules */
#define SSC_SMCCC_MAJOR_REVISION 0
#define SSC_SMCCC_MINOR_REVISION 1

/* Number of functions currently supported by Standard Service Service. */
#define SSC_SMCCC_FUNCTION_COUNT 13


/* SMCCC interface for hypervisor. Tell about itself. */
static bool handle_hypervisor(struct cpu_user_regs *regs)
{
    switch ( ARM_SMCCC_FUNC_NUM(get_user_reg(regs, 0)) )
    {
    case ARM_SMCCC_FUNC_CALL_COUNT:
        set_user_reg(regs, 0, XEN_SMCCC_FUNCTION_COUNT);
        return true;
    case ARM_SMCCC_FUNC_CALL_UID:
        set_user_reg(regs, 0, XEN_SMCCC_UID.a[0]);
        set_user_reg(regs, 1, XEN_SMCCC_UID.a[1]);
        set_user_reg(regs, 2, XEN_SMCCC_UID.a[2]);
        set_user_reg(regs, 3, XEN_SMCCC_UID.a[3]);
        return true;
    case ARM_SMCCC_FUNC_CALL_REVISION:
        set_user_reg(regs, 0, XEN_SMCCC_MAJOR_REVISION);
        set_user_reg(regs, 1, XEN_SMCCC_MINOR_REVISION);
        return true;
    }
    return false;
}

/* old (arvm7) PSCI interface */
static bool handle_arch(struct cpu_user_regs *regs)
{
    switch ( get_user_reg(regs,0) & 0xFFFFFFFF )
    {
    case PSCI_cpu_off:
    {
        uint32_t pstate = get_user_reg(regs, 1);
        perfc_incr(vpsci_cpu_off);
        set_user_reg(regs, 0, do_psci_cpu_off(pstate));
    }
    return true;
    case PSCI_cpu_on:
    {
        uint32_t vcpuid = get_user_reg(regs, 1);
        register_t epoint = get_user_reg(regs, 2);
        perfc_incr(vpsci_cpu_on);
        set_user_reg(regs, 0, do_psci_cpu_on(vcpuid, epoint));
    }
    return true;
    }
    return false;
}

/* helper function for checking arm mode 32/64 bit */
static inline int psci_mode_check(struct domain *d, register_t fid)
{
        return !( is_64bit_domain(d)^( (fid & PSCI_0_2_64BIT) >> 30 ) );
}

/* PSCI 2.0 interface */
static bool handle_ssc(struct cpu_user_regs *regs)
{
    register_t fid = get_user_reg(regs, 0);

    switch ( ARM_SMCCC_FUNC_NUM(fid) )
    {
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_PSCI_VERSION):
        perfc_incr(vpsci_version);
        set_user_reg(regs, 0, do_psci_0_2_version());
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_CPU_OFF):
        perfc_incr(vpsci_cpu_off);
        set_user_reg(regs, 0, do_psci_0_2_cpu_off());
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_MIGRATE_INFO_TYPE):
        perfc_incr(vpsci_migrate_info_type);
        set_user_reg(regs, 0, do_psci_0_2_migrate_info_type());
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_MIGRATE_INFO_UP_CPU):
        perfc_incr(vpsci_migrate_info_up_cpu);
        if ( psci_mode_check(current->domain, fid) )
            set_user_reg(regs, 0, do_psci_0_2_migrate_info_up_cpu());
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_SYSTEM_OFF):
        perfc_incr(vpsci_system_off);
        do_psci_0_2_system_off();
        set_user_reg(regs, 0, PSCI_INTERNAL_FAILURE);
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_SYSTEM_RESET):
        perfc_incr(vpsci_system_reset);
        do_psci_0_2_system_reset();
        set_user_reg(regs, 0, PSCI_INTERNAL_FAILURE);
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_CPU_ON):
        perfc_incr(vpsci_cpu_on);
        if ( psci_mode_check(current->domain, fid) )
        {
            register_t vcpuid = get_user_reg(regs, 1);
            register_t epoint = get_user_reg(regs, 2);
            register_t cid = get_user_reg(regs, 3);
            set_user_reg(regs, 0,
                         do_psci_0_2_cpu_on(vcpuid, epoint, cid));
        }
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_CPU_SUSPEND):
        perfc_incr(vpsci_cpu_suspend);
        if ( psci_mode_check(current->domain, fid) )
        {
            uint32_t pstate = get_user_reg(regs, 1);
            register_t epoint = get_user_reg(regs, 2);
            register_t cid = get_user_reg(regs, 3);
            set_user_reg(regs, 0,
                         do_psci_0_2_cpu_suspend(pstate, epoint, cid));
        }
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_AFFINITY_INFO):
        perfc_incr(vpsci_cpu_affinity_info);
        if ( psci_mode_check(current->domain, fid) )
        {
            register_t taff = get_user_reg(regs, 1);
            uint32_t laff = get_user_reg(regs,2);
            set_user_reg(regs, 0,
                         do_psci_0_2_affinity_info(taff, laff));
        }
        return true;
    case ARM_SMCCC_FUNC_NUM(PSCI_0_2_FN_MIGRATE):
        perfc_incr(vpsci_cpu_migrate);
        if ( psci_mode_check(current->domain, fid) )
        {
            uint32_t tcpu = get_user_reg(regs, 1);
            set_user_reg(regs, 0, do_psci_0_2_migrate(tcpu));
        }
        return true;
    case ARM_SMCCC_FUNC_CALL_COUNT:
        set_user_reg(regs, 0, SSC_SMCCC_FUNCTION_COUNT);
        return true;
    case ARM_SMCCC_FUNC_CALL_UID:
        set_user_reg(regs, 0, SSC_SMCCC_UID.a[0]);
        set_user_reg(regs, 1, SSC_SMCCC_UID.a[1]);
        set_user_reg(regs, 2, SSC_SMCCC_UID.a[2]);
        set_user_reg(regs, 3, SSC_SMCCC_UID.a[3]);
        return true;
    case ARM_SMCCC_FUNC_CALL_REVISION:
        set_user_reg(regs, 0, SSC_SMCCC_MAJOR_REVISION);
        set_user_reg(regs, 1, SSC_SMCCC_MINOR_REVISION);
        return true;
    }
    return false;
}

/**
 * vsmc_handle_call() - handle SMC/HVC call according to ARM SMCCC
 */
int vsmc_handle_call(struct cpu_user_regs *regs)
{
    bool handled = false;
    const union hsr hsr = { .bits = regs->hsr };

    /*
     * Check immediate value for HVC32, HVC64 and SMC64.
     * It is not so easy to check immediate value for SMC32,
     * so we will assume that it is 0x0
     */
    switch ( hsr.ec )
    {
    case HSR_EC_HVC32:
    case HSR_EC_HVC64:
    case HSR_EC_SMC64:
        if ( hsr.iss != 0)
            return 0;
        break;
    case HSR_EC_SMC32:
        break;
    default:
        return 0;
    }

    /* 64 bit calls are allowed only from 64 bit domains */
    if ( ARM_SMCCC_IS_64(get_user_reg(regs, 0)) &&
         is_32bit_domain(current->domain) )
    {
        set_user_reg(regs, 0, ARM_SMCCC_ERR_UNKNOWN_FUNCTION);
        return 1;
    }

    switch ( ARM_SMCCC_OWNER_NUM(get_user_reg(regs, 0)) )
    {
    case ARM_SMCCC_OWNER_HYPERVISOR:
        handled = handle_hypervisor(regs);
        break;
    case ARM_SMCCC_OWNER_ARCH:
        handled = handle_arch(regs);
        break;
    case ARM_SMCCC_OWNER_STANDARD:
        handled = handle_ssc(regs);
        break;
    }

    if ( !handled )
    {
        gprintk(XENLOG_INFO, "Unhandled SMC/HVC: %08"PRIregister"\n",
                get_user_reg(regs, 0));
        /* Inform caller that function is not supported */
        set_user_reg(regs, 0, ARM_SMCCC_ERR_UNKNOWN_FUNCTION);
    }

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
