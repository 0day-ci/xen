/*
 * ACPI based NUMA setup
 *
 * Copyright (C) 2016 - Cavium Inc.
 * Vijaya Kumar K <Vijaya.Kumar@cavium.com>
 *
 * Reads the ACPI MADT and SRAT table to setup NUMA information.
 * Contains Excerpts from x86 implementation
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

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/inttypes.h>
#include <xen/nodemask.h>
#include <xen/acpi.h>
#include <xen/numa.h>
#include <xen/pfn.h>
#include <acpi/srat.h>
#include <asm/page.h>
#include <asm/acpi.h>

/* Holds CPUID to MPIDR mapping read from MADT table. */
struct cpuid_to_hwid {
    uint32_t cpuid;
    uint64_t hwid;
};

#define PHYS_CPUID_INVALID 0xff

/* Holds mapping of CPU id to MPIDR read from MADT */
static struct cpuid_to_hwid __read_mostly cpuid_to_hwid_map[NR_CPUS] =
    { [0 ... NR_CPUS - 1] = {PHYS_CPUID_INVALID, MPIDR_INVALID} };
static unsigned int num_cpuid_to_hwid;

static void __init acpi_map_cpu_to_hwid(uint32_t cpuid, uint64_t mpidr)
{
    if ( mpidr == MPIDR_INVALID )
    {
        printk("Skip MADT cpu entry with invalid MPIDR\n");
        numa_failed();
        return;
    }

    cpuid_to_hwid_map[num_cpuid_to_hwid].hwid = mpidr;
    cpuid_to_hwid_map[num_cpuid_to_hwid].cpuid = cpuid;
    num_cpuid_to_hwid++;
}

static int __init acpi_parse_madt_handler(struct acpi_subtable_header *header,
                                          const unsigned long end)
{
    uint64_t mpidr;
    struct acpi_madt_generic_interrupt *p =
               container_of(header, struct acpi_madt_generic_interrupt, header);

    if ( BAD_MADT_ENTRY(p, end) )
    {
        /* Though MADT is invalid, we disable NUMA by calling numa_failed() */
        numa_failed();
        return -EINVAL;
    }

    acpi_table_print_madt_entry(header);
    mpidr = p->arm_mpidr & MPIDR_HWID_MASK;
    acpi_map_cpu_to_hwid(p->uid, mpidr);

    return 0;
}

void __init acpi_map_uid_to_mpidr(void)
{
    acpi_table_parse_madt(ACPI_MADT_TYPE_GENERIC_INTERRUPT,
                    acpi_parse_madt_handler, NR_CPUS);
}

void __init acpi_numa_arch_fixup(void) {}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
