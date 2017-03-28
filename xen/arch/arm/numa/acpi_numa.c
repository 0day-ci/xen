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

extern nodemask_t processor_nodes_parsed;

/* Holds CPUID to MPIDR mapping read from MADT table. */
struct cpuid_to_hwid {
    uint32_t cpuid;
    uint64_t hwid;
};

/* Holds NODE to MPIDR mapping. */
struct node_to_hwid {
    nodeid_t nodeid;
    uint64_t hwid;
};

#define PHYS_CPUID_INVALID 0xff

/* Holds mapping of CPU id to MPIDR read from MADT */
static struct cpuid_to_hwid __read_mostly cpuid_to_hwid_map[NR_CPUS] =
    { [0 ... NR_CPUS - 1] = {PHYS_CPUID_INVALID, MPIDR_INVALID} };
static struct node_to_hwid __read_mostly node_to_hwid_map[NR_CPUS] =
    { [0 ... NR_CPUS - 1] = {NUMA_NO_NODE, MPIDR_INVALID} };
static unsigned int cpus_in_srat;
static unsigned int num_cpuid_to_hwid;

nodeid_t __init acpi_get_nodeid(uint64_t hwid)
{
    unsigned int i;

    for ( i = 0; i < cpus_in_srat; i++ )
    {
        if ( node_to_hwid_map[i].hwid == hwid )
            return node_to_hwid_map[i].nodeid;
    }

    return NUMA_NO_NODE;
}

static uint64_t acpi_get_cpu_hwid(int cid)
{
    unsigned int i;

    for ( i = 0; i < num_cpuid_to_hwid; i++ )
    {
        if ( cpuid_to_hwid_map[i].cpuid == cid )
            return cpuid_to_hwid_map[i].hwid;
    }

    return MPIDR_INVALID;
}

static void __init acpi_map_node_to_hwid(nodeid_t nodeid, uint64_t hwid)
{
    if ( nodeid >= MAX_NUMNODES )
    {
        printk(XENLOG_WARNING
               "ACPI: NUMA: nodeid out of range %d with MPIDR 0x%lx\n",
               nodeid, hwid);
        numa_failed();
        return;
    }

    node_to_hwid_map[cpus_in_srat].nodeid = nodeid;
    node_to_hwid_map[cpus_in_srat].hwid = hwid;
}

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

/* Callback for Proximity Domain -> ACPI processor UID mapping */
static void __init
acpi_numa_gicc_affinity_init(const struct acpi_srat_gicc_affinity *pa)
{
    int pxm, node;
    uint64_t mpidr;

    if ( srat_disabled() )
        return;

    if ( pa->header.length < sizeof(struct acpi_srat_gicc_affinity) )
    {
        printk(XENLOG_WARNING "SRAT: Invalid SRAT header length: %d\n",
               pa->header.length);
        numa_failed();
        return;
    }

    if ( !(pa->flags & ACPI_SRAT_GICC_ENABLED) )
        return;

    if ( cpus_in_srat >= NR_CPUS )
    {
        printk(XENLOG_ERR
               "SRAT: cpu_to_node_map[%d] is too small to fit all cpus\n",
               NR_CPUS);
        return;
    }

    pxm = pa->proximity_domain;
    node = acpi_setup_node(pxm);
    if ( node == NUMA_NO_NODE )
    {
        numa_failed();
        return;
    }

    mpidr = acpi_get_cpu_hwid(pa->acpi_processor_uid);
    if ( mpidr == MPIDR_INVALID )
    {
        printk(XENLOG_ERR
               "SRAT: PXM %d with ACPI ID %d has no valid MPIDR in MADT\n",
               pxm, pa->acpi_processor_uid);
        numa_failed();
        return;
    }

    acpi_map_node_to_hwid(node, mpidr);
    node_set(node, processor_nodes_parsed);
    cpus_in_srat++;
    set_acpi_numa(1);
    printk(XENLOG_INFO "SRAT: PXM %d -> MPIDR 0x%lx -> Node %d\n",
           pxm, mpidr, node);
}

void __init acpi_map_uid_to_mpidr(void)
{
    acpi_table_parse_madt(ACPI_MADT_TYPE_GENERIC_INTERRUPT,
                    acpi_parse_madt_handler, NR_CPUS);
}

static int __init
acpi_parse_gicc_affinity(struct acpi_subtable_header *header,
                         const unsigned long end)
{
   const struct acpi_srat_gicc_affinity *processor_affinity
                = (struct acpi_srat_gicc_affinity *)header;

   if (!processor_affinity)
       return -EINVAL;

   acpi_table_print_srat_entry(header);
   acpi_numa_gicc_affinity_init(processor_affinity);

   return 0;
}

void __init arch_table_parse_srat(void)
{
    acpi_table_parse_srat(ACPI_SRAT_TYPE_GICC_AFFINITY,
                          acpi_parse_gicc_affinity, NR_CPUS);
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
