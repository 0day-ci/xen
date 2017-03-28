/*
 * Generic VM initialization for x86-64 NUMA setups.
 * Copyright 2002,2003 Andi Kleen, SuSE Labs.
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */

#include <xen/mm.h>
#include <xen/string.h>
#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/nodemask.h>
#include <xen/numa.h>
#include <xen/time.h>
#include <xen/smp.h>
#include <xen/pfn.h>
#include <asm/acpi.h>

nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

void __init numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{
#ifdef CONFIG_NUMA_EMU
    if ( get_numa_fake() && !numa_emulation(start_pfn, end_pfn) )
        return;
#endif

#ifdef CONFIG_ACPI_NUMA
    if ( !is_numa_off() && !numa_scan_nodes((uint64_t)start_pfn << PAGE_SHIFT,
         (uint64_t)end_pfn << PAGE_SHIFT) )
        return;
#endif

    numa_dummy_init(start_pfn, end_pfn);
}

/*
 * Setup early cpu_to_node.
 *
 * Populate cpu_to_node[] only if x86_cpu_to_apicid[],
 * and apicid_to_node[] tables have valid entries for a CPU.
 * This means we skip cpu_to_node[] initialisation for NUMA
 * emulation and faking node case (when running a kernel compiled
 * for NUMA on a non NUMA box), which is OK as cpu_to_node[]
 * is already initialized in a round robin manner at numa_init_array,
 * prior to this call, and this initialization is good enough
 * for the fake NUMA cases.
 */
void __init init_cpu_to_node(void)
{
    unsigned int i;
    nodeid_t node;

    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        uint32_t apicid = x86_cpu_to_apicid[i];
        if ( apicid == BAD_APICID )
            continue;
        node = apicid < MAX_LOCAL_APIC ? apicid_to_node[apicid] : NUMA_NO_NODE;
        if ( node == NUMA_NO_NODE || !node_online(node) )
            node = 0;
        numa_set_node(i, node);
    }
}

unsigned int __init arch_get_dma_bitsize(void)
{
    unsigned int node;

    for_each_online_node(node)
        if ( node_spanned_pages(node) &&
             !(node_start_pfn(node) >> (32 - PAGE_SHIFT)) )
            break;
    if ( node >= MAX_NUMNODES )
        panic("No node with memory below 4Gb");

    /*
     * Try to not reserve the whole node's memory for DMA, but dividing
     * its spanned pages by (arbitrarily chosen) 4.
     */
    return min_t(unsigned int,
                 flsl(node_start_pfn(node) + node_spanned_pages(node) / 4 - 1)
                 + PAGE_SHIFT, 32);
}
