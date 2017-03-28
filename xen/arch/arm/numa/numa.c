/*
 * ARM NUMA Implementation
 *
 * Copyright (C) 2016 - Cavium Inc.
 * Vijaya Kumar K <vijaya.kumar@cavium.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/mm.h>
#include <xen/nodemask.h>
#include <asm/mm.h>
#include <xen/numa.h>
#include <asm/acpi.h>
#include <xen/errno.h>
#include <xen/pfn.h>
#include <acpi/srat.h>

static uint8_t (*node_distance_fn)(nodeid_t a, nodeid_t b);

extern nodemask_t processor_nodes_parsed;
static bool_t dt_numa = 1;

/*
 * Setup early cpu_to_node.
 */
void __init init_cpu_to_node(void)
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
        numa_set_node(i, 0);
}

void __init numa_set_cpu_node(int cpu, unsigned int nid)
{
    if ( !node_isset(nid, processor_nodes_parsed) || nid >= MAX_NUMNODES )
        nid = 0;

    numa_set_node(cpu, nid);
}

uint8_t __node_distance(nodeid_t a, nodeid_t b)
{
    if ( node_distance_fn != NULL);
        return node_distance_fn(a, b);

    return a == b ? LOCAL_DISTANCE : REMOTE_DISTANCE;
}

EXPORT_SYMBOL(__node_distance);

void register_node_distance(uint8_t (fn)(nodeid_t a, nodeid_t b))
{
    node_distance_fn = fn;
}

void numa_failed(void)
{
    dt_numa = 0;
    init_dt_numa_distance();
    node_distance_fn = NULL;
    init_cpu_to_node();

#ifdef CONFIG_ACPI_NUMA
    set_acpi_numa(0);
    reset_pxm2node();
#endif
}

int __init arch_sanitize_nodes_memory(void)
{
    nodemask_t mem_nodes_parsed;
    int bank, nodeid;
    struct node *nd;
    paddr_t start, size, end;

    nodes_clear(mem_nodes_parsed);
    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        start = bootinfo.mem.bank[bank].start;
        size = bootinfo.mem.bank[bank].size;
        end = start + size;

        nodeid = get_mem_nodeid(start, end);
        if ( nodeid >= NUMA_NO_NODE )
        {
            printk(XENLOG_WARNING
                   "NUMA: node for mem bank start 0x%lx - 0x%lx not found\n",
                   start, end);

            return 0;
        }

        nd = get_numa_node(nodeid);
        if ( !node_test_and_set(nodeid, mem_nodes_parsed) )
        {
            nd->start = start;
            nd->end = end;
        }
        else
        {
            if ( start < nd->start )
                nd->start = start;
            if ( nd->end < end )
                nd->end = end;
        }
    }

    return 1;
}

static bool_t __init numa_initmem_init(paddr_t ram_start, paddr_t ram_end)
{
    int i;
    struct node *nd;
    /*
     * In arch_sanitize_nodes_memory() we update nodes[] with properly.
     * Hence we reset the nodes[] before calling numa_scan_nodes().
     */
    for ( i = 0; i < MAX_NUMNODES; i++ )
    {
        nd = get_numa_node(i);
        nd->start = 0;
        nd->end = 0;
    }

    if ( !numa_scan_nodes(ram_start, ram_end) )
            return 0;

    return 1;
}

void __init numa_init(void)
{
    int ret = 0, bank;
    paddr_t ram_start = ~0;
    paddr_t ram_end = 0;

    nodes_clear(processor_nodes_parsed);
    init_cpu_to_node();
    init_dt_numa_distance();
    if ( is_numa_off() )
        goto no_numa;

#ifdef CONFIG_ACPI_NUMA
    ret = arch_acpi_numa_init();
    if ( ret )
        printk(XENLOG_WARNING "ACPI NUMA init failed\n");
#else
    if ( !dt_numa )
        goto no_numa;

    ret = dt_numa_init();
    if ( ret )
        printk(XENLOG_WARNING "DT NUMA init failed\n");
#endif

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        paddr_t bank_start = bootinfo.mem.bank[bank].start;
        paddr_t bank_end = bank_start + bootinfo.mem.bank[bank].size;

        ram_start = min(ram_start, bank_start);
        ram_end = max(ram_end, bank_end);
    }

    if ( !ret )
        ret = numa_initmem_init(ram_start, ram_end);

    if ( !ret )
        return;

no_numa:
    numa_dummy_init(PFN_UP(ram_start),PFN_DOWN(ram_end));

    return;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
