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
}

void __init numa_init(void)
{
    int ret = 0;

    nodes_clear(processor_nodes_parsed);
    init_cpu_to_node();
    init_dt_numa_distance();
    if ( is_numa_off() )
        goto no_numa;

    if ( !dt_numa )
        goto no_numa;

    ret = dt_numa_init();
    if ( ret )
        printk(XENLOG_WARNING "DT NUMA init failed\n");

no_numa:
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
