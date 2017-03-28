/*
 * OF NUMA Parsing support.
 *
 * Copyright (C) 2015 - 2016 Cavium Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/nodemask.h>
#include <asm/mm.h>
#include <xen/numa.h>
#include <xen/device_tree.h>
#include <asm/setup.h>

extern nodemask_t processor_nodes_parsed;

/*
 * Even though we connect cpus to numa domains later in SMP
 * init, we need to know the node ids now for all cpus.
 */
static int __init dt_numa_process_cpu_node(const void *fdt, int node,
                                           const char *name,
                                           uint32_t address_cells,
                                           uint32_t size_cells)
{
    uint32_t nid;

    nid = device_tree_get_u32(fdt, node, "numa-node-id", MAX_NUMNODES);

    if ( nid >= MAX_NUMNODES )
        printk(XENLOG_WARNING "NUMA: Node id %u exceeds maximum value\n", nid);
    else
        node_set(nid, processor_nodes_parsed);

    return 0;
}

static int __init dt_numa_scan_cpu_node(const void *fdt, int node,
                                        const char *name, int depth,
                                        uint32_t address_cells,
                                        uint32_t size_cells, void *data)
{
    if ( device_tree_type_matches(fdt, node, "cpu") )
        return dt_numa_process_cpu_node(fdt, node, name, address_cells,
                                        size_cells);

    return 0;
}

int __init dt_numa_init(void)
{
    int ret;

    ret = device_tree_for_each_node((void *)device_tree_flattened,
                                    dt_numa_scan_cpu_node, NULL);
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
