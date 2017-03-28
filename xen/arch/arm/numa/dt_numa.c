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
extern nodemask_t memory_nodes_parsed;

static uint8_t node_distance[MAX_NUMNODES][MAX_NUMNODES];

static uint8_t dt_node_distance(nodeid_t nodea, nodeid_t nodeb)
{
    if ( nodea >= MAX_NUMNODES || nodeb >= MAX_NUMNODES )
        return nodea == nodeb ? LOCAL_DISTANCE : REMOTE_DISTANCE;

    return node_distance[nodea][nodeb];
}

static int dt_numa_set_distance(uint32_t nodea, uint32_t nodeb,
                                uint32_t distance)
{
   /* node_distance is uint8_t. Ensure distance is less than 255 */
   if ( nodea >= MAX_NUMNODES || nodeb >= MAX_NUMNODES || distance > 255 )
       return -EINVAL;

   node_distance[nodea][nodeb] = distance;

   return 0;
}

void init_dt_numa_distance(void)
{
    int i, j;

    for ( i = 0; i < MAX_NUMNODES; i++ )
    {
        for ( j = 0; j < MAX_NUMNODES; j++ )
        {
            /*
             * Initialize distance 10 for local distance and
             * 20 for remote distance.
             */
            if ( i  == j )
                node_distance[i][j] = LOCAL_DISTANCE;
            else
                node_distance[i][j] = REMOTE_DISTANCE;
        }
    }
}

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

static int __init dt_numa_parse_distance_map(const void *fdt, int node,
                                             const char *name,
                                             uint32_t address_cells,
                                             uint32_t size_cells)
{
    const struct fdt_property *prop;
    const __be32 *matrix;
    int entry_count, len, i;

    printk(XENLOG_INFO "NUMA: parsing numa-distance-map\n");

    prop = fdt_get_property(fdt, node, "distance-matrix", &len);
    if ( !prop )
    {
        printk(XENLOG_WARNING
               "NUMA: No distance-matrix property in distance-map\n");

        return -EINVAL;
    }

    if ( len % sizeof(uint32_t) != 0 )
    {
         printk(XENLOG_WARNING
                "distance-matrix in node is not a multiple of u32\n");

        return -EINVAL;
    }

    entry_count = len / sizeof(uint32_t);
    if ( entry_count <= 0 )
    {
        printk(XENLOG_WARNING "NUMA: Invalid distance-matrix\n");

        return -EINVAL;
    }

    matrix = (const __be32 *)prop->data;
    for ( i = 0; i + 2 < entry_count; i += 3 )
    {
        uint32_t nodea, nodeb, distance;

        nodea = dt_read_number(matrix, 1);
        matrix++;
        nodeb = dt_read_number(matrix, 1);
        matrix++;
        distance = dt_read_number(matrix, 1);
        matrix++;

        if ( dt_numa_set_distance(nodea, nodeb, distance) )
        {
            printk(XENLOG_WARNING
                   "NUMA: node-id out of range in distance matrix for [node%d -> node%d]\n",
                   nodea, nodeb);
            return -EINVAL;

        }
        printk(XENLOG_INFO "NUMA: distance[node%d -> node%d] = %d\n",
               nodea, nodeb, distance);

        /*
         * Set default distance of node B->A same as A->B.
         * No need to check for return value of numa_set_distance.
         */
        if ( nodeb > nodea )
            dt_numa_set_distance(nodeb, nodea, distance);
    }

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

void __init dt_numa_process_memory_node(uint32_t nid, paddr_t start,
                                       paddr_t size)
{
    struct node *nd;
    int i;

    i = conflicting_memblks(start, start + size);
    if ( i < 0 )
    {
         if ( numa_add_memblk(nid, start, size) )
         {
             printk(XENLOG_WARNING "DT: NUMA: node-id %u overflow \n", nid);
             numa_failed();
             return;
         }
    }
    else
    {
         nd = get_node_memblk_range(i);
         printk(XENLOG_ERR
                "NUMA DT: node %u (%"PRIx64"-%"PRIx64") overlaps with %d (%"PRIx64"-%"PRIx64")\n",
                nid, start, start + size, i, nd->start, nd->end);

         numa_failed();
         return;
    }

    node_set(nid, memory_nodes_parsed);

    return;
}

static int __init dt_numa_scan_distance_node(const void *fdt, int node,
                                             const char *name, int depth,
                                             uint32_t address_cells,
                                             uint32_t size_cells, void *data)
{
    if ( device_tree_node_matches(fdt, node, "numa-distance-map-v1") )
        return dt_numa_parse_distance_map(fdt, node, name, address_cells,
                                          size_cells);

    return 0;
}

int __init dt_numa_init(void)
{
    int ret;

    ret = device_tree_for_each_node((void *)device_tree_flattened,
                                    dt_numa_scan_cpu_node, NULL);
    if ( ret )
        return ret;

    ret = device_tree_for_each_node((void *)device_tree_flattened,
                                    dt_numa_scan_distance_node, NULL);

    if ( !ret )
        register_node_distance(&dt_node_distance);

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
