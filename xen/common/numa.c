/*
 * Common NUMA handling functions for x86 and arm.
 * Original code extracted from arch/x86/numa.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/mm.h>
#include <xen/string.h>
#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/nodemask.h>
#include <xen/numa.h>
#include <xen/keyhandler.h>
#include <xen/time.h>
#include <xen/smp.h>
#include <xen/pfn.h>
#include <asm/acpi.h>
#include <xen/sched.h>
#include <xen/softirq.h>

static int numa_setup(char *s);
custom_param("numa", numa_setup);

nodemask_t __initdata memory_nodes_parsed;
nodemask_t __initdata processor_nodes_parsed;
struct node_data node_data[MAX_NUMNODES];

/* Mapping from pdx to node id */
unsigned int memnode_shift;
static typeof(*memnodemap) _memnodemap[64];
unsigned long memnodemapsize;
uint8_t *memnodemap;

nodeid_t __read_mostly cpu_to_node[NR_CPUS] = {
    [0 ... NR_CPUS-1] = NUMA_NO_NODE
};
cpumask_t __read_mostly node_to_cpumask[MAX_NUMNODES];

static bool numa_off = 0;
static bool acpi_numa = 1;
static int num_node_memblks;
static struct node node_memblk_range[NR_NODE_MEMBLKS];
static nodeid_t memblk_nodeid[NR_NODE_MEMBLKS];
static struct node __initdata nodes[MAX_NUMNODES];

bool is_numa_off(void)
{
    return numa_off;
}

bool get_acpi_numa(void)
{
    return acpi_numa;
}

void set_acpi_numa(bool_t val)
{
    acpi_numa = val;
}

bool srat_disabled(void)
{
    return numa_off || acpi_numa == 0;
}

struct node *get_numa_node(int id)
{
    return &nodes[id];
}

nodeid_t get_memblk_nodeid(int id)
{
    return memblk_nodeid[id];
}

int __init get_mem_nodeid(paddr_t start, paddr_t end)
{
    unsigned int i;

    for ( i = 0; i < get_num_node_memblks(); i++ )
    {
        if ( start >= node_memblk_range[i].start &&
             end <= node_memblk_range[i].end )
            return memblk_nodeid[i];
    }

    return -EINVAL;
}

nodeid_t *get_memblk_nodeid_map(void)
{
    return &memblk_nodeid[0];
}

struct node *get_node_memblk_range(int memblk)
{
    return &node_memblk_range[memblk];
}

int get_num_node_memblks(void)
{
    return num_node_memblks;
}

int __init numa_add_memblk(nodeid_t nodeid, paddr_t start, uint64_t size)
{
    if (nodeid >= NR_NODE_MEMBLKS)
        return -EINVAL;

    node_memblk_range[num_node_memblks].start = start;
    node_memblk_range[num_node_memblks].end = start + size;
    memblk_nodeid[num_node_memblks] = nodeid;
    num_node_memblks++;

    return 0;
}

int valid_numa_range(paddr_t start, paddr_t end, nodeid_t node)
{
    int i;

    for (i = 0; i < get_num_node_memblks(); i++) {
        struct node *nd = get_node_memblk_range(i);

        if (nd->start <= start && nd->end > end &&
            get_memblk_nodeid(i) == node)
            return 1;
    }

    return 0;
}

int __init conflicting_memblks(paddr_t start, paddr_t end)
{
    int i;

    for (i = 0; i < get_num_node_memblks(); i++) {
        struct node *nd = get_node_memblk_range(i);
        if (nd->start == nd->end)
            continue;
        if (nd->end > start && nd->start < end)
            return i;
        if (nd->end == end && nd->start == start)
            return i;
    }
    return -1;
}

void __init cutoff_node(int i, paddr_t start, paddr_t end)
{
    struct node *nd = get_numa_node(i);

    if (nd->start < start) {
        nd->start = start;
        if (nd->end < nd->start)
            nd->start = nd->end;
    }
    if (nd->end > end) {
        nd->end = end;
        if (nd->start > nd->end)
            nd->start = nd->end;
    }
}

/*
 * Given a shift value, try to populate memnodemap[]
 * Returns :
 * 0 if OK
 * -EINVAL if memnodmap[] too small (of shift too small)
 * OR if node overlap or lost ram (shift too big)
 */
static int __init populate_memnodemap(const struct node *nodes, int numnodes,
                                      unsigned int shift, nodeid_t *nodeids)
{
    unsigned long spdx, epdx;
    int i, res = -EINVAL;

    memset(memnodemap, NUMA_NO_NODE, memnodemapsize * sizeof(*memnodemap));
    for ( i = 0; i < numnodes; i++ )
    {
        spdx = paddr_to_pdx(nodes[i].start);
        epdx = paddr_to_pdx(nodes[i].end - 1) + 1;
        if ( spdx >= epdx )
            continue;
        if ( (epdx >> shift) >= memnodemapsize )
            return 0;
        do {
            if ( memnodemap[spdx >> shift] != NUMA_NO_NODE )
                return -EINVAL;

            if ( !nodeids )
                memnodemap[spdx >> shift] = i;
            else
                memnodemap[spdx >> shift] = nodeids[i];

            spdx += (1UL << shift);
        } while ( spdx < epdx );
        res = 0;
    }

    return res;
}

static int __init allocate_cachealigned_memnodemap(void)
{
    unsigned long size = PFN_UP(memnodemapsize * sizeof(*memnodemap));
    unsigned long mfn = alloc_boot_pages(size, 1);

    if ( !mfn )
    {
        printk(KERN_ERR
               "NUMA: Unable to allocate Memory to Node hash map\n");
        memnodemapsize = 0;
        return -ENOMEM;
    }

    memnodemap = mfn_to_virt(mfn);
    mfn <<= PAGE_SHIFT;
    size <<= PAGE_SHIFT;
    printk(KERN_DEBUG "NUMA: Allocated memnodemap from %lx - %lx\n",
           mfn, mfn + size);
    memnodemapsize = size / sizeof(*memnodemap);

    return 0;
}

/*
 * The LSB of all start and end addresses in the node map is the value of the
 * maximum possible shift.
 */
static unsigned int __init extract_lsb_from_nodes(const struct node *nodes,
                                                  int numnodes)
{
    unsigned int i, nodes_used = 0;
    unsigned long spdx, epdx;
    unsigned long bitfield = 0, memtop = 0;

    for ( i = 0; i < numnodes; i++ )
    {
        spdx = paddr_to_pdx(nodes[i].start);
        epdx = paddr_to_pdx(nodes[i].end - 1) + 1;
        if ( spdx >= epdx )
            continue;
        bitfield |= spdx;
        nodes_used++;
        if ( epdx > memtop )
            memtop = epdx;
    }
    if ( nodes_used <= 1 )
        i = BITS_PER_LONG - 1;
    else
        i = find_first_bit(&bitfield, sizeof(unsigned long) * 8);

    memnodemapsize = (memtop >> i) + 1;

    return i;
}

int __init compute_memnode_shift(struct node *nodes, int numnodes,
                                 nodeid_t *nodeids, unsigned int *shift)
{
    *shift = extract_lsb_from_nodes(nodes, numnodes);

    if ( memnodemapsize <= ARRAY_SIZE(_memnodemap) )
        memnodemap = _memnodemap;
    else if ( allocate_cachealigned_memnodemap() )
        return -ENOMEM;

    printk(KERN_DEBUG "NUMA: Using %u for the hash shift.\n", *shift);

    if ( populate_memnodemap(nodes, numnodes, *shift, nodeids) )
    {
        printk(KERN_INFO "Your memory is not aligned you need to "
               "rebuild your hypervisor with a bigger NODEMAPSIZE "
               "shift=%u\n", *shift);
        return -EINVAL;
    }

    return 0;
}
/* initialize NODE_DATA given nodeid and start/end */
void __init setup_node_bootmem(nodeid_t nodeid, paddr_t start, paddr_t end)
{
    unsigned long start_pfn, end_pfn;

    start_pfn = start >> PAGE_SHIFT;
    end_pfn = end >> PAGE_SHIFT;

    NODE_DATA(nodeid)->node_start_pfn = start_pfn;
    NODE_DATA(nodeid)->node_spanned_pages = end_pfn - start_pfn;

    node_set_online(nodeid);
}

void __init numa_init_array(void)
{
    int rr, i;

    /* There are unfortunately some poorly designed mainboards around
       that only connect memory to a single CPU. This breaks the 1:1 cpu->node
       mapping. To avoid this fill in the mapping for all possible
       CPUs, as the number of CPUs is not known yet.
       We round robin the existing nodes. */
    rr = first_node(node_online_map);
    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( cpu_to_node[i] != NUMA_NO_NODE )
            continue;
        numa_set_node(i, rr);
        rr = next_node(rr, node_online_map);
        if ( rr == MAX_NUMNODES )
            rr = first_node(node_online_map);
    }
}

#ifdef CONFIG_NUMA_EMU
static int __initdata numa_fake = 0;

int get_numa_fake(void)
{
    return numa_fake;
}

/* Numa emulation */
int __init numa_emulation(uint64_t start_pfn, uint64_t end_pfn)
{
    int i;
    struct node nodes[MAX_NUMNODES];
    uint64_t sz = ((end_pfn - start_pfn) << PAGE_SHIFT) / get_numa_fake();

    /* Kludge needed for the hash function */
    if ( hweight64(sz) > 1 )
    {
        uint64_t x = 1;
        while ( (x << 1) < sz )
            x <<= 1;
        if ( x < sz / 2 )
            printk(KERN_ERR
                   "Numa emulation unbalanced. Complain to maintainer\n");
        sz = x;
    }

    memset(&nodes,0,sizeof(nodes));
    for ( i = 0; i < get_numa_fake(); i++ )
    {
        nodes[i].start = (start_pfn << PAGE_SHIFT) + i * sz;
        if ( i == get_numa_fake() - 1 )
            sz = (end_pfn << PAGE_SHIFT) - nodes[i].start;
        nodes[i].end = nodes[i].start + sz;
        printk(KERN_INFO
               "Faking node %d at %"PRIx64"-%"PRIx64" (%"PRIu64"MB)\n",
               i, nodes[i].start, nodes[i].end,
               (nodes[i].end - nodes[i].start) >> 20);
        node_set_online(i);
    }

    if ( compute_memnode_shift(nodes, get_numa_fake(), NULL, &memnode_shift) )
    {
        memnode_shift = 0;
        printk(KERN_ERR "No NUMA hash function found. Emulation disabled.\n");
        return -1;
    }
    for_each_online_node ( i )
        setup_node_bootmem(i, nodes[i].start, nodes[i].end);
    numa_init_array();

    return 0;
}
#endif

void __init numa_dummy_init(unsigned long start_pfn, unsigned long end_pfn)
{
    int i;

    printk(KERN_INFO "%s\n",
           is_numa_off() ? "NUMA turned off" : "No NUMA configuration found");

    printk(KERN_INFO "Faking a node at %016"PRIx64"-%016"PRIx64"\n",
           (uint64_t)start_pfn << PAGE_SHIFT,
           (uint64_t)end_pfn << PAGE_SHIFT);
    /* setup dummy node covering all memory */
    memnode_shift = BITS_PER_LONG - 1;
    memnodemap = _memnodemap;
    nodes_clear(node_online_map);
    node_set_online(0);
    for ( i = 0; i < nr_cpu_ids; i++ )
        numa_set_node(i, 0);
    cpumask_copy(&node_to_cpumask[0], cpumask_of(0));
    setup_node_bootmem(0, (paddr_t)start_pfn << PAGE_SHIFT,
                    (paddr_t)end_pfn << PAGE_SHIFT);
}

void numa_add_cpu(int cpu)
{
    cpumask_set_cpu(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
}

void numa_set_node(int cpu, nodeid_t node)
{
    cpu_to_node[cpu] = node;
}

/* Use the information discovered above to actually set up the nodes. */
int __init numa_scan_nodes(uint64_t start, uint64_t end)
{
    int i;
    nodemask_t all_nodes_parsed;
    struct node *memblks;
    nodeid_t *nodeids;

    /* First clean up the node list */
    for (i = 0; i < MAX_NUMNODES; i++)
        cutoff_node(i, start, end);

    if (get_acpi_numa() == 0)
        return -1;

    if (!arch_sanitize_nodes_memory()) {
        numa_failed();
        return -1;
    }

    memblks = get_node_memblk_range(0);
    nodeids = get_memblk_nodeid_map();
    if (compute_memnode_shift(node_memblk_range, num_node_memblks,
                  memblk_nodeid, &memnode_shift)) {
        memnode_shift = 0;
        printk(KERN_ERR
             "SRAT: No NUMA node hash function found. Contact maintainer\n");
        numa_failed();
        return -1;
    }

    nodes_or(all_nodes_parsed, memory_nodes_parsed, processor_nodes_parsed);

    /* Finally register nodes */
    for_each_node_mask(i, all_nodes_parsed)
    {
        struct node *nd = get_numa_node(i);
        uint64_t size = nd->end - nd->start;

        if ( size == 0 )
            printk(KERN_WARNING "SRAT: Node %u has no memory. "
                   "BIOS Bug or mis-configured hardware?\n", i);

        setup_node_bootmem(i, nd->start, nd->end);
    }
    for (i = 0; i < nr_cpu_ids; i++) {
        if (cpu_to_node[i] == NUMA_NO_NODE)
            continue;
        if (!node_isset(cpu_to_node[i], processor_nodes_parsed))
            numa_set_node(i, NUMA_NO_NODE);
    }
    numa_init_array();
    return 0;
}

/* [numa=off] */
static int __init numa_setup(char *opt)
{
    if ( !strncmp(opt,"off",3) )
        numa_off = 1;
    if ( !strncmp(opt,"on",2) )
        numa_off = 0;
#ifdef CONFIG_NUMA_EMU
    if ( !strncmp(opt, "fake=", 5) )
    {
        numa_off = 0;
        numa_fake = simple_strtoul(opt+5,NULL,0);
        if ( numa_fake >= MAX_NUMNODES )
            numa_fake = MAX_NUMNODES;
    }
#endif
#ifdef CONFIG_ACPI_NUMA
    if ( !strncmp(opt,"noacpi",6) )
    {
        numa_off = 0;
        acpi_numa = 0;
    }
#endif

    return 1;
}

static void dump_numa(unsigned char key)
{
    s_time_t now = NOW();
    unsigned int i, j, n;
    int err;
    struct domain *d;
    struct page_info *page;
    unsigned int page_num_node[MAX_NUMNODES];
    const struct vnuma_info *vnuma;

    printk("'%c' pressed -> dumping numa info (now-0x%X:%08X)\n", key,
           (uint32_t)(now >> 32), (uint32_t)now);

    for_each_online_node ( i )
    {
        paddr_t pa = pfn_to_paddr(node_start_pfn(i) + 1);

        printk("NODE%u start->%lu size->%lu free->%lu\n",
               i, node_start_pfn(i), node_spanned_pages(i),
               avail_node_heap_pages(i));
        /* sanity check phys_to_nid() */
        if ( phys_to_nid(pa) != i )
            printk("phys_to_nid(%"PRIpaddr") -> %d should be %u\n",
                   pa, phys_to_nid(pa), i);
    }

    j = cpumask_first(&cpu_online_map);
    n = 0;
    for_each_online_cpu ( i )
    {
        if ( i != j + n || cpu_to_node[j] != cpu_to_node[i] )
        {
            if ( n > 1 )
                printk("CPU%u...%u -> NODE%d\n", j, j + n - 1, cpu_to_node[j]);
            else
                printk("CPU%u -> NODE%d\n", j, cpu_to_node[j]);
            j = i;
            n = 1;
        }
        else
            ++n;
    }
    if ( n > 1 )
        printk("CPU%u...%u -> NODE%d\n", j, j + n - 1, cpu_to_node[j]);
    else
        printk("CPU%u -> NODE%d\n", j, cpu_to_node[j]);

    rcu_read_lock(&domlist_read_lock);

    printk("Memory location of each domain:\n");
    for_each_domain ( d )
    {
        process_pending_softirqs();

        printk("Domain %u (total: %u):\n", d->domain_id, d->tot_pages);

        for_each_online_node ( i )
            page_num_node[i] = 0;

        spin_lock(&d->page_alloc_lock);
        page_list_for_each(page, &d->page_list)
        {
            i = phys_to_nid((paddr_t)page_to_mfn(page) << PAGE_SHIFT);
            page_num_node[i]++;
        }
        spin_unlock(&d->page_alloc_lock);

        for_each_online_node ( i )
            printk("    Node %u: %u\n", i, page_num_node[i]);

        if ( !read_trylock(&d->vnuma_rwlock) )
            continue;

        if ( !d->vnuma )
        {
            read_unlock(&d->vnuma_rwlock);
            continue;
        }

        vnuma = d->vnuma;
        printk("     %u vnodes, %u vcpus, guest physical layout:\n",
               vnuma->nr_vnodes, d->max_vcpus);
        for ( i = 0; i < vnuma->nr_vnodes; i++ )
        {
            unsigned int start_cpu = ~0U;

            err = snprintf(keyhandler_scratch, 12, "%3u",
                    vnuma->vnode_to_pnode[i]);
            if ( err < 0 || vnuma->vnode_to_pnode[i] == NUMA_NO_NODE )
                strlcpy(keyhandler_scratch, "???", sizeof(keyhandler_scratch));

            printk("       %3u: pnode %s,", i, keyhandler_scratch);

            printk(" vcpus ");

            for ( j = 0; j < d->max_vcpus; j++ )
            {
                if ( !(j & 0x3f) )
                    process_pending_softirqs();

                if ( vnuma->vcpu_to_vnode[j] == i )
                {
                    if ( start_cpu == ~0U )
                    {
                        printk("%d", j);
                        start_cpu = j;
                    }
                }
                else if ( start_cpu != ~0U )
                {
                    if ( j - 1 != start_cpu )
                        printk("-%d ", j - 1);
                    else
                        printk(" ");
                    start_cpu = ~0U;
                }
            }

            if ( start_cpu != ~0U  && start_cpu != j - 1 )
                printk("-%d", j - 1);

            printk("\n");

            for ( j = 0; j < vnuma->nr_vmemranges; j++ )
            {
                if ( vnuma->vmemrange[j].nid == i )
                    printk("           %016"PRIx64" - %016"PRIx64"\n",
                           vnuma->vmemrange[j].start,
                           vnuma->vmemrange[j].end);
            }
        }

        read_unlock(&d->vnuma_rwlock);
    }

    rcu_read_unlock(&domlist_read_lock);
}

static int __init register_numa_trigger(void)
{
    register_keyhandler('u', dump_numa, "dump NUMA info", 1);
    return 0;
}
__initcall(register_numa_trigger);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
