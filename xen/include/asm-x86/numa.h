#ifndef _ASM_X8664_NUMA_H
#define _ASM_X8664_NUMA_H 1

#include <xen/cpumask.h>

#define NODES_SHIFT 6

typedef uint8_t nodeid_t;

extern int srat_rev;

extern nodeid_t      cpu_to_node[NR_CPUS];
extern cpumask_t     node_to_cpumask[];

#define cpu_to_node(cpu)         (cpu_to_node[cpu])
#define parent_node(node)        (node)
#define node_to_first_cpu(node)  (__ffs(node_to_cpumask[node]))
#define node_to_cpumask(node)    (node_to_cpumask[node])

extern nodeid_t pxm_to_node(unsigned int pxm);

#define ZONE_ALIGN (1UL << (MAX_ORDER+PAGE_SHIFT))

extern void numa_add_cpu(int cpu);
extern nodeid_t apicid_to_node[];

/* Simple perfect hash to map pdx to node numbers */
extern unsigned int memnode_shift;
extern uint8_t *memnodemap;

struct node_data {
    unsigned long node_start_pfn;
    unsigned long node_spanned_pages;
};

extern struct node_data node_data[];

static inline __attribute__((pure)) nodeid_t phys_to_nid(paddr_t addr)
{
    return memnodemap[paddr_to_pdx(addr) >> memnode_shift];
}

#define NODE_DATA(nid)          (&(node_data[nid]))

#define node_start_pfn(nid)     (NODE_DATA(nid)->node_start_pfn)
#define node_spanned_pages(nid) (NODE_DATA(nid)->node_spanned_pages)
#define node_end_pfn(nid)       (NODE_DATA(nid)->node_start_pfn + \
                                 NODE_DATA(nid)->node_spanned_pages)

extern int valid_numa_range(paddr_t start, paddr_t end, nodeid_t node);

void srat_parse_regions(uint64_t addr);
extern uint8_t __node_distance(nodeid_t a, nodeid_t b);
unsigned int arch_get_dma_bitsize(void);

#endif
