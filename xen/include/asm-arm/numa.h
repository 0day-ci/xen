#ifndef __ARCH_ARM_NUMA_H
#define __ARCH_ARM_NUMA_H

#include <xen/mm.h>

typedef uint8_t nodeid_t;

/* Limit number of NUMA nodes supported to 4 */
#define NODES_SHIFT 2

extern void dt_numa_process_memory_node(uint32_t nid,paddr_t start,
                                        paddr_t size);
extern void register_node_distance(uint8_t (fn)(nodeid_t a, nodeid_t b));
extern void init_dt_numa_distance(void);
extern uint8_t __node_distance(nodeid_t a, nodeid_t b);
#ifdef CONFIG_ACPI_NUMA
nodeid_t acpi_get_nodeid(uint64_t hwid);
#else
static inline nodeid_t acpi_get_nodeid(uint64_t hwid)
{
    return 0;
}
#endif /* CONFIG_ACPI_NUMA */

#ifdef CONFIG_NUMA
extern void numa_init(void);
extern int dt_numa_init(void);
extern void numa_set_cpu_node(int cpu, unsigned int nid);
extern void numa_add_cpu(int cpu);

extern nodeid_t      cpu_to_node[NR_CPUS];
extern cpumask_t     node_to_cpumask[];
/* Simple perfect hash to map pdx to node numbers */
extern unsigned int memnode_shift;
extern uint8_t *memnodemap;

#define cpu_to_node(cpu)         (cpu_to_node[cpu])
#define parent_node(node)        (node)
#define node_to_first_cpu(node)  (__ffs(node_to_cpumask[node]))
#define node_to_cpumask(node)    (node_to_cpumask[node])

static inline __attribute__((pure)) nodeid_t phys_to_nid(paddr_t addr)
{
    return memnodemap[paddr_to_pdx(addr) >> memnode_shift];
}

struct node_data {
    unsigned long node_start_pfn;
    unsigned long node_spanned_pages;
};

extern struct node_data node_data[];
#define NODE_DATA(nid)          (&(node_data[nid]))

#define node_start_pfn(nid)     (NODE_DATA(nid)->node_start_pfn)
#define node_spanned_pages(nid) (NODE_DATA(nid)->node_spanned_pages)
#define node_end_pfn(nid)       (NODE_DATA(nid)->node_start_pfn + \

#else
static inline void numa_init(void)
{
    return;
}

static inline void numa_set_cpu_node(int cpu, unsigned int nid)
{
    return;
}

static inline void numa_add_cpu(int cpu)
{
     return;
}

/* Fake one node for now. See also node_online_map. */
#define cpu_to_node(cpu) 0
#define node_to_cpumask(node)   (cpu_online_map)

static inline __attribute__((pure)) nodeid_t phys_to_nid(paddr_t addr)
{
    return 0;
}

/* XXX: implement NUMA support */
#define node_spanned_pages(nid) (total_pages)
#define node_start_pfn(nid) (pdx_to_pfn(frametable_base_pdx))
#define __node_distance(a, b) (20)
#endif /* CONFIG_NUMA */

static inline unsigned int arch_get_dma_bitsize(void)
{
    return 32;
}

#endif /* __ARCH_ARM_NUMA_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
