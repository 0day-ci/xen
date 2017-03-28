#ifndef __ARCH_ARM_NUMA_H
#define __ARCH_ARM_NUMA_H

typedef uint8_t nodeid_t;

/* Limit number of NUMA nodes supported to 4 */
#define NODES_SHIFT 2

extern void dt_numa_process_memory_node(uint32_t nid,paddr_t start,
                                        paddr_t size);
extern void register_node_distance(uint8_t (fn)(nodeid_t a, nodeid_t b));
extern void init_dt_numa_distance(void);
extern uint8_t __node_distance(nodeid_t a, nodeid_t b);
#ifdef CONFIG_NUMA
extern void numa_init(void);
extern int dt_numa_init(void);
#else
static inline void numa_init(void)
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
