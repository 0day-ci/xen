#ifndef _XEN_NUMA_H
#define _XEN_NUMA_H

#include <asm/numa.h>

#ifndef NODES_SHIFT
#define NODES_SHIFT     0
#endif

#define NUMA_NO_NODE     0xFF
#define LOCAL_DISTANCE   10
#define REMOTE_DISTANCE  20
#define NUMA_NO_DISTANCE 0xFF

#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NR_NODE_MEMBLKS (MAX_NUMNODES * 2)

struct node {
    paddr_t start;
    paddr_t end;
};

extern int compute_memnode_shift(struct node *nodes, int numnodes,
                                 nodeid_t *nodeids, unsigned int *shift);
extern void numa_init_array(void);
extern bool_t srat_disabled(void);
#ifdef CONFIG_NUMA
extern void numa_set_node(int cpu, nodeid_t node);
#else
static inline void numa_set_node(int cpu, nodeid_t node) { }
#endif
extern void srat_detect_node(int cpu);
extern void setup_node_bootmem(nodeid_t nodeid, paddr_t start, paddr_t end);
extern void init_cpu_to_node(void);
extern int valid_numa_range(paddr_t start, paddr_t end, nodeid_t node);
extern int conflicting_memblks(paddr_t start, paddr_t end);
extern void cutoff_node(int i, paddr_t start, paddr_t end);
extern struct node *get_numa_node(int id);
extern nodeid_t get_memblk_nodeid(int memblk);
extern nodeid_t *get_memblk_nodeid_map(void);
extern struct node *get_node_memblk_range(int memblk);
extern struct node *get_memblk(int memblk);
extern int numa_add_memblk(nodeid_t nodeid, paddr_t start, uint64_t size);
extern int get_mem_nodeid(paddr_t start, paddr_t end);
extern int get_num_node_memblks(void);
extern int arch_sanitize_nodes_memory(void);
extern void numa_failed(void);
extern int numa_scan_nodes(uint64_t start, uint64_t end);

#define vcpu_to_node(v) (cpu_to_node((v)->processor))

#define domain_to_node(d) \
  (((d)->vcpu != NULL && (d)->vcpu[0] != NULL) \
   ? vcpu_to_node((d)->vcpu[0]) : NUMA_NO_NODE)

bool is_numa_off(void);
bool get_acpi_numa(void);
void set_acpi_numa(bool val);
int get_numa_fake(void);
extern int numa_emulation(uint64_t start_pfn, uint64_t end_pfn);
extern void numa_dummy_init(uint64_t start_pfn, uint64_t end_pfn);
extern void numa_clear_memblks(void);
#endif /* _XEN_NUMA_H */
