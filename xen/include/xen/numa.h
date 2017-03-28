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

struct node {
    paddr_t start;
    paddr_t end;
};

extern int compute_memnode_shift(struct node *nodes, int numnodes,
                                 nodeid_t *nodeids, unsigned int *shift);
extern void numa_init_array(void);
extern bool_t srat_disabled(void);
extern void numa_set_node(int cpu, nodeid_t node);
extern nodeid_t acpi_setup_node(unsigned int pxm);
extern void srat_detect_node(int cpu);
extern void setup_node_bootmem(nodeid_t nodeid, paddr_t start, paddr_t end);
extern void init_cpu_to_node(void);

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
#endif /* _XEN_NUMA_H */
