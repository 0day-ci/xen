#ifndef __XEN_SRAT_H__
#define __XEN_SRAT_H__

extern int srat_rev;
struct pxm2node {
    unsigned int pxm;
    nodeid_t node;
};

extern nodeid_t pxm_to_node(unsigned pxm);
extern nodeid_t acpi_setup_node(unsigned pxm);
extern unsigned int node_to_pxm(nodeid_t n);
extern uint8_t acpi_node_distance(nodeid_t a, nodeid_t b);
extern void reset_pxm2node(void);
#endif /* __XEN_SRAT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
