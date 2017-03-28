/*
 * ACPI 3.0 based NUMA setup
 * Copyright 2004 Andi Kleen, SuSE Labs.
 *
 * Reads the ACPI SRAT table to figure out what memory belongs to which CPUs.
 *
 * Called from acpi_numa_init while reading the SRAT and SLIT tables.
 * Assumes all memory regions belonging to a single proximity domain
 * are in one chunk. Holes between them will be included in the node.
 *
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/inttypes.h>
#include <xen/nodemask.h>
#include <xen/acpi.h>
#include <xen/numa.h>
#include <xen/pfn.h>
#include <acpi/srat.h>
#include <asm/e820.h>
#include <asm/page.h>

extern nodemask_t processor_nodes_parsed;
extern nodemask_t memory_nodes_parsed;
/*
 * Keep BIOS's CPU2node information, should not be used for memory allocaion
 */
nodeid_t apicid_to_node[MAX_LOCAL_APIC] = {
    [0 ... MAX_LOCAL_APIC-1] = NUMA_NO_NODE
};

void __init numa_failed(void)
{
	int i;
	printk(KERN_ERR "SRAT: SRAT not used.\n");
	set_acpi_numa(0);
	for (i = 0; i < MAX_LOCAL_APIC; i++)
		apicid_to_node[i] = NUMA_NO_NODE;
	reset_pxm2node();
	mem_hotplug = 0;
}

/* Callback for Proximity Domain -> x2APIC mapping */
void __init
acpi_numa_x2apic_affinity_init(const struct acpi_srat_x2apic_cpu_affinity *pa)
{
	unsigned pxm;
	nodeid_t node;

	if (srat_disabled())
		return;
	if (pa->header.length < sizeof(struct acpi_srat_x2apic_cpu_affinity)) {
		numa_failed();
		return;
	}
	if (!(pa->flags & ACPI_SRAT_CPU_ENABLED))
		return;
	if (pa->apic_id >= MAX_LOCAL_APIC) {
		printk(KERN_INFO "SRAT: APIC %08x ignored\n", pa->apic_id);
		return;
	}

	pxm = pa->proximity_domain;
	node = acpi_setup_node(pxm);
	if (node == NUMA_NO_NODE) {
		numa_failed();
		return;
	}

	apicid_to_node[pa->apic_id] = node;
	node_set(node, processor_nodes_parsed);
	set_acpi_numa(1);
	printk(KERN_INFO "SRAT: PXM %u -> APIC %08x -> Node %u\n",
	       pxm, pa->apic_id, node);
}

/* Callback for Proximity Domain -> LAPIC mapping */
void __init
acpi_numa_processor_affinity_init(const struct acpi_srat_cpu_affinity *pa)
{
	unsigned pxm;
	nodeid_t node;

	if (srat_disabled())
		return;
	if (pa->header.length != sizeof(struct acpi_srat_cpu_affinity)) {
		numa_failed();
		return;
	}
	if (!(pa->flags & ACPI_SRAT_CPU_ENABLED))
		return;
	pxm = pa->proximity_domain_lo;
	if (srat_rev >= 2) {
		pxm |= pa->proximity_domain_hi[0] << 8;
		pxm |= pa->proximity_domain_hi[1] << 16;
		pxm |= pa->proximity_domain_hi[2] << 24;
	}
	node = acpi_setup_node(pxm);
	if (node == NUMA_NO_NODE) {
		numa_failed();
		return;
	}
	apicid_to_node[pa->apic_id] = node;
	node_set(node, processor_nodes_parsed);
	set_acpi_numa(1);
	printk(KERN_INFO "SRAT: PXM %u -> APIC %02x -> Node %u\n",
	       pxm, pa->apic_id, node);
}

/* Sanity check to catch more bad SRATs (they are amazingly common).
   Make sure the PXMs cover all memory. */
int __init arch_sanitize_nodes_memory(void)
{
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		int j, found;
		unsigned long long start, end;

		if (e820.map[i].type != E820_RAM) {
			continue;
		}

		start = e820.map[i].addr;
		end = e820.map[i].addr + e820.map[i].size - 1;

		do {
			found = 0;
			for_each_node_mask(j, memory_nodes_parsed)
			{
		                struct node *nd = get_numa_node(j);

				if (start < nd->end
				    && end > nd->start) {
					if (start >= nd->start) {
						start = nd->end;
						found = 1;
					}
					if (end <= nd->end) {
						end = nd->start;
						found = 1;
					}
				}
			}
		} while (found && start < end);

		if (start < end) {
			printk(KERN_ERR "SRAT: No PXM for e820 range: "
				"%016Lx - %016Lx\n", start, end);
			return 0;
		}
	}
	return 1;
}

void __init acpi_numa_arch_fixup(void) {}

static uint64_t __initdata srat_region_mask;

static int __init srat_parse_region(struct acpi_subtable_header *header,
				    const unsigned long end)
{
	struct acpi_srat_mem_affinity *ma;

	if (!header)
		return -EINVAL;

	ma = container_of(header, struct acpi_srat_mem_affinity, header);

	if (!ma->length ||
	    !(ma->flags & ACPI_SRAT_MEM_ENABLED) ||
	    (ma->flags & ACPI_SRAT_MEM_NON_VOLATILE))
		return 0;

	if (is_numa_off())
		printk(KERN_INFO "SRAT: %013"PRIx64"-%013"PRIx64"\n",
		       ma->base_address, ma->base_address + ma->length - 1);

	srat_region_mask |= ma->base_address |
			    pdx_region_mask(ma->base_address, ma->length);

	return 0;
}

void __init srat_parse_regions(uint64_t addr)
{
	uint64_t mask;
	unsigned int i;

	if (acpi_disabled || (get_acpi_numa() == 0) ||
	    acpi_table_parse(ACPI_SIG_SRAT, acpi_parse_srat))
		return;

	srat_region_mask = pdx_init_mask(addr);
	acpi_table_parse_srat(ACPI_SRAT_TYPE_MEMORY_AFFINITY,
			      srat_parse_region, 0);

	for (mask = srat_region_mask, i = 0; mask && i < e820.nr_map; i++) {
		if (e820.map[i].type != E820_RAM)
			continue;

		if (~mask & pdx_region_mask(e820.map[i].addr, e820.map[i].size))
			mask = 0;
	}

	pfn_pdx_hole_setup(mask >> PAGE_SHIFT);
}

uint8_t __node_distance(nodeid_t a, nodeid_t b)
{
	return acpi_node_distance(a, b);
}

EXPORT_SYMBOL(__node_distance);

static int __init
acpi_parse_x2apic_affinity(struct acpi_subtable_header *header,
			   const unsigned long end)
{
	const struct acpi_srat_x2apic_cpu_affinity *processor_affinity
		= container_of(header, struct acpi_srat_x2apic_cpu_affinity,
			       header);

	if (!header)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	acpi_numa_x2apic_affinity_init(processor_affinity);

	return 0;
}

static int __init
acpi_parse_processor_affinity(struct acpi_subtable_header *header,
			      const unsigned long end)
{
	const struct acpi_srat_cpu_affinity *processor_affinity
		= container_of(header, struct acpi_srat_cpu_affinity, header);

	if (!header)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	acpi_numa_processor_affinity_init(processor_affinity);

	return 0;
}

void __init arch_table_parse_srat(void)
{
	acpi_table_parse_srat(ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY,
			      acpi_parse_x2apic_affinity, 0);
	acpi_table_parse_srat(ACPI_SRAT_TYPE_CPU_AFFINITY,
			      acpi_parse_processor_affinity, 0);
}
