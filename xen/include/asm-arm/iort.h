#ifndef _XEN_ASM_IORT_H
#define _XEN_ASM_IORT_H

int estimate_iort_size(size_t *iort_size);

int prepare_iort(struct acpi_table_iort *fw_iort_table,
                struct acpi_table_iort *hwdom_table, u32 *iort_size);

#endif /* _XEN_ASM_IORT_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
