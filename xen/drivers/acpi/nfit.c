/*
 * xen/drivers/acpi/nfit.c
 *
 * Copyright (C) 2017, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/pmem.h>

static struct acpi_table_nfit *nfit __read_mostly = NULL;

/* ACPI 6.1: GUID of a byte addressable persistent memory region */
static const uint8_t nfit_spa_pmem_uuid[] =
{
    0x79, 0xd3, 0xf0, 0x66, 0xf3, 0xb4, 0x74, 0x40,
    0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7, 0x8c, 0xdb,
};

/**
 * Enumerate each sub-table of NFIT.
 *
 * For a sub-table of type @type, @parse_cb() (if not NULL) is called
 * to parse the sub-table. @parse_cb() returns 0 on success, and
 * returns non-zero error code on errors.
 *
 * Parameters:
 *  nfit:      NFIT
 *  type:      the type of sub-table that will be parsed
 *  parse_cb:  the function used to parse each sub-table
 *  arg:       the argument passed to @parse_cb()
 *
 * Return:
 *  0 on success, non-zero on failure
 */
static int acpi_nfit_foreach_subtable(
    struct acpi_table_nfit *nfit, enum acpi_nfit_type type,
    int (*parse_cb)(const struct acpi_nfit_header *, void *arg), void *arg)
{
    struct acpi_table_header *table = (struct acpi_table_header *)nfit;
    struct acpi_nfit_header *hdr;
    uint32_t hdr_offset = sizeof(*nfit);
    int ret = 0;

    while ( hdr_offset < table->length )
    {
        hdr = (void *)nfit + hdr_offset;
        hdr_offset += hdr->length;
        if ( hdr->type == type && parse_cb )
        {
            ret = parse_cb(hdr, arg);
            if ( ret )
                break;
        }
    }

    return ret;
}

static int __init acpi_nfit_spa_probe_pmem(const struct acpi_nfit_header *hdr,
                                           void *opaque)
{
    struct acpi_nfit_system_address *spa =
        (struct acpi_nfit_system_address *)hdr;
    unsigned long smfn = paddr_to_pfn(spa->address);
    unsigned long emfn = paddr_to_pfn(spa->address + spa->length);
    int rc;

    if ( memcmp(spa->range_guid, nfit_spa_pmem_uuid, 16) )
        return 0;

    rc = pmem_register(smfn, emfn);
    if ( rc )
        printk(XENLOG_ERR
               "NFIT: failed to add pmem mfns: 0x%lx - 0x%lx, err %d\n",
               smfn, emfn, rc);
    else
        printk(XENLOG_INFO "NFIT: pmem mfn 0x%lx - 0x%lx\n", smfn, emfn);

    /* ignore the error and continue to add the next pmem range */
    return 0;
}

void __init acpi_nfit_init(void)
{
    acpi_status status;
    acpi_physical_address nfit_addr;
    acpi_native_uint nfit_len;

    status = acpi_get_table_phys(ACPI_SIG_NFIT, 0, &nfit_addr, &nfit_len);
    if ( ACPI_FAILURE(status) )
         return;

    map_pages_to_xen((unsigned long)__va(nfit_addr), PFN_DOWN(nfit_addr),
                     PFN_UP(nfit_addr + nfit_len) - PFN_DOWN(nfit_addr),
                     PAGE_HYPERVISOR);
    nfit = (struct acpi_table_nfit *)__va(nfit_addr);

    acpi_nfit_foreach_subtable(nfit, ACPI_NFIT_TYPE_SYSTEM_ADDRESS,
                               acpi_nfit_spa_probe_pmem, NULL);
}
