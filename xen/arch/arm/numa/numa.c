/*
 * ARM NUMA Implementation
 *
 * Copyright (C) 2016 - Cavium Inc.
 * Vijaya Kumar K <vijaya.kumar@cavium.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/mm.h>
#include <xen/nodemask.h>
#include <asm/mm.h>
#include <xen/numa.h>
#include <asm/acpi.h>

extern nodemask_t processor_nodes_parsed;

void __init numa_init(void)
{
    int ret = 0;

    nodes_clear(processor_nodes_parsed);
    if ( is_numa_off() )
        goto no_numa;

    ret = dt_numa_init();
    if ( ret )
        printk(XENLOG_WARNING "DT NUMA init failed\n");

no_numa:
    return;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
