/*
 * xen/include/xen/pmem.h
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

#ifndef __XEN_PMEM_H__
#define __XEN_PMEM_H__
#ifdef CONFIG_PMEM

#include <xen/types.h>

int pmem_register(unsigned long smfn, unsigned long emfn);

#endif /* CONFIG_PMEM */
#endif /* __XEN_PMEM_H__ */
