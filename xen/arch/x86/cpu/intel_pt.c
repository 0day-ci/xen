/*
 * intel_pt.c: Support Intel Processor Trace Virtualization.
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Luwei Kang <luwei.kang@intel.com>
 */

#include <xen/types.h>
#include <xen/cache.h>
#include <xen/init.h>

/* intel_pt: Flag to enable Intel Processor Trace (default on). */
bool_t __read_mostly opt_intel_pt = 1;
boolean_param("intel_pt", opt_intel_pt);
