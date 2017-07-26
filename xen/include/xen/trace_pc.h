/******************************************************************************
 * trace_pc.h
 *
 * Declarations for the program counter tracing hypercall
 *
 * Copyright (C) 2017 Felix Schmoll <eggi.innovations@gmail.com>
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

#ifndef __TRACE_PC_H__
#define __TRACE_PC_H__

#include <xen/sched.h>
#include <xen/types.h>

#include <asm/current.h>

void __sanitizer_cov_trace_pc(void);

#endif /* __TRACE_PC_H__ */
