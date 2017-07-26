/******************************************************************************
 * trace_pc_stub.c
 *
 * Edge function/stub for the program counter tracing hypercall.
 *
 * Copyright (c) 2017 Felix Schmoll <eggi.innovations@gmail.com>
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

#include <xen/trace_pc.h>
#include <xen/kernel.h>

void __sanitizer_cov_trace_pc(void)
{
    struct domain *d;

    if ( system_state < SYS_STATE_active )
        return;

    d = current->domain;

    if ( d->tracing_buffer &&
        (d->tracing_buffer_pos < d->tracing_buffer_size) )
    {
        d->tracing_buffer[d->tracing_buffer_pos++] =
            (uint64_t) __builtin_return_address(0);
    }
}
