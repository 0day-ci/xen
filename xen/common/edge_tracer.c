/******************************************************************************
 * edge_tracer.c
 *
 * Copyright (c) 2017 Felix Schmoll
 */

#include <xen/edge_trace.h>
#include <xen/kernel.h>

void __sanitizer_cov_trace_pc(void)
{
        struct domain *d;

        if( system_state < SYS_STATE_active )
            return;

        d = current->domain;

        if(d->tracing_buffer &&
           d->tracing_buffer_pos < d->tracing_buffer_size)
        {
            d->tracing_buffer[d->tracing_buffer_pos++] =
                (uint64_t) __builtin_return_address(0);
        }
}
