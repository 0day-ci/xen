/******************************************************************************
 * trace_pc.c
 *
 * Implementation of the program counter tracing hypercall.
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

#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <public/trace_pc.h>

long do_trace_pc(domid_t dom, int mode, unsigned int size,
                 XEN_GUEST_HANDLE_PARAM(uint64_t) buf)
{
#ifdef CONFIG_TRACE_PC
    int ret = 0;
    struct domain *d;

    if ( dom == DOMID_SELF )
        d = current->domain;
    else
        d = get_domain_by_id(dom);

    if ( !d )
        return -EINVAL; /* invalid domain */

    switch ( mode )
    {
    case XEN_TRACE_PC_START:
    {
        if ( d->tracing_buffer )
        {
            ret = -EBUSY; /* domain already being traced */
            break;
        }

        d->tracing_buffer_pos = 0;
        d->tracing_buffer_size = size;
        d->tracing_buffer = xmalloc_array(uint64_t, size);

        if ( !d->tracing_buffer )
            ret = -ENOMEM;
        break;
    }

    case XEN_TRACE_PC_STOP:
    {
        uint64_t* temp = d->tracing_buffer;
        d->tracing_buffer = NULL;

        if ( copy_to_guest(buf, temp, d->tracing_buffer_pos) )
            ret = -EFAULT;

        xfree(temp);

        ret = d->tracing_buffer_pos;
        break;
    }

    default:
        ret = -ENOSYS;
    }

    if ( dom != DOMID_SELF )
        put_domain(d);

    return ret;
#else
    return 0;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
