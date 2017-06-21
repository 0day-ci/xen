/******************************************************************************
 * edge_trace.c
 *
 * Copyright (c) 2017 Felix Schmoll
 */

#include <xen/edge_trace.h>
#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <xen/sched.h>

long do_edge_trace(domid_t dom, int mode, unsigned int size,
    XEN_GUEST_HANDLE_PARAM(uint64_t) buf)
{
    int ret = 0;
    struct domain *d;

    if( dom == DOMID_SELF )
        d = current->domain;
    else
        d = get_domain_by_id(dom);

    if( !d )
        return -EINVAL; /* invalid domain */

    switch ( mode )
    {
        case TRACE_START:
        {
            if( d->tracing_buffer )
            {
                ret = -EBUSY; /* domain already being traced */
                break;
            }

            d->tracing_buffer_pos = 0;
            d->tracing_buffer_size = size;
            d->tracing_buffer = xmalloc_array(uint64_t, size);

            if( !d->tracing_buffer )
                ret = -ENOMEM;
            break;
        }

        case TRACE_STOP:
        {
            uint64_t* temp = d->tracing_buffer;
            d->tracing_buffer = NULL;

            if( copy_to_guest(buf, temp, d->tracing_buffer_pos) )
                ret = -EFAULT;

            xfree(temp);

            ret = d->tracing_buffer_pos;
            break;
        }

        default:
            ret = -ENOSYS;
    }

    if( dom != DOMID_SELF )
        put_domain(d);

    return ret;
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
