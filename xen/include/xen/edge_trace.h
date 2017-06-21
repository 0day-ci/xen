/******************************************************************************
 * edge_trace.h
 *
 * Information structure that lives at the bottom of the per-cpu Xen stack.
 */

#ifndef __TRACE_H__
#define __TRACE_H__

#include <xen/types.h>
#include <xen/sched.h>
#include <asm/current.h>

#define TRACE_START 0
#define TRACE_STOP 1

void __sanitizer_cov_trace_pc(void);

#endif
