/*
 * topology.c: obtain vCPU topology from hypervisor
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "util.h"
#include "hypercall.h"
#include "topology.h"
#include <xen/memory.h>

unsigned int *topology_id;
unsigned int topology_id_size;

int init_cpu_topology_info(void)
{
    int rc;
    struct xen_cpu_topology_info cpu_topology =
        { .domid = DOMID_SELF, .size = hvm_info->nr_vcpus };

    topology_id = scratch_alloc(sizeof(*topology_id) * hvm_info->nr_vcpus, 0);
    set_xen_guest_handle(cpu_topology.tid.h, topology_id);
    rc = hypercall_memory_op(XENMEM_get_cpu_topology, &cpu_topology);
    if ( rc < 0 )
        printf("Failed to retrieve cpu topology, rc = %d\n", rc);
    topology_id_size = hvm_info->nr_vcpus;
    return rc;
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
