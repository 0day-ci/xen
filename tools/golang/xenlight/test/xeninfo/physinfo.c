#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>
#include "print.h"

int main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);
    libxl_physinfo info;
    libxl_physinfo_init(&info);
    int err= libxl_get_physinfo(context,&info);
    if(err != 0){
        return err;
    }

    printf("%d\n%d\n%d\n%d\n%d\n", info.threads_per_core, info.cores_per_socket, info.max_cpu_id, info.nr_cpus, info.cpu_khz);
    printf("%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n", info.total_pages, info.free_pages, info.scrub_pages, info.outstanding_pages, info.sharing_freed_pages, info.sharing_used_frames);
    printf("%u\n",info.nr_nodes);
    printf("%s\n%s\n", bool_to_string(info.cap_hvm), bool_to_string(info.cap_hvm_directio));

    int i;
    for(i = 0; i < 8; i++){
        printf("%u\n", info.hw_cap[i]);
    }

    libxl_physinfo_init(&info);
    libxl_ctx_free(context);

}

