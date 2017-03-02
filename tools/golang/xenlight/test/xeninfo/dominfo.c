#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>
#include "print.h"

int main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);
    libxl_dominfo info;
    libxl_dominfo_init(&info);
    int err = libxl_domain_info(context, &info, 0);
    if (err != 0)
        return err;
    
	printf("%d\n%d\n", info.domid, info.ssidref);
	printf("%s\n%s\n%s\n%s\n%s\n%s\n", bool_to_string(info.running), 
			bool_to_string(info.blocked), bool_to_string(info.paused),
			bool_to_string(info.shutdown), bool_to_string(info.dying), 
			bool_to_string(info.never_stop));
	long cpu_time = info.cpu_time / ((long) 1<<35);
	printf("%d\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%d\n%d\n%d\n", info.shutdown_reason, 
			info.outstanding_memkb, info.current_memkb, info.shared_memkb, 
			info.paged_memkb, info.max_memkb, cpu_time, info.vcpu_max_id, 
			info.vcpu_online, info.cpupool);
	printf("%d\n", info.domain_type);

	libxl_dominfo_dispose(&info);
	libxl_ctx_free(context);

}
