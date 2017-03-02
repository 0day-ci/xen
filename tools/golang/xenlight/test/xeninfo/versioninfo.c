#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>

main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);
    libxl_version_info *info = libxl_get_version_info(context);

    printf("%d\n%d\n", info->xen_version_major, info->xen_version_minor);
    printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n", info->xen_version_extra, info->compiler, 
		    info->compile_by, info->compile_domain, info->compile_date, 
		    info->capabilities, info->changeset);
    printf("%lu\n%d\n", info->virt_start, info->pagesize);
    printf("%s\n%s\n", info->commandline, info->build_id);

    libxl_ctx_free(context);

}
