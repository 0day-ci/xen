#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>

int main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);

    int max_cpus = libxl_get_max_cpus(context);
    printf("%d\n", max_cpus);

    libxl_ctx_free(context);

}

