#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>

int main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);

    int online_cpus = libxl_get_online_cpus(context);
    printf("%d\n", online_cpus);

    libxl_ctx_free(context);

}

