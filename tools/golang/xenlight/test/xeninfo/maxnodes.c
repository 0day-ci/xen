#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>

int main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);

    int max_nodes = libxl_get_max_nodes(context);
    printf("%d\n", max_nodes);

   libxl_ctx_free(context);

}

