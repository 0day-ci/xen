#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>
#include "print.h"

int main(){

    libxl_ctx *context;
    libxl_ctx_alloc(&context,LIBXL_VERSION, 0, NULL);

    uint64_t free_memory;
    int err = libxl_get_free_memory(context, &free_memory);
    if (err < 0)
    {
        printf("%d\n", err);
    }
    else
    {
        printf("%lu\n", free_memory);
    }
    libxl_ctx_free(context);

}

