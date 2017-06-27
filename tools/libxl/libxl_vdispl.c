/*
 * Copyright (C) 2016 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_internal.h"

static int libxl__device_from_vdispl(libxl__gc *gc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__device *device)
{
   return 0;
}

static int libxl__from_xenstore_vdispl(libxl__gc *gc, const char *be_path,
                                       uint32_t devid,
                                       libxl_device_vdispl *vdispl)
{
    vdispl->devid = devid;

    return libxl__backendpath_parse_domid(gc, be_path, &vdispl->backend_domid);
}

static void libxl__update_config_vdispl(libxl__gc *gc,
                                        libxl_device_vdispl *dst,
                                        libxl_device_vdispl *src)
{

}

static int libxl_device_vdispl_compare(libxl_device_vdispl *d1,
                                       libxl_device_vdispl *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_vdispl_add(libxl__egc *egc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__ao_device *aodev)
{

}

libxl_device_vdispl *libxl_device_vdispl_list(libxl_ctx *ctx, uint32_t domid,
                                              int *num)
{
    return libxl__device_list(&libxl__vdispl_devtype, ctx, domid, num);
}

void libxl_device_vdispl_list_free(libxl_device_vdispl* list, int num)
{
    libxl__device_list_free(&libxl__vdispl_devtype, list, num);
}

int libxl_device_vdispl_getinfo(libxl_ctx *ctx, uint32_t domid,
                                libxl_device_vdispl *vdispl,
                                libxl_vdisplinfo *info)
{
     return 0;
}

LIBXL_DEFINE_DEVICE_ADD(vdispl)
static LIBXL_DEFINE_DEVICES_ADD(vdispl)
LIBXL_DEFINE_DEVICE_REMOVE(vdispl)

DEFINE_DEVICE_TYPE_STRUCT(vdispl,
    .update_config = (void (*)(libxl__gc *, void *, void *))
                     libxl__update_config_vdispl,
    .from_xenstore = (int (*)(libxl__gc *, const char *, uint32_t, void *))
                     libxl__from_xenstore_vdispl
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
