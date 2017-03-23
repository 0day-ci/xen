/*
 * Copyright (C) 2017      Aporeto
 * Author Stefano Stabellini <stefano@aporeto.com>
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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

int libxl__device_xen_9pfs_setdefault(libxl__gc *gc, libxl_device_xen_9pfs *xen_9pfs)
{
    int rc;

    rc = libxl__resolve_domid(gc, xen_9pfs->backend_domname, &xen_9pfs->backend_domid);
    return rc;
}

static int libxl__device_from_xen_9pfs(libxl__gc *gc, uint32_t domid,
                                   libxl_device_xen_9pfs *xen_9pfs,
                                   libxl__device *device)
{
   device->backend_devid   = xen_9pfs->devid;
   device->backend_domid   = xen_9pfs->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_9PFS;
   device->devid           = xen_9pfs->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_9PFS;

   return 0;
}


int libxl__device_xen_9pfs_add(libxl__gc *gc, uint32_t domid,
                           libxl_device_xen_9pfs *xen_9pfs)
{
    flexarray_t *front;
    flexarray_t *back;
    libxl__device device;
    int rc;

    rc = libxl__device_xen_9pfs_setdefault(gc, xen_9pfs);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    if (xen_9pfs->devid == -1) {
        if ((xen_9pfs->devid = libxl__device_nextid(gc, domid, "9pfs")) < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = libxl__device_from_xen_9pfs(gc, domid, xen_9pfs, &device);
    if (rc != 0) goto out;

    flexarray_append_pair(back, "frontend-id", libxl__sprintf(gc, "%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(front, "backend-id",
                          libxl__sprintf(gc, "%d", xen_9pfs->backend_domid));
    flexarray_append_pair(front, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(front, "tag", xen_9pfs->tag);
    flexarray_append_pair(back, "path", xen_9pfs->path);
    flexarray_append_pair(back, "security_model", xen_9pfs->security_model);

    libxl__device_generic_add(gc, XBT_NULL, &device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              NULL);
    rc = 0;
out:
    return rc;
}

LIBXL_DEFINE_DEVICE_REMOVE(xen_9pfs)

