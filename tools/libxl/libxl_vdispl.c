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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

static int libxl__device_vdispl_setdefault(libxl__gc *gc, domid_t domid,
                                           libxl_device_vdispl *vdispl)
{
    int rc;

    rc = libxl__resolve_domid(gc, vdispl->backend_domname,
                              &vdispl->backend_domid);

    if (vdispl->devid == -1) {
        vdispl->devid = libxl__device_nextid(gc, domid,
                (char*)libxl__device_kind_to_string(LIBXL__DEVICE_KIND_VDISPL));
    }

    return rc;
}

static int libxl__device_from_vdispl(libxl__gc *gc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__device *device)
{
   device->backend_devid   = vdispl->devid;
   device->backend_domid   = vdispl->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_VDISPL;
   device->devid           = vdispl->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_VDISPL;

   return 0;
}

LIBXL_DEFINE_DEVICE_COMMIT(vdispl)

static void libxl__device_vdispl_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vdispl *vdispl,
                                   libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    flexarray_t *front;
    flexarray_t *back;
    int rc;

    rc = libxl__device_vdispl_setdefault(gc, domid, vdispl);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(back, "handle");
    flexarray_append(back, GCSPRINTF("%d", vdispl->devid));

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vdispl->backend_domid));
    flexarray_append(front, "state");
    flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(front, "handle");
    flexarray_append(front, GCSPRINTF("%d", vdispl->devid));
    flexarray_append(front, "be_alloc");
    flexarray_append(front, GCSPRINTF("%d", vdispl->be_alloc));

out:
    libxl__device_vdispl_commit(egc, domid, vdispl, front, back, aodev, rc);
}

static int libxl__device_vdispl_getinfo(libxl__gc *gc, struct xs_handle *xsh,
                                        const char* libxl_path,
                                        libxl_vdisplinfo *info)
{
    char *val;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/be_alloc", libxl_path));
    info->be_alloc = val ? strtoul(val, NULL, 10) : 0;

    return 0;
}

static void libxl__update_config_vdispl(libxl__gc *gc, void *dst, void *src)
{
    libxl_device_vdispl *d, *s;

    d = (libxl_device_vdispl*)dst;
    s = (libxl_device_vdispl*)src;

    d->devid = s->devid;
    d->be_alloc = s->be_alloc;
}

static int libxl_device_vdispl_compare(libxl_device_vdispl *d1,
                                       libxl_device_vdispl *d2)
{
    return COMPARE_DEVID(d1, d2);
}

LIBXL_DEFINE_DEVICE_ADD(vdispl)
static LIBXL_DEFINE_DEVICES_ADD(vdispl)
LIBXL_DEFINE_DEVICE_REMOVE(vdispl)

LIBXL_DEFINE_DEVICE_LIST_GET(vdispl)
LIBXL_DEFINE_DEVICE_LIST_FREE(vdispl)

LIBXL_DEFINE_DEVID_TO_DEVICE(vdispl)
LIBXL_DEFINE_DEVICE_GETINFO(vdispl)

DEFINE_DEVICE_TYPE_STRUCT(vdispl,
    .update_config = libxl__update_config_vdispl
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
