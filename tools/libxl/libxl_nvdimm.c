/*
 * tools/libxl/libxl_nvdimm.c
 *
 * Copyright (C) 2017,  Intel Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libxl_internal.h"
#include "libxl_arch.h"
#include "libxl_nvdimm.h"

#include <xenctrl.h>

#define BLK_DEVICE_ROOT "/sys/dev/block"

static int nvdimm_sysfs_read(libxl__gc *gc,
                             unsigned int major, unsigned int minor,
                             const char *name, void **data_r)
{
    char *path = libxl__sprintf(gc, BLK_DEVICE_ROOT"/%u:%u/device/%s",
                                major, minor, name);
    return libxl__read_sysfs_file_contents(gc, path, data_r, NULL);
}

static int nvdimm_get_spa(libxl__gc *gc, unsigned int major, unsigned int minor,
                          uint64_t *spa_r)
{
    void *data;
    int ret = nvdimm_sysfs_read(gc, major, minor, "resource", &data);

    if ( ret )
        return ret;

    *spa_r = strtoll(data, NULL, 0);
    return 0;
}

static int nvdimm_get_size(libxl__gc *gc, unsigned int major, unsigned int minor,
                           uint64_t *size_r)
{
    void *data;
    int ret = nvdimm_sysfs_read(gc, major, minor, "size", &data);

    if ( ret )
        return ret;

    *size_r = strtoll(data, NULL, 0);

    return 0;
}

static int add_pages(libxl__gc *gc, uint32_t domid,
                     xen_pfn_t mfn, xen_pfn_t gpfn, unsigned long nr_mfns)
{
    unsigned int nr;
    int ret = 0;

    while ( nr_mfns )
    {
        nr = min(nr_mfns, (unsigned long) UINT_MAX);

        ret = xc_domain_populate_pmemmap(CTX->xch, domid, mfn, gpfn, nr);
        if ( ret )
        {
            LOG(ERROR, "failed to map pmem pages, "
                "mfn 0x%" PRIx64", gpfn 0x%" PRIx64 ", nr_mfns %u, err %d",
                mfn, gpfn, nr, ret);
            break;
        }

        nr_mfns -= nr;
        mfn += nr;
        gpfn += nr;
    }

    return ret;
}

int libxl_nvdimm_add_device(libxl__gc *gc,
                            uint32_t domid, const char *path,
                            uint64_t guest_spa, uint64_t guest_size)
{
    int fd;
    struct stat st;
    unsigned int major, minor;
    uint64_t host_spa, host_size;
    xen_pfn_t mfn, gpfn;
    unsigned long nr_gpfns;
    int ret;

    if ( (guest_spa & ~XC_PAGE_MASK) || (guest_size & ~XC_PAGE_MASK) )
        return -EINVAL;

    fd = open(path, O_RDONLY);
    if ( fd < 0 )
    {
        LOG(ERROR, "failed to open file %s (err: %d)", path, errno);
        return -EIO;
    }

    ret = fstat(fd, &st);
    if ( ret )
    {
        LOG(ERROR, "failed to get status of file %s (err: %d)",
            path, errno);
        goto out;
    }

    switch ( st.st_mode & S_IFMT )
    {
    case S_IFBLK:
        major = major(st.st_rdev);
        minor = minor(st.st_rdev);
        break;

    default:
        LOG(ERROR, "only support block device now");
        ret = -EINVAL;
        goto out;
    }

    ret = nvdimm_get_spa(gc, major, minor, &host_spa);
    if ( ret )
    {
        LOG(ERROR, "failed to get SPA of device %u:%u", major, minor);
        goto out;
    }
    else if ( host_spa & ~XC_PAGE_MASK )
    {
        ret = -EINVAL;
        goto out;
    }

    ret = nvdimm_get_size(gc, major, minor, &host_size);
    if ( ret )
    {
        LOG(ERROR, "failed to get size of device %u:%u", major, minor);
        goto out;
    }
    else if ( guest_size > host_size )
    {
        LOG(ERROR, "vNVDIMM size %" PRIu64 " expires NVDIMM size %" PRIu64,
            guest_size, host_size);
        ret = -EINVAL;
        goto out;
    }

    mfn = host_spa >> XC_PAGE_SHIFT;
    gpfn = guest_spa >> XC_PAGE_SHIFT;
    nr_gpfns = guest_size >> XC_PAGE_SHIFT;
    ret = add_pages(gc, domid, mfn, gpfn, nr_gpfns);

 out:
    close(fd);
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
