/*
 * tools/libxl/libxl_nvdimm.h
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

#ifndef LIBXL_NVDIMM_H
#define LIBXL_NVDIMM_H

#include <stdint.h>
#include "libxl_internal.h"

#if defined(__linux__)

int libxl_nvdimm_add_device(libxl__gc *gc,
                            uint32_t domid, const char *path,
                            uint64_t spa, uint64_t length);

#else

static inline int libxl_nvdimm_add_device(libxl__gc *gc,
                                          uint32_t domid, const char *path,
                                          uint64_t spa, uint64_t length)
{
    return -ENOSYS;
}

#endif /* __linux__ */

#endif /* !LIBXL_NVDIMM_H */
