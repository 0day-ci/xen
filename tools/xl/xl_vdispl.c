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

#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_vdisplattach(int argc, char **argv)
{
    int opt;
    int rc;
    char *oparg;
    uint32_t domid;
    libxl_device_vdispl vdispl;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vdispl-attach", 1) {
        /* No options */
    }

    libxl_device_vdispl_init(&vdispl);
    domid = find_domain(argv[optind++]);

    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        if (MATCH_OPTION("devId", *argv, oparg)) {
            vdispl.devid = atoi(oparg);
        } else if (MATCH_OPTION("backend", *argv, oparg)) {
            vdispl.backend_domid = find_domain(oparg);
            replace_string(&vdispl.backend_domname, oparg);
        } else if (MATCH_OPTION("beAlloc", *argv, oparg)) {
            vdispl.be_alloc = strtoul(oparg, NULL, 0);
        } else {
            fprintf(stderr, "unrecognized argument `%s'\n", *argv);
            rc = 1;
            goto out;
        }
    }

    if (dryrun_only) {
        char *json = libxl_device_vdispl_to_json(ctx, &vdispl);
        printf("vdispl: %s\n", json);
        free(json);
        goto out;
    }

    if (libxl_device_vdispl_add(ctx, domid, &vdispl, 0)) {
        fprintf(stderr, "libxl_device_vdispl_add failed.\n");
        rc = ERROR_FAIL;
    }

    rc = 0;

out:
    libxl_device_vdispl_dispose(&vdispl);
    return rc;
}

int main_vdispllist(int argc, char **argv)
{
   int opt;
   int i, n;
   libxl_device_vdispl *vdispls;
   libxl_vdisplinfo vdisplinfo;

   SWITCH_FOREACH_OPT(opt, "", NULL, "vdispl-list", 1) {
       /* No options */
   }

   /* vdisplinfo.uuid should be outputted too */
   printf("%-5s %-3s %-6s %-5s %-8s %-40s %-40s\n",
           "Vdev", "BE", "handle", "state", "be-alloc", "BE-path", "FE-path");
   for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
       uint32_t domid;

       if (libxl_domain_qualifier_to_domid(ctx, *argv, &domid) < 0) {
           fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
           continue;
       }

       vdispls = libxl_device_vdispl_list(ctx, domid, &n);

       if (!vdispls) {
           continue;
       }

       for (i = 0; i < n; i++) {
           libxl_vdisplinfo_init(&vdisplinfo);
           if (libxl_device_vdispl_getinfo(ctx, domid, &vdispls[i],
                                           &vdisplinfo) == 0) {
               /*      Vdev BE   hdl   st  be-alloc BE-path FE-path*/
               printf("%-5d %-3d %-6d %-5d %-8d %-40s %-40s\n",
                       vdisplinfo.devid, vdisplinfo.backend_id,
                       vdisplinfo.frontend_id,
                       vdisplinfo.state, vdisplinfo.be_alloc,
                       vdisplinfo.backend, vdisplinfo.frontend);
           }
           libxl_vdisplinfo_dispose(&vdisplinfo);
       }

       libxl_device_vdispl_list_free(vdispls, n);
   }
   return 0;
}

int main_vdispldetach(int argc, char **argv)
{
    uint32_t domid, devid;
    int opt, rc;
    libxl_device_vdispl vdispl;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vdispl-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);
    devid = atoi(argv[optind++]);

    libxl_device_vdispl_init(&vdispl);

    if (libxl_devid_to_device_vdispl(ctx, domid, devid, &vdispl)) {
        fprintf(stderr, "Error: Device %d not connected.\n", devid);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl_device_vdispl_remove(ctx, domid, &vdispl, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_vdispl_remove failed.\n");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    libxl_device_vdispl_dispose(&vdispl);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
