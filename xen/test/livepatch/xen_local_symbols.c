/*
 * Copyright (c) 2017 Oracle and/or its affiliates. All rights reserved.
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#include <public/sysctl.h>
#include "livepatch_depends.h"

/* Same name as in xen_hello_world */
static const char hello_world_patch_this_fnc[] = "xen_extra_version";
extern const char *xen_hello_world(void);

/*
 * The hooks are static here (LOCAL) and also in xen_hello_world.c
 * and their name is exactly the same.
 */
static void apply_hook(void)
{
    printk(KERN_DEBUG "local_symbols: Hook executing.\n");
}

static void revert_hook(void)
{
    printk(KERN_DEBUG "local_symbols: Hook unloaded.\n");
}

LIVEPATCH_LOAD_HOOK(apply_hook);
LIVEPATCH_UNLOAD_HOOK(revert_hook);

struct livepatch_func __section(".livepatch.funcs") livepatch_xen_local_symbols = {
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .name = hello_world_patch_this_fnc,
    .new_addr = xen_hello_world,
    .old_addr = xen_extra_version,
    .new_size = NEW_CODE_SZ,
    .old_size = OLD_CODE_SZ,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
