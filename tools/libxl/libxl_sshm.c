#include "libxl_osdeps.h"
#include "libxl_internal.h"
#include <stdio.h>

#define TRY_TRANSACTION_OR_FAIL(aborting)  do {                         \
        if (!xs_transaction_end(CTX->xsh, xt, aborting) && !aborting) { \
            if (EAGAIN == errno) {                                      \
                goto retry_transaction;                                 \
            } else {                                                    \
                rc = ERROR_FAIL;                                        \
            }                                                           \
        }                                                               \
    }while(0);

#define SSHM_ERROR(domid, sshmid, f, ...)                               \
    LOGD(ERROR, domid, "static_shm id = %s:" f, sshmid, ##__VA_ARGS__)


/* The caller have to guarentee that {s,m}begin < {s,m}end */
static int libxl__sshm_do_map(libxl__gc *gc, uint32_t mid, uint32_t sid,
                              libxl_static_shm *sshm,
                              uint64_t mbegin, uint64_t mend)
{
    int rc;
    int i;
    unsigned int num_mpages, num_spages, offset;
    int *errs;
    xen_ulong_t *idxs;
    xen_pfn_t *gpfns;

    num_mpages = (mend - mbegin) >> 12;
    num_spages = (sshm->end - sshm->begin) >> 12;
    offset = sshm->offset >> 12;

    /* Check range. Test offset < mpages first to avoid overflow */
    if ((offset >= num_mpages) || (num_mpages - offset < num_spages)) {
        SSHM_ERROR(sid, sshm->id, "exceeds master's address space.");
        rc = ERROR_INVAL;
        goto out;
    }

    /* fill out the pfn's and do the mapping */
    errs = libxl__calloc(gc, num_spages, sizeof(int));
    idxs = libxl__calloc(gc, num_spages, sizeof(xen_ulong_t));
    gpfns = libxl__calloc(gc, num_spages, sizeof(xen_pfn_t));
    for (i = 0; i < num_spages; i++) {
        idxs[i] = (mbegin >> 12) + offset + i;
        gpfns[i]= (sshm->begin >> 12) + i;
    }
    rc = xc_domain_add_to_physmap_batch(CTX->xch,
                                        sid, mid,
                                        XENMAPSPACE_gmfn_foreign,
                                        num_spages,
                                        idxs, gpfns, errs);

    for (i = 0; i< num_spages; i++) {
        if (errs[i]) {
            SSHM_ERROR(sid, sshm->id,
                       "can't map at address 0x%"PRIx64".",
                       sshm->begin + (offset << 12) );
            rc = ERROR_FAIL;
        }
    }
    if (rc) { goto out; }

    rc = 0;

 out:
    return rc;
}

static int libxl__sshm_add_master(libxl__gc *gc, uint32_t domid,
                                  libxl_static_shm *sshm)
{
    int rc, aborting;
    char *sshm_path, *dom_path, *dom_role_path;
    char *ents[11];
    struct xs_permissions noperm;
    xs_transaction_t xt = XBT_NULL;

    sshm_path = libxl__xs_get_sshmpath(gc, sshm->id);
    dom_path = libxl__xs_get_dompath(gc, domid);
    /* the domain should be in xenstore by now */
    assert(dom_path);
    dom_role_path = GCSPRINTF("%s/static_shm/%s/role", dom_path, sshm->id);


 retry_transaction:
    /* Within the transaction, goto out by default means aborting */
    aborting = 1;
    rc = libxl__xs_transaction_start(gc, &xt);
    if (rc) { goto out; }

    if (NULL == libxl__xs_read(gc, xt, sshm_path)) {
        rc = libxl__xs_write_checked(gc, xt, dom_role_path, "master");
        if (rc) { goto out; };

        ents[0] = "master";
        ents[1] = GCSPRINTF("%"PRIu32, domid);
        ents[2] = "begin";
        ents[3] = GCSPRINTF("0x%"PRIx64, sshm->begin);
        ents[4] = "end";
        ents[5] = GCSPRINTF("0x%"PRIx64, sshm->end);
        ents[6] = "prot";
        ents[7] = libxl__strdup(gc, libxl_sshm_prot_to_string(sshm->prot));
        ents[8] = "cache_policy";
        ents[9] = libxl__strdup(gc,
                      libxl_sshm_cachepolicy_to_string(sshm->cache_policy));
        ents[10] = NULL;

        /* could only be accessed by Dom0 */
        noperm.id = 0;
        noperm.perms = XS_PERM_NONE;
        libxl__xs_mknod(gc, xt, sshm_path, &noperm, 1);
        libxl__xs_writev(gc, xt, sshm_path, ents);
    } else {
        SSHM_ERROR(domid, sshm->id, "can only have one master.");
        rc = ERROR_FAIL;
        goto out;
    }

    aborting = rc = 0;

 out:
    TRY_TRANSACTION_OR_FAIL(aborting);
    return rc;
}

static int libxl__sshm_add_slave(libxl__gc *gc, uint32_t domid,
                                       libxl_static_shm *sshm)
{
    int rc, aborting;
    char *sshm_path, *slave_path, *dom_path, *dom_sshm_path, *dom_role_path;
    char *ents[9];
    const char *xs_value;
    libxl_static_shm master_sshm;
    uint32_t master_domid;
    xs_transaction_t xt = XBT_NULL;

    sshm_path = libxl__xs_get_sshmpath(gc, sshm->id);
    slave_path = GCSPRINTF("%s/slaves/%"PRIu32, sshm_path, domid);
    dom_path = libxl__xs_get_dompath(gc, domid);
    /* the domain should be in xenstore by now */
    assert(dom_path);
    dom_sshm_path = GCSPRINTF("%s/static_shm/%s", dom_path, sshm->id);
    dom_role_path = GCSPRINTF("%s/role", dom_sshm_path);

 retry_transaction:
    /* Within the transaction, goto out by default means aborting */
    aborting = 1;
    rc = libxl__xs_transaction_start(gc, &xt);
    if (rc) { goto out; }

    if (NULL == libxl__xs_read(gc, xt, sshm_path)) {
        SSHM_ERROR(domid, sshm->id, "no master found.");
        rc = ERROR_FAIL;
        goto out;
    } else {
        /* check the master info to see if we could do the mapping */
        if (NULL != libxl__xs_read(gc, xt, dom_sshm_path)) {
                    SSHM_ERROR(domid, sshm->id,
                               "domain tried to share the same region twice.");
                    rc = ERROR_FAIL;
                    goto out;
        }

        rc = libxl__xs_read_checked(gc, xt,
                                    GCSPRINTF("%s/prot", sshm_path),
                                    &xs_value);
        if (rc) { goto out; }
        libxl_sshm_prot_from_string(xs_value, &master_sshm.prot);

        rc = libxl__xs_read_checked(gc, xt,
                                    GCSPRINTF("%s/begin", sshm_path),
                                    &xs_value);
        if (rc) { goto out; }
        master_sshm.begin = strtoull(xs_value, NULL, 16);

        rc = libxl__xs_read_checked(gc, xt,
                                    GCSPRINTF("%s/end", sshm_path),
                                    &xs_value);
        if (rc) { goto out; }
        master_sshm.end = strtoull(xs_value, NULL, 16);

        rc = libxl__xs_read_checked(gc, xt,
                                    GCSPRINTF("%s/master", sshm_path),
                                    &xs_value);
        if (rc) { goto out; }
        master_domid = strtoull(xs_value, NULL, 16);

        /* check if the slave is asking too much permission */
        if (LIBXL_SSHM_PROT_UNKNOWN == sshm->prot) {
            sshm->prot = master_sshm.prot;
        }
        if (master_sshm.prot < sshm->prot) {
            SSHM_ERROR(domid, sshm->id, "slave is asking too much permission.");
            rc = ERROR_INVAL;
            goto out;
        }

        /* all checks passed, do the job */
        rc = libxl__sshm_do_map(gc, master_domid, domid, sshm,
                                master_sshm.begin, master_sshm.end);
        if (rc) {
            rc = ERROR_INVAL;
            goto out;
        }

        rc = libxl__xs_write_checked(gc, xt, dom_role_path, "slave");
        if (rc) { goto out; }

        /* fill in slave info */
        ents[0] = "begin";
        ents[1] = GCSPRINTF("0x%"PRIx64, sshm->begin);
        ents[2] = "end";
        ents[3] = GCSPRINTF("0x%"PRIx64, sshm->end);
        ents[4] = "offset";
        ents[5] = GCSPRINTF("0x%"PRIx64, sshm->offset);
        ents[6] = "prot";
        ents[7] = libxl__strdup(gc, libxl_sshm_prot_to_string(sshm->prot));
        ents[8] = NULL;
        libxl__xs_writev(gc, xt, slave_path, ents);
    }

    aborting = rc = 0;

 out:
    TRY_TRANSACTION_OR_FAIL(aborting);
    return rc;
}

/* Compare function for sorting sshm ranges by sshm->begin */
static int sshm_range_cmp(const void *a, const void *b)
{
    libxl_static_shm *const *sshma = a, *const *sshmb = b;
    return (*sshma)->begin > (*sshmb)->begin ? 1 : -1;
}

/* check if the sshm slave configs in @sshm overlap */
static int libxl__sshm_check_overlap(libxl__gc *gc, uint32_t domid,
                                     libxl_static_shm *sshms, int len)
{

    const libxl_static_shm **slave_sshms = NULL;
    int num_slaves;
    int i;

    slave_sshms = libxl__calloc(gc, len, sizeof(slave_sshms[0]));
    num_slaves = 0;
    for (i = 0; i < len; ++i) {
        if (LIBXL_SSHM_ROLE_SLAVE == sshms[i].role)
            slave_sshms[num_slaves++] = sshms + i;
    }
    qsort(slave_sshms, num_slaves, sizeof(slave_sshms[0]), sshm_range_cmp);

    for (i = 0; i < num_slaves - 1; ++i) {
        if (slave_sshms[i+1]->begin < slave_sshms[i]->end) {
            SSHM_ERROR(domid, slave_sshms[i+1]->id, "slave ranges overlap.");
            return ERROR_INVAL;
        }
    }

    return 0;
}

static int libxl__sshm_del_single(libxl__gc *gc, xs_transaction_t xt,
                                  uint32_t domid, const char *id, bool master)
{
    char *sshm_path, *slaves_path;

    sshm_path = libxl__xs_get_sshmpath(gc, id);
    slaves_path = GCSPRINTF("%s/slaves", sshm_path);

    if (master) {
        /* we know that domid can't be both a master and a slave for one id,
         * so the number of slaves won't change during iteration. Simply check
         * sshm_path/slavea to tell if there are still living slaves. */
        if (NULL != libxl__xs_read(gc, xt, slaves_path)) {
            SSHM_ERROR(domid, id,
                       "can't remove master when there are living slaves.");
            return ERROR_FAIL;
        }
        libxl__xs_path_cleanup(gc, xt, sshm_path);
    } else {
        libxl__xs_path_cleanup(gc, xt,
            GCSPRINTF("%s/%"PRIu32, slaves_path, domid));
    }

    return 0;
}

/* Delete an static_shm entry in the xensotre. Will also return success if
 * the path doesn't exist. */
int libxl__sshm_del(libxl__gc *gc,  uint32_t domid)
{
    int rc, aborting;
    xs_transaction_t xt = XBT_NULL;
    char *dom_path, *dom_sshm_path;
    const char *role;
    char **sshm_ents;
    unsigned int sshm_num;
    int i;

    if (LIBXL_DOMAIN_TYPE_HVM != libxl__domain_type(gc, domid))
        return 0;

    dom_path = libxl__xs_get_dompath(gc, domid);
    dom_sshm_path = GCSPRINTF("%s/static_shm", dom_path);

 retry_transaction:
    /* Within the transaction, goto out by default means aborting */
    aborting = 1;
    rc = libxl__xs_transaction_start(gc, &xt);
    if (rc) { goto out; }

    if (NULL == libxl__xs_read(gc, xt, dom_sshm_path)) {
        /* no sshms, just do nothing */
        rc = aborting = 0;
        goto out;
    }

    sshm_ents = libxl__xs_directory(gc, xt, dom_sshm_path, &sshm_num);

    for (i = 0; i < sshm_num; ++i) {
        rc = libxl__xs_read_checked(gc, xt,
                 GCSPRINTF("%s/%s/role", dom_sshm_path, sshm_ents[i]), &role);
        if (rc) { goto out; }

        rc = libxl__sshm_del_single(gc, xt, domid,
                 sshm_ents[i], role[0] == 'm' ? 1 : 0);
        if (rc) { goto out; }
    }

        libxl__xs_path_cleanup(gc, xt, dom_sshm_path);

    aborting = rc = 0;

 out:
    TRY_TRANSACTION_OR_FAIL(aborting);
    return rc;
}

int libxl__sshm_add(libxl__gc *gc,  uint32_t domid,
                    libxl_static_shm *sshms, int len)
{
    int rc, i;

    if (LIBXL_DOMAIN_TYPE_HVM != libxl__domain_type(gc, domid))
        return 0;
    rc = libxl__sshm_check_overlap(gc, domid, sshms, len);
    if (rc) { return rc; };

    for (i = 0; i < len; ++i) {
        if (LIBXL_SSHM_ROLE_SLAVE == sshms[i].role) {
           rc = libxl__sshm_add_slave(gc, domid, sshms+i);
        } else {
           rc = libxl__sshm_add_master(gc, domid, sshms+i);
        }
        if (rc) { return rc; };
    }

    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
