/*
 * psr.c: Platform Shared Resource related service for guest.
 *
 * Copyright (c) 2014, Intel Corporation
 * Author: Dongxiao Xu <dongxiao.xu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#include <xen/cpu.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <asm/psr.h>

/*
 * Terminology:
 * - CAT         Cache Allocation Technology
 * - CBM         Capacity BitMasks
 * - CDP         Code and Data Prioritization
 * - COS/CLOS    Class of Service. Also mean COS registers.
 * - COS_MAX     Max number of COS for the feature (minus 1)
 * - MSRs        Machine Specific Registers
 * - PSR         Intel Platform Shared Resource
 */

#define PSR_CMT        (1<<0)
#define PSR_CAT        (1<<1)
#define PSR_CDP        (1<<2)

#define CAT_CBM_LEN_MASK 0x1f
#define CAT_COS_MAX_MASK 0xffff

/*
 * Per SDM chapter 'Cache Allocation Technology: Cache Mask Configuration',
 * the MSRs ranging from 0C90H through 0D0FH (inclusive), enables support for
 * up to 128 L3 CAT Classes of Service. The COS_ID=[0,127].
 *
 * The MSRs ranging from 0D10H through 0D4FH (inclusive), enables support for
 * up to 64 L2 CAT COS. The COS_ID=[0,63].
 *
 * So, the maximum COS register count of one feature is 128.
 */
#define MAX_COS_REG_CNT  128

#define PSR_ASSOC_REG_SHIFT 32

enum psr_feat_type {
    PSR_SOCKET_L3_CAT,
    PSR_SOCKET_L3_CDP,
    PSR_SOCKET_L2_CAT,
    PSR_SOCKET_MAX_FEAT,
};

/*
 * This structure represents one feature.
 * feat_props  - Feature properties, including operation callback functions
                 and feature common values.
 * cos_reg_val - Array to store the values of COS registers. One entry stores
 *               the value of one COS register.
 *               For L3 CAT and L2 CAT, one entry corresponds to one COS_ID.
 *               For CDP, two entries correspond to one COS_ID. E.g.
 *               COS_ID=0 corresponds to cos_reg_val[0] (Data) and
 *               cos_reg_val[1] (Code).
 */
struct feat_node {
    /*
     * This structure defines feature operation callback functions. Every
     * feature enabled MUST implement such callback functions and register
     * them to props.
     *
     * Feature specific behaviors will be encapsulated into these callback
     * functions. Then, the main flows will not be changed when introducing
     * a new feature.
     *
     * Feature independent HW info and common values are also defined in it.
     */
    struct feat_props {
        /*
         * cos_num, cos_max and cbm_len are common values for all features
         * so far.
         * cos_num - COS registers number that feature uses for one COS ID.
         *           It is defined in SDM.
         * cos_max - The max COS registers number got through CPUID.
         * cbm_len - The length of CBM got through CPUID.
         */
        unsigned int cos_num;
        unsigned int cos_max;
        unsigned int cbm_len;

        /* get_feat_info is used to get feature HW info. */
        bool (*get_feat_info)(const struct feat_node *feat,
                              uint32_t data[], unsigned int array_len);

        /* get_val is used to get feature COS register value. */
        void (*get_val)(const struct feat_node *feat, unsigned int cos,
                        uint32_t *val);
    } *props;

    uint32_t cos_reg_val[MAX_COS_REG_CNT];
};

/*
 * PSR features are managed per socket. Below structure defines the members
 * used to manage these features.
 * features  - A feature node array used to manage all features enabled.
 * ref_lock  - A lock to protect cos_ref.
 * cos_ref   - A reference count array to record how many domains are using the
 *             COS ID. Every entry of cos_ref corresponds to one COS ID.
 */
struct psr_socket_info {
    struct feat_node *features[PSR_SOCKET_MAX_FEAT];
    spinlock_t ref_lock;
    unsigned int cos_ref[MAX_COS_REG_CNT];
};

struct psr_assoc {
    uint64_t val;
    uint64_t cos_mask;
};

struct psr_cmt *__read_mostly psr_cmt;

static struct psr_socket_info *__read_mostly socket_info;

static unsigned int opt_psr;
static unsigned int __initdata opt_rmid_max = 255;
static unsigned int __read_mostly opt_cos_max = MAX_COS_REG_CNT;
static uint64_t rmid_mask;
static DEFINE_PER_CPU(struct psr_assoc, psr_assoc);

/*
 * Declare global feature node for every feature to facilitate the feature
 * array creation. It is used to transiently store a spare node.
 */
static struct feat_node *feat_l3_cat;

/* Common functions */
#define cat_default_val(len) (0xffffffff >> (32 - (len)))

/*
 * Use this function to check if any allocation feature has been enabled
 * in cmdline.
 */
static bool psr_alloc_feat_enabled(void)
{
    return !!socket_info;
}

static void free_socket_resources(unsigned int socket)
{
    unsigned int i;
    struct psr_socket_info *info = socket_info + socket;

    if ( !info )
        return;

    /*
     * Free resources of features. The global feature object, e.g. feat_l3_cat,
     * may not be freed here if it is not added into array. It is simply being
     * kept until the next CPU online attempt.
     */
    for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
    {
        if ( !info->features[i] )
            continue;

        xfree(info->features[i]);
        info->features[i] = NULL;
    }
}

static bool feat_init_done(const struct psr_socket_info *info)
{
    unsigned int i;

    for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
    {
        if ( !info->features[i] )
            continue;

        return true;
    }

    return false;
}

static enum psr_feat_type psr_cbm_type_to_feat_type(enum cbm_type type)
{
    enum psr_feat_type feat_type;

    switch ( type )
    {
    case PSR_CBM_TYPE_L3:
        feat_type = PSR_SOCKET_L3_CAT;
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return feat_type;
}

/* CAT common functions implementation. */
static void cat_init_feature(const struct cpuid_leaf *regs,
                             struct feat_node *feat,
                             struct psr_socket_info *info,
                             enum psr_feat_type type)
{
    unsigned int socket, i;

    /* No valid value so do not enable feature. */
    if ( !regs->a || !regs->d )
        return;

    feat->props->cbm_len = (regs->a & CAT_CBM_LEN_MASK) + 1;
    feat->props->cos_max = min(opt_cos_max, regs->d & CAT_COS_MAX_MASK);

    switch ( type )
    {
    case PSR_SOCKET_L3_CAT:
        /* cos=0 is reserved as default cbm(all bits within cbm_len are 1). */
        feat->cos_reg_val[0] = cat_default_val(feat->props->cbm_len);

        /*
         * To handle cpu offline and then online case, we need restore MSRs to
         * default values.
         */
        for ( i = 1; i <= feat->props->cos_max; i++ )
        {
            wrmsrl(MSR_IA32_PSR_L3_MASK(i), feat->cos_reg_val[0]);
            feat->cos_reg_val[i] = feat->cos_reg_val[0];
        }

        break;

    default:
        return;
    }

    /* Add this feature into array. */
    info->features[type] = feat;

    socket = cpu_to_socket(smp_processor_id());
    if ( !opt_cpu_info )
        return;

    printk(XENLOG_INFO "%s CAT: enabled on socket %u, cos_max:%u, cbm_len:%u\n",
           ((type == PSR_SOCKET_L3_CAT) ? "L3" : "L2"),
           socket, feat->props->cos_max, feat->props->cbm_len);
}

static bool cat_get_feat_info(const struct feat_node *feat,
                              uint32_t data[], unsigned int array_len)
{
    if ( array_len != PSR_INFO_ARRAY_SIZE )
        return false;

    data[PSR_INFO_IDX_COS_MAX] = feat->props->cos_max;
    data[PSR_INFO_IDX_CAT_CBM_LEN] = feat->props->cbm_len;
    data[PSR_INFO_IDX_CAT_FLAG] = 0;

    return true;
}

static void cat_get_val(const struct feat_node *feat, unsigned int cos,
                        uint32_t *val)
{
    *val = feat->cos_reg_val[cos];
}

/* L3 CAT ops */
static struct feat_props l3_cat_props = {
    .cos_num = 1,
    .get_feat_info = cat_get_feat_info,
    .get_val = cat_get_val,
};

static void __init parse_psr_bool(char *s, char *value, char *feature,
                                  unsigned int mask)
{
    if ( !strcmp(s, feature) )
    {
        if ( !value )
            opt_psr |= mask;
        else
        {
            int val_int = parse_bool(value);

            if ( val_int == 0 )
                opt_psr &= ~mask;
            else if ( val_int == 1 )
                opt_psr |= mask;
        }
    }
}

static void __init parse_psr_param(char *s)
{
    char *ss, *val_str;

    do {
        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        val_str = strchr(s, ':');
        if ( val_str )
            *val_str++ = '\0';

        parse_psr_bool(s, val_str, "cmt", PSR_CMT);
        parse_psr_bool(s, val_str, "cat", PSR_CAT);
        parse_psr_bool(s, val_str, "cdp", PSR_CDP);

        if ( val_str && !strcmp(s, "rmid_max") )
            opt_rmid_max = simple_strtoul(val_str, NULL, 0);

        if ( val_str && !strcmp(s, "cos_max") )
            opt_cos_max = simple_strtoul(val_str, NULL, 0);

        s = ss + 1;
    } while ( ss );
}
custom_param("psr", parse_psr_param);

static void __init init_psr_cmt(unsigned int rmid_max)
{
    unsigned int eax, ebx, ecx, edx;
    unsigned int rmid;

    if ( !boot_cpu_has(X86_FEATURE_PQM) )
        return;

    cpuid_count(0xf, 0, &eax, &ebx, &ecx, &edx);
    if ( !edx )
        return;

    psr_cmt = xzalloc(struct psr_cmt);
    if ( !psr_cmt )
        return;

    psr_cmt->features = edx;
    psr_cmt->rmid_max = min(rmid_max, ebx);
    rmid_mask = ~(~0ull << get_count_order(ebx));

    if ( psr_cmt->features & PSR_RESOURCE_TYPE_L3 )
    {
        cpuid_count(0xf, 1, &eax, &ebx, &ecx, &edx);
        psr_cmt->l3.upscaling_factor = ebx;
        psr_cmt->l3.rmid_max = ecx;
        psr_cmt->l3.features = edx;
    }

    psr_cmt->rmid_max = min(psr_cmt->rmid_max, psr_cmt->l3.rmid_max);
    psr_cmt->rmid_to_dom = xmalloc_array(domid_t, psr_cmt->rmid_max + 1UL);
    if ( !psr_cmt->rmid_to_dom )
    {
        xfree(psr_cmt);
        psr_cmt = NULL;
        return;
    }

    /*
     * Once CMT is enabled each CPU will always require a RMID to associate
     * with it. To reduce the waste of RMID, reserve RMID 0 for all CPUs that
     * have no domain being monitored.
     */
    psr_cmt->rmid_to_dom[0] = DOMID_XEN;
    for ( rmid = 1; rmid <= psr_cmt->rmid_max; rmid++ )
        psr_cmt->rmid_to_dom[rmid] = DOMID_INVALID;

    printk(XENLOG_INFO "Cache Monitoring Technology enabled\n");
}

/* Called with domain lock held, no psr specific lock needed */
int psr_alloc_rmid(struct domain *d)
{
    unsigned int rmid;

    ASSERT(psr_cmt_enabled());

    if ( d->arch.psr_rmid > 0 )
        return -EEXIST;

    for ( rmid = 1; rmid <= psr_cmt->rmid_max; rmid++ )
    {
        if ( psr_cmt->rmid_to_dom[rmid] != DOMID_INVALID )
            continue;

        psr_cmt->rmid_to_dom[rmid] = d->domain_id;
        break;
    }

    /* No RMID available, assign RMID=0 by default. */
    if ( rmid > psr_cmt->rmid_max )
    {
        d->arch.psr_rmid = 0;
        return -EOVERFLOW;
    }

    d->arch.psr_rmid = rmid;

    return 0;
}

/* Called with domain lock held, no psr specific lock needed */
void psr_free_rmid(struct domain *d)
{
    unsigned int rmid;

    rmid = d->arch.psr_rmid;
    /* We do not free system reserved "RMID=0". */
    if ( rmid == 0 )
        return;

    psr_cmt->rmid_to_dom[rmid] = DOMID_INVALID;
    d->arch.psr_rmid = 0;
}

static unsigned int get_max_cos_max(const struct psr_socket_info *info)
{
    const struct feat_node *feat;
    unsigned int cos_max = 0, i;

    for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
    {
        feat = info->features[i];
        if ( !feat )
            continue;

        cos_max = max(feat->props->cos_max, cos_max);
    }

    return cos_max;
}

static void psr_assoc_init(void)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);

    if ( psr_alloc_feat_enabled() )
    {
        unsigned int socket = cpu_to_socket(smp_processor_id());
        const struct psr_socket_info *info = socket_info + socket;
        unsigned int cos_max = get_max_cos_max(info);

        if ( feat_init_done(info) )
            psra->cos_mask = ((1ull << get_count_order(cos_max)) - 1) <<
                             PSR_ASSOC_REG_SHIFT;
    }

    if ( psr_cmt_enabled() || psra->cos_mask )
        rdmsrl(MSR_IA32_PSR_ASSOC, psra->val);
}

static inline void psr_assoc_rmid(uint64_t *reg, unsigned int rmid)
{
    *reg = (*reg & ~rmid_mask) | (rmid & rmid_mask);
}

static void psr_assoc_cos(uint64_t *reg, unsigned int cos,
                          uint64_t cos_mask)
{
    *reg = (*reg & ~cos_mask) |
            (((uint64_t)cos << PSR_ASSOC_REG_SHIFT) & cos_mask);
}

void psr_ctxt_switch_to(struct domain *d)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);
    uint64_t reg = psra->val;

    if ( psr_cmt_enabled() )
        psr_assoc_rmid(&reg, d->arch.psr_rmid);

    if ( psra->cos_mask )
        psr_assoc_cos(&reg, d->arch.psr_cos_ids ?
                      d->arch.psr_cos_ids[cpu_to_socket(smp_processor_id())] :
                      0, psra->cos_mask);

    if ( reg != psra->val )
    {
        wrmsrl(MSR_IA32_PSR_ASSOC, reg);
        psra->val = reg;
    }
}

static struct psr_socket_info *get_socket_info(unsigned int socket)
{
    if ( !socket_info )
        return ERR_PTR(-ENODEV);

    if ( socket >= nr_sockets )
        return ERR_PTR(-ERANGE);

    if ( !feat_init_done(socket_info + socket) )
        return ERR_PTR(-ENOENT);

    return socket_info + socket;
}

static struct feat_node * psr_get_feat(unsigned int socket,
                                       enum cbm_type type)
{
    const struct psr_socket_info *info = get_socket_info(socket);
    enum psr_feat_type feat_type;

    if ( IS_ERR(info) )
        return ERR_PTR(PTR_ERR(info));

    feat_type = psr_cbm_type_to_feat_type(type);
    if ( feat_type > ARRAY_SIZE(info->features) )
        return NULL;

    return info->features[feat_type];
}

int psr_get_info(unsigned int socket, enum cbm_type type,
                 uint32_t data[], unsigned int array_len)
{
    const struct feat_node *feat;

    if ( !data )
        return -EINVAL;

    feat = psr_get_feat(socket, type);
    if ( IS_ERR(feat) )
        return PTR_ERR(feat);

    if ( !feat )
        return -ENOENT;

    if ( feat->props->get_feat_info(feat, data, array_len) )
        return 0;

    return -EINVAL;
}

int psr_get_val(struct domain *d, unsigned int socket,
                uint32_t *val, enum cbm_type type)
{
    const struct feat_node *feat;
    unsigned int cos;

    ASSERT(d && val);

    feat = psr_get_feat(socket, type);
    if ( IS_ERR(feat) )
        return PTR_ERR(feat);

    if ( !feat )
        return -ENOENT;

    cos = d->arch.psr_cos_ids[socket];
    /*
     * If input cos exceeds current feature's cos_max, we should return its
     * default value which is stored in cos 0. This case only happens
     * when more than two features enabled concurrently and at least one
     * features's cos_max is bigger than others. When a domain's working cos
     * id is bigger than some features' cos_max, HW automatically works as
     * default value for those features which cos_max is smaller.
     */
    if ( cos > feat->props->cos_max )
        cos = 0;

    feat->props->get_val(feat, cos, val);

    return 0;
}

int psr_set_l3_cbm(struct domain *d, unsigned int socket,
                   uint64_t cbm, enum cbm_type type)
{
    return 0;
}

/* Called with domain lock held, no extra lock needed for 'psr_cos_ids' */
static void psr_free_cos(struct domain *d)
{
    xfree(d->arch.psr_cos_ids);
    d->arch.psr_cos_ids = NULL;
}

static int psr_alloc_cos(struct domain *d)
{
    d->arch.psr_cos_ids = xzalloc_array(unsigned int, nr_sockets);
    if ( !d->arch.psr_cos_ids )
        return -ENOMEM;

    return 0;
}

int psr_domain_init(struct domain *d)
{
    /* Init to success value */
    int ret = 0;

    if ( psr_alloc_feat_enabled() )
        ret = psr_alloc_cos(d);

    return ret;
}

void psr_domain_free(struct domain *d)
{
    psr_free_rmid(d);
    psr_free_cos(d);
}

static void __init init_psr(void)
{
    if ( opt_cos_max < 1 )
    {
        printk(XENLOG_INFO "CAT: disabled, cos_max is too small\n");
        return;
    }

    socket_info = xzalloc_array(struct psr_socket_info, nr_sockets);

    if ( !socket_info )
    {
        printk(XENLOG_INFO "Failed to alloc socket_info!\n");
        return;
    }
}

static void __init psr_free(void)
{
    xfree(socket_info);
    socket_info = NULL;
}

static int psr_cpu_prepare(void)
{
    if ( !psr_alloc_feat_enabled() )
        return 0;

    /* Malloc memory for the global feature node here. */
    if ( feat_l3_cat == NULL &&
         (feat_l3_cat = xzalloc(struct feat_node)) == NULL )
        return -ENOMEM;

    return 0;
}

static void psr_cpu_init(void)
{
    struct psr_socket_info *info;
    unsigned int socket;
    unsigned int cpu = smp_processor_id();
    struct feat_node *feat;
    struct cpuid_leaf regs;

    if ( !psr_alloc_feat_enabled() || !boot_cpu_has(X86_FEATURE_PQE) )
        goto assoc_init;

    if ( boot_cpu_data.cpuid_level < PSR_CPUID_LEVEL_CAT )
    {
        setup_clear_cpu_cap(X86_FEATURE_PQE);
        goto assoc_init;
    }

    socket = cpu_to_socket(cpu);
    info = socket_info + socket;
    if ( feat_init_done(info) )
        goto assoc_init;

    spin_lock_init(&info->ref_lock);

    cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 0, &regs);
    if ( regs.b & PSR_RESOURCE_TYPE_L3 )
    {
        cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 1, &regs);

        feat = feat_l3_cat;
        feat_l3_cat = NULL;
        feat->props = &l3_cat_props;

        cat_init_feature(&regs, feat, info, PSR_SOCKET_L3_CAT);
    }

 assoc_init:
    psr_assoc_init();
}

static void psr_cpu_fini(unsigned int cpu)
{
    unsigned int socket = cpu_to_socket(cpu);

    if ( !psr_alloc_feat_enabled() )
        return;

    /*
     * We only free when we are the last CPU in the socket. The socket_cpumask
     * is cleared prior to this notification code by remove_siblinginfo().
     */
    if ( socket_cpumask[socket] && cpumask_empty(socket_cpumask[socket]) )
        free_socket_resources(socket);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    int rc = 0;
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = psr_cpu_prepare();
        break;
    case CPU_STARTING:
        psr_cpu_init();
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        psr_cpu_fini(cpu);
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
    /*
     * Ensure socket_cpumask is still valid in CPU_DEAD notification
     * (E.g. our CPU_DEAD notification should be called ahead of
     * cpu_smpboot_free).
     */
    .priority = -1
};

static int __init psr_presmp_init(void)
{
    if ( (opt_psr & PSR_CMT) && opt_rmid_max )
        init_psr_cmt(opt_rmid_max);

    if ( opt_psr & PSR_CAT )
        init_psr();

    if ( psr_cpu_prepare() )
        psr_free();

    psr_cpu_init();
    if ( psr_cmt_enabled() || psr_alloc_feat_enabled() )
        register_cpu_notifier(&cpu_nfb);

    return 0;
}
presmp_initcall(psr_presmp_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
