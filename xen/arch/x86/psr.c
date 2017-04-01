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

        /* write_msr is used to write out feature MSR register. */
        void (*write_msr)(unsigned int cos, uint32_t val,
                          struct feat_node *feat);
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
static struct feat_node *feat_l3_cdp;

/* Common functions */
#define cat_default_val(len) (0xffffffff >> (32 - (len)))

/*
 * get_cdp_data - get DATA COS register value from input COS ID.
 * @feat:        the feature node.
 * @cos:         the COS ID.
 */
#define get_cdp_data(feat, cos)              \
            ( (feat)->cos_reg_val[(cos) * 2] )

/*
 * get_cdp_code - get CODE COS register value from input COS ID.
 * @feat:        the feature node.
 * @cos:         the COS ID.
 */
#define get_cdp_code(feat, cos)              \
            ( (feat)->cos_reg_val[(cos) * 2 + 1] )

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
    struct domain *d;

    if ( !info )
        return;

    /* Restore domain cos id to 0 when socket is offline. */
    for_each_domain ( d )
    {
        unsigned int cos = d->arch.psr_cos_ids[socket];
        if ( cos == 0 )
            continue;

        spin_lock(&info->ref_lock);
        ASSERT(!cos || info->cos_ref[cos]);
        info->cos_ref[cos]--;
        spin_unlock(&info->ref_lock);

        d->arch.psr_cos_ids[socket] = 0;
    }

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
    case PSR_CBM_TYPE_L3_DATA:
    case PSR_CBM_TYPE_L3_CODE:
        feat_type = PSR_SOCKET_L3_CDP;
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return feat_type;
}

/* CAT common functions implementation. */
static bool psr_check_cbm(unsigned int cbm_len, unsigned long cbm)
{
    unsigned int first_bit, zero_bit;

    /* Set bits should only in the range of [0, cbm_len]. */
    if ( cbm & (~0ul << cbm_len) )
        return false;

    /* At least one bit need to be set. */
    if ( cbm == 0 )
        return false;

    first_bit = find_first_bit(&cbm, cbm_len);
    zero_bit = find_next_zero_bit(&cbm, cbm_len, first_bit);

    /* Set bits should be contiguous. */
    if ( zero_bit < cbm_len &&
         find_next_bit(&cbm, cbm_len, zero_bit) < cbm_len )
        return false;

    return true;
}

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

    case PSR_SOCKET_L3_CDP:
    {
        unsigned long val;

        /* Cut half of cos_max when CDP is enabled. */
        feat->props->cos_max >>= 1;

        /* We only write mask1 since mask0 is always all ones by default. */
        wrmsrl(MSR_IA32_PSR_L3_MASK(1), cat_default_val(feat->props->cbm_len));
        rdmsrl(MSR_IA32_PSR_L3_QOS_CFG, val);
        wrmsrl(MSR_IA32_PSR_L3_QOS_CFG, val | (1 << PSR_L3_QOS_CDP_ENABLE_BIT));

        /* cos=0 is reserved as default cbm(all bits within cbm_len are 1). */
        get_cdp_code(feat, 0) = cat_default_val(feat->props->cbm_len);
        get_cdp_data(feat, 0) = cat_default_val(feat->props->cbm_len);

        /*
         * To handle cpu offline and then online case, we need restore MSRs to
         * default values.
         */
        for ( i = 1; i <= feat->props->cos_max; i++ )
        {
            wrmsrl(MSR_IA32_PSR_L3_MASK_DATA(i), get_cdp_data(feat, 0));
            wrmsrl(MSR_IA32_PSR_L3_MASK_CODE(i), get_cdp_code(feat, 0));
            get_cdp_code(feat, i) = get_cdp_code(feat, 0);
            get_cdp_data(feat, i) = get_cdp_data(feat, 0);
        }

        break;
    }

    default:
        return;
    }

    /* Add this feature into array. */
    info->features[type] = feat;

    socket = cpu_to_socket(smp_processor_id());
    if ( !opt_cpu_info )
        return;

    printk(XENLOG_INFO "%s: enabled on socket %u, cos_max:%u, cbm_len:%u\n",
           ((type == PSR_SOCKET_L3_CDP) ? "CDP" :
            ((type == PSR_SOCKET_L3_CAT) ? "L3 CAT": "L2 CAT")),
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
static void l3_cat_write_msr(unsigned int cos, uint32_t val,
                             struct feat_node *feat)
{
    if ( feat->cos_reg_val[cos] != val )
    {
        feat->cos_reg_val[cos] = val;
        wrmsrl(MSR_IA32_PSR_L3_MASK(cos), val);
    }
}

static struct feat_props l3_cat_props = {
    .cos_num = 1,
    .get_feat_info = cat_get_feat_info,
    .get_val = cat_get_val,
    .write_msr = l3_cat_write_msr,
};

/* L3 CDP ops */
static bool l3_cdp_get_feat_info(const struct feat_node *feat,
                                 uint32_t data[], uint32_t array_len)
{
    if ( !cat_get_feat_info(feat, data, array_len) )
        return false;

    data[PSR_INFO_IDX_CAT_FLAG] |= XEN_SYSCTL_PSR_CAT_L3_CDP;

    return true;
}

static struct feat_props l3_cdp_props = {
    .cos_num = 2,
    .get_feat_info = l3_cdp_get_feat_info,
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

    /* If type is L3 CAT but we cannot find it in feature array, try CDP. */
    if ( !feat && type == PSR_CBM_TYPE_L3 )
    {
        feat = psr_get_feat(socket, PSR_CBM_TYPE_L3_CODE);
        if ( IS_ERR(feat) )
            return PTR_ERR(feat);
    }

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

/* Set value functions */
static unsigned int get_cos_num(const struct psr_socket_info *info)
{
    unsigned int num = 0, i;

    /* Get all features total amount. */
    for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
    {
        const struct feat_node *feat = info->features[i];
        if ( !feat )
            continue;

        feat = info->features[i];

        num += feat->props->cos_num;
    }

    return num;
}

static int gather_val_array(uint32_t val[],
                            unsigned int array_len,
                            const struct psr_socket_info *info,
                            unsigned int old_cos)
{
    unsigned int i;

    if ( !val )
        return -EINVAL;

    /* Get all features current values according to old_cos. */
    for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
    {
        unsigned int cos = old_cos;
        const struct feat_node *feat = info->features[i];
        if ( !feat )
            continue;

        if ( array_len < feat->props->cos_num )
            return -ENOSPC;

        /*
         * If old_cos exceeds current feature's cos_max, we should get
         * default value. So assign cos to 0 which stores default value.
         */
        if ( cos > feat->props->cos_max )
            cos = 0;

        /* Value getting order is same as feature array. */
        feat->props->get_val(feat, cos, &val[0]);

        array_len -= feat->props->cos_num;

        val += feat->props->cos_num;
    }

    return 0;
}

static int insert_val_to_array(uint32_t val[],
                               unsigned int array_len,
                               const struct psr_socket_info *info,
                               enum psr_feat_type feat_type,
                               enum cbm_type type,
                               uint32_t new_val)
{
    const struct feat_node *feat;
    unsigned int i;

    ASSERT(feat_type < PSR_SOCKET_MAX_FEAT);

    /* Insert new value into array according to feature's position in array. */
    for ( i = 0; i < feat_type; i++ )
    {
        feat = info->features[i];
        if ( !feat )
            continue;

        if ( array_len <= feat->props->cos_num )
            return -ENOSPC;

        array_len -= feat->props->cos_num;

        val += feat->props->cos_num;
    }

    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    if ( array_len < feat->props->cos_num )
        return -ENOSPC;

    if ( !psr_check_cbm(feat->props->cbm_len, new_val) )
        return -EINVAL;

    /* Value setting position is same as feature array. */
    val[0] = new_val;

    return 0;
}

static int find_cos(const uint32_t val[], unsigned int array_len,
                    enum psr_feat_type feat_type,
                    const struct psr_socket_info *info,
                    spinlock_t *ref_lock)
{
    unsigned int cos, i;
    const unsigned int *ref = info->cos_ref;
    const struct feat_node *feat;
    unsigned int cos_max;

    ASSERT(spin_is_locked(ref_lock));

    /* cos_max is the one of the feature which is being set. */
    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    cos_max = feat->props->cos_max;

    for ( cos = 0; cos <= cos_max; cos++ )
    {
        const uint32_t *val_ptr = val;
        bool found = false;

        if ( cos && !ref[cos] )
            continue;

        /*
         * If fail to find cos in below loop, need find whole feature array
         * again from beginning.
         */
        for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
        {
            uint32_t default_val = 0;

            feat = info->features[i];
            if ( !feat )
                continue;

            /*
             * COS ID 0 always stores the default value so input 0 to get
             * default value.
             */
            feat->props->get_val(feat, 0, &default_val);

            /*
             * Compare value according to feature array order.
             * We must follow this order because value array is assembled
             * as this order.
             */
            if ( cos > feat->props->cos_max )
            {
                /*
                 * If cos is bigger than feature's cos_max, the val should be
                 * default value. Otherwise, it fails to find a COS ID. So we
                 * have to exit find flow.
                 */
                if ( val[0] != default_val )
                    return -EINVAL;

                found = true;
            }
            else
            {
                if ( val[0] == feat->cos_reg_val[cos] )
                    found = true;
            }

            /* If fail to match, go to next cos to compare. */
            if ( !found )
                break;

            val_ptr += feat->props->cos_num;
            if ( val_ptr - val > array_len )
                return -ENOSPC;
        }

        /* For this COS ID all entries in the values array do match. Use it. */
        if ( found )
            return cos;
    }

    return -ENOENT;
}

static bool fits_cos_max(const uint32_t val[],
                         uint32_t array_len,
                         const struct psr_socket_info *info,
                         unsigned int cos)
{
    unsigned int i;

    for ( i = 0; i < PSR_SOCKET_MAX_FEAT; i++ )
    {
        uint32_t default_val = 0;
        const struct feat_node *feat = info->features[i];
        if ( !feat )
            continue;

        if ( array_len < feat->props->cos_num )
            return false;

        if ( cos > feat->props->cos_max )
        {
            feat->props->get_val(feat, 0, &default_val);
            if ( val[0] != default_val )
                return false;
        }

        array_len -= feat->props->cos_num;

        val += feat->props->cos_num;
    }

    return true;
}

static int pick_avail_cos(const struct psr_socket_info *info,
                          spinlock_t *ref_lock,
                          const uint32_t val[], unsigned int array_len,
                          unsigned int old_cos,
                          enum psr_feat_type feat_type)
{
    unsigned int cos;
    unsigned int cos_max = 0;
    const struct feat_node *feat;
    const unsigned int *ref = info->cos_ref;

    ASSERT(spin_is_locked(ref_lock));

    /* cos_max is the one of the feature which is being set. */
    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    cos_max = feat->props->cos_max;
    if ( !cos_max )
        return -ENOENT;

    /* We cannot use id 0 because it stores the default values. */
    if ( old_cos && ref[old_cos] == 1 &&
         fits_cos_max(val, array_len, info, old_cos) )
            return old_cos;

    /* Find an unused one other than cos0. */
    for ( cos = 1; cos <= cos_max; cos++ )
    {
        /*
         * ref is 0 means this COS is not used by other domain and
         * can be used for current setting.
         */
        if ( !ref[cos] )
        {
            if ( !fits_cos_max(val, array_len, info, cos) )
                break;

            return cos;
        }
    }

    return -EOVERFLOW;
}

static unsigned int get_socket_cpu(unsigned int socket)
{
    if ( likely(socket < nr_sockets) )
        return cpumask_any(socket_cpumask[socket]);

    return nr_cpu_ids;
}

struct cos_write_info
{
    unsigned int cos;
    struct feat_node *feature;
    uint32_t val;
};

static void do_write_psr_msr(void *data)
{
    struct cos_write_info *info = data;
    unsigned int cos            = info->cos;
    struct feat_node *feat      = info->feature;

    if ( cos > feat->props->cos_max )
        return;

    feat->props->write_msr(cos, info->val, feat);
}

static int write_psr_msr(unsigned int socket, unsigned int cos,
                         uint32_t val, enum psr_feat_type feat_type)
{
    struct psr_socket_info *info = get_socket_info(socket);
    struct cos_write_info data =
    {
        .cos = cos,
        .feature = info->features[feat_type],
        .val = val,
    };

    if ( socket == cpu_to_socket(smp_processor_id()) )
        do_write_psr_msr(&data);
    else
    {
        unsigned int cpu = get_socket_cpu(socket);

        if ( cpu >= nr_cpu_ids )
            return -ENOTSOCK;
        on_selected_cpus(cpumask_of(cpu), do_write_psr_msr, &data, 1);
    }

    return 0;
}

/* The whole set process is protected by domctl_lock. */
int psr_set_val(struct domain *d, unsigned int socket,
                uint32_t val, enum cbm_type type)
{
    unsigned int old_cos;
    int cos, ret;
    unsigned int *ref;
    uint32_t *val_array;
    struct psr_socket_info *info = get_socket_info(socket);
    unsigned int array_len;
    enum psr_feat_type feat_type;

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    feat_type = psr_cbm_type_to_feat_type(type);
    if ( feat_type > ARRAY_SIZE(info->features) ||
         !info->features[feat_type] )
        return -ENOENT;

    /*
     * Step 0:
     * old_cos means the COS ID current domain is using. By default, it is 0.
     *
     * For every COS ID, there is a reference count to record how many domains
     * are using the COS register corresponding to this COS ID.
     * - If ref[old_cos] is 0, that means this COS is not used by any domain.
     * - If ref[old_cos] is 1, that means this COS is only used by current
     *   domain.
     * - If ref[old_cos] is more than 1, that mean multiple domains are using
     *   this COS.
     */
    old_cos = d->arch.psr_cos_ids[socket];
    ASSERT(old_cos < MAX_COS_REG_CNT);

    ref = info->cos_ref;

    /*
     * Step 1:
     * Gather a value array to store all features cos_reg_val[old_cos].
     * And, set the input new val into array according to the feature's
     * position in array.
     */
    array_len = get_cos_num(info);
    val_array = xzalloc_array(uint32_t, array_len);
    if ( !val_array )
        return -ENOMEM;

    if ( (ret = gather_val_array(val_array, array_len, info, old_cos)) != 0 )
        goto free_array;

    if ( (ret = insert_val_to_array(val_array, array_len, info,
                                    feat_type, type, val)) != 0 )
        goto free_array;

    spin_lock(&info->ref_lock);

    /*
     * Step 2:
     * Try to find if there is already a COS ID on which all features' values
     * are same as the array. Then, we can reuse this COS ID.
     */
    cos = find_cos(val_array, array_len, feat_type, info, &info->ref_lock);
    if ( cos == old_cos )
    {
        ret = 0;
        goto unlock_free_array;
    }

    /*
     * Step 3:
     * If fail to find, we need pick an available COS ID.
     * In fact, only COS ID which ref is 1 or 0 can be picked for current
     * domain. If old_cos is not 0 and its ref==1, that means only current
     * domain is using this old_cos ID. So, this old_cos ID certainly can
     * be reused by current domain. Ref==0 means there is no any domain
     * using this COS ID. So it can be used for current domain too.
     */
    if ( cos < 0 )
    {
        cos = pick_avail_cos(info, &info->ref_lock, val_array,
                             array_len, old_cos, feat_type);
        if ( cos < 0 )
        {
            ret = cos;
            goto unlock_free_array;
        }

        /*
         * Step 4:
         * Write all features MSRs according to the COS ID.
         */
        ret = write_psr_msr(socket, cos, val, feat_type);
        if ( ret )
            goto unlock_free_array;
    }

    /*
     * Step 5:
     * Find the COS ID (find_cos result is '>= 0' or an available COS ID is
     * picked, then update ref according to COS ID.
     */
    ref[cos]++;
    ASSERT(!cos || ref[cos]);
    ASSERT(!old_cos || ref[old_cos]);
    ref[old_cos]--;
    spin_unlock(&info->ref_lock);

    /*
     * Step 6:
     * Save the COS ID into current domain's psr_cos_ids[] so that we can know
     * which COS the domain is using on the socket. One domain can only use
     * one COS ID at same time on each socket.
     */
    d->arch.psr_cos_ids[socket] = cos;

    xfree(val_array);
    return ret;

 unlock_free_array:
    spin_unlock(&info->ref_lock);
 free_array:
    xfree(val_array);
    return ret;
}

/* Called with domain lock held, no extra lock needed for 'psr_cos_ids' */
static void psr_free_cos(struct domain *d)
{
    unsigned int socket, cos;

    ASSERT(socket_info);

    if ( !d->arch.psr_cos_ids )
        return;

    /* Domain is destroied so its cos_ref should be decreased. */
    for ( socket = 0; socket < nr_sockets; socket++ )
    {
        struct psr_socket_info *info;

        /* cos 0 is default one which does not need be handled. */
        cos = d->arch.psr_cos_ids[socket];
        if ( cos == 0 )
            continue;

        info = socket_info + socket;
        spin_lock(&info->ref_lock);
        ASSERT(!cos || info->cos_ref[cos]);
        info->cos_ref[cos]--;
        spin_unlock(&info->ref_lock);
    }

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

    if ( feat_l3_cdp == NULL &&
         (feat_l3_cdp = xzalloc(struct feat_node)) == NULL )
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

        if ( (regs.c & PSR_CAT_CDP_CAPABILITY) && (opt_psr & PSR_CDP) &&
             !info->features[PSR_SOCKET_L3_CDP] )
        {
            feat = feat_l3_cdp;
            feat_l3_cdp = NULL;
            feat->props = &l3_cdp_props;
            cat_init_feature(&regs, feat, info, PSR_SOCKET_L3_CDP);
        }
        else
        {
            feat = feat_l3_cat;
            feat_l3_cat = NULL;
            feat->props = &l3_cat_props;
            cat_init_feature(&regs, feat, info, PSR_SOCKET_L3_CAT);
        }
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

    if ( opt_psr & (PSR_CAT | PSR_CDP) )
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
