#include <xen/init.h>
#include <xen/compile.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <acpi/actables.h>
#include <xen/list.h>

struct pcirc_idmap
{
    struct acpi_iort_id_mapping idmap;
    struct list_head entry;
};


int add_to_new_idmap_list(struct list_head *new_idmap_list,
        unsigned int ib, unsigned int ob,
        unsigned int oref, unsigned int idc)
{
    struct pcirc_idmap *new_e = xzalloc(struct pcirc_idmap);
    if ( !new_e )
    {
        printk("Unable to allocate memory\n");
        return -ENOMEM;
    }

    new_e->idmap.input_base = ib;
    new_e->idmap.output_base = ob;
    new_e->idmap.output_reference = oref;
    new_e->idmap.id_count = idc;

    list_add_tail(&new_e->entry, new_idmap_list);

    return 0;
}

/*
 * returns the number of pci_idmaps created as a result of parsing
 * the smmu nodes for this pci_idmap
 * the pci_idmaps are added to the new_idmap_list
 *
 * if get_count_only is set new_idmap_list is not populated, just the
 * id_count is updated.
 *
 * This method is called in estimate size flow and write hwdom iort flow
 */
static int update_id_mapping(struct acpi_iort_id_mapping *pci_idmap,
        struct acpi_iort_node *smmu_node,
        struct list_head *new_idmap_list /* [out] */,
        int get_count_only,
        unsigned int *id_count /* [out] */)
{
    /* local varialbes to hold input output base and count values.
     * p_ for pci idmap; s for smmu idmap */
    unsigned int p_ib, p_ob, p_idc, s_ib, s_ob, s_idc, delta, i;
    struct acpi_iort_id_mapping *smmu_idmap = NULL;
    int ret;

    p_ib = pci_idmap->input_base;
    p_ob = pci_idmap->output_base;
    p_idc = pci_idmap->id_count;

    if(get_count_only)
        *id_count = 0;

    for ( i = 0; i < smmu_node->mapping_count; i++ )
    {
        smmu_idmap = (struct acpi_iort_id_mapping*)((u8*)smmu_node
                + smmu_node->mapping_offset);
        s_ib = smmu_idmap->input_base;
        s_ob = smmu_idmap->output_base;
        s_idc = smmu_idmap->id_count;

        if ( s_ib <= p_ob )
        {
            if ( s_ib + s_idc < p_ob )
                continue;

            delta = p_ob - s_ib;

            if ( get_count_only )
            {
                (*id_count)++;
                continue;
            }

            ret = add_to_new_idmap_list(new_idmap_list, p_ib, s_ob + delta,
                    smmu_idmap->output_reference,
                    s_ib + s_idc <= p_ob + p_idc ? s_idc - delta : p_idc);
            if (ret)
                goto err;
        }
        else
        {
            if( p_ob + p_idc < s_ib )
                continue;

            delta = s_ib - p_ob;

            if ( get_count_only )
            {
                (*id_count)++;
                continue;
            }

            ret = add_to_new_idmap_list(new_idmap_list, p_ib + delta, s_ob,
                    smmu_idmap->output_reference,
                    s_ib + s_idc < p_ob + p_idc ? s_idc : p_idc - delta);
            if (ret)
                goto err;
        }
    }

    return 0;
err:
    return ret;
}

/*
 *  This method scans the idarray for a pcirc_node
 *  For each idmap there could be one or more entries in smmu idmap array
 *
 *  update_id_mapping will add correspoding smmu idmap entries but will
 *  change mapping, so a pci idmap entry would have output_ref as its group
 *
 * idlist is populated when get_num_ids == 0
 * - stores updated ids by removing smmu output reference
 */
static int scan_idarray(u8 *iort_base_ptr, struct acpi_iort_node *node,
        struct list_head *idmaplist, int get_num_ids,
        unsigned int *num_ids)
{
    int i = 0, ret = 0;
    unsigned int id_count = 0;
    struct acpi_iort_node *onode; /* output node */
    struct acpi_iort_id_mapping *idmap = (struct acpi_iort_id_mapping*)
                                        ((u8*)node + node->mapping_offset);

    for ( i = 0; i < node->mapping_count; i++ )
    {
        onode = (struct acpi_iort_node*)(iort_base_ptr +
                idmap->output_reference);
        switch ( onode->type )
        {
            case ACPI_IORT_NODE_ITS_GROUP:
                continue;
            case ACPI_IORT_NODE_SMMU:
            case ACPI_IORT_NODE_SMMU_V3:
                ret = update_id_mapping(idmap, onode, idmaplist, get_num_ids,
                        &id_count);
                if ( ret )
                    goto end;
                if (get_num_ids)
                    *num_ids += id_count;
            break;
        }
        idmap++;
    }

end:
    return ret;
}

/*
 * This method estimates the size of pci_rc node
 * and returns any extra bytes added due to accomodting smmu_id_array elements
 * which map to a single element of pci_rc id_array.
 */
static int estimate_pcirc_node_size(u8 *iort_base_ptr,
        struct acpi_iort_node *node,
        unsigned int *node_size)
{
    int ret;
    unsigned int num_ids = 0;

    *node_size = 0;
    ret = scan_idarray(iort_base_ptr, node, NULL, 1, &num_ids);
    if ( !ret )
        *node_size += num_ids*sizeof(struct acpi_iort_id_mapping) +
            sizeof(struct acpi_iort_node) -1 +
            sizeof(struct acpi_iort_root_complex);

    return ret;
}

/*
 *  This method parses the iort_table pci_rc nodes.
 *  For each element in the pci_rc: id_array smmu output reference
 *    has to be patched up with ITS group output reference.
 *  Each element in the id_array may map to mulpile entries in smmu id_array.
 *    Thus when patching the smmu output refrence, extra elements in id_array
 *    need to be created.
 *  Thus the size of the resultant id_array need to identified before the actual
 *    patching is done hardware domains's IORT table will have PCIRC
 *    and ITS group nodes only.
 */
int estimate_iort_size(size_t *iort_size)
{
    unsigned int i;
    unsigned int node_size = 0;
    struct acpi_table_iort *fw_iort;
    struct acpi_iort_node *node = NULL;

    if ( acpi_get_table(ACPI_SIG_IORT, 0,
                (struct acpi_table_header **)&fw_iort) )
    {
        printk("Failed to get IORT table\n");
        goto err;
    }

    *iort_size = sizeof(struct acpi_table_iort);
    node = (struct acpi_iort_node *)((u8*)fw_iort + fw_iort->node_offset);

    if (!node)
        goto err;

    /* Iterate over the pci_rc nodes in firmware iort table */
    for ( i = 0; i < fw_iort->node_count; i++ )
    {
        switch (node->type)
        {
            case ACPI_IORT_NODE_PCI_ROOT_COMPLEX:
                if( !estimate_pcirc_node_size((u8*)fw_iort, node, &node_size) )
                    *iort_size += node_size;
                else
                    goto err;
                break;

            case ACPI_IORT_NODE_ITS_GROUP:
                *iort_size += node->length;
                break;
        }

        node = (struct acpi_iort_node *)((uint8_t*)node + node->length);
    }

    return 0;
err:
    return -EINVAL;
}

void write_itsgroup_nodes (struct acpi_table_iort *hwdom_iort,
        struct acpi_table_iort *fw_iort,
        uint64_t *ofstmap, unsigned int *pos)
{
    int i;
    struct acpi_iort_node *node = NULL;
    /* Iterate over all its groups in firmware IORT table
     * and copy them in hwdom iort table.
     */

    /* First Node */
    node = (struct acpi_iort_node *)((u8*)fw_iort + fw_iort->node_offset);
    for ( i = 0; i < fw_iort->node_count; i++ )
    {
        if ( node->type == ACPI_IORT_NODE_ITS_GROUP )
        {
            u32 l,u;
            /* Copy ITS group node into dom0 IORT Table */
            ACPI_MEMCPY((u8*)hwdom_iort + *pos, node, node->length);

            /* keep the new and old offsets, this would resolve smmu idarray's
             * output ref offsets to the new offsets in hwdom iort table */
            l = (uint32_t)((u8*)node - (u8*)fw_iort);
            u = *pos ;
            *ofstmap = ((uint64_t)(u) << 32)| l;

            hwdom_iort->node_count++;
            *pos += node->length;
            ofstmap++;
        }
        node = (struct acpi_iort_node *)((u8*)node + node->length);
    }
}

unsigned int write_single_pcirc_node(u8 *hwdom_iort, unsigned int pos,
        struct acpi_iort_node *node,
        struct list_head *new_idmap_list)
{
    unsigned int sz;
    struct acpi_iort_node *local;
    struct pcirc_idmap *pidmap;
    local = (struct acpi_iort_node *)(hwdom_iort + pos);

    /* write the pci_rc node */
    sz = sizeof(struct acpi_iort_node) -1 +
    /* -1 as acpi_iort_node has an extra char */
        sizeof (struct acpi_iort_root_complex) ;
    ACPI_MEMCPY(hwdom_iort + pos, node, sz);

    pos += sz;
    local->mapping_offset = sz;
    local->mapping_count = 0;
    local->length = sz;

    list_for_each_entry(pidmap, new_idmap_list, entry)
    {
        ACPI_MEMCPY(hwdom_iort + pos, &pidmap->idmap,
                sizeof(struct acpi_iort_id_mapping));
        pos += sizeof(struct acpi_iort_id_mapping);
        local->mapping_count++;
        local->length += sizeof(struct acpi_iort_id_mapping);
    }

    return pos;
}

int write_pcirc_nodes(struct acpi_table_iort *hwdom_iort,
        struct acpi_table_iort *fw_iort,
        uint64_t  *its_ofstmap, unsigned int *pos)
{
    int i, j, ret;
    struct acpi_iort_node *node = NULL;

    /* Iterate over all PCI_Nodes */
    /* First Node */
    node = (struct acpi_iort_node *)((u8*)fw_iort + fw_iort->node_offset);
    for ( i = 0; i < fw_iort->node_count; i++ )
    {
        if ( node->type == ACPI_IORT_NODE_PCI_ROOT_COMPLEX )
        {
            struct pcirc_idmap *pidmap;
            struct list_head new_idmap_list;
            INIT_LIST_HEAD(&new_idmap_list);

            /* hide smmu nodes and update new_idmap_list with output
             * refrence of pci idarray as its group
             */
            ret = scan_idarray((u8*)fw_iort, node, &new_idmap_list, 0, NULL);
            if ( ret ) {
                printk("%s: scan_idarry Failed \r\n", __func__);
                goto end;
            }

            /* fixup its_group offsets as per new iort table */
            list_for_each_entry(pidmap, &new_idmap_list, entry)
            {
                /* search output reference offset in its_ofmap
                 * and replace with new offset
                 */
                for (j =0; j < fw_iort->node_count; j++)
                {
                    if( !its_ofstmap[j] )
                        break;

                    if(pidmap->idmap.output_reference
                            == (its_ofstmap[j] & 0xffffffff))
                    {
                        pidmap->idmap.output_reference = its_ofstmap[j] >> 32;
                        break;
                    }

                }
            }

            *pos = write_single_pcirc_node((u8*)hwdom_iort, *pos, node,
                    &new_idmap_list);
            hwdom_iort->node_count++;

            /* free new_idmap_list */
            list_for_each_entry(pidmap, &new_idmap_list, entry)
                xfree(pidmap);
        }
        /* Next Node */
        node = (struct acpi_iort_node *)((u8*)node + node->length);
    }
    return 0;
end:
    return -EINVAL;
}

/*
 *   Prepares IORT table for hardware domain, removing all the smmu nodes.
 *  IORT table for hardware domain will have the following structure.
 *  [IORT Header]
 *  [ITS Group Nodes]
 *  [PCI RC Node -N]
 */
int prepare_iort(struct acpi_table_iort *fw_iort,
        struct acpi_table_iort *hwdom_iort,
        unsigned int *iort_size)
{
    unsigned int pos; /* offset into local iort table */
    uint64_t *its_ofstmap;

    pos = sizeof(struct acpi_table_iort);

    its_ofstmap = xzalloc_array(uint64_t, fw_iort->node_count);
    if (!its_ofstmap)
        goto end;

    /* Copy FW iort header, node_count and node_offset updated later */
    ACPI_MEMCPY(hwdom_iort, fw_iort, sizeof(struct acpi_table_iort));
    hwdom_iort->node_offset = pos;
    hwdom_iort->node_count = 0;

    write_itsgroup_nodes(hwdom_iort, fw_iort, its_ofstmap, &pos);

    if( write_pcirc_nodes(hwdom_iort, fw_iort, its_ofstmap, &pos) )
    {
        printk("Error in write_pcirc_nodes \r\n");
        goto end;
    }

    hwdom_iort->header.length = pos;

    xfree(its_ofstmap);
    *iort_size = pos;
    return 0;
end:
    return -EINVAL;
}
