// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_cmds_dump_ops.c - kParser KMOD-CLI debug dump operations
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include "kparser.h"

/* forward declarations of dump functions which dump config structures for debug purposes */
static void kparser_dump_node(const struct kparser_parse_node *obj);
static void kparser_dump_proto_table(const struct kparser_proto_table *obj);
static void kparser_dump_tlv_parse_node(const struct kparser_parse_tlv_node *obj);
static void kparser_dump_metadatatable(const struct kparser_metadata_table *obj);
static void kparser_dump_cond_tables(const struct kparser_condexpr_tables *obj);

/* debug code: dump kparser_parameterized_len structure */
static void kparser_dump_param_len(const struct kparser_parameterized_len *pflen)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!pflen) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("pflen.src_off:%u\n", pflen->src_off);
	pr_debug("pflen.size:%u\n", pflen->size);
	pr_debug("pflen.endian:%d\n", pflen->endian);
	pr_debug("pflen.mask:%u\n", pflen->mask);
	pr_debug("pflen.right_shift:%u\n", pflen->right_shift);
	pr_debug("pflen.multiplier:%u\n", pflen->multiplier);
	pr_debug("pflen.add_value:%u\n", pflen->add_value);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_parameterized_next_proto structure */
static void kparser_dump_param_next_proto(const struct kparser_parameterized_next_proto
					  *pfnext_proto)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!pfnext_proto) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("pfnext_proto.src_off:%u\n", pfnext_proto->src_off);
	pr_debug("pfnext_proto.mask:%u\n", pfnext_proto->mask);
	pr_debug("pfnext_proto.size:%u\n", pfnext_proto->size);
	pr_debug("pfnext_proto.right_shift:%u\n", pfnext_proto->right_shift);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_condexpr_expr structure */
static void kparser_dump_cond_expr(const struct kparser_condexpr_expr *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("type:%u, src_off:%u, len:%u, mask:%04x value:%04x\n",
		 obj->type, obj->src_off,
			obj->length, obj->mask, obj->value);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_condexpr_table structure */
static void kparser_dump_cond_table(const struct kparser_condexpr_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("default_fail:%d, type:%u\n", obj->default_fail, obj->type);
	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);

	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		kparser_dump_cond_expr(obj->entries[i]);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_condexpr_tables structure */
static void kparser_dump_cond_tables(const struct kparser_condexpr_tables *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		kparser_dump_cond_table(obj->entries[i]);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_proto_node structure */
static void kparser_dump_proto_node(const struct kparser_proto_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("encap:%u\n", obj->encap);
	pr_debug("overlay:%u\n", obj->overlay);
	pr_debug("min_len:%lu\n", obj->min_len);

	pr_debug("ops.flag_fields_length:%d\n", obj->ops.flag_fields_length);

	pr_debug("ops.len_parameterized:%d\n", obj->ops.len_parameterized);
	kparser_dump_param_len(&obj->ops.pflen);

	kparser_dump_param_next_proto(&obj->ops.pfnext_proto);

	pr_debug("ops.cond_exprs_parameterized:%d\n", obj->ops.cond_exprs_parameterized);
	kparser_dump_cond_tables(&obj->ops.cond_exprs);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_proto_tlvs_table structure */
static void kparser_dump_proto_tlvs_table(const struct kparser_proto_tlvs_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		pr_debug("[%d]: val: %04x\n", i, obj->entries[i].type);
		kparser_dump_tlv_parse_node(obj->entries[i].node);
	}

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_parse_tlv_node structure */
static void kparser_dump_tlv_parse_node(const struct kparser_parse_tlv_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s\n", obj->name);
	pr_debug("unknown_tlv_type_ret:%d\n", obj->unknown_overlay_ret);

	pr_debug("proto_tlv_node.min_len: %lu\n", obj->proto_tlv_node.min_len);
	pr_debug("proto_tlv_node.max_len: %lu\n", obj->proto_tlv_node.max_len);
	pr_debug("proto_tlv_node.is_padding: %u\n", obj->proto_tlv_node.is_padding);
	pr_debug("proto_tlv_node.overlay_type_parameterized: %u\n",
		 obj->proto_tlv_node.ops.overlay_type_parameterized);
	kparser_dump_param_next_proto(&obj->proto_tlv_node.ops.pfoverlay_type);
	pr_debug("proto_tlv_node.cond_exprs_parameterized: %u\n",
		 obj->proto_tlv_node.ops.cond_exprs_parameterized);
	kparser_dump_cond_tables(&obj->proto_tlv_node.ops.cond_exprs);

	kparser_dump_proto_tlvs_table(obj->overlay_table);
	kparser_dump_tlv_parse_node(obj->overlay_wildcard_node);
	kparser_dump_metadatatable(obj->metadata_table);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_parse_tlvs_node structure */
static void kparser_dump_tlvs_parse_node(const struct kparser_parse_tlvs_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_tlvs_table(obj->tlv_proto_table);

	pr_debug("unknown_tlv_type_ret:%d\n", obj->unknown_tlv_type_ret);

	kparser_dump_tlv_parse_node(obj->tlv_wildcard_node);

	pr_debug("config:max_loop: %u\n", obj->config.max_loop);
	pr_debug("config:max_non: %u\n", obj->config.max_non);
	pr_debug("config:max_plen: %u\n", obj->config.max_plen);
	pr_debug("config:max_c_pad: %u\n", obj->config.max_c_pad);
	pr_debug("config:disp_limit_exceed: %u\n", obj->config.disp_limit_exceed);
	pr_debug("config:exceed_loop_cnt_is_err: %u\n", obj->config.exceed_loop_cnt_is_err);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_proto_tlvs_node structure */
static void kparser_dump_tlvs_proto_node(const struct kparser_proto_tlvs_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_node(&obj->proto_node);

	kparser_dump_param_len(&obj->ops.pfstart_offset);
	pr_debug("ops.len_parameterized:%d\n", obj->ops.len_parameterized);
	kparser_dump_param_len(&obj->ops.pflen);
	kparser_dump_param_next_proto(&obj->ops.pftype);

	pr_debug("start_offset:%lu\n", obj->start_offset);
	pr_debug("pad1_val:%u\n", obj->pad1_val);
	pr_debug("padn_val:%u\n", obj->padn_val);
	pr_debug("eol_val:%u\n", obj->eol_val);
	pr_debug("pad1_enable:%u\n", obj->pad1_enable);
	pr_debug("padn_enable:%u\n", obj->padn_enable);
	pr_debug("eol_enable:%u\n", obj->eol_enable);
	pr_debug("fixed_start_offset:%u\n", obj->fixed_start_offset);
	pr_debug("min_len:%lu\n", obj->min_len);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_flag_field structure */
static void kparser_dump_flag_field(const struct kparser_flag_field *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("flag:%04x, mask:%04x size:%lu\n", obj->flag, obj->mask, obj->size);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_flag_fields structure */
static void kparser_dump_flag_fields(const struct kparser_flag_fields *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_idx:%lu, fields:%p\n", obj->num_idx, obj->fields);

	if (!obj->fields)
		goto done;

	for (i = 0; i < obj->num_idx; i++)
		kparser_dump_flag_field(&obj->fields[i]);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_parse_flag_field_node structure */
static void kparser_dump_parse_flag_field_node(const struct kparser_parse_flag_field_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s\n", obj->name);

	kparser_dump_metadatatable(obj->metadata_table);
	kparser_dump_cond_tables(&obj->ops.cond_exprs);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_proto_flag_fields_table structure */
static void kparser_dump_proto_flag_fields_table(const struct kparser_proto_flag_fields_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%d, entries:%p\n", obj->num_ents, obj->entries);

	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		pr_debug("proto_flag_fields_table_entry_flag:%x\n", obj->entries[i].flag);
		kparser_dump_parse_flag_field_node(obj->entries[i].node);
	}
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_parse_flag_fields_node structure */
static void kparser_dump_flags_parse_node(const struct kparser_parse_flag_fields_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_flag_fields_table(obj->flag_fields_proto_table);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_proto_flag_fields_node structure */
static void kparser_dump_flags_proto_node(const struct kparser_proto_flag_fields_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_node(&obj->proto_node);

	pr_debug("ops.get_flags_parameterized:%d\n", obj->ops.get_flags_parameterized);
	pr_debug("ops.pfget_flags: src_off:%u mask:%04x size:%u\n",
		 obj->ops.pfget_flags.src_off,
		 obj->ops.pfget_flags.mask,
		 obj->ops.pfget_flags.size);

	pr_debug("ops.start_fields_offset_parameterized:%d\n",
		 obj->ops.start_fields_offset_parameterized);
	kparser_dump_param_len(&obj->ops.pfstart_fields_offset);

	pr_debug("ops.flag_feilds_len:%u ops.hdr_length:%u\n",
		 obj->ops.flag_fields_len, obj->ops.hdr_length);

	kparser_dump_flag_fields(obj->flag_fields);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_metadata_table structure */
static void kparser_dump_metadatatable(const struct kparser_metadata_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		pr_debug("mde[%d]:%04x\n", i, obj->entries[i].val);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_proto_table structure */
static void kparser_dump_proto_table(const struct kparser_proto_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		pr_debug("[%d]: val: %d\n", i, obj->entries[i].value);
		kparser_dump_node(obj->entries[i].node);
	}

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump kparser_parse_node structure */
static void kparser_dump_node(const struct kparser_parse_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s: type: %d\n", obj->name, obj->node_type);
	pr_debug("unknown_ret:%d\n", obj->unknown_ret);

	switch (obj->node_type) {
	case KPARSER_NODE_TYPE_PLAIN:
		kparser_dump_proto_node(&obj->proto_node);
		break;

	case KPARSER_NODE_TYPE_TLVS:
		kparser_dump_tlvs_proto_node(&obj->tlvs_proto_node);
		kparser_dump_tlvs_parse_node((const struct kparser_parse_tlvs_node *)obj);
		break;

	case KPARSER_NODE_TYPE_FLAG_FIELDS:
		kparser_dump_flags_proto_node(&obj->flag_fields_proto_node);
		kparser_dump_flags_parse_node((const struct kparser_parse_flag_fields_node *)obj);
		break;

	default:
		pr_debug("unknown node type:%d\n", obj->node_type);
		break;
	}

	kparser_dump_proto_table(obj->proto_table);

	kparser_dump_node(obj->wildcard_node);

	kparser_dump_metadatatable(obj->metadata_table);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}

/* debug code: dump whole parse tree from kparser_parser structure */
void kparser_dump_parser_tree(const struct kparser_parser *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __func__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s\n", obj->name);

	pr_debug("config: flags:%02x\n", obj->config.flags);
	pr_debug("config: max_nodes:%u\n", obj->config.max_nodes);
	pr_debug("config: max_encaps:%u\n", obj->config.max_encaps);
	pr_debug("config: max_frames:%u\n", obj->config.max_frames);
	pr_debug("config: metameta_size:%lu\n", obj->config.metameta_size);
	pr_debug("config: frame_size:%lu\n", obj->config.frame_size);

	pr_debug("cntrs_len: %lu\n", obj->cntrs_len);
	for (i = 0; i < (sizeof(obj->cntrs_conf.cntrs) /
				sizeof(obj->cntrs_conf.cntrs[0])); i++) {
		pr_debug("cntrs:%d: max_value:%u\n", i,
			 obj->cntrs_conf.cntrs[i].max_value);
		pr_debug("cntrs:%d: array_limit:%u\n", i,
			 obj->cntrs_conf.cntrs[i].array_limit);
		pr_debug("cntrs:%d: el_size:%lu\n", i,
			 obj->cntrs_conf.cntrs[i].el_size);
		pr_debug("cntrs:%d: reset_on_encap:%d\n", i,
			 obj->cntrs_conf.cntrs[i].reset_on_encap);
		pr_debug("cntrs:%d: overwrite_last:%d\n", i,
			 obj->cntrs_conf.cntrs[i].overwrite_last);
		pr_debug("cntrs:%d: error_on_exceeded:%d\n", i,
			 obj->cntrs_conf.cntrs[i].error_on_exceeded);
		if (obj->cntrs)
			pr_debug("cntr[%d]:%d", i, obj->cntrs->cntr[i]);
	}

	kparser_dump_node(obj->root_node);
	kparser_dump_node(obj->okay_node);
	kparser_dump_node(obj->fail_node);
	kparser_dump_node(obj->atencap_node);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __func__, __LINE__);
}
