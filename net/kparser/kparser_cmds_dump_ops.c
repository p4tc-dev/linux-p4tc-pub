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
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!pflen) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.src_off:%u\n", pflen->src_off);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.size:%u\n", pflen->size);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.endian:%d\n", pflen->endian);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.mask:%u\n", pflen->mask);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.right_shift:%u\n", pflen->right_shift);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.multiplier:%u\n", pflen->multiplier);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pflen.add_value:%u\n", pflen->add_value);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_parameterized_next_proto structure */
static void kparser_dump_param_next_proto(const struct kparser_parameterized_next_proto
					  *pfnext_proto)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!pfnext_proto) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "pfnext_proto.src_off:%u\n", pfnext_proto->src_off);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "pfnext_proto.mask:%u\n", pfnext_proto->mask);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "pfnext_proto.size:%u\n", pfnext_proto->size);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "pfnext_proto.right_shift:%u\n", pfnext_proto->right_shift);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_condexpr_expr structure */
static void kparser_dump_cond_expr(const struct kparser_condexpr_expr *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "type:%u, src_off:%u, len:%u, mask:%04x value:%04x\n",
				 obj->type, obj->src_off,
				 obj->length, obj->mask, obj->value);
done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_condexpr_table structure */
static void kparser_dump_cond_table(const struct kparser_condexpr_table *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "default_fail:%d, type:%u\n", obj->default_fail, obj->type);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);

	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		kparser_dump_cond_expr(obj->entries[i]);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_condexpr_tables structure */
static void kparser_dump_cond_tables(const struct kparser_condexpr_tables *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		kparser_dump_cond_table(obj->entries[i]);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_proto_node structure */
static void kparser_dump_proto_node(const struct kparser_proto_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "encap:%u\n", obj->encap);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "overlay:%u\n", obj->overlay);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "min_len:%lu\n", obj->min_len);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "ops.flag_fields_length:%d\n", obj->ops.flag_fields_length);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "ops.len_parameterized:%d\n", obj->ops.len_parameterized);
	kparser_dump_param_len(&obj->ops.pflen);

	kparser_dump_param_next_proto(&obj->ops.pfnext_proto);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "ops.cond_exprs_parameterized:%d\n",
				 obj->ops.cond_exprs_parameterized);
	kparser_dump_cond_tables(&obj->ops.cond_exprs);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_proto_tlvs_table structure */
static void kparser_dump_proto_tlvs_table(const struct kparser_proto_tlvs_table *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "[%d]: val: %04x\n", i, obj->entries[i].type);
		kparser_dump_tlv_parse_node(obj->entries[i].node);
	}

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_parse_tlv_node structure */
static void kparser_dump_tlv_parse_node(const struct kparser_parse_tlv_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "name: %s\n", obj->name);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "unknown_tlv_type_ret:%d\n", obj->unknown_overlay_ret);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "proto_tlv_node.min_len: %lu\n", obj->proto_tlv_node.min_len);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "proto_tlv_node.max_len: %lu\n", obj->proto_tlv_node.max_len);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "proto_tlv_node.is_padding: %u\n", obj->proto_tlv_node.is_padding);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "proto_tlv_node.overlay_type_parameterized: %u\n",
				 obj->proto_tlv_node.ops.overlay_type_parameterized);
	kparser_dump_param_next_proto(&obj->proto_tlv_node.ops.pfoverlay_type);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "proto_tlv_node.cond_exprs_parameterized: %u\n",
		 obj->proto_tlv_node.ops.cond_exprs_parameterized);
	kparser_dump_cond_tables(&obj->proto_tlv_node.ops.cond_exprs);

	kparser_dump_proto_tlvs_table(obj->overlay_table);
	kparser_dump_tlv_parse_node(obj->overlay_wildcard_node);
	kparser_dump_metadatatable(obj->metadata_table);
done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_parse_tlvs_node structure */
static void kparser_dump_tlvs_parse_node(const struct kparser_parse_tlvs_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	kparser_dump_proto_tlvs_table(obj->tlv_proto_table);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "unknown_tlv_type_ret:%d\n", obj->unknown_tlv_type_ret);

	kparser_dump_tlv_parse_node(obj->tlv_wildcard_node);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config:max_loop: %u\n", obj->config.max_loop);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config:max_non: %u\n", obj->config.max_non);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config:max_plen: %u\n", obj->config.max_plen);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config:max_c_pad: %u\n", obj->config.max_c_pad);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config:disp_limit_exceed: %u\n", obj->config.disp_limit_exceed);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config:exceed_loop_cnt_is_err: %u\n",
				 obj->config.exceed_loop_cnt_is_err);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_proto_tlvs_node structure */
static void kparser_dump_tlvs_proto_node(const struct kparser_proto_tlvs_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	kparser_dump_proto_node(&obj->proto_node);

	kparser_dump_param_len(&obj->ops.pfstart_offset);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "ops.len_parameterized:%d\n", obj->ops.len_parameterized);
	kparser_dump_param_len(&obj->ops.pflen);
	kparser_dump_param_next_proto(&obj->ops.pftype);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "start_offset:%lu\n", obj->start_offset);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "pad1_val:%u\n", obj->pad1_val);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "padn_val:%u\n", obj->padn_val);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "eol_val:%u\n", obj->eol_val);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "pad1_enable:%u\n", obj->pad1_enable);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "padn_enable:%u\n", obj->padn_enable);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "eol_enable:%u\n", obj->eol_enable);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "fixed_start_offset:%u\n", obj->fixed_start_offset);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "min_len:%lu\n", obj->min_len);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_flag_field structure */
static void kparser_dump_flag_field(const struct kparser_flag_field *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "flag:%04x, mask:%04x size:%lu\n",
				 obj->flag, obj->mask, obj->size);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_flag_fields structure */
static void kparser_dump_flag_fields(const struct kparser_flag_fields *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_idx:%lu, fields:%p\n", obj->num_idx, obj->fields);

	if (!obj->fields)
		goto done;

	for (i = 0; i < obj->num_idx; i++)
		kparser_dump_flag_field(&obj->fields[i]);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_parse_flag_field_node structure */
static void kparser_dump_parse_flag_field_node(const struct kparser_parse_flag_field_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "name: %s\n", obj->name);

	kparser_dump_metadatatable(obj->metadata_table);
	kparser_dump_cond_tables(&obj->ops.cond_exprs);
done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_proto_flag_fields_table structure */
static void kparser_dump_proto_flag_fields_table(const struct kparser_proto_flag_fields_table *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_ents:%d, entries:%p\n", obj->num_ents, obj->entries);

	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "proto_flag_fields_table_entry_flag:%x\n",
					 obj->entries[i].flag);
		kparser_dump_parse_flag_field_node(obj->entries[i].node);
	}
done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_parse_flag_fields_node structure */
static void kparser_dump_flags_parse_node(const struct kparser_parse_flag_fields_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	kparser_dump_proto_flag_fields_table(obj->flag_fields_proto_table);
done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_proto_flag_fields_node structure */
static void kparser_dump_flags_proto_node(const struct kparser_proto_flag_fields_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	kparser_dump_proto_node(&obj->proto_node);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "ops.get_flags_parameterized:%d\n",
				 obj->ops.get_flags_parameterized);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "ops.pfget_flags: src_off:%u mask:%04x size:%u\n",
		 obj->ops.pfget_flags.src_off,
		 obj->ops.pfget_flags.mask,
		 obj->ops.pfget_flags.size);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "ops.start_fields_offset_parameterized:%d\n",
				 obj->ops.start_fields_offset_parameterized);
	kparser_dump_param_len(&obj->ops.pfstart_fields_offset);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "ops.flag_feilds_len:%u ops.hdr_length:%u\n",
				 obj->ops.flag_fields_len, obj->ops.hdr_length);

	kparser_dump_flag_fields(obj->flag_fields);
done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_metadata_table structure */
static void kparser_dump_metadatatable(const struct kparser_metadata_table *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "mde[%d]:%04x\n", i, obj->entries[i].val);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_proto_table structure */
static void kparser_dump_proto_table(const struct kparser_proto_table *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "[%d]: val: %d\n", i, obj->entries[i].value);
		kparser_dump_node(obj->entries[i].node);
	}

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump kparser_parse_node structure */
static void kparser_dump_node(const struct kparser_parse_node *obj)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "name: %s: type: %d\n", obj->name, obj->node_type);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "unknown_ret:%d\n", obj->unknown_ret);

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
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "unknown node type:%d\n", obj->node_type);
		break;
	}

	kparser_dump_proto_table(obj->proto_table);

	kparser_dump_node(obj->wildcard_node);

	kparser_dump_metadatatable(obj->metadata_table);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

/* debug code: dump whole parse tree from kparser_parser structure */
void kparser_dump_parser_tree(const struct kparser_parser *obj)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	if (!obj) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "obj NULL");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "name: %s\n", obj->name);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "config: flags:%02x\n", obj->config.flags);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config: max_nodes:%u\n", obj->config.max_nodes);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config: max_encaps:%u\n", obj->config.max_encaps);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config: max_frames:%u\n", obj->config.max_frames);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config: metameta_size:%lu\n", obj->config.metameta_size);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "config: frame_size:%lu\n", obj->config.frame_size);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs_len: %lu\n", obj->cntrs_len);
	for (i = 0; i < (sizeof(obj->cntrs_conf.cntrs) /
				sizeof(obj->cntrs_conf.cntrs[0])); i++) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs:%d: max_value:%u\n", i,
					 obj->cntrs_conf.cntrs[i].max_value);
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs:%d: array_limit:%u\n", i,
					 obj->cntrs_conf.cntrs[i].array_limit);
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs:%d: el_size:%lu\n", i,
					 obj->cntrs_conf.cntrs[i].el_size);
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs:%d: reset_on_encap:%d\n", i,
					 obj->cntrs_conf.cntrs[i].reset_on_encap);
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs:%d: overwrite_last:%d\n", i,
					 obj->cntrs_conf.cntrs[i].overwrite_last);
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "cntrs:%d: error_on_exceeded:%d\n", i,
					 obj->cntrs_conf.cntrs[i].error_on_exceeded);
		if (obj->cntrs)
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "cntr[%d]:%d", i, obj->cntrs->cntr[i]);
	}

	kparser_dump_node(obj->root_node);
	kparser_dump_node(obj->okay_node);
	kparser_dump_node(obj->fail_node);
	kparser_dump_node(obj->atencap_node);

done:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}
