// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_datapath.c - kParser main datapath source file for parsing logic - data path
 *
 * Authors:     Tom Herbert <tom@sipanda.io>
 *              Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <linux/rhashtable.h>
#include <linux/skbuff.h>
#include <net/kparser.h>

#include "kparser.h"
#include "kparser_condexpr.h"
#include "kparser_metaextract.h"
#include "kparser_types.h"

/* Lookup a type in a node table
 * TODO: as of now, this table is an array, but in future, this needs to be
 * converted to hash table for performance benefits
 */
static const struct kparser_parse_node *lookup_node(__u32 dflags,
						    int type,
						    const struct kparser_proto_table *table,
						    bool *isencap)
{
	struct kparser_proto_table_entry __rcu *entries;
	__u32 tmp;
	int i;

	if (!table)
		return NULL;

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "type:0x%04x ents:%d, types:[%x, %x]\n",
				 type, table->num_ents, ntohs(type), ntohl(type));

	for (i = 0; i < table->num_ents; i++) {
		entries = rcu_dereference(table->entries);
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "type:0x%x evalue:0x%x\n",
					 type, entries[i].value);
		if (type == entries[i].value) {
			*isencap = entries[i].encap;
			return entries[i].node;
		} else if (ntohs(type) == entries[i].value) {
			// for 2 bytes
			*isencap = entries[i].encap;
			return entries[i].node;
		} else if (ntohl(type) == entries[i].value) {
			// for 4 bytes
			*isencap = entries[i].encap;
			return entries[i].node;
		}
		// for 3 bytes
		tmp = ntohl(type);
		tmp = tmp >> 8;
		KPARSER_KMOD_DEBUG_PRINT(dflags, "tmp:%x", tmp);
		if (tmp == entries[i].value) {
			*isencap = entries[i].encap;
			return entries[i].node;
		}
	}

	return NULL;
}

/* Lookup a type in a node TLV table */
static const struct kparser_parse_tlv_node
*lookup_tlv_node(__u32 dflags, __u8 type,
		 const struct kparser_proto_tlvs_table *table)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(dflags, "type:%d\n", type);

	for (i = 0; i < table->num_ents; i++) {
		KPARSER_KMOD_DEBUG_PRINT(dflags, "table_type:%d\n",
					 table->entries[i].type);
		if (type == table->entries[i].type)
			return table->entries[i].node;
	}

	return NULL;
}

/* Lookup a flag-fields index in a protocol node flag-fields table
 * TODO: This needs to optimized later to use array for better performance
 */
static const struct kparser_parse_flag_field_node
*lookup_flag_field_node(__u32 dflags, __u32 flag,
			const struct kparser_proto_flag_fields_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++) {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "flag:%x eflag[%d]:%x\n", flag, i,
					 table->entries[i].flag);
		if (flag == table->entries[i].flag)
			return table->entries[i].node;
	}

	return NULL;
}

/* Metadata table processing */
static int extract_metadata_table(__u32 dflags,
				  const struct kparser_parser *parser,
				  const struct kparser_metadata_table *metadata_table,
				  const void *_hdr, size_t hdr_len, size_t hdr_offset,
				  void *_metadata, void *_frame,
				  const struct kparser_ctrl_data *ctrl)
{
	struct kparser_metadata_extract *entries;
	int i, ret;

	KPARSER_KMOD_DEBUG_PRINT(dflags, "cnt:%d\n", metadata_table->num_ents);

	for (i = 0; i < metadata_table->num_ents; i++) {
		entries = rcu_dereference(metadata_table->entries);
		ret = kparser_metadata_extract(parser, entries[i],
					       _hdr, hdr_len, hdr_offset,
					       _metadata, _frame, ctrl);
		if (ret != KPARSER_OKAY)
			break;
	}
	return ret;
}

/* evaluate next proto parameterized context */
static int eval_parameterized_next_proto(__u32 dflags,
					 const struct kparser_parameterized_next_proto *pf,
					 void *_hdr)
{
	__u32 next_proto;
	__u32 mask = pf->mask;

	_hdr += pf->src_off;

	switch (pf->size) {
	case 1:
		next_proto = *(__u8 *)_hdr;
		if (pf->mask > 0xff)
			mask = 0xff;
		break;
	case 2:
		next_proto = *(__u16 *)_hdr;
		if (pf->mask > 0xffff)
			mask = 0xffff;
		break;
	case 3:
		memcpy(&next_proto, _hdr, 3);
		if (pf->mask > 0xffffff)
			mask = 0xffffff;
		break;
	case 4:
		next_proto = *(__u32 *)_hdr;
		if (pf->mask > 0xffffffff)
			mask = 0xffffffff;
		break;

	default:
		return KPARSER_STOP_UNKNOWN_PROTO;
	}

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "next_proto:%x mask:%x rs:%x pf->src_off:%u pf->size:%u",
				 next_proto, mask,
				 pf->right_shift, pf->src_off, pf->size);

	return (next_proto & mask) >> pf->right_shift;
}

/* evaluate len parameterized context */
static ssize_t eval_parameterized_len(const struct kparser_parameterized_len *pf, void *_hdr)
{
	__u32 len;

	_hdr += pf->src_off;

	switch (pf->size) {
	case 1:
		len = *(__u8 *)_hdr;
		break;
	case 2:
		len = *(__u16 *)_hdr;
		break;
	case 3:
		len = 0;
		memcpy(&len, _hdr, 3);
		break; /* TODO */
	case 4:
		len = *(__u32 *)_hdr;
		break;
	default:
		return KPARSER_STOP_LENGTH;
	}

	len = (len & pf->mask) >> pf->right_shift;

	return (len * pf->multiplier) + pf->add_value;
}

/* evaluate conditionals */
static bool eval_cond_exprs_and_table(const struct kparser_condexpr_table *table, void *_hdr)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (!kparser_expr_evaluate(table->entries[i], _hdr))
			return false;

	return true;
}

/* evaluate table of conditionals */
static bool eval_cond_exprs_or_table(const struct kparser_condexpr_table *table, void *_hdr)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (kparser_expr_evaluate(table->entries[i], _hdr))
			return true;

	return false;
}

/* evaluate list of table of conditionals */
static int eval_cond_exprs(__u32 dflags,
			   const struct kparser_condexpr_tables *tables,
			   void *_hdr)
{
	bool res;
	int i;

	for (i = 0; i < tables->num_ents; i++) {
		const struct kparser_condexpr_table *table = tables->entries[i];

		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "type:%d err:%d\n",
					 table->type, table->default_fail);

		switch (table->type) {
		case KPARSER_CONDEXPR_TYPE_OR:
			res = eval_cond_exprs_or_table(table, _hdr);
			break;
		case KPARSER_CONDEXPR_TYPE_AND:
			res = eval_cond_exprs_and_table(table, _hdr);
			break;
		}
		if (!res) {
			KPARSER_KMOD_DEBUG_PRINT(dflags,
						 "i:%d type:%d err:%d\n",
						 i, table->type,
						 table->default_fail);

			return table->default_fail;
		}
	}

	return KPARSER_OKAY;
}

/* process one tlv node */
static int kparser_parse_one_tlv(__u32 dflags,
				 const struct kparser_parser *parser,
				 const struct kparser_parse_tlvs_node *parse_tlvs_node,
				 const struct kparser_parse_tlv_node *parse_tlv_node,
				 void *_obj_ref, void *_hdr,
				 size_t tlv_len, size_t tlv_offset, void *_metadata,
				 void *_frame, struct kparser_ctrl_data *ctrl)
{
	const struct kparser_parse_tlv_node *next_parse_tlv_node;
	const struct kparser_metadata_table *metadata_table;
	const struct kparser_proto_tlv_node *proto_tlv_node;
	const struct kparser_proto_tlv_node_ops *proto_ops;
	struct kparser_proto_tlvs_table *overlay_table;
	int type, ret;

parse_again:

	proto_tlv_node = &parse_tlv_node->proto_tlv_node;

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "kParser parsing TLV %s\n",
				 parse_tlv_node->name);

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "tlv_len:%lu min_len:%lu\n",
				 tlv_len, proto_tlv_node->min_len);

	if (tlv_len < proto_tlv_node->min_len || tlv_len > proto_tlv_node->max_len) {
		/* Treat check length error as an unrecognized TLV */
		parse_tlv_node = rcu_dereference(parse_tlvs_node->tlv_wildcard_node);
		if (parse_tlv_node)
			goto parse_again;
		else
			return parse_tlvs_node->unknown_tlv_type_ret;
	}

	proto_ops = &proto_tlv_node->ops;

	KPARSER_KMOD_DEBUG_PRINT(dflags, "cond_exprs_parameterized:%d\n",
				 proto_ops->cond_exprs_parameterized);

	if (proto_ops->cond_exprs_parameterized) {
		ret = eval_cond_exprs(dflags,
				      &proto_ops->cond_exprs, _hdr);
		if (ret != KPARSER_OKAY)
			return ret;
	}

	metadata_table = rcu_dereference(parse_tlv_node->metadata_table);
	if (metadata_table) {
		ret = extract_metadata_table(dflags,
					     parser,
					     metadata_table,
					     _hdr, tlv_len, tlv_offset,
					     _metadata,
					     _frame, ctrl);
		if (ret != KPARSER_OKAY)
			return ret;
	}

	overlay_table = rcu_dereference(parse_tlv_node->overlay_table);
	if (!overlay_table)
		return KPARSER_OKAY;

	/* We have an TLV overlay  node */
	if (proto_ops && proto_ops->overlay_type_parameterized)
		type = eval_parameterized_next_proto(dflags,
						     &proto_ops->pfoverlay_type,
						     _hdr);
	else
		type = tlv_len;

	if (type < 0)
		return type;

	/* Get TLV node */
	next_parse_tlv_node = lookup_tlv_node(dflags, type, overlay_table);
	if (next_parse_tlv_node) {
		parse_tlv_node = next_parse_tlv_node;
		goto parse_again;
	}

	/* Unknown TLV overlay node */
	next_parse_tlv_node = rcu_dereference(parse_tlv_node->overlay_wildcard_node);
	if (next_parse_tlv_node) {
		parse_tlv_node = next_parse_tlv_node;
		goto parse_again;
	}

	return parse_tlv_node->unknown_overlay_ret;
}

/* tlv loop limit validator */
static int loop_limit_exceeded(int ret, unsigned int disp)
{
	switch (disp) {
	case KPARSER_LOOP_DISP_STOP_OKAY:
		return KPARSER_STOP_OKAY;
	case KPARSER_LOOP_DISP_STOP_NODE_OKAY:
		return KPARSER_STOP_NODE_OKAY;
	case KPARSER_LOOP_DISP_STOP_SUB_NODE_OKAY:
		return KPARSER_STOP_SUB_NODE_OKAY;
	case KPARSER_LOOP_DISP_STOP_FAIL:
	default:
		return ret;
	}
}

/* process packet value using parameters provided */
static __u64 eval_get_value(const struct kparser_parameterized_get_value *pf, void *_hdr)
{
	__u64 ret;

	(void)__kparser_metadata_bytes_extract(_hdr + pf->src_off, (__u8 *)&ret, pf->size, false);

	return ret;
}

/* process and parse multiple tlvs */
static int kparser_parse_tlvs(__u32 dflags,
			      const struct kparser_parser *parser,
			      const struct kparser_parse_node *parse_node,
			      void *_obj_ref,
			      void *_hdr, size_t hdr_len, size_t hdr_offset,
			      void *_metadata, void *_frame,
			      const struct kparser_ctrl_data *ctrl)
{
	unsigned int loop_cnt = 0, non_pad_cnt = 0, pad_len = 0;
	const struct kparser_proto_tlvs_table *tlv_proto_table;
	const struct kparser_parse_tlvs_node *parse_tlvs_node;
	const struct kparser_proto_tlvs_node *proto_tlvs_node;
	const struct kparser_parse_tlv_node *parse_tlv_node;
	struct kparser_ctrl_data tlv_ctrl = {};
	unsigned int consec_pad = 0;
	size_t len, tlv_offset;
	ssize_t off, tlv_len;
	__u8 *cp = _hdr;
	int type = -1, ret;

	parse_tlvs_node = (struct kparser_parse_tlvs_node *)parse_node;
	proto_tlvs_node = (struct kparser_proto_tlvs_node *)&parse_node->tlvs_proto_node;

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "fixed_start_offset:%d start_offset:%lu\n",
				 proto_tlvs_node->fixed_start_offset,
				 proto_tlvs_node->start_offset);

	/* Assume hlen marks end of TLVs */
	if (proto_tlvs_node->fixed_start_offset)
		off = proto_tlvs_node->start_offset;
	else
		off = eval_parameterized_len(&proto_tlvs_node->ops.pfstart_offset, cp);

	KPARSER_KMOD_DEBUG_PRINT(dflags, "off:%ld\n", off);

	if (off < 0)
		return KPARSER_STOP_LENGTH;

	/* We assume start offset is less than or equal to minimal length */
	len = hdr_len - off;

	cp += off;
	tlv_offset = hdr_offset + off;

	KPARSER_KMOD_DEBUG_PRINT(dflags, "len:%ld tlv_offset:%ld\n",
				 len, tlv_offset);

	/* This is the main TLV processing loop */
	while (len > 0) {
		if (++loop_cnt > parse_tlvs_node->config.max_loop)
			return loop_limit_exceeded(KPARSER_STOP_LOOP_CNT,
						   parse_tlvs_node->config.disp_limit_exceed);

		if (proto_tlvs_node->pad1_enable &&
		    *cp == proto_tlvs_node->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			tlv_offset++;
			len--;
			if (++pad_len > parse_tlvs_node->config.max_plen ||
			    ++consec_pad > parse_tlvs_node->config.max_c_pad)
				return loop_limit_exceeded(KPARSER_STOP_TLV_PADDING,
							   parse_tlvs_node->
							   config.disp_limit_exceed);
			continue;
		}

		if (proto_tlvs_node->eol_enable &&
		    *cp == proto_tlvs_node->eol_val) {
			cp++;
			tlv_offset++;
			len--;

			/* Hit EOL, we're done */
			break;
		}

		if (len < proto_tlvs_node->min_len) {
			/* Length error */
			return loop_limit_exceeded(KPARSER_STOP_TLV_LENGTH,
						   parse_tlvs_node->config.disp_limit_exceed);
		}

		/* If the len function is not set this degenerates to an
		 * array of fixed sized values (which maybe be useful in
		 * itself now that I think about it)
		 */
		do {
			KPARSER_KMOD_DEBUG_PRINT(dflags,
						 "len_parameterized:%d min_len:%lu\n",
						 proto_tlvs_node->ops.len_parameterized,
						 proto_tlvs_node->min_len);
			if (proto_tlvs_node->ops.len_parameterized) {
				tlv_len = eval_parameterized_len(&proto_tlvs_node->ops.pflen, cp);
			} else {
				tlv_len = proto_tlvs_node->min_len;
				break;
			}

			KPARSER_KMOD_DEBUG_PRINT(dflags,
						 "tlv_len:%lu\n", tlv_len);

			if (!tlv_len || len < tlv_len)
				return loop_limit_exceeded(KPARSER_STOP_TLV_LENGTH,
							   parse_tlvs_node->config.
							   disp_limit_exceed);

			if (tlv_len < proto_tlvs_node->min_len)
				return loop_limit_exceeded(KPARSER_STOP_TLV_LENGTH,
							   parse_tlvs_node->config.
							   disp_limit_exceed);
		} while (0);

		type = eval_parameterized_next_proto(dflags,
						     &proto_tlvs_node->ops.pftype,
						     cp);

		KPARSER_KMOD_DEBUG_PRINT(dflags, "type:%d\n", type);

		if (proto_tlvs_node->padn_enable &&
		    type == proto_tlvs_node->padn_val) {
			/* N byte padding, just advance */
			pad_len += tlv_len;
			if (pad_len > parse_tlvs_node->config.max_plen ||
			    ++consec_pad > parse_tlvs_node->config.max_c_pad)
				return loop_limit_exceeded(KPARSER_STOP_TLV_PADDING,
							   parse_tlvs_node->config.
							   disp_limit_exceed);
			goto next_tlv;
		}

		/* Get TLV node */
		tlv_proto_table = rcu_dereference(parse_tlvs_node->tlv_proto_table);
		if (tlv_proto_table)
			parse_tlv_node = lookup_tlv_node(dflags, type, tlv_proto_table);
parse_one_tlv:
		if (parse_tlv_node) {
			const struct kparser_proto_tlv_node *proto_tlv_node =
				&parse_tlv_node->proto_tlv_node;

			if (proto_tlv_node) {
				if (proto_tlv_node->is_padding) {
					pad_len += tlv_len;
					if (pad_len > parse_tlvs_node->config.max_plen ||
					    ++consec_pad > parse_tlvs_node->config.max_c_pad)
						return loop_limit_exceeded(KPARSER_STOP_TLV_PADDING,
									   parse_tlvs_node->config.
									   disp_limit_exceed);
				} else if (++non_pad_cnt > parse_tlvs_node->config.max_non) {
					return loop_limit_exceeded(KPARSER_STOP_OPTION_LIMIT,
								   parse_tlvs_node->
								   config.disp_limit_exceed);
				}
			}

			ret = kparser_parse_one_tlv(dflags, parser,
						    parse_tlvs_node,
						    parse_tlv_node,
						    _obj_ref, cp, tlv_len,
						    tlv_offset, _metadata,
						    _frame, &tlv_ctrl);
			if (ret != KPARSER_OKAY)
				return ret;
		} else {
			/* Unknown TLV */
			parse_tlv_node = rcu_dereference(parse_tlvs_node->tlv_wildcard_node);
			if (parse_tlv_node) {
				/* If a wilcard node is present parse that
				 * node as an overlay to this one. The
				 * wild card node can perform error processing
				 */
				goto parse_one_tlv;
			}
			/* Return default error code. Returning
			 * KPARSER_OKAY means skip
			 */
			if (parse_tlvs_node->unknown_tlv_type_ret != KPARSER_OKAY)
				return parse_tlvs_node->unknown_tlv_type_ret;
		}

		/* Move over current header */
next_tlv:
		cp += tlv_len;
		tlv_offset += tlv_len;
		len -= tlv_len;
	}

	return KPARSER_OKAY;
}

/* process and parse flag fields */
static ssize_t kparser_parse_flag_fields(__u32 dflags,
					 const struct kparser_parser *parser,
					 const struct kparser_parse_node *parse_node,
					 void *_obj_ref,
					 void *_hdr, size_t hdr_len,
					 size_t hdr_offset, void *_metadata,
					 void *_frame,
					 const struct kparser_ctrl_data *ctrl,
					 size_t parse_len)
{
	const struct kparser_parse_flag_fields_node *parse_flag_fields_node;
	const struct kparser_proto_flag_fields_node *proto_flag_fields_node;
	const struct kparser_parse_flag_field_node *parse_flag_field_node;
	const struct kparser_metadata_table *metadata_table;
	ssize_t off = -1, field_len, field_offset, res = 0;
	const struct kparser_flag_fields *flag_fields;
	__u32 flags = 0;
	int i, ret;

	parse_flag_fields_node = (struct kparser_parse_flag_fields_node *)parse_node;
	proto_flag_fields_node = (struct kparser_proto_flag_fields_node *)&parse_node->proto_node;

	flag_fields = rcu_dereference(proto_flag_fields_node->flag_fields);
	if (!flag_fields)
		return KPARSER_OKAY;

	if (proto_flag_fields_node->ops.get_flags_parameterized)
		flags = eval_get_value(&proto_flag_fields_node->ops.pfget_flags, _hdr);

	/* Position at start of field data */
	if (proto_flag_fields_node->ops.flag_fields_len)
		off = proto_flag_fields_node->ops.hdr_length;
	else if (proto_flag_fields_node->ops.start_fields_offset_parameterized)
		off = eval_parameterized_len(&proto_flag_fields_node->ops.pfstart_fields_offset,
					     _hdr);
	else
		return KPARSER_STOP_LENGTH;

	if (off < 0)
		return off;

	if (hdr_offset + off > parse_len)
		return KPARSER_STOP_LENGTH;
	_hdr += off;
	hdr_offset += off;

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "flag_fields->num_idx:%lu\n",
				 flag_fields->num_idx);

	for (i = 0; i < flag_fields->num_idx; i++) {
		off = kparser_flag_fields_offset(i, flags, flag_fields);
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "off:%ld pflag:%x flag:%x\n",
					 off, flags, flag_fields->fields[i].flag);
		if (off < 0)
			continue;

		if (hdr_offset + flag_fields->fields[i].size > parse_len)
			return KPARSER_STOP_LENGTH;

		res += flag_fields->fields[i].size;

		/* Flag field is present, try to find in the parse node
		 * table based on index in proto flag-fields
		 */
		parse_flag_field_node =
			lookup_flag_field_node(dflags,
					       flag_fields->fields[i].flag,
					       parse_flag_fields_node->flag_fields_proto_table);
		if (parse_flag_field_node) {
			const struct kparser_parse_flag_field_node_ops
				*ops = &parse_flag_field_node->ops;
			__u8 *cp = _hdr + off;

			field_len = flag_fields->fields[i].size;
			field_offset = hdr_offset + off;

			if (field_offset > parse_len)
				return KPARSER_STOP_LENGTH;

			KPARSER_KMOD_DEBUG_PRINT(dflags,
						 "kParser parsing flag-field %s\n",
						 parse_flag_field_node->name);

			if (eval_cond_exprs(dflags, &ops->cond_exprs, cp) < 0)
				return KPARSER_STOP_COMPARE;

			metadata_table = rcu_dereference(parse_flag_field_node->metadata_table);
			if (metadata_table) {
				ret = extract_metadata_table(dflags,
							     parser,
							     parse_flag_field_node->metadata_table,
							     cp, field_len, field_offset, _metadata,
							     _frame, ctrl);
				if (ret != KPARSER_OKAY)
					return ret;
			}
		}
	}

	return res;
}

/* process ok/fail/atencap nodes */
static int __kparser_run_exit_node(__u32 dflags,
				   const struct kparser_parser *parser,
				   const struct kparser_parse_node *parse_node,
				   void *_obj_ref, void *_hdr,
				   size_t hdr_offset, ssize_t hdr_len,
				   void *_metadata, void *_frame,
				   struct kparser_ctrl_data *ctrl)
{
	const struct kparser_metadata_table *metadata_table;
	int ret;

	KPARSER_KMOD_DEBUG_PRINT(dflags,
				 "exit node:%s\n", parse_node->name);
	/* Run an exit parse node. This is an okay_node, fail_node, or
	 * atencap_node
	 */
	metadata_table = rcu_dereference(parse_node->metadata_table);
	if (metadata_table) {
		ret = extract_metadata_table(dflags,
					     parser, metadata_table, _hdr,
					     hdr_len, hdr_offset, _metadata,
					     _frame, ctrl);
		if (ret != KPARSER_OKAY)
			return ret;
	}

	return KPARSER_OKAY;
}

/* __kparser_parse(): Function to parse a void * packet buffer using a parser instance key.
 *
 * parser: Non NULL kparser_get_parser() returned and cached opaque pointer
 * referencing a valid parser instance.
 * _hdr: input packet buffer
 * parse_len: length of input packet buffer
 * _metadata: User provided metadata buffer. It must be same as configured
 * metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 *
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 *
 * rcu lock must be held before calling this function.
 */
int ___kparser_parse(const void *obj, void *_hdr, size_t parse_len,
		     struct sk_buff *skb, void *_metadata, size_t metadata_len)
{
	return 0;
}

int __kparser_parse(const void *obj, void *_hdr, size_t parse_len,
		    void *_metadata, size_t metadata_len)
{
	const struct kparser_parse_node *next_parse_node, *atencap_node;
	const struct kparser_parse_node *parse_node, *wildcard_node;
	struct kparser_ctrl_data ctrl = { .ret = KPARSER_OKAY };
	const struct kparser_metadata_table *metadata_table;
	const struct kparser_proto_table *proto_table;
	const struct kparser_proto_node *proto_node;
	const struct kparser_parser *parser = obj;
	int type = -1, i, ret, framescnt;
	struct kparser_counters *cntrs;
	void *_frame, *_obj_ref = NULL;
	const void *base_hdr = _hdr;
	ssize_t hdr_offset = 0;
	ssize_t hdr_len, res;
	__u32 frame_num = 0;
	__u32 dflags = 0;
	bool currencap;

	if (parser && parser->config.max_encaps > framescnt)
		framescnt = parser->config.max_encaps;

	if (!parser || !_metadata || metadata_len == 0 || !_hdr || parse_len == 0 ||
	    (((framescnt * parser->config.frame_size) +
	       parser->config.metameta_size) > metadata_len)) {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "one or more empty/invalid param(s)\n");
		return -EINVAL;
	}

	if (parser->kparser_start_signature != KPARSERSTARTSIGNATURE ||
	    parser->kparser_end_signature != KPARSERENDSIGNATURE) {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "%s:corrupted kparser signature:start:0x%02x, end:0x%02x\n",
			 __func__, parser->kparser_start_signature, parser->kparser_end_signature);
		return -EINVAL;
	}

	if (parse_len < parser->config.metameta_size) {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "parse buf err, parse_len:%lu, mmd_len:%lu\n",
					 parse_len, parser->config.metameta_size);
		return -EINVAL;
	}

	_frame = _metadata + parser->config.metameta_size;
	dflags = parser->config.flags;

	if (dflags & KPARSER_F_DEBUG_DATAPATH) {
		/* This code is required for regression tests also */
		pr_alert("kParserdump:len:%lu\n", parse_len);
		print_hex_dump_bytes("kParserdump:rcvd_pkt:",
				     DUMP_PREFIX_OFFSET, _hdr, parse_len);
	}

	ctrl.hdr_base = _hdr;
	ctrl.node_cnt = 0;
	ctrl.encap_levels = 0;

	cntrs = rcu_dereference(parser->cntrs);
	if (cntrs) {
		/* Initialize parser counters */
		memset(cntrs, 0, sizeof(parser->cntrs_len));
	}

	parse_node = rcu_dereference(parser->root_node);
	if (!parse_node) {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "root node missing,parser:%s\n",
					 parser->name);
		return -ENOENT;
	}

	/* Main parsing loop. The loop normal teminates when we encounter a
	 * leaf protocol node, an error condition, hitting limit on layers of
	 * encapsulation, protocol condition to stop (i.e. flags that
	 * indicate to stop at flow label or hitting fragment), or
	 * unknown protocol result in table lookup for next node.
	 */
	do {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "Parsing node:%s\n",
					 parse_node->name);
		currencap = false;
		proto_node = &parse_node->proto_node;
		hdr_len = proto_node->min_len;

		if (++ctrl.node_cnt > parser->config.max_nodes) {
			ctrl.ret = KPARSER_STOP_MAX_NODES;
			goto parser_out;
		}
		/* Protocol node length checks */
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "kParser parsing %s\n",
					 parse_node->name);
		/* when SKB is passed, if parse_len < hdr_len, then
		 * try to do skb_pullup(hdr_len) here. reset parse_len based on
		 * new parse_len, reset data ptr. Do this inside this loop.
		 */
		if (parse_len < hdr_len) {
			ctrl.ret = KPARSER_STOP_LENGTH;
			goto parser_out;
		}

		do {
			if (!proto_node->ops.len_parameterized)
				break;

			hdr_len = eval_parameterized_len(&proto_node->ops.pflen, _hdr);

			KPARSER_KMOD_DEBUG_PRINT(dflags,
						 "eval_hdr_len:%ld min_len:%lu\n",
						 hdr_len, proto_node->min_len);

			if (hdr_len < proto_node->min_len) {
				ctrl.ret = hdr_len < 0 ? hdr_len : KPARSER_STOP_LENGTH;
				goto parser_out;
			}
			if (parse_len < hdr_len) {
				ctrl.ret = KPARSER_STOP_LENGTH;
				goto parser_out;
			}
		} while (0);

		hdr_offset = _hdr - base_hdr;
		ctrl.pkt_len = parse_len;

		/* Callback processing order
		 *    1) Extract Metadata
		 *    2) Process TLVs
		 *	2.a) Extract metadata from TLVs
		 *	2.b) Process TLVs
		 *    3) Process protocol
		 */

		metadata_table = rcu_dereference(parse_node->metadata_table);
		/* Extract metadata, per node processing */
		if (metadata_table) {
			ctrl.ret = extract_metadata_table(dflags,
							  parser,
							  metadata_table,
							  _hdr, hdr_len, hdr_offset,
							  _metadata, _frame, &ctrl);
			if (ctrl.ret != KPARSER_OKAY)
				goto parser_out;
		}

		/* Process node type */
		switch (parse_node->node_type) {
		case KPARSER_NODE_TYPE_PLAIN:
		default:
			break;
		case KPARSER_NODE_TYPE_TLVS:
			/* Process TLV nodes */
			ctrl.ret = kparser_parse_tlvs(dflags, parser,
						      parse_node,
						      _obj_ref, _hdr, hdr_len,
						      hdr_offset, _metadata,
						      _frame, &ctrl);
check_processing_return:
			switch (ctrl.ret) {
			case KPARSER_STOP_OKAY:
				goto parser_out;
			case KPARSER_OKAY:
				break; /* Go to the next node */
			case KPARSER_STOP_NODE_OKAY:
				/* Note KPARSER_STOP_NODE_OKAY means that
				 * post loop processing is not
				 * performed
				 */
				ctrl.ret = KPARSER_OKAY;
				goto after_post_processing;
			case KPARSER_STOP_SUB_NODE_OKAY:
				ctrl.ret = KPARSER_OKAY;
				break; /* Just go to next node */
			default:
				goto parser_out;
			}
			break;
		case KPARSER_NODE_TYPE_FLAG_FIELDS:
			/* Process flag-fields */
			res = kparser_parse_flag_fields(dflags, parser,
							parse_node,
							_obj_ref,
							_hdr, hdr_len,
							hdr_offset,
							_metadata,
							_frame,
							&ctrl, parse_len);
			if (res < 0) {
				ctrl.ret = res;
				goto check_processing_return;
			}
			hdr_len += res;
		}

after_post_processing:
		/* Proceed to next protocol layer */

		proto_table = rcu_dereference(parse_node->proto_table);
		wildcard_node = rcu_dereference(parse_node->wildcard_node);
		if (!proto_table && !wildcard_node) {
			/* Leaf parse node */
			KPARSER_KMOD_DEBUG_PRINT(dflags, "Leaf node");
			goto parser_out;
		}

		if (proto_table) {
			do {
				if (proto_node->ops.cond_exprs_parameterized) {
					ctrl.ret =
						eval_cond_exprs(dflags,
								&proto_node->ops.cond_exprs,
								_hdr);
					if (ctrl.ret != KPARSER_OKAY)
						goto parser_out;
				}

				if (!proto_table)
					break;
				type =
					eval_parameterized_next_proto(dflags,
								      &proto_node->ops.pfnext_proto,
								      _hdr);
				KPARSER_KMOD_DEBUG_PRINT(dflags,
							 "nxt_proto key:%x\n",
							 type);
				if (type < 0) {
					ctrl.ret = type;
					goto parser_out;
				}

				/* Get next node */
				next_parse_node = lookup_node(dflags,
							      type,
							      proto_table,
							      &currencap);

				if (next_parse_node)
					goto found_next;
			} while (0);
		}

		/* Try wildcard node. Either table lookup failed to find a
		 * node or there is only a wildcard
		 */
		if (wildcard_node) {
			/* Perform default processing in a wildcard node */
			next_parse_node = wildcard_node;
		} else {
			/* Return default code. Parsing will stop
			 * with the inidicated code
			 */
			ctrl.ret = parse_node->unknown_ret;
			goto parser_out;
		}

found_next:
		/* Found next protocol node, set up to process */
		if (!proto_node->overlay) {
			/* Move over current header */
			_hdr += hdr_len;
			parse_len -= hdr_len;
		}

		parse_node = next_parse_node;
		if (currencap || proto_node->encap) {
			/* Check is there is an atencap_node configured for
			 * the parser
			 */
			atencap_node = rcu_dereference(parser->atencap_node);
			if (atencap_node) {
				ret = __kparser_run_exit_node(dflags,
							      parser,
							      atencap_node,
							      _obj_ref,
							      _hdr, hdr_offset,
							      hdr_len,
							      _metadata, _frame,
							      &ctrl);
				if (ret != KPARSER_OKAY)
					goto parser_out;
			}

			/* New encapsulation layer. Check against
			 * number of encap layers allowed and also
			 * if we need a new metadata frame.
			 */
			if (++ctrl.encap_levels > parser->config.max_encaps) {
				ctrl.ret = KPARSER_STOP_ENCAP_DEPTH;
				goto parser_out;
			}

			if (frame_num < parser->config.max_frames) {
				_frame += parser->config.frame_size;
				frame_num++;
			}

			/* Check if parser has counters that need to be reset
			 * at encap
			 */
			if (parser->cntrs)
				for (i = 0; i < KPARSER_CNTR_NUM_CNTRS; i++)
					if (parser->cntrs_conf.cntrs[i].reset_on_encap)
						cntrs->cntr[i] = 0;
		}

	} while (1);

parser_out:
	/* Convert PANDA_OKAY to PANDA_STOP_OKAY if parser is exiting normally.
	 * This means that okay_node will see PANDA_STOP_OKAY in ctrl.ret
	 */
	ctrl.ret = ctrl.ret == KPARSER_OKAY ? KPARSER_STOP_OKAY : ctrl.ret;

	parse_node = (ctrl.ret == KPARSER_OKAY || KPARSER_IS_OK_CODE(ctrl.ret)) ?
		      rcu_dereference(parser->okay_node) : rcu_dereference(parser->fail_node);

	if (!parse_node) {
		if (dflags & KPARSER_F_DEBUG_DATAPATH) {
			/* This code is required for regression tests also */
			pr_alert("kParserdump:metadata_len:%lu\n", metadata_len);
			print_hex_dump_bytes("kParserdump:md:",
					     DUMP_PREFIX_OFFSET,
					     _metadata, metadata_len);
		}
		return ctrl.ret;
	}

	/* Run an exit parse node. This is either the okay node or the fail
	 * node that is set in parser config
	 */
	ret = __kparser_run_exit_node(dflags, parser, parse_node, _obj_ref,
				      _hdr, hdr_offset, hdr_len,
				      _metadata, _frame, &ctrl);
	if (ret != KPARSER_OKAY)
		ctrl.ret = (ctrl.ret == KPARSER_STOP_OKAY) ? ret : ctrl.ret;

	if (dflags & KPARSER_F_DEBUG_DATAPATH) {
		/* This code is required for regression tests also */
		pr_alert("kParserdump:metadata_len:%lu\n", metadata_len);
		print_hex_dump_bytes("kParserdump:md:", DUMP_PREFIX_OFFSET,
				     _metadata, metadata_len);
	}

	return ctrl.ret;
}
EXPORT_SYMBOL(__kparser_parse);

static inline void *
kparser_get_parser_ctx(const struct kparser_hkey *kparser_key)
{
	void *ptr, *parser;

	if (!kparser_key)
		return NULL;

	if (kparser_key->id >= KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_START &&
	    kparser_key->id <= KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_STOP) {
		rcu_read_lock();
		ptr = kparser_fast_lookup_array[kparser_key->id];
		rcu_read_unlock();
	} else {
		ptr = kparser_namespace_lookup(KPARSER_NS_PARSER, kparser_key);
	}

	parser = rcu_dereference(ptr);

	return parser;
}

/* kparser_parse(): Function to parse a skb using a parser instance key.
 *
 * skb: input packet skb
 * kparser_key: key of the associated kParser parser object which must be
 *              already created via CLI.
 * _metadata: User provided metadata buffer. It must be same as configured
 *            metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 * avoid_ref: Set this flag in case caller wants to avoid holding the reference
 *            of the active parser object to save performance on the data path.
 *            But please be advised, caller should hold the reference of the
 *            parser object while using this data path. In this case, the CLI
 *            can be used in advance to get the reference, and caller will also
 *            need to release the reference via CLI once it is done with the
 *            data path.
 *
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 */
int kparser_parse(struct sk_buff *skb,
		  const struct kparser_hkey *kparser_key,
		  void *_metadata, size_t metadata_len, bool avoid_ref)
{
	struct kparser_glue_parser *k_prsr;
	struct kparser_parser *parser;
	void *data, *ptr;
	size_t pktlen;
	int err;
	__u32 dflags = 0;

	data = skb_mac_header(skb);
	pktlen = skb_mac_header_len(skb) + skb->len;
	if (pktlen > KPARSER_MAX_SKB_PACKET_LEN) {
		skb_pull(skb, KPARSER_MAX_SKB_PACKET_LEN);
		data = skb_mac_header(skb);
		pktlen = skb_mac_header_len(skb) + skb->len;
	}

	err = skb_linearize(skb);
	if (err < 0)
		return err;
	WARN_ON(skb->data_len);

	/* TODO: do this pullup inside the loop of ___kparser_parse(), when
	 * parse_len < hdr_len
	 * if (pktlen > KPARSER_MAX_SKB_PACKET_LEN) {
	 *	skb_pull(skb, KPARSER_MAX_SKB_PACKET_LEN);
	 *	data = skb_mac_header(skb);
	 *	pktlen = skb_mac_header_len(skb) + skb->len;
	 * }
	 * err = skb_linearize(skb);
	 * if (err < 0)
	 *	return err;
	 * WARN_ON(skb->data_len);
	 * ___kparser_parse(parser, skb, _metadata, metadata_len);
	 */
	k_prsr = kparser_get_parser_ctx(kparser_key);
	if (!k_prsr) {
		if (kparser_key)
			KPARSER_KMOD_DEBUG_PRINT(dflags, "parser {%s:%u} is not found\n",
						 kparser_key->name, kparser_key->id);
		return -EINVAL;
	}

	rcu_read_lock();

	if (likely(!avoid_ref))
		kparser_ref_get(&k_prsr->glue.refcount);
	parser = &k_prsr->parser;

	ptr = kparser_namespace_lookup(KPARSER_NS_PARSER, kparser_key);
	k_prsr = rcu_dereference(ptr);
	parser = &k_prsr->parser;
	if (!parser) {
		KPARSER_KMOD_DEBUG_PRINT(dflags,
					 "parser htbl lookup failure for key:{%s:%u}\n",
					 kparser_key->name, kparser_key->id);
		rcu_read_unlock();
		if (likely(!avoid_ref))
			kparser_ref_put(&k_prsr->glue.refcount);
		return -ENOENT;
	}

	err = __kparser_parse(parser, data, pktlen, _metadata, metadata_len);

	rcu_read_unlock();

	if (likely(!avoid_ref))
		kparser_ref_put(&k_prsr->glue.refcount);

	return err;
}
EXPORT_SYMBOL(kparser_parse);

/* kparser_get_parser(): Function to get an opaque reference of a parser instance and mark it
 * immutable so that while actively using, it can not be deleted. The parser is identified by a key.
 * It marks the associated parser and whole parse tree immutable so that when it is locked, it can
 * not be deleted.
 *
 * kparser_key: key of the associated kParser parser object which must be
 * already created via CLI.
 *
 * return: NULL if key not found, else an opaque parser instance pointer which
 * can be used in the following APIs 3 and 4.
 * avoid_ref: Set this flag in case caller wants to avoid holding the reference
 *            of the active parser object to save performance on the data path.
 *            But please be advised, caller should hold the reference of the
 *            parser object while using this data path. In this case, the CLI
 *            can be used in advance to get the reference, and caller will also
 *            need to release the reference via CLI once it is done with the
 *            data path.
 *
 * NOTE: This call makes the whole parser tree immutable. If caller calls this
 * more than once, later caller will need to release the same parser exactly that
 * many times using the API kparser_put_parser().
 */
const void *kparser_get_parser(const struct kparser_hkey *kparser_key,
			       bool avoid_ref)
{
	struct kparser_glue_parser *k_prsr;

	k_prsr = kparser_get_parser_ctx(kparser_key);
	if (!k_prsr)
		return NULL;

	if (likely(!avoid_ref))
		kparser_ref_get(&k_prsr->glue.refcount);

	return &k_prsr->parser;
}
EXPORT_SYMBOL(kparser_get_parser);

/* kparser_put_parser(): Function to return and undo the read only operation done previously by
 * kparser_get_parser(). The parser instance is identified by using a previously obtained opaque
 * parser pointer via API kparser_get_parser(). This undo the immutable change so that any component
 * of the whole parse tree can be deleted again.
 *
 * parser: void *, Non NULL opaque pointer which was previously returned by kparser_get_parser().
 * Caller can use cached opaque pointer as long as system does not restart and kparser.ko is not
 * reloaded.
 * avoid_ref: Set this flag only when this was used in the prio call to
 *            kparser_get_parser(). Incorrect usage of this flag might cause
 *            error and make the parser state unstable.
 *
 * return: boolean, true if put operation is success, else false.
 *
 * NOTE: This call makes the whole parser tree deletable for the very last call.
 */
bool kparser_put_parser(const void *obj, bool avoid_ref)
{
	const struct kparser_parser *parser = obj;
	struct kparser_glue_parser *k_parser;

	if (!parser)
		return false;

	if (likely(!avoid_ref)) {
		k_parser = container_of(parser, struct kparser_glue_parser, parser);
		kparser_ref_put(&k_parser->glue.refcount);
	}

	return true;
}
EXPORT_SYMBOL(kparser_put_parser);
