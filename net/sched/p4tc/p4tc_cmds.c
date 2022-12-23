// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_cmds.c - P4 TC cmds
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>

#include <net/act_api.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/p4tc_types.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/p4tc.h>

#include <uapi/linux/p4tc.h>

#define GET_OPA(operands_list) \
	(list_first_entry(operands_list, struct p4tc_cmd_operand, \
			  oper_list_node))

#define GET_OPB(operands_list) (list_next_entry(GET_OPA(operands_list), \
						oper_list_node))

#define GET_OPC(operands_list) (list_next_entry(GET_OPB(operands_list), \
						oper_list_node))

static void *p4tc_fetch_metadata(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_constant(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_key(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			    struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_table(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			      struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_result(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			       struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_hdrfield(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_param(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			      struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_dev(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			    struct tcf_p4act *cmd, struct tcf_result *res);
static void *p4tc_fetch_reg(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			    struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_SET(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_ACT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_PRINT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			  struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_TBLAPP(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			   struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_SNDPORTEGR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			       struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_MIRPORTEGR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			       struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_PLUS(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_SUB(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_CONCAT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			   struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_BAND(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_BOR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res);
static int p4tc_cmd_BXOR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res);

static void kfree_opentry(struct p4tc_cmd_operate *ope)
{
	if (!ope)
		return;

	ope->cmd->free_operation(ope, NULL);
}

static void copy_k2u_operand(struct p4tc_cmd_operand *k,
			     struct p4tc_u_operand *u)
{
	u->pipeid = k->pipeid;
	u->immedv = k->immedv;
	u->immedv2 = k->immedv2;
	u->oper_type = k->oper_type;
	u->oper_datatype = k->oper_datatype->typeid;
	u->oper_cbitsize = k->oper_cbitsize;
	u->oper_startbit = k->oper_bitstart;
	u->oper_endbit = k->oper_bitend;
	u->oper_flags = k->oper_flags;
}

static int copy_u2k_operand(struct p4tc_u_operand *uopnd,
			    struct p4tc_cmd_operand *kopnd,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_type *type;

	type = p4type_find_byid(uopnd->oper_datatype);
	if (kopnd->oper_flags & DATA_HAS_TYPE_INFO && !type) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid operand type");
		return -EINVAL;
	}

	kopnd->pipeid = uopnd->pipeid;
	kopnd->immedv = uopnd->immedv;
	kopnd->immedv2 = uopnd->immedv2;
	kopnd->oper_type = uopnd->oper_type;
	kopnd->oper_datatype = type;
	kopnd->oper_cbitsize = uopnd->oper_cbitsize;
	kopnd->oper_bitstart = uopnd->oper_startbit;
	kopnd->oper_bitend = uopnd->oper_endbit;
	kopnd->oper_bitsize = 1 + kopnd->oper_bitend - kopnd->oper_bitstart;
	kopnd->oper_flags = uopnd->oper_flags;

	return 0;
}

static int p4tc_cmds_fill_operands_list(struct sk_buff *skb,
					struct list_head *operands_list)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_u_operand oper = {0};
	int i = 1;
	struct p4tc_cmd_operand *cursor;
	struct nlattr *nest_count;
	u32 plen;

	list_for_each_entry(cursor, operands_list, oper_list_node) {
		nest_count = nla_nest_start(skb, i);

		copy_k2u_operand(cursor, &oper);
		if (nla_put(skb, P4TC_CMD_OPND_INFO,
			    sizeof(struct p4tc_u_operand), &oper))
			goto nla_put_failure;

		if (cursor->path_or_value &&
		    nla_put_string(skb, P4TC_CMD_OPND_PATH, cursor->path_or_value))
			goto nla_put_failure;

		if (cursor->path_or_value_extra &&
		    nla_put_string(skb, P4TC_CMD_OPND_PATH_EXTRA,
				   cursor->path_or_value_extra))
			goto nla_put_failure;

		if (cursor->print_prefix &&
		    nla_put_string(skb, P4TC_CMD_OPND_PREFIX,
				   cursor->print_prefix))
			goto nla_put_failure;

		plen = cursor->immedv_large_sz;

		if (plen && nla_put(skb, P4TC_CMD_OPND_LARGE_CONSTANT, plen,
				    cursor->immedv_large))
			goto nla_put_failure;
		nla_nest_end(skb, nest_count);
		i++;
	}

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

/* under spin lock */
int p4tc_cmds_fillup(struct sk_buff *skb, struct list_head *cmd_operations)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_u_operate op = { };
	int i = 1;
	struct nlattr *nest_op, *nest_opnds;
	struct p4tc_cmd_operate *entry;
	int err;

	list_for_each_entry(entry, cmd_operations, cmd_operations) {
		nest_op = nla_nest_start(skb, i);

		op.op_type = entry->op_id;
		op.op_flags = entry->op_flags;
		op.op_ctl1 =  entry->ctl1;
		op.op_ctl2 =  entry->ctl2;
		if (nla_put(skb, P4TC_CMD_OPERATION,
			    sizeof(struct p4tc_u_operate), &op))
			goto nla_put_failure;

		if (!list_empty(&entry->operands_list)) {
			nest_opnds = nla_nest_start(skb, P4TC_CMD_OPER_LIST);
			err = p4tc_cmds_fill_operands_list(skb,
							   &entry->operands_list);
			if (err < 0)
				goto nla_put_failure;
			nla_nest_end(skb, nest_opnds);
		}

		nla_nest_end(skb, nest_op);
		i++;
	}

	return 0;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

void p4tc_cmds_release_ope_list(struct list_head *entries)
{
	struct p4tc_cmd_operate *entry, *e;

	list_for_each_entry_safe(entry, e, entries, cmd_operations) {
		list_del(&entry->cmd_operations);
		kfree_opentry(entry);
	}
}

static void kfree_tmp_oplist(struct p4tc_cmd_operate *oplist[])
{
	int i = 0;
	struct p4tc_cmd_operate *ope;

	for (i = 0; i < P4TC_CMDS_LIST_MAX; i++) {
		ope = oplist[i];
		if (!ope)
			continue;

		kfree_opentry(ope);
	}
}

static int validate_metadata_operand(struct p4tc_cmd_operand *kopnd,
				     struct p4tc_type *container_type,
				     struct netlink_ext_ack *extack)
{
	struct p4tc_type_ops *type_ops = container_type->ops;
	int err;

	if (kopnd->oper_cbitsize < kopnd->oper_bitsize) {
		NL_SET_ERR_MSG_MOD(extack,
				   "bitsize has to be <= cbitsize\n");
		return -EINVAL;
	}

	if (type_ops->validate_p4t) {
		if (kopnd->oper_type == P4TC_OPER_CONST)
			if (kopnd->oper_flags & DATA_IS_IMMEDIATE) {
				err = type_ops->validate_p4t(container_type,
							     &kopnd->immedv,
							     kopnd->oper_bitstart,
							     kopnd->oper_bitend,
							     extack);
			} else {
				err = type_ops->validate_p4t(container_type,
							     kopnd->immedv_large,
							     kopnd->oper_bitstart,
							     kopnd->oper_bitend,
							     extack);
			}
		else
			err = type_ops->validate_p4t(container_type,
						     NULL,
						     kopnd->oper_bitstart,
						     kopnd->oper_bitend,
						     extack);
		if (err)
			return err;
	}

	return 0;
}

static int validate_table_operand(struct p4tc_act *act,
				  struct p4tc_cmd_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;

	table = tcf_table_find_byany(act->pipeline,
				     (const char*)kopnd->path_or_value,
				     kopnd->immedv, extack);
	if (IS_ERR(table))
		return PTR_ERR(table);

	if (kopnd->immedv2) {
		if (!tcf_table_key_find(table, kopnd->immedv2)) {
			NL_SET_ERR_MSG_MOD(extack, "Unknown key id");
			return -EINVAL;
		}
	} else {
		kopnd->immedv2 = table->tbl_default_key;
	}

	kopnd->oper_value_ops = &table->tbl_value_ops;

	return 0;
}

static int validate_key_operand(struct p4tc_act *act,
				struct p4tc_cmd_operand *kopnd,
				struct netlink_ext_ack *extack)
{
	struct p4tc_type *t = kopnd->oper_datatype;
	struct p4tc_table *table;

	kopnd->pipeid = act->pipeline->common.p_id;

	table = tcf_table_find_byany(act->pipeline,
				     (const char*)kopnd->path_or_value,
				     kopnd->immedv, extack);
	if (IS_ERR(table))
		return PTR_ERR(table);
	kopnd->immedv = table->tbl_id;

	if (!tcf_table_key_find(table, kopnd->immedv2)) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown key id");
		return -EINVAL;
	}

	if (kopnd->oper_flags & DATA_HAS_TYPE_INFO) {
		if (kopnd->oper_bitstart != 0) {
			NL_SET_ERR_MSG_MOD(extack, "Key bitstart must be zero");
			return -EINVAL;
		}

		if (t->typeid != P4T_KEY) {
			NL_SET_ERR_MSG_MOD(extack, "Key type must be key");
			return -EINVAL;
		}

		if (table->tbl_keysz != kopnd->oper_bitsize) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Type size doesn't match table keysz");
			return -EINVAL;
		}

		t->bitsz = kopnd->oper_bitsize;
	} else {
		t = p4type_find_byid(P4T_KEY);
		if (!t)
			return -EINVAL;

		kopnd->oper_bitstart = 0;
		kopnd->oper_bitend = table->tbl_keysz - 1;
		kopnd->oper_bitsize = table->tbl_keysz;
		kopnd->oper_datatype = t;
	}

	return 0;
}

static int validate_hdrfield_operand_type(struct p4tc_cmd_operand *kopnd,
					  struct p4tc_header_field *hdrfield,
					  struct netlink_ext_ack *extack)
{
	if (hdrfield->startbit != kopnd->oper_bitstart ||
	    hdrfield->endbit != kopnd->oper_bitend ||
	    hdrfield->datatype != kopnd->oper_datatype->typeid) {
		NL_SET_ERR_MSG_MOD(extack, "Header field type mismatch");
		return -EINVAL;
	}

	return 0;
}

static int validate_hdrfield_operand(struct p4tc_act *act,
				     struct p4tc_cmd_operand *kopnd,
				     struct netlink_ext_ack *extack)
{
	struct p4tc_header_field *hdrfield;
	struct p4tc_parser *parser;
	struct p4tc_type *typ;

	kopnd->pipeid = act->pipeline->common.p_id;

	parser = tcf_parser_find_byany(act->pipeline,
				       (const char*)kopnd->path_or_value,
				       kopnd->immedv, extack);
	if (IS_ERR(parser))
		return PTR_ERR(parser);
	kopnd->immedv = parser->parser_inst_id;

	hdrfield = tcf_hdrfield_find_byany(parser,
					   (const char*)kopnd->path_or_value_extra,
					   kopnd->immedv2, extack);
	if (IS_ERR(hdrfield))
		return PTR_ERR(hdrfield);
	kopnd->immedv2 = hdrfield->hdr_field_id;

	if (kopnd->oper_flags & DATA_HAS_TYPE_INFO) {
		if (validate_hdrfield_operand_type(kopnd, hdrfield, extack) < 0)
			return -EINVAL;
	} else {
		kopnd->oper_bitstart = hdrfield->startbit;
		kopnd->oper_bitend = hdrfield->endbit;
		kopnd->oper_datatype = p4type_find_byid(hdrfield->datatype);
		kopnd->oper_bitsize = hdrfield->endbit - hdrfield->startbit + 1;
		kopnd->oper_cbitsize = kopnd->oper_datatype->container_bitsz;
	}
	typ = kopnd->oper_datatype;
	if (typ->ops->create_bitops) {
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = typ->ops->create_bitops(kopnd->oper_bitsize,
						     kopnd->oper_bitstart,
						     kopnd->oper_bitend,
						     extack);
		if (IS_ERR(mask_shift))
			return PTR_ERR(mask_shift);

		kopnd->oper_mask_shift = mask_shift;
	}

	kopnd->oper_value_ops = &hdrfield->h_value_ops;

	refcount_inc(&act->pipeline->p_hdrs_used);

	return 0;
}

int validate_dev_operand(struct net *net, struct p4tc_cmd_operand *kopnd,
			 struct netlink_ext_ack *extack)
{
	struct net_device *dev;

	if (kopnd->oper_datatype->typeid != P4T_DEV) {
		NL_SET_ERR_MSG_MOD(extack, "dev parameter must be dev");
		return -EINVAL;
	}

	if (kopnd->oper_datatype->ops->validate_p4t(kopnd->oper_datatype,
						    &kopnd->immedv,
						    kopnd->oper_bitstart,
						    kopnd->oper_bitend,
						    extack) < 0) {
		return -EINVAL;
	}

	dev = dev_get_by_index(net, kopnd->immedv);
	if (!dev) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid ifindex");
		return -EINVAL;
	}

	kopnd->priv = dev;

	return 0;
}

static int validate_param_operand(struct p4tc_act *act,
				  struct p4tc_cmd_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param;
	struct p4tc_type *t;

	param = tcf_param_find_byany(act,
				    (const char*)kopnd->path_or_value,
				    kopnd->immedv2, extack);

	if (IS_ERR(param))
		return PTR_ERR(param);

	kopnd->pipeid = act->pipeline->common.p_id;
	kopnd->immedv = act->a_id;
	kopnd->immedv2 = param->id;

	t = p4type_find_byid(param->type);
	if (kopnd->oper_flags & DATA_HAS_TYPE_INFO) {
		if (t->typeid != kopnd->oper_datatype->typeid) {
			NL_SET_ERR_MSG_MOD(extack, "Param type mismatch");
			return -EINVAL;
		}

		if (t->bitsz != kopnd->oper_datatype->bitsz) {
			NL_SET_ERR_MSG_MOD(extack, "Param size mismatch");
			return -EINVAL;
		}
	} else {
		kopnd->oper_datatype = t;
		kopnd->oper_bitstart = 0;
		kopnd->oper_bitend = t->bitsz - 1;
		kopnd->oper_bitsize = t->bitsz;
	}

	if (kopnd->oper_bitstart != 0) {
		NL_SET_ERR_MSG_MOD(extack, "Param startbit must be zero");
		return -EINVAL;
	}

	if (kopnd->oper_bitstart > kopnd->oper_bitend) {
		NL_SET_ERR_MSG_MOD(extack, "Param startbit > endbit");
		return -EINVAL;
	}

	if (t->ops->create_bitops) {
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = t->ops->create_bitops(kopnd->oper_bitsize,
						   kopnd->oper_bitstart,
						   kopnd->oper_bitend,
						   extack);
		if (IS_ERR(mask_shift))
			return PTR_ERR(mask_shift);

		kopnd->oper_mask_shift = mask_shift;
	}

	return 0;
}

static int validate_res_operand(struct p4tc_cmd_operand *kopnd,
				struct netlink_ext_ack *extack)
{
	if (kopnd->immedv == P4TC_CMDS_RESULTS_HIT ||
	    kopnd->immedv == P4TC_CMDS_RESULTS_MISS)
		return 0;

	NL_SET_ERR_MSG_MOD(extack, "Invalid result field");
	return -EINVAL;
}

static int validate_reg_operand(struct p4tc_act *act,
				struct p4tc_cmd_operand *kopnd,
				struct netlink_ext_ack *extack)
{
	struct p4tc_register *reg;
	struct p4tc_type *t;

	reg = tcf_register_find_byany(act->pipeline,
				      (const char *)kopnd->path_or_value,
				      kopnd->immedv, extack);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	kopnd->pipeid = act->pipeline->common.p_id;

	if (kopnd->immedv2 >= reg->reg_num_elems) {
		NL_SET_ERR_MSG_MOD(extack, "Register index out of bounds");
		return -EINVAL;
	}
	kopnd->immedv = reg->reg_id;

	t = reg->reg_type;
	kopnd->oper_datatype = t;

	if (kopnd->oper_flags & DATA_HAS_TYPE_INFO) {
		if (reg->reg_type->typeid != kopnd->oper_datatype->typeid) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid register data type");
			return -EINVAL;
		}

		if (kopnd->oper_bitstart > kopnd->oper_bitend) {
			NL_SET_ERR_MSG_MOD(extack, "Register startbit > endbit");
			return -EINVAL;
		}
	} else {
		kopnd->oper_bitstart = 0;
		kopnd->oper_bitend = t->bitsz - 1;
		kopnd->oper_bitsize = t->bitsz;
	}

	if (t->ops->create_bitops) {
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = t->ops->create_bitops(kopnd->oper_bitsize,
						   kopnd->oper_bitstart,
						   kopnd->oper_bitend,
						   extack);
		if (IS_ERR(mask_shift))
			return PTR_ERR(mask_shift);

		kopnd->oper_mask_shift = mask_shift;
	}

	/* Should never fail */
	WARN_ON(!refcount_inc_not_zero(&reg->reg_ref));

	kopnd->priv = reg;

	return 0;
}

static struct p4tc_type_mask_shift *
create_metadata_bitops(struct p4tc_cmd_operand *kopnd,
		       struct p4tc_metadata *meta, struct p4tc_type *t,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;
	u8 bitstart, bitend;
	u32 bitsz;

	bitstart = meta->m_startbit + kopnd->oper_bitstart;
	bitend = meta->m_startbit + kopnd->oper_bitend;
	bitsz = bitend - bitstart + 1;
	mask_shift = t->ops->create_bitops(bitsz, bitstart, bitend,
					   extack);
	return mask_shift;
}

static int __validate_metadata_operand(struct p4tc_act *act,
				       struct p4tc_cmd_operand *kopnd,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_type *container_type;
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;
	u32 bitsz;
	int err;

	if (kopnd->oper_flags & DATA_USES_ROOT_PIPE)
		pipeline = tcf_pipeline_find_byid(0);
	else
		pipeline = act->pipeline;

	kopnd->pipeid = pipeline->common.p_id;

	meta = tcf_meta_find_byany(pipeline, (const char *)kopnd->path_or_value,
				   kopnd->immedv, extack);
	if (IS_ERR(meta))
		return PTR_ERR(meta);
	kopnd->immedv = meta->m_id;

	if (!(kopnd->oper_flags & DATA_IS_SLICE)) {
		kopnd->oper_bitstart = meta->m_startbit;
		kopnd->oper_bitend = meta->m_endbit;

		bitsz = meta->m_endbit - meta->m_startbit + 1;
		kopnd->oper_bitsize = bitsz;
	} else {
		bitsz = kopnd->oper_bitend - kopnd->oper_bitstart + 1;
	}

	if (kopnd->oper_flags & DATA_HAS_TYPE_INFO) {
		if (meta->m_datatype != kopnd->oper_datatype->typeid) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid metadata data type");
			return -EINVAL;
		}

		if (bitsz < kopnd->oper_bitsize) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid metadata bit size");
			return -EINVAL;
		}

		if (kopnd->oper_bitstart > meta->m_endbit) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid metadata slice start bit");
			return -EINVAL;
		}

		if (kopnd->oper_bitend > meta->m_endbit) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid metadata slice end bit");
			return -EINVAL;
		}
	} else {
		kopnd->oper_datatype = p4type_find_byid(meta->m_datatype);
		kopnd->oper_bitsize = bitsz;
		kopnd->oper_cbitsize = bitsz;
	}

	container_type = p4type_find_byid(meta->m_datatype);
	if (!container_type) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid metadata type");
		return -EINVAL;
	}

	err = validate_metadata_operand(kopnd, container_type, extack);
	if (err < 0)
		return err;

	if (container_type->ops->create_bitops) {
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = create_metadata_bitops(kopnd, meta,
						    container_type, extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;

		kopnd->oper_mask_shift = mask_shift;
	}
	kopnd->oper_value_ops = &meta->m_value_ops;

	return 0;
}

static struct p4tc_type_mask_shift *
create_constant_bitops(struct p4tc_cmd_operand *kopnd, struct p4tc_type *t,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;

	mask_shift = t->ops->create_bitops(t->bitsz,
					   kopnd->oper_bitstart,
					   kopnd->oper_bitend, extack);
	return mask_shift;
}

static int validate_large_operand(struct p4tc_cmd_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_type *t = kopnd->oper_datatype;
	int err = 0;

	err = validate_metadata_operand(kopnd, t, extack);
	if (err)
		return err;
	if (t->ops->create_bitops) {
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = create_constant_bitops(kopnd, t, extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;

		kopnd->oper_mask_shift = mask_shift;
	}

	return 0;
}

/*Data is constant <=32 bits */
static int validate_immediate_operand(struct p4tc_cmd_operand *kopnd,
				      struct netlink_ext_ack *extack)
{
	struct p4tc_type *t = kopnd->oper_datatype;
	int err = 0;

	err = validate_metadata_operand(kopnd, t, extack);
	if (err)
		return err;
	if (t->ops->create_bitops) {
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = create_constant_bitops(kopnd, t, extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;

		kopnd->oper_mask_shift = mask_shift;
	}

	return 0;
}

static int validate_operand(struct net *net, struct p4tc_act *act,
			    struct p4tc_cmd_operand *kopnd,
			    struct netlink_ext_ack *extack)
{
	int err = 0;

	if (!kopnd)
		return err;

	switch(kopnd->oper_type) {
	case P4TC_OPER_CONST:
		if (kopnd->oper_flags & DATA_IS_IMMEDIATE)
			err = validate_immediate_operand(kopnd, extack);
		else
			err = validate_large_operand(kopnd, extack);
		break;
	case P4TC_OPER_META:
		err = __validate_metadata_operand(act, kopnd, extack);
		break;
	case P4TC_OPER_ACTID:
		err = 0;
		break;
	case P4TC_OPER_TBL:
		err = validate_table_operand(act, kopnd, extack);
		break;
	case P4TC_OPER_KEY:
		err = validate_key_operand(act, kopnd, extack);
		break;
	case P4TC_OPER_RES:
		err = validate_res_operand(kopnd, extack);
		break;
	case P4TC_OPER_HDRFIELD:
		err = validate_hdrfield_operand(act, kopnd, extack);
		break;
	case P4TC_OPER_PARAM:
		err = validate_param_operand(act, kopnd, extack);
		break;
	case P4TC_OPER_DEV:
		err = validate_dev_operand(net, kopnd, extack);
		break;
	case P4TC_OPER_REG:
		err = validate_reg_operand(act, kopnd, extack);
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown operand type");
		err = -EINVAL;
	}

	return err;
}

#define noop

static void _free_operand(struct p4tc_cmd_operand *op)
{
	if (op->oper_type == P4TC_OPER_HDRFIELD) {
		struct p4tc_pipeline *pipeline;

		pipeline = tcf_pipeline_find_byid(op->pipeid);
		/* Should never be NULL */
		if (pipeline)
			refcount_dec(&pipeline->p_hdrs_used);
	} else if (op->oper_type == P4TC_OPER_REG) {
		struct p4tc_pipeline *pipeline;

		pipeline = tcf_pipeline_find_byid(op->pipeid);
		/* Should never be NULL */
		if (pipeline) {
			struct p4tc_register *reg;

			reg = tcf_register_find_byid(pipeline, op->immedv);
			/* The cmd creation may be aborted before we call
			 * validate_operand, but the free function will always
			 * be called after an abort. With this in mind, what may
			 * happen is this function is called and
			 * validate_operand is never called. When that happends,
			 * the refcount was not incremented. To account for this
			 * case, we need to check the refcount before decrementing
			 */
			if (reg && !refcount_dec_not_one(&reg->reg_ref))
				noop;
		}
	}
	if (op->oper_mask_shift)
		p4t_release(op->oper_mask_shift);
	kfree(op->path_or_value);
	kfree(op->path_or_value_extra);
	kfree(op->print_prefix);
	kfree(op);
}

static void _free_operand_list(struct list_head *operands_list)
{
	struct p4tc_cmd_operand *op, *tmp;

	list_for_each_entry_safe(op, tmp, operands_list, oper_list_node) {
		list_del(&op->oper_list_node);
		_free_operand(op);
	}
}

static void _free_operation(struct p4tc_cmd_operate *ope,
			    struct netlink_ext_ack *extack)
{
	_free_operand_list(&ope->operands_list);

	kfree(ope);
}

static void free_op_SET(struct p4tc_cmd_operate *ope,
			struct netlink_ext_ack *extack)
{
	return _free_operation(ope, extack);
}

/* XXX: copied from act_api::tcf_free_cookie_rcu - at some point share the code */
static void _tcf_free_cookie_rcu(struct rcu_head *p)
{
	struct tc_cookie *cookie = container_of(p, struct tc_cookie, rcu);

	kfree(cookie->data);
	kfree(cookie);
}

/* XXX: copied from act_api::tcf_set_action_cookie - at some point share the code */
static void _tcf_set_action_cookie(struct tc_cookie __rcu **old_cookie,
				   struct tc_cookie *new_cookie)
{
	struct tc_cookie *old;

	old = xchg((__force struct tc_cookie **)old_cookie, new_cookie);
	if (old)
		call_rcu(&old->rcu, _tcf_free_cookie_rcu);
}

/* XXX: copied from act_api::free_tcf - at some point share the code */
static void _free_tcf(struct tc_action *p)
{
	struct tcf_chain *chain = rcu_dereference_protected(p->goto_chain, 1);

	free_percpu(p->cpu_bstats);
	free_percpu(p->cpu_bstats_hw);
	free_percpu(p->cpu_qstats);

	_tcf_set_action_cookie(&p->act_cookie, NULL);
	if (chain)
		tcf_chain_put_by_act(chain);

	kfree(p);
}

static void free_op_ACT(struct p4tc_cmd_operate *ope,
			struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A;
	struct tc_action *p = NULL;

	A = GET_OPA(&ope->operands_list);
	if (A)
		p = A->action;

	if (p) {
		struct tcf_idrinfo *idrinfo = p->idrinfo;

		if (refcount_dec_and_mutex_lock(&p->tcfa_refcnt,
						&idrinfo->lock)) {
			idr_remove(&idrinfo->action_idr, p->tcfa_index);
			mutex_unlock(&idrinfo->lock);

			if (p->ops->cleanup)
				p->ops->cleanup(p);

			gen_kill_estimator(&p->tcfa_rate_est);
			_free_tcf(p);
		}

		atomic_dec(&p->tcfa_bindcnt);
	}

	return _free_operation(ope, extack);
}

static int __validate_BINARITH(struct net *net, struct p4tc_act *act,
			       struct list_head *operands_list,
			       const size_t max_operands,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A, *cursor;
	struct p4tc_type *Atype;
	int err;
	int i = 0;

	A = GET_OPA(operands_list);
	err = validate_operand(net, act, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	switch (A->oper_type) {
	case P4TC_OPER_KEY:
	case P4TC_OPER_META:
	case P4TC_OPER_HDRFIELD:
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand A must be key, metadata or hdrfield");
		return -EINVAL;
	}

	cursor = A;
	list_for_each_entry_continue(cursor, operands_list, oper_list_node) {
		struct p4tc_type *cursor_type;

		if (i == max_operands - 1) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Operands list exceeds maximum allowed value");
			return -EINVAL;
		}

		switch (cursor->oper_type) {
		case P4TC_OPER_KEY:
		case P4TC_OPER_META:
		case P4TC_OPER_CONST:
		case P4TC_OPER_HDRFIELD:
		case P4TC_OPER_PARAM:
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Rvalue operand must be key, metadata, const, hdrfield or param");
			return -EINVAL;
		}

		err = validate_operand(net, act, cursor, extack);
		if (err < 0)
			return err;

		cursor_type = cursor->oper_datatype;
		if (!cursor_type->ops->host_read) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Rvalue operand's types must have host_read op");
			return -EINVAL;
		}
		if (cursor->oper_bitsize % 8 != 0) {
			NL_SET_ERR_MSG_MOD(extack,
					   "All Rvalues must have bitsize multiple of 8");
			return -EINVAL;
		}
		i++;
	}

	Atype = A->oper_datatype;
	if (!Atype->ops->host_write) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand A's type must have host_write op");
		return -EINVAL;
	}

	return 0;
}

static int validate_num_opnds(struct p4tc_cmd_operate *ope, u32 cmd_num_opnds)
{
	if (ope->num_opnds != cmd_num_opnds)
		return -EINVAL;

	return 0;
}

/* Syntax: act ACTION_ID ACTION_INDEX
 * Operation: The tc action instance of kind ID ACTION_ID and index ACTION_INDEX
 * is executed.
 * Restriction: The action instance must exist.
 */
int validate_ACT(struct net *net, struct p4tc_act *act,
		 struct p4tc_cmd_operate *ope,
		 u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct tc_action_ops *action_ops;
	struct p4tc_cmd_operand *A;
	struct tc_action *action;
	int err;

	err = validate_num_opnds(ope, cmd_num_opnds);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "ACT must have only 1 operands");
		return err;
	}

	A = GET_OPA(&ope->operands_list);
	if (A->oper_type != P4TC_OPER_ACTID) {
		NL_SET_ERR_MSG_MOD(extack, "ACT: Operand type MUST be P4TC_OPER_ACTID\n");
		return -EINVAL;
	}

	A->oper_datatype = p4type_find_byid(P4T_U32);

	if (A->oper_flags & DATA_USES_ROOT_PIPE) {
		action_ops = tc_lookup_action_byid(A->immedv);
		if (!action_ops) {
			NL_SET_ERR_MSG_MOD(extack,
					   "ACT: unknown Action Kind");
			return -EINVAL;
		}
		A->pipeid = 0;
	} else {
		act = tcf_action_find_byany(act->pipeline,
					    (const char*)A->path_or_value,
					    A->immedv, extack);

		if (IS_ERR(act))
			return PTR_ERR(act);

		A->pipeid = act->pipeline->common.p_id;
		A->immedv = act->a_id;

		action_ops = &act->ops;
	}

	if (__tcf_idr_search(net, action_ops, &action, A->immedv2) == false) {
		NL_SET_ERR_MSG_MOD(extack, "ACT: unknown Action index\n");
		module_put(action_ops->owner);
		return -EINVAL;
	}

	A->action = action;
	atomic_inc(&action->tcfa_bindcnt);
	return 0;
}

/* Syntax: set A B
 * Operation: B is written to A.
 * A could header, or metadata or key
 * B could be a constant, header, or metadata
 * Restriction: A and B dont have to be of the same size and type
 * as long as B's value could be less bits than A
 * (example a U16 setting into a U32, etc)
 */
int validate_SET(struct net *net, struct p4tc_act *act,
		 struct p4tc_cmd_operate *ope,
		 u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A, *B;
	struct p4tc_type *Atype;
	struct p4tc_type *Btype;
	int err = 0;

	err = validate_num_opnds(ope, cmd_num_opnds);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "SET must have only 2 operands");
		return err;
	}

	A = GET_OPA(&ope->operands_list);

	if (A->oper_type == P4TC_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A cannot be constant\n");
		return -EINVAL;
	}

	if (A->oper_type == P4TC_OPER_RES) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand A cannot be a results field\n");
		return -EINVAL;
	}

	if (A->oper_type == P4TC_OPER_PARAM) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A cannot be a param");
		return -EINVAL;
	}

	B = GET_OPB(&ope->operands_list);
	if (B->oper_type == P4TC_OPER_KEY) {
		NL_SET_ERR_MSG_MOD(extack, "Operand B cannot be key\n");
		return -EINVAL;
	}

	err = validate_operand(net, act, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = validate_operand(net, act, B, extack);
	if (err)
		return err;

	Atype = A->oper_datatype;
	Btype = B->oper_datatype;
	if (!Atype->ops->host_read || !Btype->ops->host_read) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Types of A and B must have host_read op");
		return -EINVAL;
	}

	if (!Atype->ops->host_write || !Btype->ops->host_write) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Types of A and B must have host_write op");
		return -EINVAL;
	}

	if (A->oper_bitsize < B->oper_bitsize) {
		NL_SET_ERR_MSG_MOD(extack,
				   "set: B.bitsize has to be <= A.bitsize\n");
		return -EINVAL;
	}

	if (A->oper_bitsize != B->oper_bitsize) {
		/* We allow them as long as the value of B can fit in A
		 * which has already been verified at this point
		 */
		u64 Amaxval;
		u64 Bmaxval;

		/* Anything can be assigned to P4T_U128 */
		if (A->oper_datatype->typeid == P4T_U128)
			return 0;

		Amaxval = GENMASK_ULL(A->oper_bitend, A->oper_bitstart);

		if (B->oper_type == P4TC_OPER_CONST)
			Bmaxval = B->immedv;
		else
			Bmaxval = GENMASK_ULL(B->oper_bitend, B->oper_bitstart);

		if (Bmaxval > Amaxval) {
			NL_SET_ERR_MSG_MOD(extack,
					   "set: B bits has to fit in A\n");
			return -EINVAL;
		}
	}

	return 0;
}

int validate_PRINT(struct net *net, struct p4tc_act *act,
		   struct p4tc_cmd_operate *ope,
		   u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A;
	int err;

	err = validate_num_opnds(ope, cmd_num_opnds);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "print must have only 1 operands");
		return err;
	}

	A = GET_OPA(&ope->operands_list);

	if (A->oper_type == P4TC_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A cannot be constant\n");
		return -EINVAL;
	}

	return validate_operand(net, act, A, extack);
}

int validate_TBLAPP(struct net *net, struct p4tc_act *act,
		    struct p4tc_cmd_operate *ope,
		    u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A;
	int err;

	err = validate_num_opnds(ope, cmd_num_opnds);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "tableapply must have only 1 operands");
		return err;
	}

	A = GET_OPA(&ope->operands_list);
	if (A->oper_type != P4TC_OPER_TBL) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A must be a table\n");
		return -EINVAL;
	}

	err = validate_operand(net, act, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	return 0;
}

int validate_SNDPORTEGR(struct net *net, struct p4tc_act *act,
			struct p4tc_cmd_operate *ope,
			u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A;
	int err;

	err = validate_num_opnds(ope, cmd_num_opnds);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "send_port_egress must have only 1 operands");
		return err;
	}

	A = GET_OPA(&ope->operands_list);

	err = validate_operand(net, act, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	return 0;
}

int validate_BINARITH(struct net *net, struct p4tc_act *act,
		      struct p4tc_cmd_operate *ope,
		      u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A, *B, *C;
	struct p4tc_type *Atype;
	struct p4tc_type *Btype;
	struct p4tc_type *Ctype;
	int err;

	err = __validate_BINARITH(net, act, &ope->operands_list, cmd_num_opnds,
				  extack);
	if (err)
		return err;

	A = GET_OPA(&ope->operands_list);
	B = GET_OPB(&ope->operands_list);
	C = GET_OPC(&ope->operands_list);

	Atype = A->oper_datatype;
	Btype = B->oper_datatype;
	Ctype = C->oper_datatype;

	/* For now, they must be the same.
	 * Will change that very soon.
	 */
	if (Atype != Btype || Atype != Ctype) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Type of A, B and C must be the same");
		return -EINVAL;
	}

	return 0;
}

int validate_CONCAT(struct net *net, struct p4tc_act *act,
		    struct p4tc_cmd_operate *ope,
		    u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *cursor, *A;
	size_t rvalue_tot_sz = 0;
	int err;
	int i = 0;

	A = GET_OPA(&ope->operands_list);

	err = __validate_BINARITH(net, act, &ope->operands_list,
				  cmd_num_opnds, extack);
	if (err)
		return err;

	cursor = A;
	list_for_each_entry_continue(cursor, &ope->operands_list, oper_list_node) {
		if (cursor->oper_bitsize % 8 != 0) {
			NL_SET_ERR_MSG_MOD(extack,
					   "All Rvalues must have bitsize multiple of 8");
			return -EINVAL;
		}
		rvalue_tot_sz += cursor->oper_bitsize;
		i++;
	}

	if (i < 2) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Concat must have at least 3 operands");
		return -EINVAL;
	}

	if (A->oper_bitsize < rvalue_tot_sz) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Rvalue operands concatenated must fit inside operand A");
		return -EINVAL;
	}

	return 0;
}

static void p4tc_reg_lock(struct p4tc_cmd_operand *A,
			  struct p4tc_cmd_operand *B,
			  struct p4tc_cmd_operand *C)
{
	struct p4tc_register *regA, *regB, *regC;

	if (A->oper_type == P4TC_OPER_REG) {
		regA = A->priv;
		spin_lock_bh(&regA->reg_value_lock);
	}

	if (B && B->oper_type == P4TC_OPER_REG) {
		regB = B->priv;
		spin_lock_bh(&regB->reg_value_lock);
	}

	if (C && C->oper_type == P4TC_OPER_REG) {
		regC = C->priv;
		spin_lock_bh(&regC->reg_value_lock);
	}
}

static void p4tc_reg_unlock(struct p4tc_cmd_operand *A,
			    struct p4tc_cmd_operand *B,
			    struct p4tc_cmd_operand *C)
{
	struct p4tc_register *regA, *regB, *regC;

	if (C && C->oper_type == P4TC_OPER_REG) {
		regC = C->priv;
		spin_unlock_bh(&regC->reg_value_lock);
	}

	if (B && B->oper_type == P4TC_OPER_REG) {
		regB = B->priv;
		spin_unlock_bh(&regB->reg_value_lock);
	}

	if (A->oper_type == P4TC_OPER_REG) {
		regA = A->priv;
		spin_unlock_bh(&regA->reg_value_lock);
	}
}

static int p4tc_cmp_op(struct p4tc_cmd_operand *A, struct p4tc_cmd_operand *B,
		       void *Aval, void *Bval)
{
	int res;

	p4tc_reg_lock(A, B, NULL);

	res = p4t_cmp(A->oper_mask_shift, A->oper_datatype, Aval,
		      B->oper_mask_shift, B->oper_datatype, Bval);

	p4tc_reg_unlock(A, B, NULL);

	return res;
}

static int p4tc_copy_op(struct p4tc_cmd_operand *A, struct p4tc_cmd_operand *B,
			void *Aval, void *Bval)
{
	int res;

	p4tc_reg_lock(A, B, NULL);

	res = p4t_copy(A->oper_mask_shift, A->oper_datatype, Aval,
		       B->oper_mask_shift, B->oper_datatype, Bval);

	p4tc_reg_unlock(A, B, NULL);

	return res;
}

/* Syntax: BRANCHOP A B
 * BRANCHOP := BEQ, BNEQ, etc
 * Operation: B's value is compared to A's value.
 * XXX: In the future we will take expressions instead of values
 * A could a constant, header, or metadata or key
 * B could be a constant, header, metadata, or key
 * Restriction: A and B cannot both be constants
 */

/* if A == B <ctl1> else <ctl2> */
static int p4tc_cmd_BEQ(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	int res_cmp;
	void *Bval;
	void *Aval;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	Aval = A->fetch(skb, A, cmd, res);
	Bval = B->fetch(skb, B, cmd, res);

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4tc_cmp_op(A, B, Aval, Bval);
	if (!res_cmp)
		return op->ctl1;

	return op->ctl2;
}

/* if A != B <ctl1> else <ctl2> */
static int p4tc_cmd_BNE(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	int res_cmp;
	void *Bval;
	void *Aval;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	Aval = A->fetch(skb, A, cmd, res);
	Bval = B->fetch(skb, B, cmd, res);

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4tc_cmp_op(A, B, Aval, Bval);
	if (res_cmp)
		return op->ctl1;

	return op->ctl2;
}

/* if A < B <ctl1> else <ctl2> */
static int p4tc_cmd_BLT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	int res_cmp;
	void *Bval;
	void *Aval;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	Aval = A->fetch(skb, A, cmd, res);
	Bval = B->fetch(skb, B, cmd, res);

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4tc_cmp_op(A, B, Aval, Bval);
	if (res_cmp < 0)
		return op->ctl1;

	return op->ctl2;
}

/* if A <= B <ctl1> else <ctl2> */
static int p4tc_cmd_BLE(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	int res_cmp;
	void *Bval;
	void *Aval;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	Aval = A->fetch(skb, A, cmd, res);
	Bval = B->fetch(skb, B, cmd, res);

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4tc_cmp_op(A, B, Aval, Bval);
	if (!res_cmp || res_cmp < 0)
		return op->ctl1;

	return op->ctl2;
}

/* if A > B <ctl1> else <ctl2> */
static int p4tc_cmd_BGT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	int res_cmp;
	void *Bval;
	void *Aval;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	Aval = A->fetch(skb, A, cmd, res);
	Bval = B->fetch(skb, B, cmd, res);

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4tc_cmp_op(A, B, Aval, Bval);
	if (res_cmp > 0)
		return op->ctl1;

	return op->ctl2;
}

/* if A >= B <ctl1> else <ctl2> */
static int p4tc_cmd_BGE(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	int res_cmp;
	void *Bval;
	void *Aval;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	Aval = A->fetch(skb, A, cmd, res);
	Bval = B->fetch(skb, B, cmd, res);

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4tc_cmp_op(A, B, Aval, Bval);
	if (!res_cmp || res_cmp > 0)
		return op->ctl1;

	return op->ctl2;
}

int validate_BRN(struct net *net, struct p4tc_act *act,
		 struct p4tc_cmd_operate *ope,
		 u32 cmd_num_opnds, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A, *B;
	int err = 0;

	if (validate_num_opnds(ope, cmd_num_opnds) < 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Branch: branch must have only 2 operands");
		return -EINVAL;
	}

	A = GET_OPA(&ope->operands_list);
	B = GET_OPB(&ope->operands_list);

	err = validate_operand(net, act, A, extack);
	if (err)
		return err;

	err = validate_operand(net, act, B, extack);
	if (err)
		return err;

	if (A->oper_type == P4TC_OPER_CONST && B &&
	    B->oper_type == P4TC_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Branch: A and B can't both be constant\n");
		return -EINVAL;
	}

	if (!p4tc_type_unsigned(A->oper_datatype->typeid) ||
	    !p4tc_type_unsigned(B->oper_datatype->typeid)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operands A and B must be unsigned\n");
		return -EINVAL;
	}

	return 0;
}

static void free_op_BRN(struct p4tc_cmd_operate *ope,
			struct netlink_ext_ack *extack)
{
	return _free_operation(ope, extack);
}

static void free_op_PRINT(struct p4tc_cmd_operate *ope,
			  struct netlink_ext_ack *extack)
{
	return _free_operation(ope, extack);
}

static void free_op_TBLAPP(struct p4tc_cmd_operate *ope,
			   struct netlink_ext_ack *extack)
{

	return _free_operation(ope, extack);
}

static void free_op_SNDPORTEGR(struct p4tc_cmd_operate *ope,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A;
	struct net_device *dev;

	A = GET_OPA(&ope->operands_list);

	dev = A->priv;
	netdev_put(dev, NULL);

	return _free_operation(ope, extack);
}

static void free_op_BINARITH(struct p4tc_cmd_operate *ope,
			     struct netlink_ext_ack *extack)
{
	return _free_operation(ope, extack);
}

static struct p4tc_cmd_s cmds[] = {
	{ P4TC_CMD_OP_SET, 2, validate_SET, free_op_SET, p4tc_cmd_SET },
	{ P4TC_CMD_OP_ACT, 1, validate_ACT, free_op_ACT, p4tc_cmd_ACT },
	{ P4TC_CMD_OP_BEQ, 2, validate_BRN, free_op_BRN, p4tc_cmd_BEQ },
	{ P4TC_CMD_OP_BNE, 2, validate_BRN, free_op_BRN, p4tc_cmd_BNE },
	{ P4TC_CMD_OP_BGT, 2, validate_BRN, free_op_BRN, p4tc_cmd_BGT },
	{ P4TC_CMD_OP_BLT, 2, validate_BRN, free_op_BRN, p4tc_cmd_BLT },
	{ P4TC_CMD_OP_BGE, 2, validate_BRN, free_op_BRN, p4tc_cmd_BGE },
	{ P4TC_CMD_OP_BLE, 2, validate_BRN, free_op_BRN, p4tc_cmd_BLE },
	{ P4TC_CMD_OP_PRINT, 1, validate_PRINT, free_op_PRINT, p4tc_cmd_PRINT },
	{ P4TC_CMD_OP_TBLAPP, 1, validate_TBLAPP, free_op_TBLAPP,
		p4tc_cmd_TBLAPP },
	{ P4TC_CMD_OP_SNDPORTEGR, 1, validate_SNDPORTEGR, free_op_SNDPORTEGR,
	  p4tc_cmd_SNDPORTEGR },
	{ P4TC_CMD_OP_MIRPORTEGR, 1, validate_SNDPORTEGR, free_op_SNDPORTEGR,
	  p4tc_cmd_MIRPORTEGR },
	{ P4TC_CMD_OP_PLUS, 3, validate_BINARITH, free_op_BINARITH,
		p4tc_cmd_PLUS },
	{ P4TC_CMD_OP_SUB, 3, validate_BINARITH, free_op_BINARITH,
		p4tc_cmd_SUB },
	{ P4TC_CMD_OP_CONCAT, P4TC_CMD_OPERS_MAX, validate_CONCAT,
		free_op_BINARITH, p4tc_cmd_CONCAT },
	{ P4TC_CMD_OP_BAND, 3, validate_BINARITH, free_op_BINARITH,
		p4tc_cmd_BAND },
	{ P4TC_CMD_OP_BOR, 3, validate_BINARITH, free_op_BINARITH,
		p4tc_cmd_BOR },
	{ P4TC_CMD_OP_BXOR, 3, validate_BINARITH, free_op_BINARITH,
		p4tc_cmd_BXOR },
};

static struct p4tc_cmd_s *p4tc_get_cmd_byid(u16 cmdid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (cmdid == cmds[i].cmdid)
			return &cmds[i];
	}

	return NULL;
}

/* Operands */
static const struct nla_policy p4tc_cmd_policy_oper[P4TC_CMD_OPND_MAX + 1] = {
	[P4TC_CMD_OPND_INFO] = { .type = NLA_BINARY,
				    .len = sizeof(struct p4tc_u_operand) },
	[P4TC_CMD_OPND_PATH] = { .type = NLA_STRING, .len = TEMPLATENAMSZ },
	[P4TC_CMD_OPND_PATH_EXTRA] = { .type = NLA_STRING, .len = TEMPLATENAMSZ },
	[P4TC_CMD_OPND_LARGE_CONSTANT] = {
		.type = NLA_BINARY,
		.len = BITS_TO_BYTES(P4T_MAX_BITSZ),
	},
	[P4TC_CMD_OPND_PREFIX] = { .type = NLA_STRING, .len = TEMPLATENAMSZ },
};

/*
 * XXX: P4TC_CMD_POLICY is used to disable overwriting extacks downstream
 * Could we use error pointers instead of this P4TC_CMD_POLICY trickery?
 */
#define P4TC_CMD_POLICY 12345
static int p4tc_cmds_process_opnd(struct nlattr *nla,
				  struct p4tc_cmd_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	int oper_extra_sz = 0;
	int oper_prefix_sz = 0;
	u32 wantbits = 0;
	int oper_sz = 0;
	int err = 0;
	struct nlattr *tb[P4TC_CMD_OPND_MAX + 1];
	struct p4tc_u_operand *uopnd;

	err = nla_parse_nested(tb, P4TC_CMD_OPND_MAX, nla,
			       p4tc_cmd_policy_oper, extack);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "parse error: P4TC_CMD_OPND_\n");
		return -EINVAL;
	}

	if (!tb[P4TC_CMD_OPND_INFO]) {
		NL_SET_ERR_MSG_MOD(extack, "operand information is mandatory");
		return -EINVAL;
	}

	uopnd = nla_data(tb[P4TC_CMD_OPND_INFO]);

	if (uopnd->oper_type == P4TC_OPER_META) {
		kopnd->fetch = p4tc_fetch_metadata;
	} else if (uopnd->oper_type == P4TC_OPER_CONST) {
		kopnd->fetch = p4tc_fetch_constant;
	} else if (uopnd->oper_type == P4TC_OPER_ACTID) {
		kopnd->fetch = NULL;
	} else if (uopnd->oper_type == P4TC_OPER_TBL) {
		kopnd->fetch = p4tc_fetch_table;
	} else if (uopnd->oper_type == P4TC_OPER_KEY) {
		kopnd->fetch = p4tc_fetch_key;
	} else if (uopnd->oper_type == P4TC_OPER_RES) {
		kopnd->fetch = p4tc_fetch_result;
	} else if (uopnd->oper_type == P4TC_OPER_HDRFIELD) {
		kopnd->fetch = p4tc_fetch_hdrfield;
	} else if (uopnd->oper_type == P4TC_OPER_PARAM) {
		kopnd->fetch = p4tc_fetch_param;
	} else if (uopnd->oper_type == P4TC_OPER_DEV) {
		kopnd->fetch = p4tc_fetch_dev;
	} else if (uopnd->oper_type == P4TC_OPER_REG) {
		kopnd->fetch = p4tc_fetch_reg;
	} else {
		NL_SET_ERR_MSG_MOD(extack, "Unknown operand type");
		return -EINVAL;
	}

	wantbits = 1 + uopnd->oper_endbit - uopnd->oper_startbit;
	if (uopnd->oper_flags & DATA_HAS_TYPE_INFO &&
	    uopnd->oper_type != P4TC_OPER_ACTID &&
	    uopnd->oper_type != P4TC_OPER_TBL &&
	    uopnd->oper_type != P4TC_OPER_REG &&
	    uopnd->oper_cbitsize < wantbits) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Start and end bit dont fit in space");
		return -EINVAL;
	}

	err = copy_u2k_operand(uopnd, kopnd, extack);
	if (err < 0)
		return err;

	if (tb[P4TC_CMD_OPND_LARGE_CONSTANT]) {
		int const_sz;

		const_sz = nla_len(tb[P4TC_CMD_OPND_LARGE_CONSTANT]);
		if (const_sz)
			memcpy(kopnd->immedv_large,
			       nla_data(tb[P4TC_CMD_OPND_LARGE_CONSTANT]),
			       const_sz);
		else
			kopnd->oper_flags |= DATA_IS_IMMEDIATE;

		kopnd->immedv_large_sz = const_sz;
	}

	if (tb[P4TC_CMD_OPND_PATH])
		oper_sz = nla_len(tb[P4TC_CMD_OPND_PATH]);

	kopnd->path_or_value_sz = oper_sz;

	if (oper_sz) {
		kopnd->path_or_value = kzalloc(oper_sz, GFP_KERNEL);
		if (!kopnd->path_or_value) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Failed to alloc operand path data");
			return -ENOMEM;
		}

		nla_memcpy(kopnd->path_or_value, tb[P4TC_CMD_OPND_PATH], oper_sz);
	}

	if (tb[P4TC_CMD_OPND_PATH_EXTRA])
		oper_extra_sz = nla_len(tb[P4TC_CMD_OPND_PATH_EXTRA]);

	kopnd->path_or_value_extra_sz = oper_extra_sz;

	if (oper_extra_sz) {
		kopnd->path_or_value_extra = kzalloc(oper_extra_sz, GFP_KERNEL);
		if (!kopnd->path_or_value_extra) {
			kfree(kopnd->path_or_value);
			NL_SET_ERR_MSG_MOD(extack,
					   "Failed to alloc extra operand path data");
			return -ENOMEM;
		}

		nla_memcpy(kopnd->path_or_value_extra, tb[P4TC_CMD_OPND_PATH_EXTRA],
			   oper_extra_sz);
	}

	if (tb[P4TC_CMD_OPND_PREFIX])
		oper_prefix_sz = nla_len(tb[P4TC_CMD_OPND_PREFIX]);

	if (!oper_prefix_sz)
		return 0;

	kopnd->print_prefix_sz = oper_prefix_sz;

	kopnd->print_prefix = kzalloc(oper_prefix_sz, GFP_KERNEL);
	if (!kopnd->print_prefix) {
		kfree(kopnd->path_or_value);
		kfree(kopnd->path_or_value_extra);
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to alloc operand print prefix");
		return -ENOMEM;
	}

	nla_memcpy(kopnd->print_prefix, tb[P4TC_CMD_OPND_PREFIX],
		   oper_prefix_sz);
	return 0;
}

/* Operation */
static const struct nla_policy cmd_ops_policy[P4TC_CMD_OPER_MAX + 1] = {
	[P4TC_CMD_OPERATION] = {
		.type = NLA_BINARY,
		.len = sizeof(struct p4tc_u_operate)
	},
	[P4TC_CMD_OPER_LIST] = { .type = NLA_NESTED },
};

static struct p4tc_cmd_operate *uope_to_kope(struct p4tc_u_operate *uope)
{
	struct p4tc_cmd_operate *ope;

	if (!uope)
		return NULL;

	ope = kzalloc(sizeof(*ope), GFP_KERNEL);
	if (!ope)
		return NULL;

	ope->op_id = uope->op_type;
	ope->op_flags = uope->op_flags;
	ope->op_cnt = 0;

	ope->ctl1 = uope->op_ctl1;
	ope->ctl2 = uope->op_ctl2;

	INIT_LIST_HEAD(&ope->operands_list);

	return ope;
}

static int p4tc_cmd_process_operands_list(struct nlattr *nla,
					  struct p4tc_cmd_operate *ope,
					  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_CMD_OPERS_MAX + 1];
	struct p4tc_cmd_operand *opnd;
	int err;
	int i;

	err = nla_parse_nested(tb, P4TC_CMD_OPERS_MAX, nla, NULL, NULL);
	if (err < 0)
		return err;

	for (i = 1; i < P4TC_CMD_OPERS_MAX + 1 && tb[i]; i++) {
		opnd = kzalloc(sizeof(*opnd), GFP_KERNEL);
		if (!opnd)
			return -ENOMEM;
		err = p4tc_cmds_process_opnd(tb[i], opnd, extack);
		/* Will add to list because p4tc_cmd_process_opnd may have
		 * allocated memory inside opnd even in case of failure,
		 * and this memory must be freed
		 */
		list_add_tail(&opnd->oper_list_node, &ope->operands_list);
		if (err < 0)
			return P4TC_CMD_POLICY;
		ope->num_opnds++;
	}

	return 0;
}

static int p4tc_cmd_process_ops(struct net *net, struct p4tc_act *act,
				struct nlattr *nla,
				struct p4tc_cmd_operate **op_entry,
				struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operate *ope = NULL;
	int err = 0;
	struct nlattr *tb[P4TC_CMD_OPER_MAX + 1];
	struct p4tc_cmd_s *cmd_t;

	err = nla_parse_nested(tb, P4TC_CMD_OPER_MAX, nla, cmd_ops_policy,
			       extack);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "parse error: P4TC_CMD_OPER_\n");
		return P4TC_CMD_POLICY;
	}

	ope = uope_to_kope(nla_data(tb[P4TC_CMD_OPERATION]));
	if (!ope)
		return -ENOMEM;

	cmd_t = p4tc_get_cmd_byid(ope->op_id);
	if (!cmd_t) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown operation ID\n");
		kfree(ope);
		return -EINVAL;
	}

	if (tb[P4TC_CMD_OPER_LIST]) {
		err = p4tc_cmd_process_operands_list(tb[P4TC_CMD_OPER_LIST],
						     ope, extack);
		if (err) {
			err = P4TC_CMD_POLICY;
			goto set_results;
		}
	}

	err = cmd_t->validate_operands(net, act, ope, cmd_t->num_opnds, extack);
	if (err) {
		//XXX: think about getting rid of this P4TC_CMD_POLICY
		err =  P4TC_CMD_POLICY;
		goto set_results;
	}

set_results:
	ope->cmd = cmd_t;
	*op_entry = ope;

	return err;
}

static inline int cmd_is_branch(u32 cmdid)
{
	if (cmdid == P4TC_CMD_OP_BEQ || cmdid == P4TC_CMD_OP_BNE ||
	    cmdid == P4TC_CMD_OP_BLT || cmdid == P4TC_CMD_OP_BLE ||
	    cmdid == P4TC_CMD_OP_BGT || cmdid == P4TC_CMD_OP_BGE)
		return 1;

	return 0;
}

static int cmd_brn_validate(struct p4tc_cmd_operate *oplist[], int cnt,
			    struct netlink_ext_ack *extack)
{
	int inscnt = cnt - 1;
	int i;

	for (i = 1; i < inscnt; i++) {
		struct p4tc_cmd_operate *ope = oplist[i - 1];
		u32 jmp_cnt = 0;

		if (!cmd_is_branch(ope->op_id))
			continue;

		if (TC_ACT_EXT_CMP(ope->ctl1, TC_ACT_JUMP)) {
			jmp_cnt = ope->ctl1 & TC_ACT_EXT_VAL_MASK;
			if (jmp_cnt + i >= inscnt) {
				NL_SET_ERR_MSG(extack,
					       "ctl1 excessive branch");
				return -EINVAL;
			}
		}

		if (TC_ACT_EXT_CMP(ope->ctl2, TC_ACT_JUMP)) {
			jmp_cnt = ope->ctl2 & TC_ACT_EXT_VAL_MASK;
			if (jmp_cnt + i >= inscnt) {
				NL_SET_ERR_MSG(extack,
					       "ctl2 excessive branch");
				return -EINVAL;
			}
		}
	}

	return 0;
}

static void p4tc_cmds_ops_pass_to_list(struct p4tc_cmd_operate **oplist,
				       struct list_head *cmd_operations)
{
	int i;

	for (i = 0; i < P4TC_CMDS_LIST_MAX && oplist[i]; i++) {
		struct p4tc_cmd_operate *ope = oplist[i];

		list_add_tail(&ope->cmd_operations, cmd_operations);
	}
}

static void p4tc_cmd_ops_del_list(struct list_head *cmd_operations)
{
	struct p4tc_cmd_operate *ope, *tmp;

	list_for_each_entry_safe(ope, tmp, cmd_operations, cmd_operations) {
		list_del(&ope->cmd_operations);
		kfree_opentry(ope);
	}
}

static int p4tc_cmds_copy_opnd(struct p4tc_cmd_operand **new_kopnd,
			       struct p4tc_cmd_operand *kopnd,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift = NULL;
	struct p4tc_cmd_operand *_new_kopnd;
	int err = 0;

	_new_kopnd = kzalloc(sizeof(*_new_kopnd), GFP_KERNEL);
	if (!_new_kopnd)
		return -ENOMEM;

	memcpy(_new_kopnd, kopnd, sizeof(*_new_kopnd));
	memset(&_new_kopnd->oper_list_node, 0, sizeof(struct list_head));

	if (kopnd->oper_type == P4TC_OPER_CONST &&
	    kopnd->oper_datatype->ops->create_bitops) {
		mask_shift = create_constant_bitops(kopnd,
						    kopnd->oper_datatype,
						    extack);
		if (IS_ERR(mask_shift)) {
			err = -EINVAL;
			goto err;
		}
	} else if (kopnd->oper_type == P4TC_OPER_META &&
		   kopnd->oper_datatype->ops->create_bitops) {
		struct p4tc_pipeline *pipeline;
		struct p4tc_metadata *meta;

		pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
		if (!pipeline) {
			err = -EINVAL;
			goto err;
		}

		meta = tcf_meta_find_byid(pipeline, kopnd->immedv);
		if (!meta) {
			err = -EINVAL;
			goto err;
		}

		mask_shift = create_metadata_bitops(kopnd, meta,
						    kopnd->oper_datatype,
						    extack);
		if (IS_ERR(mask_shift)) {
			err = -EINVAL;
			goto err;
		}
	} else if (kopnd->oper_type == P4TC_OPER_HDRFIELD  ||
		   kopnd->oper_type == P4TC_OPER_PARAM ||
		   kopnd->oper_type == P4TC_OPER_REG) {
		if (kopnd->oper_datatype->ops->create_bitops) {
			struct p4tc_type_ops *ops = kopnd->oper_datatype->ops;

			mask_shift = ops->create_bitops(kopnd->oper_bitsize,
							kopnd->oper_bitstart,
							kopnd->oper_bitend,
							extack);
			if (IS_ERR(mask_shift)) {
				err = -EINVAL;
				goto err;
			}
		}
	}

	_new_kopnd->oper_mask_shift = mask_shift;

	if (kopnd->path_or_value_sz) {
		_new_kopnd->path_or_value = kzalloc(kopnd->path_or_value_sz,
						    GFP_KERNEL);
		if (!_new_kopnd->path_or_value) {
			err = -ENOMEM;
			goto err;
		}

		memcpy(_new_kopnd->path_or_value, kopnd->path_or_value,
		       kopnd->path_or_value_sz);
	}

	if (kopnd->path_or_value_extra_sz) {
		_new_kopnd->path_or_value_extra = kzalloc(kopnd->path_or_value_extra_sz,
							  GFP_KERNEL);
		if (!_new_kopnd->path_or_value_extra) {
			err = -ENOMEM;
			goto err;
		}

		memcpy(_new_kopnd->path_or_value_extra, kopnd->path_or_value_extra,
		       kopnd->path_or_value_extra_sz);
	}

	memcpy(_new_kopnd->immedv_large, kopnd->immedv_large,
	       kopnd->immedv_large_sz);

	*new_kopnd = _new_kopnd;

	return 0;

err:
	kfree(_new_kopnd->path_or_value);
	kfree(_new_kopnd->path_or_value_extra);
	kfree(_new_kopnd);

	return err;
}

static int p4tc_cmds_copy_ops(struct p4tc_cmd_operate **new_op_entry,
			      struct p4tc_cmd_operate *op_entry,
			      struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operate *_new_op_entry;
	struct p4tc_cmd_operand *cursor;
	int err = 0;

	_new_op_entry = kzalloc(sizeof(*_new_op_entry), GFP_KERNEL);
	if (!_new_op_entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&_new_op_entry->operands_list);
	list_for_each_entry(cursor, &op_entry->operands_list, oper_list_node) {
		struct p4tc_cmd_operand *new_opnd = NULL;

		err = p4tc_cmds_copy_opnd(&new_opnd, cursor, extack);
		if (new_opnd) {
			struct list_head *head;

			head = &new_opnd->oper_list_node;
			list_add_tail(&new_opnd->oper_list_node,
				      &_new_op_entry->operands_list);
		}
		if (err < 0)
			goto set_results;
	}

	_new_op_entry->op_id = op_entry->op_id;
	_new_op_entry->op_flags = op_entry->op_flags;
	_new_op_entry->op_cnt = op_entry->op_cnt;

	_new_op_entry->ctl1 = op_entry->ctl1;
	_new_op_entry->ctl2 = op_entry->ctl2;
	_new_op_entry->cmd = op_entry->cmd;

set_results:
	*new_op_entry = _new_op_entry;

	return err;
}

int p4tc_cmds_copy(struct list_head *new_cmd_operations,
		   struct list_head *cmd_operations,
		   bool delete_old, struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operate *oplist[P4TC_CMDS_LIST_MAX] = {NULL};
	int i = 0;
	struct p4tc_cmd_operate *op;
	int err;

	if (delete_old)
		p4tc_cmd_ops_del_list(new_cmd_operations);

	list_for_each_entry(op, cmd_operations, cmd_operations) {
		err = p4tc_cmds_copy_ops(&oplist[i], op, extack);
		if (err < 0)
			goto free_oplist;

		i++;
	}

	p4tc_cmds_ops_pass_to_list(oplist, new_cmd_operations);

	return 0;

free_oplist:
	kfree_tmp_oplist(oplist);
	return err;
}

#define SEPARATOR "/"

int p4tc_cmds_parse(struct net *net,
		    struct p4tc_act *act,
		    struct nlattr *nla, bool ovr,
		    struct netlink_ext_ack *extack)
{
	/* XXX: oplist and oplist_attr
	 * could bloat the stack depending on P4TC_CMDS_LIST_MAX
	 */
	struct p4tc_cmd_operate *oplist[P4TC_CMDS_LIST_MAX] = {NULL};
	struct nlattr *oplist_attr[P4TC_CMDS_LIST_MAX + 1];
	int err;
	int i;

	err = nla_parse_nested(oplist_attr, P4TC_CMDS_LIST_MAX, nla, NULL,
			       extack);
	if (err < 0)
		return err;

	for (i = 1; i < P4TC_CMDS_LIST_MAX + 1 && oplist_attr[i]; i++) {
		if (!oplist_attr[i])
			break;
		err =
		    p4tc_cmd_process_ops(net, act, oplist_attr[i],
					 &oplist[i - 1], extack);
		if (err) {
			kfree_tmp_oplist(oplist);

			if (err == P4TC_CMD_POLICY)
				err = -EINVAL;

			return err;
		}
	}

	err = cmd_brn_validate(oplist, i, extack);
	if (err < 0) {
		kfree_tmp_oplist(oplist);
		return err;
	}

	if (ovr)
		p4tc_cmd_ops_del_list(&act->cmd_operations);

	/*XXX: At this point we have all the cmds and they are valid */
	p4tc_cmds_ops_pass_to_list(oplist, &act->cmd_operations);

	return 0;
}

static void *p4tc_fetch_constant(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res)
{
	if (op->oper_flags & DATA_IS_IMMEDIATE)
		return &op->immedv;

	return op->immedv_large;
}

static void *p4tc_fetch_table(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			      struct tcf_p4act *cmd, struct tcf_result *res)
{
	return op->oper_value_ops->fetch(skb, op->oper_value_ops);
}

static void *p4tc_fetch_result(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			       struct tcf_p4act *cmd, struct tcf_result *res)
{
	if (op->immedv == P4TC_CMDS_RESULTS_HIT)
		return &res->hit;
	else
		return &res->miss;
}

static void *p4tc_fetch_hdrfield(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return op->oper_value_ops->fetch(skb, op->oper_value_ops);
}

static void *p4tc_fetch_param(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			      struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct tcf_p4act_params *params;
	struct p4tc_act_param *param;

	params = rcu_dereference(cmd->params);
	param = idr_find(&params->params_idr, op->immedv2);

	return param->value;
}

static void *p4tc_fetch_key(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			    struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_skb_ext *p4tc_skb_ext;

	p4tc_skb_ext = skb_ext_find(skb, P4TC_SKB_EXT);
	if (unlikely(!p4tc_skb_ext))
		return NULL;

	return p4tc_skb_ext->p4tc_ext->key;
}

static void *p4tc_fetch_dev(struct sk_buff *skb, struct p4tc_cmd_operand *op,
			    struct tcf_p4act *cmd, struct tcf_result *res)
{
	return op->priv;
}

static void *p4tc_fetch_metadata(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return op->oper_value_ops->fetch(skb, op->oper_value_ops);
}

static void *p4tc_fetch_reg(struct sk_buff *skb,
			    struct p4tc_cmd_operand *op,
			    struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_register *reg = op->priv;
	size_t bytesz;

	bytesz = BITS_TO_BYTES(reg->reg_type->container_bitsz);

	return reg->reg_value + bytesz * op->immedv2;
}

/* SET A B  - A is set from B
 *
 * Assumes everything has been vetted - meaning no checks here
 *
 */
static int p4tc_cmd_SET(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A, *B;
	void *src;
	void *dst;
	int err;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);

	src = B->fetch(skb, B, cmd, res);
	dst = A->fetch(skb, A, cmd, res);

	if (!src || !dst)
		return TC_ACT_SHOT;

	err = p4tc_copy_op(A, B, dst, src);

	if (err)
		return TC_ACT_SHOT;

	return op->ctl1;
}

/* ACT A - execute action A
 *
 * Assumes everything has been vetted - meaning no checks here
 *
 */
static int p4tc_cmd_ACT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A = GET_OPA(&op->operands_list);
	const struct tc_action *action = A->action;

	return action->ops->act(skb, action, res);
}

static int p4tc_cmd_PRINT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			  struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A = GET_OPA(&op->operands_list);
	u64 readval[BITS_TO_U64(P4T_MAX_BITSZ)] = {0};
	char name[(TEMPLATENAMSZ * 4)];
	struct p4tc_type *val_t;
	void *val;

	A = GET_OPA(&op->operands_list);
	val = A->fetch(skb, A, cmd, res);
	val_t = A->oper_datatype;

	if (!val)
		return TC_ACT_OK;

	p4tc_reg_lock(A, NULL, NULL);
	if (val_t->ops->host_read)
		val_t->ops->host_read(val_t, A->oper_mask_shift, val,
				      &readval);
	else
		memcpy(&readval, val, BITS_TO_BYTES(A->oper_bitsize));
	/* This is a debug function, so performance is not a priority */
	if (A->oper_type == P4TC_OPER_META) {
		struct p4tc_pipeline *pipeline = NULL;
		char *path = (char *)A->print_prefix;
		struct p4tc_metadata *meta;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		meta = tcf_meta_find_byid(pipeline, A->immedv);

		if (A->path_or_value_sz)
			snprintf(name,
				 (TEMPLATENAMSZ << 1) + P4TC_CMD_MAX_OPER_PATH_LEN,
				 "%s %s.%s", path, pipeline->common.name,
				 meta->common.name);
		else
			snprintf(name, TEMPLATENAMSZ << 1, "%s.%s",
				 pipeline->common.name, meta->common.name);

		val_t->ops->print(val_t, name, &readval);
	} else if (A->oper_type == P4TC_OPER_HDRFIELD) {
		struct p4tc_header_field *hdrfield;
		struct p4tc_pipeline *pipeline;
		struct p4tc_parser *parser;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		parser = tcf_parser_find_byid(pipeline, A->immedv);
		hdrfield = tcf_hdrfield_find_byid(parser, A->immedv2);

		snprintf(name, TEMPLATENAMSZ * 4, "hdrfield.%s.%s.%s",
			 pipeline->common.name, parser->parser_name,
			 hdrfield->common.name);

		val_t->ops->print(val_t, name, &readval);
	} else if (A->oper_type == P4TC_OPER_KEY) {
		struct p4tc_table *table;
		struct p4tc_pipeline *pipeline;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		table = tcf_table_find_byid(pipeline, A->immedv);
		snprintf(name, TEMPLATENAMSZ * 3, "key.%s.%s.%u",
			 pipeline->common.name, table->common.name,
			 A->immedv2);
		val_t->ops->print(val_t, name, &readval);
	} else if (A->oper_type == P4TC_OPER_PARAM) {
		val_t->ops->print(val_t, "param", &readval);
	} else if (A->oper_type == P4TC_OPER_RES) {
		if (A->immedv == P4TC_CMDS_RESULTS_HIT)
			val_t->ops->print(val_t, "res.hit", &readval);
		else if (A->immedv == P4TC_CMDS_RESULTS_MISS)
			val_t->ops->print(val_t, "res.miss", &readval);
	} else if (A->oper_type == P4TC_OPER_REG) {
		struct p4tc_pipeline *pipeline;
		struct p4tc_register *reg;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		reg = tcf_register_find_byid(pipeline, A->immedv);
		snprintf(name, TEMPLATENAMSZ * 2, "register.%s.%s[%u]",
			 pipeline->common.name, reg->common.name, A->immedv2);
		val_t->ops->print(val_t, name, &readval);
	} else {
		pr_info("Unsupported operand for print\n");
	}
	p4tc_reg_unlock(A, NULL, NULL);

	return op->ctl1;
}

#define REDIRECT_RECURSION_LIMIT    4
static DEFINE_PER_CPU(unsigned int, redirect_rec_level);

static int p4tc_cmd_SNDPORTEGR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			       struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct sk_buff *skb2 = skb;
	int retval = TC_ACT_STOLEN;
	struct p4tc_cmd_operand *A;
	struct net_device *dev;
	unsigned int rec_level;
	bool expects_nh;
	int mac_len;
	bool at_nh;
	int err;

	A = GET_OPA(&op->operands_list);
	dev = A->fetch(skb, A, cmd, res);

	rec_level = __this_cpu_inc_return(redirect_rec_level);
	if (unlikely(rec_level > REDIRECT_RECURSION_LIMIT)) {
		net_warn_ratelimited("SNDPORTEGR: exceeded redirect recursion limit on dev %s\n",
				     netdev_name(skb->dev));
		__this_cpu_dec(redirect_rec_level);
		return TC_ACT_SHOT;
	}

	if (unlikely(!dev)) {
		pr_notice_once("SNDPORTEGR: target device is gone\n");
		__this_cpu_dec(redirect_rec_level);
		return TC_ACT_SHOT;
	}

	if (unlikely(!(dev->flags & IFF_UP))) {
		net_notice_ratelimited("SNDPORTEGR: device %s is down\n",
				       dev->name);
		__this_cpu_dec(redirect_rec_level);
		return TC_ACT_SHOT;
	}

	nf_reset_ct(skb2);

	expects_nh = !dev_is_mac_header_xmit(dev);
	at_nh = skb->data == skb_network_header(skb);
	if (at_nh != expects_nh) {
		mac_len = skb_at_tc_ingress(skb) ? skb->mac_len :
			  skb_network_header(skb) - skb_mac_header(skb);
		if (expects_nh) {
			/* target device/action expect data at nh */
			skb_pull_rcsum(skb2, mac_len);
		} else {
			/* target device/action expect data at mac */
			skb_push_rcsum(skb2, mac_len);
		}
	}

	skb_set_redirected(skb2, skb2->tc_at_ingress);
	skb2->skb_iif = skb->dev->ifindex;
	skb2->dev = dev;

	err  = dev_queue_xmit(skb2);
	if (err)
		retval = TC_ACT_SHOT;

	 __this_cpu_dec(redirect_rec_level);

	return retval;
}

static int p4tc_cmd_MIRPORTEGR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			       struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct sk_buff *skb2 = skb;
	int retval = TC_ACT_PIPE;
	struct p4tc_cmd_operand *A;
	struct net_device *dev;
	unsigned int rec_level;
	bool expects_nh;
	int mac_len;
	bool at_nh;
	int err;

	A = GET_OPA(&op->operands_list);
	dev = A->fetch(skb, A, cmd, res);

	rec_level = __this_cpu_inc_return(redirect_rec_level);
	if (unlikely(rec_level > REDIRECT_RECURSION_LIMIT)) {
		net_warn_ratelimited("MIRPORTEGR: exceeded redirect recursion limit on dev %s\n",
				     netdev_name(skb->dev));
		__this_cpu_dec(redirect_rec_level);
		return TC_ACT_SHOT;
	}

	if (unlikely(!dev)) {
		pr_notice_once("MIRPORTEGR: target device is gone\n");
		__this_cpu_dec(redirect_rec_level);
		return TC_ACT_SHOT;
	}

	if (unlikely(!(dev->flags & IFF_UP))) {
		net_notice_ratelimited("MIRPORTEGR: device %s is down\n",
				       dev->name);
		__this_cpu_dec(redirect_rec_level);
		return TC_ACT_SHOT;
	}

	skb2 = skb_clone(skb, GFP_ATOMIC);
	if (!skb2) {
		 __this_cpu_dec(redirect_rec_level);
		return retval;
	}

	nf_reset_ct(skb2);

	expects_nh = !dev_is_mac_header_xmit(dev);
	at_nh = skb->data == skb_network_header(skb);
	if (at_nh != expects_nh) {
		mac_len = skb_at_tc_ingress(skb) ? skb->mac_len :
			  skb_network_header(skb) - skb_mac_header(skb);
		if (expects_nh) {
			/* target device/action expect data at nh */
			skb_pull_rcsum(skb2, mac_len);
		} else {
			/* target device/action expect data at mac */
			skb_push_rcsum(skb2, mac_len);
		}
	}


	skb2->skb_iif = skb->dev->ifindex;
	skb2->dev = dev;

	err  = dev_queue_xmit(skb2);
	if (err)
		retval = TC_ACT_SHOT;

	 __this_cpu_dec(redirect_rec_level);

	return retval;
}

static int p4tc_cmd_TBLAPP(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			   struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A = GET_OPA(&op->operands_list);
	struct p4tc_table *table = A->fetch(skb, A, cmd, res);
	struct p4tc_table_entry *entry;
	struct p4tc_table_key *key;
	int ret;

	A = GET_OPA(&op->operands_list);
	table = A->fetch(skb, A, cmd, res);
	if (unlikely(!table))
		return TC_ACT_SHOT;

	if (table->tbl_preacts) {
		ret = tcf_action_exec(skb, table->tbl_preacts,
				      table->tbl_num_preacts, res);
		/* Should check what return code should cause return */
		if (ret == TC_ACT_SHOT)
			return ret;
	}

	/* Sets key */
	key = tcf_table_key_find(table, A->immedv2);
	ret = tcf_action_exec(skb, key->key_acts, key->key_num_acts, res);
	if (ret != TC_ACT_PIPE)
		return ret;

	entry = p4tc_table_entry_lookup(skb, table, table->tbl_keysz);
	if (IS_ERR(entry))
		entry = NULL;

	res->hit = entry ? true : false;
	res->miss = !res->hit;

	ret = TC_ACT_PIPE;
	if (res->hit) {
		struct p4tc_table_defact *hitact;

		hitact = rcu_dereference(table->tbl_default_hitact);
		if (entry->acts)
			ret = tcf_action_exec(skb, entry->acts, entry->num_acts,
					      res);
		else if (hitact)
			ret = tcf_action_exec(skb, hitact->default_acts, 1,
					      res);
	} else {
		struct p4tc_table_defact *missact;

		missact = rcu_dereference(table->tbl_default_missact);
		if (missact)
			ret = tcf_action_exec(skb, missact->default_acts, 1,
					      res);
	}
	if (ret != TC_ACT_PIPE)
		return ret;

	return tcf_action_exec(skb, table->tbl_postacts,
			       table->tbl_num_postacts, res);
}

static int p4tc_cmd_BINARITH(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			     struct tcf_p4act *cmd, struct tcf_result *res,
			     void (*p4tc_arith_op)(u64 *res, u64 *opB, u64 *opC))
{
	u64 result[BITS_TO_U64(P4T_MAX_BITSZ)] = {0};
	u64 Bval[BITS_TO_U64(P4T_MAX_BITSZ)] = {0};
	u64 Cval[BITS_TO_U64(P4T_MAX_BITSZ)] = {0};
	struct p4tc_cmd_operand *A, *B, *C;
	struct p4tc_type_ops *srcC_ops;
	struct p4tc_type_ops *srcB_ops;
	struct p4tc_type_ops *dst_ops;
	void *srcB;
	void *srcC;
	void *dst;

	A = GET_OPA(&op->operands_list);
	B = GET_OPB(&op->operands_list);
	C = GET_OPC(&op->operands_list);

	dst = A->fetch(skb, A, cmd, res);
	srcB = B->fetch(skb, B, cmd, res);
	srcC = C->fetch(skb, C, cmd, res);

	if (!srcB || !srcC || !dst)
		return TC_ACT_SHOT;

	dst_ops = A->oper_datatype->ops;
	srcB_ops = B->oper_datatype->ops;
	srcC_ops = C->oper_datatype->ops;

	p4tc_reg_lock(A, B, C);

	srcB_ops->host_read(B->oper_datatype, B->oper_mask_shift, srcB, Bval);
	srcC_ops->host_read(C->oper_datatype, C->oper_mask_shift, srcC, Cval);

	p4tc_arith_op(result, Bval, Cval);

	dst_ops->host_write(A->oper_datatype, A->oper_mask_shift, result, dst);

	p4tc_reg_unlock(A, B, C);

	return op->ctl1;
}

/* For this first implementation we are not handling overflows yet */
static void plus_op(u64 *res, u64 *opB, u64 *opC)
{
	int i;

	for (i = 0; i < BITS_TO_U64(P4T_MAX_BITSZ); i++)
		res[i] = opB[i] + opC[i];
}

static int p4tc_cmd_PLUS(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, plus_op);
}

/* For this first implementation we are not handling overflows yet */
static void sub_op(u64 *res, u64 *opB, u64 *opC)
{
	int i;

	for (i = 0; i < BITS_TO_U64(P4T_MAX_BITSZ); i++)
		res[i] = opB[i] - opC[i];
}

static int p4tc_cmd_SUB(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, sub_op);
}

static void band_op(u64 *res, u64 *opB, u64 *opC)
{
	int i;

	for (i = 0; i < BITS_TO_U64(P4T_MAX_BITSZ); i++)
		res[i] = opB[i] & opC[i];
}

static int p4tc_cmd_BAND(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, band_op);
}

static void bor_op(u64 *res, u64 *opB, u64 *opC)
{
	int i;

	for (i = 0; i < BITS_TO_U64(P4T_MAX_BITSZ); i++)
		res[i] = opB[i] | opC[i];
}

static int p4tc_cmd_BOR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, bor_op);
}

static void bxor_op(u64 *res, u64 *opB, u64 *opC)
{
	int i;

	for (i = 0; i < BITS_TO_U64(P4T_MAX_BITSZ); i++)
		res[i] = opB[i] ^ opC[i];
}

static int p4tc_cmd_BXOR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, bxor_op);
}

static int p4tc_cmd_CONCAT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			   struct tcf_p4act *cmd, struct tcf_result *res)
{
	u64 RvalAcc[BITS_TO_U64(P4T_MAX_BITSZ)] = {0};
	size_t rvalue_tot_sz = 0;
	struct p4tc_cmd_operand *cursor;
	struct p4tc_type_ops *dst_ops;
	struct p4tc_cmd_operand *A;
	void *dst;

	A = GET_OPA(&op->operands_list);

	cursor = A;
	list_for_each_entry_continue(cursor, &op->operands_list, oper_list_node) {
		size_t cursor_bytesz = BITS_TO_BYTES(cursor->oper_bitsize);
		struct p4tc_type *cursor_type = cursor->oper_datatype;
		struct p4tc_type_ops *cursor_type_ops = cursor_type->ops;
		void *srcR = cursor->fetch(skb, cursor, cmd, res);
		u64 Rval[BITS_TO_U64(P4T_MAX_BITSZ)] = {0};

		cursor_type_ops->host_read(cursor->oper_datatype,
					   cursor->oper_mask_shift,
					   srcR,
					   &Rval);
		memcpy((char *)RvalAcc + rvalue_tot_sz, &Rval, cursor_bytesz);
		rvalue_tot_sz += cursor_bytesz;
	}

	dst = A->fetch(skb, A, cmd, res);
	dst_ops = A->oper_datatype->ops;
	dst_ops->host_write(A->oper_datatype, A->oper_mask_shift, RvalAcc, dst);

	return op->ctl1;
}
