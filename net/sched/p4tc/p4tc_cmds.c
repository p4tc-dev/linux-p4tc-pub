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
	if (!type) {
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

/* under spin lock */
int p4tc_cmds_fillup(struct sk_buff *skb, struct list_head *cmd_operations)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_u_operand oper = { };
	struct p4tc_u_operate op = { };
	int i = 1, plen = 4;
	struct p4tc_cmd_operate *entry;
	struct nlattr *nest_op, *nest_opnd;

	list_for_each_entry(entry, cmd_operations, cmd_operations) {
		if (!entry)
			continue;
		nest_op = nla_nest_start(skb, i);

		op.op_type = entry->op_id;
		op.op_flags = entry->op_flags;
		op.op_ctl1 =  entry->ctl1;
		op.op_ctl2 =  entry->ctl2;
		if (nla_put(skb, P4TC_CMD_OPERATION,
			    sizeof(struct p4tc_u_operate), &op))
			goto nla_put_failure;

		if (entry->opA) {
			nest_opnd = nla_nest_start(skb, P4TC_CMD_OPER_A);
			copy_k2u_operand(entry->opA, &oper);

			if (nla_put(skb, P4TC_CMD_OPND_INFO,
				    sizeof(struct p4tc_u_operand), &oper))
				goto nla_put_failure;

			plen = entry->opA->path_or_value_sz;

			if (plen && nla_put(skb, P4TC_CMD_OPND_PATH, plen,
					    entry->opA->path_or_value))
				goto nla_put_failure;

			nla_nest_end(skb, nest_opnd);
		}

		if (entry->opB) {
			nest_opnd = nla_nest_start(skb, P4TC_CMD_OPER_B);
			copy_k2u_operand(entry->opB, &oper);

			if (nla_put(skb, P4TC_CMD_OPND_INFO,
				    sizeof(struct p4tc_u_operand), &oper))
				goto nla_put_failure;

			plen = entry->opB->path_or_value_sz;
			if (plen && nla_put(skb, P4TC_CMD_OPND_PATH, plen,
					    entry->opB->path_or_value))
				goto nla_put_failure;

			nla_nest_end(skb, nest_opnd);
		}

		if (entry->opC) {
			nest_opnd = nla_nest_start(skb, P4TC_CMD_OPER_C);

			copy_k2u_operand(entry->opC, &oper);

			if (nla_put(skb, P4TC_CMD_OPND_INFO,
				    sizeof(struct p4tc_u_operand), &oper))
				goto nla_put_failure;

			plen = entry->opB->path_or_value_sz;
			if (plen && nla_put(skb, P4TC_CMD_OPND_PATH, plen,
					    entry->opC->path_or_value))
				goto nla_put_failure;

			nla_nest_end(skb, nest_opnd);
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
							     kopnd->path_or_value,
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

static int validate_table_operand(struct p4tc_cmd_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_table_class *tclass;
	struct p4tc_pipeline *pipeline;

	pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
	if (!pipeline) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to find pipeline");
		return -EINVAL;
	}

	tclass = tcf_tclass_find_byid(pipeline, kopnd->immedv);
	if (!tclass) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown table class");
		return -EINVAL;
	}

	if (kopnd->immedv2) {
		if (!tcf_table_key_find(tclass, kopnd->immedv2)) {
			NL_SET_ERR_MSG_MOD(extack, "Unknown key id");
			return -EINVAL;
		}
	} else {
		kopnd->immedv2 = tclass->tbc_default_key;
	}

	kopnd->oper_value_ops = &tclass->tbc_value_ops;

	return 0;
}

static int validate_key_operand(struct p4tc_cmd_operand *kopnd,
				struct netlink_ext_ack *extack)
{
	struct p4tc_type *t = kopnd->oper_datatype;
	struct p4tc_table_class *tclass;
	struct p4tc_pipeline *pipeline;

	pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
	if (!pipeline) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to find pipeline");
		return -EINVAL;
	}

	tclass = tcf_tclass_find_byid(pipeline, kopnd->immedv);
	if (!tclass) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown table class");
		return -EINVAL;
	}

	if (!tcf_table_key_find(tclass, kopnd->immedv2)) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown key id");
		return -EINVAL;
	}

	if (tclass->tbc_keysz != t->bitsz) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Type size doesn't match table class keysz");
		return -EINVAL;
	}

	return 0;
}

static int validate_hdrfield_operand(struct p4tc_cmd_operand *kopnd,
				     struct netlink_ext_ack *extack)
{
	struct p4tc_header_field *hdrfield;
	struct p4tc_parser *parser;
	struct p4tc_pipeline *pipeline;

	pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
	if (!pipeline) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to find pipeline");
		return -EINVAL;
	}

	parser = tcf_parser_find_byid(pipeline, kopnd->immedv);
	if (!parser) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown parser inst id");
		return -EINVAL;
	}

	hdrfield = tcf_hdrfield_find_byid(parser, kopnd->immedv2);
	if (!hdrfield) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown header field id");
		return -EINVAL;
	}

	if (hdrfield->startbit != kopnd->oper_bitstart ||
	    hdrfield->endbit != kopnd->oper_bitend ||
	    hdrfield->datatype != kopnd->oper_datatype->typeid) {
		NL_SET_ERR_MSG_MOD(extack, "Header field type mismatch");
		return -EINVAL;
	}

	kopnd->oper_value_ops = &hdrfield->h_value_ops;

	refcount_inc(&pipeline->p_hdrs_used);

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

static int validate_param_operand(struct p4tc_cmd_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline;
	struct p4tc_act_param *param;
	struct p4tc_type *t;
	struct p4tc_act *act;

	pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
	if (!pipeline) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to find pipeline");
		return -EINVAL;
	}

	act = tcf_action_find_byid(pipeline, kopnd->immedv);
	if (!act) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown action template id");
		return -EINVAL;
	}

	param = tcf_param_find_byid(&act->params_idr, kopnd->immedv2);
	if (!param) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown param id");
		return -EINVAL;
	}

	t = p4type_find_byid(param->type);
	if (t->typeid != kopnd->oper_datatype->typeid) {
		NL_SET_ERR_MSG_MOD(extack, "Param type mismatch");
		return -EINVAL;
	}

	if (t->bitsz != kopnd->oper_datatype->bitsz) {
		NL_SET_ERR_MSG_MOD(extack, "Param size mismatch");
		return -EINVAL;
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

static struct p4tc_type_mask_shift *
create_metadata_bitops(struct p4tc_cmd_operand *kopnd,
		       struct p4tc_metadata *meta, struct p4tc_type *t,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;
	u8 bitstart, bitend;
	u32 bitsz;

	bitstart = meta->m_startbit + kopnd->oper_bitstart;
	bitend = bitstart + kopnd->oper_bitend;
	bitsz = meta->m_endbit - meta->m_startbit + 1;
	mask_shift = t->ops->create_bitops(bitsz, bitstart, bitend,
					   extack);
	return mask_shift;
}

static int __validate_metadata_operand(struct p4tc_cmd_operand *kopnd,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_type *container_type;
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;
	u32 bitsz;
	int err;

	pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
	if (!pipeline) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to find pipeline");
		return -EINVAL;
	}

	meta = tcf_meta_find_byid(pipeline, kopnd->immedv);
	if (!meta) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown metadata");
		return -EINVAL;
	}

	if (meta->m_datatype != kopnd->oper_datatype->typeid) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid metadata data type");
		return -EINVAL;
	}

	bitsz = meta->m_endbit - meta->m_startbit + 1;

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

static int validate_operand(struct net *net, struct p4tc_cmd_operand *kopnd,
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
		err = __validate_metadata_operand(kopnd, extack);
		break;
	case P4TC_OPER_ACTID:
		/* Need to write this */
		err = 0;
		break;
	case P4TC_OPER_TBL:
		err = validate_table_operand(kopnd, extack);
		break;
	case P4TC_OPER_KEY:
		err = validate_key_operand(kopnd, extack);
		break;
	case P4TC_OPER_RES:
		err = validate_res_operand(kopnd, extack);
		break;
	case P4TC_OPER_HDRFIELD:
		err = validate_hdrfield_operand(kopnd, extack);
		break;
	case P4TC_OPER_PARAM:
		err = validate_param_operand(kopnd, extack);
		break;
	case P4TC_OPER_DEV:
		err = validate_dev_operand(net, kopnd, extack);
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown operand type");
		err = -EINVAL;
	}

	return err;
}

static void _free_operand(struct p4tc_cmd_operand *op)
{
	if (op->oper_type == P4TC_OPER_HDRFIELD) {
		struct p4tc_pipeline *pipeline;

		pipeline = tcf_pipeline_find_byid(op->pipeid);
		/* Should never be NULL */
		if (pipeline)
			refcount_dec(&pipeline->p_hdrs_used);
	}
	if (op->oper_mask_shift)
		p4t_release(op->oper_mask_shift);
	kfree(op->path_or_value);
	kfree(op);
}

static void _free_operation(struct p4tc_cmd_operate *ope,
			    struct p4tc_cmd_operand *A,
			    struct p4tc_cmd_operand *B,
			    struct p4tc_cmd_operand *C,
			    struct netlink_ext_ack *extack)
{
	if (A)
		_free_operand(A);

	if (B)
		_free_operand(B);

	if (C)
		_free_operand(C);

	kfree(ope);
}

static void free_op_SET(struct p4tc_cmd_operate *ope,
			struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A = ope->opA;
	struct p4tc_cmd_operand *B = ope->opB;
	struct p4tc_cmd_operand *C = ope->opC;

	return _free_operation(ope, A, B, C, extack);
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
	struct p4tc_cmd_operand *A = ope->opA;
	struct p4tc_cmd_operand *B = ope->opB;
	struct p4tc_cmd_operand *C = ope->opC;
	struct tc_action *p = NULL;

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

	return _free_operation(ope, A, B, C, extack);
}

static int __validate_BINARITH(struct p4tc_cmd_operand *A,
			       struct p4tc_cmd_operand *B,
			       struct p4tc_cmd_operand *C,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_type *Atype;
	struct p4tc_type *Btype;
	struct p4tc_type *Ctype;

	switch (A->oper_type) {
	case P4TC_OPER_META:
	case P4TC_OPER_HDRFIELD:
	case P4TC_OPER_KEY:
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand A must be key, metadata or hdrfield");
		return -EINVAL;
	}

	switch (B->oper_type) {
	case P4TC_OPER_ACTID:
	case P4TC_OPER_TBL:
	case P4TC_OPER_DEV:
	case P4TC_OPER_RES:
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand B must be key, metadata, const, hdrfield or param");
		return -EINVAL;
	default:
		break;
	}

	switch (C->oper_type) {
	case P4TC_OPER_ACTID:
	case P4TC_OPER_TBL:
	case P4TC_OPER_DEV:
	case P4TC_OPER_RES:
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand C must be key, metadata, const, hdrfield or param");
		return -EINVAL;
	default:
		break;
	}

	Atype = A->oper_datatype;
	Btype = B->oper_datatype;
	Ctype = C->oper_datatype;

	if (!Btype->ops->host_read || !Ctype->ops->host_read) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operands B and C's types must have host_read op");
		return -EINVAL;
	}

	if (!Atype->ops->host_write) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand A's type must have host_write op");
		return -EINVAL;
	}

	return 0;
}

/* Syntax: act ACTION_ID ACTION_INDEX
 * Operation: The tc action instance of kind ID ACTION_ID and index ACTION_INDEX
 * is executed.
 * Restriction: The action instance must exist.
 */
int validate_ACT(struct net *net, struct p4tc_cmd_operand *A,
		 struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		 struct netlink_ext_ack *extack)
{
	struct tc_action_ops *action_ops;
	struct tc_action *action;

	if (A->oper_type != P4TC_OPER_ACTID) {
		NL_SET_ERR_MSG_MOD(extack,
				   "ACT: Operand type MUST be P4TC_OPER_ACTID\n");
		return -EINVAL;
	}

	if (B || C) {
		NL_SET_ERR_MSG_MOD(extack,
				   "ACT: Operand B and C are not allowed\n");
		return -EINVAL;
	}

	if (A->pipeid) {
		struct p4tc_pipeline *pipeline;
		struct p4tc_act *act;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		if (!pipeline) {
			NL_SET_ERR_MSG_MOD(extack,
					   "ACT: Unknown pipeline id");
			return -EINVAL;
		}

		act = tcf_action_find_byid(pipeline, A->immedv);
		if (!act) {
			NL_SET_ERR_MSG_MOD(extack, "ACT: unknown Action Kind\n");
			return -EINVAL;
		}

		action_ops = &act->ops;
	} else {
		action_ops = tc_lookup_action_byid(A->immedv);
		if (!action_ops) {
			NL_SET_ERR_MSG_MOD(extack, "ACT: unknown Action Kind\n");
			return -EINVAL;
		}
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
int validate_SET(struct net *net, struct p4tc_cmd_operand *A,
		 struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		 struct netlink_ext_ack *extack)
{
	struct p4tc_type *Atype;
	struct p4tc_type *Btype;
	int err = 0;

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

	if (B->oper_type == P4TC_OPER_KEY) {
		NL_SET_ERR_MSG_MOD(extack, "Operand B cannot be key\n");
		return -EINVAL;
	}

	if (C) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid set operation with C\n");
		return -EINVAL;
	}

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

	err = validate_operand(net, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = validate_operand(net, B, extack);
	if (err)
		return err;

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

int validate_PRINT(struct net *net, struct p4tc_cmd_operand *A,
		   struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		   struct netlink_ext_ack *extack)
{
	if (A->oper_type == P4TC_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A cannot be constant\n");
		return -EINVAL;
	}

	if (B || C) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Invalid print operation with B or C\n");
		return -EINVAL;
	}

	return validate_operand(net, A, extack);
}

int validate_TBLAPP(struct net *net, struct p4tc_cmd_operand *A,
		    struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		    struct netlink_ext_ack *extack)
{
	int err = 0;

	if (A->oper_type != P4TC_OPER_TBL) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A must be a table\n");
		return -EINVAL;
	}

	if (B || C) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Invalid table apply operation with B or C\n");
		return -EINVAL;
	}


	err = validate_operand(net, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	return 0;
}

int validate_SNDPORTEGR(struct net *net, struct p4tc_cmd_operand *A,
			struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
			struct netlink_ext_ack *extack)
{
	int err = 0;

	if (B || C) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Invalid send_port_egress operation with B or C\n");
		return -EINVAL;
	}

	err = validate_operand(net, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	return 0;
}

int validate_BINARITH(struct net *net, struct p4tc_cmd_operand *A,
		      struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		      struct netlink_ext_ack *extack)
{
	struct p4tc_type *Atype;
	struct p4tc_type *Btype;
	struct p4tc_type *Ctype;

	int err;

	err = validate_operand(net, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = validate_operand(net, B, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = validate_operand(net, C, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = __validate_BINARITH(A, B, C, extack);
	if (err)
		return err;

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

int validate_CONCAT(struct net *net, struct p4tc_cmd_operand *A,
		    struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		    struct netlink_ext_ack *extack)
{
	struct p4tc_type *Atype;
	struct p4tc_type *Btype;
	struct p4tc_type *Ctype;
	int err;

	err = validate_operand(net, A, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = validate_operand(net, B, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = validate_operand(net, C, extack);
	if (err)		/*a better NL_SET_ERR_MSG_MOD done by validate_operand() */
		return err;

	err = __validate_BINARITH(A, B, C, extack);
	if (err)
		return err;

	Atype = A->oper_datatype;
	Btype = B->oper_datatype;
	Ctype = C->oper_datatype;

	if (Atype->bitsz < Btype->bitsz + Ctype->bitsz) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operands B and C concatenated must fit inside operand A");
		return -EINVAL;
	}

	if (Btype->bitsz % 8 != 0 ||
	    Ctype->bitsz % 8 != 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operands B and C must have bitsz multiple of 8");
		return -EINVAL;
	}

	return 0;
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
	struct p4tc_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4tc_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, cmd, res);
	void *Aval = op->opA->fetch(skb, op->opA, cmd, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (!res_cmp)
		return op->ctl1;

	return op->ctl2;
}

/* if A != B <ctl1> else <ctl2> */
static int p4tc_cmd_BNE(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4tc_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, cmd, res);
	void *Aval = op->opA->fetch(skb, op->opA, cmd, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (res_cmp)
		return op->ctl1;

	return op->ctl2;
}

/* if A < B <ctl1> else <ctl2> */
static int p4tc_cmd_BLT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4tc_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, cmd, res);
	void *Aval = op->opA->fetch(skb, op->opA, cmd, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (res_cmp < 0)
		return op->ctl1;

	return op->ctl2;
}

/* if A <= B <ctl1> else <ctl2> */
static int p4tc_cmd_BLE(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4tc_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, cmd, res);
	void *Aval = op->opA->fetch(skb, op->opA, cmd, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (!res_cmp || res_cmp < 0)
		return op->ctl1;

	return op->ctl2;
}

/* if A > B <ctl1> else <ctl2> */
static int p4tc_cmd_BGT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4tc_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, cmd, res);
	void *Aval = op->opA->fetch(skb, op->opA, cmd, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (res_cmp > 0)
		return op->ctl1;

	return op->ctl2;
}

/* if A >= B <ctl1> else <ctl2> */
static int p4tc_cmd_BGE(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4tc_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, cmd, res);
	void *Aval = op->opA->fetch(skb, op->opA, cmd, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (!res_cmp || res_cmp > 0)
		return op->ctl1;

	return op->ctl2;
}

int validate_BRN(struct net *net, struct p4tc_cmd_operand *A,
		 struct p4tc_cmd_operand *B, struct p4tc_cmd_operand *C,
		 struct netlink_ext_ack *extack)
{
	int err = 0;

	if (A->oper_type == P4TC_OPER_CONST && B &&
	    B->oper_type == P4TC_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Branch: A and B can't both be constant\n");
		return -EINVAL;
	}

	if (C) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid branch operation with C\n");
		return -EINVAL;
	}

	if ((A && !p4tc_type_unsigned(A->oper_datatype->typeid)) ||
	    (B && !p4tc_type_unsigned(B->oper_datatype->typeid))) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operands A and B must be unsigned\n");
		return -EINVAL;
	}

	err = validate_operand(net, A, extack);
	if (err)
		return err;

	err = validate_operand(net, B, extack);
	if (err)
		return err;

	return 0;
}

static void free_op_BRN(struct p4tc_cmd_operate *ope,
			struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A = ope->opA;
	struct p4tc_cmd_operand *B = ope->opB;
	struct p4tc_cmd_operand *C = ope->opC;

	return _free_operation(ope, A, B, C, extack);
}

static void free_op_PRINT(struct p4tc_cmd_operate *ope,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A = ope->opA;

	return _free_operation(ope, A, NULL, NULL, extack);
}

static void free_op_TBLAPP(struct p4tc_cmd_operate *ope,
			   struct netlink_ext_ack *extack)
{

	struct p4tc_cmd_operand *A = ope->opA;

	return _free_operation(ope, A, NULL, NULL, extack);
}

static void free_op_SNDPORTEGR(struct p4tc_cmd_operate *ope,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A = ope->opA;
	struct net_device *dev = A->priv;

	netdev_put(dev, NULL);

	return _free_operation(ope, A, NULL, NULL, extack);
}

static void free_op_BINARITH(struct p4tc_cmd_operate *ope,
			     struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *A = ope->opA;
	struct p4tc_cmd_operand *B = ope->opB;
	struct p4tc_cmd_operand *C = ope->opC;

	return _free_operation(ope, A, B, C, extack);
}

static struct p4tc_cmd_s cmds[] = {
	{ P4TC_CMD_OP_SET, validate_SET, free_op_SET, p4tc_cmd_SET },
	{ P4TC_CMD_OP_ACT, validate_ACT, free_op_ACT, p4tc_cmd_ACT },
	{ P4TC_CMD_OP_BEQ, validate_BRN, free_op_BRN, p4tc_cmd_BEQ },
	{ P4TC_CMD_OP_BNE, validate_BRN, free_op_BRN, p4tc_cmd_BNE },
	{ P4TC_CMD_OP_BGT, validate_BRN, free_op_BRN, p4tc_cmd_BGT },
	{ P4TC_CMD_OP_BLT, validate_BRN, free_op_BRN, p4tc_cmd_BLT },
	{ P4TC_CMD_OP_BGE, validate_BRN, free_op_BRN, p4tc_cmd_BGE },
	{ P4TC_CMD_OP_BLE, validate_BRN, free_op_BRN, p4tc_cmd_BLE },
	{ P4TC_CMD_OP_PRINT, validate_PRINT, free_op_PRINT, p4tc_cmd_PRINT },
	{ P4TC_CMD_OP_TBLAPP, validate_TBLAPP, free_op_TBLAPP, p4tc_cmd_TBLAPP },
	{ P4TC_CMD_OP_SNDPORTEGR, validate_SNDPORTEGR, free_op_SNDPORTEGR,
	  p4tc_cmd_SNDPORTEGR },
	{ P4TC_CMD_OP_MIRPORTEGR, validate_SNDPORTEGR, free_op_SNDPORTEGR,
	  p4tc_cmd_MIRPORTEGR },
	{ P4TC_CMD_OP_PLUS, validate_BINARITH, free_op_BINARITH, p4tc_cmd_PLUS },
	{ P4TC_CMD_OP_SUB, validate_BINARITH, free_op_BINARITH, p4tc_cmd_SUB },
	{ P4TC_CMD_OP_CONCAT, validate_CONCAT, free_op_BINARITH, p4tc_cmd_CONCAT },
	{ P4TC_CMD_OP_BAND, validate_BINARITH, free_op_BINARITH, p4tc_cmd_BAND },
	{ P4TC_CMD_OP_BOR, validate_BINARITH, free_op_BINARITH, p4tc_cmd_BOR },
	{ P4TC_CMD_OP_BXOR, validate_BINARITH, free_op_BINARITH, p4tc_cmd_BXOR },
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
	[P4TC_CMD_OPND_PATH] = { .type = NLA_BINARY,
				    .len = P4TC_CMD_MAX_OPER_PATH_LEN },
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
	} else {
		NL_SET_ERR_MSG_MOD(extack, "Unknown operand type");
		return -EINVAL;
	}

	wantbits = 1 + uopnd->oper_endbit - uopnd->oper_startbit;
	if (uopnd->oper_type != P4TC_OPER_ACTID &&
	    uopnd->oper_type != P4TC_OPER_TBL &&
	    uopnd->oper_cbitsize < wantbits) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Start and end bit dont fit in space");
		return -EINVAL;
	}

	err = copy_u2k_operand(uopnd, kopnd, extack);
	if (err < 0)
		return err;

	if (tb[P4TC_CMD_OPND_PATH])
		oper_sz = nla_len(tb[P4TC_CMD_OPND_PATH]);

	kopnd->path_or_value_sz = oper_sz;

	if (!oper_sz) {
		kopnd->oper_flags |= DATA_IS_IMMEDIATE;
		return 0;
	}

	kopnd->path_or_value = kzalloc(oper_sz, GFP_KERNEL);
	if (!kopnd->path_or_value) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to alloc operand path data");
		return -ENOMEM;
	}

	err = nla_memcpy(kopnd->path_or_value, tb[P4TC_CMD_OPND_PATH],
			 oper_sz);
	if (unlikely(err != oper_sz)) {
		NL_SET_ERR_MSG_MOD(extack, "Malformed operand path data");
		kfree(kopnd->path_or_value);
		return -EINVAL;
	}

	return 0;
}

/* Operation */
static const struct nla_policy cmd_ops_policy[P4TC_CMD_OPER_MAX + 1] = {
	[P4TC_CMD_OPERATION] = {
		.type = NLA_BINARY,
		.len = sizeof(struct p4tc_u_operate)
	},
	[P4TC_CMD_OPER_A] = { .type = NLA_NESTED },
	[P4TC_CMD_OPER_B] = { .type = NLA_NESTED },
	[P4TC_CMD_OPER_C] = { .type = NLA_NESTED },
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
	return ope;
}

static int p4tc_cmd_process_ops(struct net *net, struct nlattr *nla,
				struct p4tc_cmd_operate **op_entry,
				struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *opndA = NULL;
	struct p4tc_cmd_operand *opndB = NULL;
	struct p4tc_cmd_operand *opndC = NULL;
	struct p4tc_cmd_operate *ope = NULL;
	int err = 0, tbits = 0;
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

	if (tb[P4TC_CMD_OPER_A]) {
		opndA = kzalloc(sizeof(*opndA), GFP_KERNEL);
		if (!opndA)
			return -ENOMEM;

		err = p4tc_cmds_process_opnd(tb[P4TC_CMD_OPER_A], opndA,
					     extack);
		if (err < 0) {
			//XXX: think about getting rid of this P4TC_CMD_POLICY
			err =  P4TC_CMD_POLICY;
			goto set_results;
		}

		tbits = opndA->oper_bitsize;
	}

	if (tb[P4TC_CMD_OPER_B]) {
		opndB = kzalloc(sizeof(*opndB), GFP_KERNEL);
		if (!opndB) {
			err =  -ENOMEM;
			goto set_results;
		}

		err = p4tc_cmds_process_opnd(tb[P4TC_CMD_OPER_B], opndB,
					     extack);
		if (err < 0) {
			//XXX: think about getting rid of this P4TC_CMD_POLICY
			err =  P4TC_CMD_POLICY;
			goto set_results;
		}

		tbits = opndB->oper_bitsize;
	}

	if (tb[P4TC_CMD_OPER_C]) {
		opndC = kzalloc(sizeof(*opndC), GFP_KERNEL);
		if (!opndC) {
			err =  -ENOMEM;
			goto set_results;
		}

		err = p4tc_cmds_process_opnd(tb[P4TC_CMD_OPER_C], opndC,
					     extack);
		if (err < 0) {
			//XXX: think about getting rid of this P4TC_CMD_POLICY
			err =  P4TC_CMD_POLICY;
			goto set_results;
		}

		tbits = opndC->oper_bitsize;
	}

	if (cmd_t->validate_operands(net, opndA, opndB, opndC, extack)) {
		//XXX: think about getting rid of this P4TC_CMD_POLICY
		err =  P4TC_CMD_POLICY;
		goto set_results;
	}

set_results:
	ope->cmd = cmd_t;
	*op_entry = ope;
	ope->opA = opndA;
	ope->opB = opndB;
	ope->opC = opndC;

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

	_new_kopnd = kzalloc(sizeof(*_new_kopnd), GFP_KERNEL);
	if (!_new_kopnd)
		return -ENOMEM;

	memcpy(_new_kopnd, kopnd, sizeof(*_new_kopnd));

	if (kopnd->oper_type == P4TC_OPER_CONST &&
	    kopnd->oper_datatype->ops->create_bitops) {
		mask_shift = create_constant_bitops(kopnd,
						    kopnd->oper_datatype,
						    extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;
	} else if (kopnd->oper_type == P4TC_OPER_META &&
		   kopnd->oper_datatype->ops->create_bitops) {
		struct p4tc_pipeline *pipeline;
		struct p4tc_metadata *meta;

		pipeline = tcf_pipeline_find_byid(kopnd->pipeid);
		if (!pipeline)
			return -EINVAL;

		meta = tcf_meta_find_byid(pipeline, kopnd->immedv);
		if (!meta)
			return -EINVAL;

		mask_shift = create_metadata_bitops(kopnd, meta,
						    kopnd->oper_datatype,
						    extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;
	}

	_new_kopnd->path_or_value = kzalloc(kopnd->path_or_value_sz,
					    GFP_KERNEL);
	if (!_new_kopnd->path_or_value)
		return -ENOMEM;
	memcpy(_new_kopnd->path_or_value, kopnd->path_or_value,
	       kopnd->path_or_value_sz);

	_new_kopnd->oper_mask_shift = mask_shift;

	*new_kopnd = _new_kopnd;

	return 0;
}

static int p4tc_cmds_copy_ops(struct p4tc_cmd_operate **new_op_entry,
			      struct p4tc_cmd_operate *op_entry,
			      struct netlink_ext_ack *extack)
{
	struct p4tc_cmd_operand *opndA = NULL;
	struct p4tc_cmd_operand *opndB = NULL;
	struct p4tc_cmd_operand *opndC = NULL;
	struct p4tc_cmd_operate *_new_op_entry;
	int err;

	_new_op_entry = kzalloc(sizeof(*_new_op_entry), GFP_KERNEL);
	if (!_new_op_entry)
		return -ENOMEM;

	if (op_entry->opA) {
		err = p4tc_cmds_copy_opnd(&opndA, op_entry->opA, extack);
		if (err < 0)
			goto set_results;
	}

	if (op_entry->opB) {
		err = p4tc_cmds_copy_opnd(&opndB, op_entry->opB, extack);
		if (err < 0)
			goto set_results;
	}

	if (op_entry->opC) {
		err = p4tc_cmds_copy_opnd(&opndC, op_entry->opC, extack);
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
	_new_op_entry->opA = opndA;
	_new_op_entry->opB = opndB;
	_new_op_entry->opC = opndC;

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
		    struct list_head *cmd_operations,
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

	for (i = 1; i < P4TC_CMDS_LIST_MAX && oplist_attr[i]; i++) {
		struct p4tc_cmd_operate *o = oplist[i - 1];

		err =
		    p4tc_cmd_process_ops(net, oplist_attr[i], &oplist[i - 1],
					 extack);
		o = oplist[i - 1];
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
		p4tc_cmd_ops_del_list(cmd_operations);

	/*XXX: At this point we have all the cmds and they are valid */
	p4tc_cmds_ops_pass_to_list(oplist, cmd_operations);

	return 0;
}

static void *p4tc_fetch_constant(struct sk_buff *skb,
				 struct p4tc_cmd_operand *op,
				 struct tcf_p4act *cmd, struct tcf_result *res)
{
	if (op->oper_flags & DATA_IS_IMMEDIATE)
		return &op->immedv;

	if (op->path_or_value_sz)
		return op->path_or_value;

	return NULL;
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

/* SET A B  - A is set from B
 *
 * Assumes everything has been vetted - meaning no checks here
 *
 */
static int p4tc_cmd_SET(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	void *src = op->opB->fetch(skb, op->opB, cmd, res);
	void *dst = op->opA->fetch(skb, op->opA, cmd, res);
	struct p4tc_type *dst_t = op->opA->oper_datatype;
	struct p4tc_type *src_t = op->opB->oper_datatype;
	struct p4tc_type_ops *dst_ops = dst_t->ops;
	struct p4tc_type_ops *src_ops = src_t->ops;
	int err;

	//XXX: We should return SHOT for any failure...
	//imagine running a series of commands on a packet
	//which gets partially modified. You really dont want
	//to proceed with other commands if one in the middle
	//fails neither do you want that packet sent anywhere.
	if (!src || !dst)
		return TC_ACT_SHOT;

	err = p4t_copy(op->opA->oper_mask_shift, dst_ops, dst,
		       op->opB->oper_mask_shift, src_ops, src);
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
	const struct tc_action *action = op->opA->action;

	return action->ops->act(skb, action, res);
}

static int p4tc_cmd_PRINT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			  struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A = op->opA;
	struct p4tc_type *val_t = A->oper_datatype;
	void *val = A->fetch(skb, A, cmd, res);
	char name[(TEMPLATENAMSZ * 4)];

	if (!val)
		return TC_ACT_OK;

	/* This is a debug function, so performance is not a priority */
	if (A->oper_type == P4TC_OPER_META) {
		struct p4tc_pipeline *pipeline = NULL;
		char *path = (char *)A->path_or_value;
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

		val_t->ops->print(name, val);
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

		val_t->ops->print(name, val);
	} else if (A->oper_type == P4TC_OPER_KEY) {
		struct p4tc_table_class *tclass;
		struct p4tc_pipeline *pipeline;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		tclass = tcf_tclass_find_byid(pipeline, A->immedv);
		snprintf(name, TEMPLATENAMSZ * 3, "key.%s.%s.%u",
			 pipeline->common.name, tclass->common.name,
			 A->immedv2);
		val_t->ops->print(name, val);
	} else if (A->oper_type == P4TC_OPER_PARAM) {
		val_t->ops->print("param", val);
	} else if (A->oper_type == P4TC_OPER_RES) {
		if (A->immedv == P4TC_CMDS_RESULTS_HIT)
			val_t->ops->print("res.hit", val);
		else if (A->immedv == P4TC_CMDS_RESULTS_MISS)
			val_t->ops->print("res.miss", val);
	} else {
		pr_info("Unsupported operand for print\n");
	}

	return op->ctl1;
}

#define REDIRECT_RECURSION_LIMIT    4
static DEFINE_PER_CPU(unsigned int, redirect_rec_level);

static int p4tc_cmd_SNDPORTEGR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			       struct tcf_p4act *cmd, struct tcf_result *res)
{
	struct p4tc_cmd_operand *A = op->opA;
	struct net_device *dev = A->fetch(skb, A, cmd, res);
	struct sk_buff *skb2 = skb;
	int retval = TC_ACT_STOLEN;
	unsigned int rec_level;
	bool expects_nh;
	int mac_len;
	bool at_nh;
	int err;

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
	struct p4tc_cmd_operand *A = op->opA;
	struct net_device *dev = A->fetch(skb, A, cmd, res);
	struct sk_buff *skb2 = skb;
	int retval = TC_ACT_PIPE;
	unsigned int rec_level;
	bool expects_nh;
	int mac_len;
	bool at_nh;
	int err;

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
	struct p4tc_cmd_operand *A = op->opA;
	struct p4tc_table_class *tclass = A->fetch(skb, A, cmd, res);
	struct p4tc_table_instance *tinst;
	struct p4tc_table_entry *entry;
	struct p4tc_table_key *key;
	int ret;

	if (unlikely(!tclass))
		return TC_ACT_SHOT;

	if (tclass->tbc_preacts) {
		ret = tcf_action_exec(skb, tclass->tbc_preacts,
				      tclass->tbc_num_preacts, res);
		/* Should check what return code should cause return */
		if (ret == TC_ACT_SHOT)
			return ret;
	}

	/* Sets key */
	key = tcf_table_key_find(tclass, A->immedv2);
	ret = tcf_action_exec(skb, key->key_acts, key->key_num_acts, res);
	if (ret != TC_ACT_PIPE)
		return ret;

	/* We assume one instance per table which has id 1 */
	tinst = tcf_tinst_find_byany(NULL, 1, NULL, tclass, NULL);
	if (!tinst)
		return TC_ACT_OK;

	entry = p4tc_table_entry_lookup(skb, tinst, tclass->tbc_keysz);
	if (IS_ERR(entry))
		entry = NULL;

	res->hit = entry ? true : false;
	res->miss = !res->hit;

	ret = TC_ACT_PIPE;
	if (res->hit) {
		if (entry->acts)
			ret = tcf_action_exec(skb, entry->acts, entry->num_acts,
					      res);
		else if (tclass->tbc_default_hitact)
			ret = tcf_action_exec(skb, tclass->tbc_default_hitact,
					      1, res);
	} else {
		if (tclass->tbc_default_missact)
			ret = tcf_action_exec(skb, tclass->tbc_default_missact,
					      1, res);
	}
	if (ret != TC_ACT_PIPE)
		return ret;

	return tcf_action_exec(skb, tclass->tbc_postacts,
			       tclass->tbc_num_postacts, res);
}

static int p4tc_cmd_BINARITH(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			     struct tcf_p4act *cmd, struct tcf_result *res,
			     void (*p4tc_arith_op)(u64 *res, u64 *opB, u64 *opC))
{
	void *srcB = op->opB->fetch(skb, op->opB, cmd, res);
	void *srcC = op->opC->fetch(skb, op->opC, cmd, res);
	void *dst = op->opA->fetch(skb, op->opA, cmd, res);
	struct p4tc_type *dst_t = op->opA->oper_datatype;
	struct p4tc_type *srcB_t = op->opB->oper_datatype;
	struct p4tc_type *srcC_t = op->opC->oper_datatype;
	struct p4tc_type_ops *dst_ops = dst_t->ops;
	struct p4tc_type_ops *srcB_ops = srcB_t->ops;
	struct p4tc_type_ops *srcC_ops = srcC_t->ops;
	u64 result[2] = {0};
	u64 Bval[2] = {0};
	u64 Cval[2] = {0};

	if (!srcB || !srcC || !dst)
		return TC_ACT_SHOT;

	srcB_ops->host_read(op->opB->oper_mask_shift, srcB, Bval);
	srcC_ops->host_read(op->opC->oper_mask_shift, srcC, Cval);

	p4tc_arith_op(result, Bval, Cval);

	dst_ops->host_write(op->opA->oper_mask_shift, result, dst);

	return op->ctl1;
}

/* For this first implementation we are not handling overflows yet */
static void plus_op(u64 *res, u64 *opB, u64 *opC)
{
	res[0] = opB[0] + opC[0];
	res[1] = opB[1] + opC[1];
}

static int p4tc_cmd_PLUS(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, plus_op);
}

/* For this first implementation we are not handling overflows yet */
static void sub_op(u64 *res, u64 *opB, u64 *opC)
{
	res[0] = opB[0] - opC[0];
	res[1] = opB[1] - opC[1];
}

static int p4tc_cmd_SUB(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, sub_op);
}

static void band_op(u64 *res, u64 *opB, u64 *opC)
{
	res[0] = opB[0] & opC[0];
	res[1] = opB[1] & opC[1];
}

static int p4tc_cmd_BAND(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, band_op);
}

static void bor_op(u64 *res, u64 *opB, u64 *opC)
{
	res[0] = opB[0] | opC[0];
	res[1] = opB[1] | opC[1];
}

static int p4tc_cmd_BOR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, bor_op);
}

static void bxor_op(u64 *res, u64 *opB, u64 *opC)
{
	res[0] = opB[0] ^ opC[0];
	res[1] = opB[1] ^ opC[1];
}

static int p4tc_cmd_BXOR(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			 struct tcf_p4act *cmd, struct tcf_result *res)
{
	return p4tc_cmd_BINARITH(skb, op, cmd, res, bxor_op);
}

static int p4tc_cmd_CONCAT(struct sk_buff *skb, struct p4tc_cmd_operate *op,
			   struct tcf_p4act *cmd, struct tcf_result *res)
{
	void *srcB = op->opB->fetch(skb, op->opB, cmd, res);
	void *srcC = op->opC->fetch(skb, op->opC, cmd, res);
	void *dst = op->opA->fetch(skb, op->opA, cmd, res);
	struct p4tc_type *dst_t = op->opA->oper_datatype;
	struct p4tc_type *srcB_t = op->opB->oper_datatype;
	struct p4tc_type *srcC_t = op->opC->oper_datatype;
	struct p4tc_type_ops *dst_ops = dst_t->ops;
	struct p4tc_type_ops *srcB_ops = srcB_t->ops;
	struct p4tc_type_ops *srcC_ops = srcC_t->ops;
	__uint128_t Bval;
	__uint128_t Cval;

	memset(&Bval, 0, sizeof(Bval));
	memset(&Cval, 0, sizeof(Cval));

	if (!srcB || !srcC || !dst)
		return TC_ACT_SHOT;

	srcB_ops->host_read(op->opB->oper_mask_shift, srcB, &Bval);
	srcC_ops->host_read(op->opC->oper_mask_shift, srcC, &Cval);

	/* operand B's bitsz must be a multiple of 8 */
	memcpy((char *)&Bval + BITS_TO_BYTES(srcB_t->bitsz), &Cval,
	       BITS_TO_BYTES(srcC_t->bitsz));

	dst_ops->host_write(op->opA->oper_mask_shift, &Bval, dst);

	return op->ctl1;
}
