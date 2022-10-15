// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/act_metact.c - P4 metact
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/module.h>
#include <linux/init.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_metact.h>
#include <net/tc_act/tc_metact.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>

#include <net/p4_types.h>

static void *fetch_metadata(struct sk_buff *skb, struct tca_meta_operand *op,
			    struct tcf_metact_info *metact,
			    struct tcf_result *res);
static void *fetch_constant(struct sk_buff *skb, struct tca_meta_operand *op,
			    struct tcf_metact_info *metact,
			    struct tcf_result *res);
static void *fetch_key(struct sk_buff *skb, struct tca_meta_operand *op,
		       struct tcf_metact_info *metact,
		       struct tcf_result *res);
static void *fetch_table(struct sk_buff *skb, struct tca_meta_operand *op,
			 struct tcf_metact_info *metact,
			 struct tcf_result *res);
static void *fetch_result(struct sk_buff *skb, struct tca_meta_operand *op,
			  struct tcf_metact_info *metact,
			  struct tcf_result *res);
static void *fetch_hdrfield(struct sk_buff *skb, struct tca_meta_operand *op,
			    struct tcf_metact_info *metact,
			    struct tcf_result *res);
static void *fetch_param(struct sk_buff *skb, struct tca_meta_operand *op,
			 struct tcf_metact_info *metact,
			 struct tcf_result *res);
static void *fetch_dev(struct sk_buff *skb, struct tca_meta_operand *op,
		       struct tcf_metact_info *metact,
		       struct tcf_result *res);
static int metact_SET(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact, struct tcf_result *res);
static int metact_ACT(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact, struct tcf_result *res);
static int metact_PRINT(struct sk_buff *skb, struct tca_meta_operate *op,
			struct tcf_metact_info *metact, struct tcf_result *res);
static int metact_TBLAPP(struct sk_buff *skb, struct tca_meta_operate *op,
			 struct tcf_metact_info *metact,
			 struct tcf_result *res);
static int metact_SNDPORTEGR(struct sk_buff *skb, struct tca_meta_operate *op,
			     struct tcf_metact_info *metact,
			     struct tcf_result *res);
static int metact_MIRPORTEGR(struct sk_buff *skb, struct tca_meta_operate *op,
			     struct tcf_metact_info *metact,
			     struct tcf_result *res);


static void kfree_opentry(struct tca_meta_operate *ope)
{
	if (!ope)
		return;

	ope->cmd->free_operation(ope, NULL);
}

static void copy_k2u_operand(struct tca_meta_operand *k,
			     struct tca_u_meta_operand *u)
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

static int copy_u2k_operand(struct tca_u_meta_operand *uopnd,
			    struct tca_meta_operand *kopnd,
			    struct netlink_ext_ack *extack)
{
	struct p4_type *type;

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
int fillup_metact_cmds(struct sk_buff *skb, struct list_head *meta_operations)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tca_u_meta_operand oper = { };
	struct tca_u_meta_operate op = { };
	int i = 1, plen = 4;
	struct tca_meta_operate *entry;
	struct nlattr *nest_op, *nest_opnd;

	list_for_each_entry(entry, meta_operations, meta_operations) {
		if (!entry)
			continue;
		nest_op = nla_nest_start_noflag(skb, i);

		op.op_type = entry->op_id;
		op.op_flags = entry->op_flags;
		op.op_ctl1 =  entry->ctl1;
		op.op_ctl2 =  entry->ctl2;
		if (nla_put(skb, TCAA_METACT_OPERATION,
			    sizeof(struct tca_u_meta_operate), &op))
			goto nla_put_failure;

		if (entry->opA) {
			nest_opnd = nla_nest_start_noflag(skb,
							  TCAA_METACT_OPER_A);
			copy_k2u_operand(entry->opA, &oper);

			if (nla_put(skb, TCAA_METACT_OPND_INFO,
				    sizeof(struct tca_u_meta_operand), &oper))
				goto nla_put_failure;

			plen = entry->opA->path_or_value_sz;

			if (plen && nla_put(skb, TCAA_METACT_OPND_PATH, plen,
					    entry->opA->path_or_value))
				goto nla_put_failure;

			nla_nest_end(skb, nest_opnd);
		}

		if (entry->opB) {
			nest_opnd = nla_nest_start_noflag(skb,
							  TCAA_METACT_OPER_B);
			copy_k2u_operand(entry->opB, &oper);

			if (nla_put(skb, TCAA_METACT_OPND_INFO,
				    sizeof(struct tca_u_meta_operand), &oper))
				goto nla_put_failure;

			plen = entry->opB->path_or_value_sz;
			if (plen && nla_put(skb, TCAA_METACT_OPND_PATH, plen,
					    entry->opB->path_or_value))
				goto nla_put_failure;

			nla_nest_end(skb, nest_opnd);
		}

		if (entry->opC) {
			nest_opnd = nla_nest_start_noflag(skb,
							  TCAA_METACT_OPER_C);

			copy_k2u_operand(entry->opC, &oper);

			if (nla_put(skb, TCAA_METACT_OPND_INFO,
				    sizeof(struct tca_u_meta_operand), &oper))
				goto nla_put_failure;

			plen = entry->opB->path_or_value_sz;
			if (plen && nla_put(skb, TCAA_METACT_OPND_PATH, plen,
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

void release_ope_list(struct list_head *entries)
{
	struct tca_meta_operate *entry, *e;

	list_for_each_entry_safe(entry, e, entries, meta_operations) {
		list_del(&entry->meta_operations);
		kfree_opentry(entry);
	}
}

static void kfree_tmp_oplist(struct tca_meta_operate *oplist[])
{
	int i = 0;
	struct tca_meta_operate *ope;

	for (i = 0; i < TCA_METACT_LIST_MAX; i++) {
		ope = oplist[i];
		if (!ope)
			continue;

		kfree_opentry(ope);
	}
}

static int validate_metadata_operand(struct tca_meta_operand *kopnd,
				     struct p4_type *container_type,
				     struct netlink_ext_ack *extack)
{
	struct p4_type_ops *type_ops = container_type->ops;
	int err;

	if (kopnd->oper_cbitsize < kopnd->oper_bitsize) {
		NL_SET_ERR_MSG_MOD(extack,
				   "bitsize has to be <= cbitsize\n");
		return -EINVAL;
	}

	if (type_ops->validate_p4t) {
		if (kopnd->oper_type == METACT_OPER_CONST)
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

static int validate_table_operand(struct tca_meta_operand *kopnd,
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

static int validate_key_operand(struct tca_meta_operand *kopnd,
				struct netlink_ext_ack *extack)
{
	struct p4_type *t = kopnd->oper_datatype;
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

static int validate_hdrfield_operand(struct tca_meta_operand *kopnd,
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

	return 0;
}

int validate_dev_operand(struct net *net, struct tca_meta_operand *kopnd,
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

static int validate_param_operand(struct tca_meta_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline;
	struct p4tc_act_param *param;
	struct p4_type *t;
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

static int validate_res_operand(struct tca_meta_operand *kopnd,
				 struct netlink_ext_ack *extack)
{
	if (kopnd->immedv == METACT_RESULTS_HIT ||
	    kopnd->immedv == METACT_RESULTS_MISS)
		return 0;

	NL_SET_ERR_MSG_MOD(extack, "Invalid result field");
	return -EINVAL;
}

static struct p4_type_mask_shift *
create_metadata_bitops(struct tca_meta_operand *kopnd,
		       struct p4tc_metadata *meta, struct p4_type *t,
		       struct netlink_ext_ack *extack)
{
	struct p4_type_mask_shift *mask_shift;
	u8 bitstart, bitend;
	u32 bitsz;

	bitstart = meta->m_startbit + kopnd->oper_bitstart;
	bitend = bitstart + kopnd->oper_bitend;
	bitsz = meta->m_endbit - meta->m_startbit + 1;
	mask_shift = t->ops->create_bitops(bitsz, bitstart, bitend,
					   extack);
	return mask_shift;
}

static int __validate_metadata_operand(struct tca_meta_operand *kopnd,
				       struct netlink_ext_ack *extack)
{
	struct p4_type *container_type;
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
		struct p4_type_mask_shift *mask_shift;

		mask_shift = create_metadata_bitops(kopnd, meta,
						    container_type, extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;

		kopnd->oper_mask_shift = mask_shift;
	}
	kopnd->oper_value_ops = &meta->m_value_ops;

	return 0;
}

static struct p4_type_mask_shift *
create_constant_bitops(struct tca_meta_operand *kopnd, struct p4_type *t,
		       struct netlink_ext_ack *extack)
{
	struct p4_type_mask_shift *mask_shift;

	mask_shift = t->ops->create_bitops(t->bitsz,
					   kopnd->oper_bitstart,
					   kopnd->oper_bitend, extack);
	return mask_shift;
}

static int validate_large_operand(struct tca_meta_operand *kopnd,
				  struct netlink_ext_ack *extack)
{
	struct p4_type *t = kopnd->oper_datatype;
	int err = 0;

	err = validate_metadata_operand(kopnd, t, extack);
	if (err)
		return err;
	if (t->ops->create_bitops) {
		struct p4_type_mask_shift *mask_shift;

		mask_shift = create_constant_bitops(kopnd, t, extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;

		kopnd->oper_mask_shift = mask_shift;
	}

	return 0;
}

/*Data is constant <=32 bits */
static int validate_immediate_operand(struct tca_meta_operand *kopnd,
				      struct netlink_ext_ack *extack)
{
	struct p4_type *t = kopnd->oper_datatype;
	int err = 0;

	err = validate_metadata_operand(kopnd, t, extack);
	if (err)
		return err;
	if (t->ops->create_bitops) {
		struct p4_type_mask_shift *mask_shift;

		mask_shift = create_constant_bitops(kopnd, t, extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;

		kopnd->oper_mask_shift = mask_shift;
	}

	return 0;
}

static int validate_operand(struct net *net, struct tca_meta_operand *kopnd,
			    struct netlink_ext_ack *extack)
{
	int err = 0;

	if (!kopnd)
		return err;

	switch(kopnd->oper_type) {
	case METACT_OPER_CONST:
		if (kopnd->oper_flags & DATA_IS_IMMEDIATE)
			err = validate_immediate_operand(kopnd, extack);
		else
			err = validate_large_operand(kopnd, extack);
		break;
	case METACT_OPER_META:
		err = __validate_metadata_operand(kopnd, extack);
		break;
	case METACT_OPER_ACTID:
		/* Need to write this */
		err = 0;
		break;
	case METACT_OPER_TBL:
		err = validate_table_operand(kopnd, extack);
		break;
	case METACT_OPER_KEY:
		err = validate_key_operand(kopnd, extack);
		break;
	case METACT_OPER_RES:
		err = validate_res_operand(kopnd, extack);
		break;
	case METACT_OPER_HDRFIELD:
		err = validate_hdrfield_operand(kopnd, extack);
		break;
	case METACT_OPER_PARAM:
		err = validate_param_operand(kopnd, extack);
		break;
	case METACT_OPER_DEV:
		err = validate_dev_operand(net, kopnd, extack);
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown operand type");
		err = -EINVAL;
	}

	return err;
}

static void _free_operation(struct tca_meta_operate *ope,
			    struct tca_meta_operand *A,
			    struct tca_meta_operand *B,
			    struct tca_meta_operand *C,
			    struct netlink_ext_ack *extack)
{
	if (A) {
		if (A->oper_mask_shift)
			p4t_release(A->oper_mask_shift);
		kfree(A->path_or_value);
		kfree(A);
	}

	if (B) {
		if (B->oper_mask_shift)
			p4t_release(B->oper_mask_shift);
		kfree(B->path_or_value);
		kfree(B);
	}

	if (C) {
		if (C->oper_mask_shift)
			p4t_release(C->oper_mask_shift);
		kfree(C->path_or_value);
		kfree(C);
	}

	kfree(ope);
}

static void free_op_SET(struct tca_meta_operate *ope,
			struct netlink_ext_ack *extack)
{
	struct tca_meta_operand *A = ope->opA;
	struct tca_meta_operand *B = ope->opB;
	struct tca_meta_operand *C = ope->opC;

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

static void free_op_ACT(struct tca_meta_operate *ope,
			struct netlink_ext_ack *extack)
{
	struct tca_meta_operand *A = ope->opA;
	struct tca_meta_operand *B = ope->opB;
	struct tca_meta_operand *C = ope->opC;
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

/* Syntax: act ACTION_ID ACTION_INDEX
 * Operation: The tc action instance of kind ID ACTION_ID and index ACTION_INDEX
 * is executed.
 * Restriction: The action instance must exist.
 */
int validate_ACT(struct net *net, struct tca_meta_operand *A,
		 struct tca_meta_operand *B, struct tca_meta_operand *C,
		 struct netlink_ext_ack *extack)
{
	struct tc_action_ops *action_ops;
	struct tc_action *action;

	if (A->oper_type != METACT_OPER_ACTID) {
		NL_SET_ERR_MSG_MOD(extack,
				   "ACT: Operand type MUST be METACT_OPER_ACTID\n");
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
		if (action_ops->lookup_ops(net, &action, action_ops,
					   A->immedv2) == false) {
			NL_SET_ERR_MSG_MOD(extack, "ACT: unknown Action index\n");
			module_put(action_ops->owner);
			return -EINVAL;
		}
	} else {
		action_ops = tc_lookup_action_byid(A->immedv);
		if (!action_ops) {
			NL_SET_ERR_MSG_MOD(extack, "ACT: unknown Action Kind\n");
			return -EINVAL;
		}

		if (action_ops->lookup(net, &action, A->immedv2) == false) {
			NL_SET_ERR_MSG_MOD(extack, "ACT: unknown Action index\n");
			module_put(action_ops->owner);
			return -EINVAL;
		}
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
int validate_SET(struct net *net, struct tca_meta_operand *A,
		 struct tca_meta_operand *B, struct tca_meta_operand *C,
		 struct netlink_ext_ack *extack)
{
	struct p4_type *Atype;
	struct p4_type *Btype;
	int err = 0;

	if (A->oper_type == METACT_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A cannot be constant\n");
		return -EINVAL;
	}

	if (A->oper_type == METACT_OPER_RES) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Operand A cannot be a results field\n");
		return -EINVAL;
	}

	if (A->oper_type == METACT_OPER_PARAM) {
		NL_SET_ERR_MSG_MOD(extack, "Operand A cannot be a param");
		return -EINVAL;
	}

	if (B->oper_type == METACT_OPER_KEY) {
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

		if (B->oper_type == METACT_OPER_CONST)
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

int validate_PRINT(struct net *net, struct tca_meta_operand *A,
		   struct tca_meta_operand *B, struct tca_meta_operand *C,
		   struct netlink_ext_ack *extack)
{
	if (A->oper_type == METACT_OPER_CONST) {
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

int validate_TBLAPP(struct net *net, struct tca_meta_operand *A,
		    struct tca_meta_operand *B, struct tca_meta_operand *C,
		    struct netlink_ext_ack *extack)
{
	int err = 0;

	if (A->oper_type != METACT_OPER_TBL) {
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

int validate_SNDPORTEGR(struct net *net, struct tca_meta_operand *A,
			struct tca_meta_operand *B, struct tca_meta_operand *C,
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

/* Syntax: BRANCHOP A B
 * BRANCHOP := BEQ, BNEQ, etc
 * Operation: B's value is compared to A's value.
 * XXX: In the future we will take expressions instead of values
 * A could a constant, header, or metadata or key
 * B could be a constant, header, metadata, or key
 * Restriction: A and B cannot both be constants
 */

/* if A == B <ctl1> else <ctl2> */
static int metact_BEQ(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact,
		      struct tcf_result *res)
{
	struct p4_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, metact, res);
	void *Aval = op->opA->fetch(skb, op->opA, metact, res);
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
static int metact_BNE(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact,
		      struct tcf_result *res)
{
	struct p4_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, metact, res);
	void *Aval = op->opA->fetch(skb, op->opA, metact, res);
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
static int metact_BLT(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact,
		      struct tcf_result *res)
{
	struct p4_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, metact, res);
	void *Aval = op->opA->fetch(skb, op->opA, metact, res);
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
static int metact_BLE(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact,
		      struct tcf_result *res)
{
	struct p4_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, metact, res);
	void *Aval = op->opA->fetch(skb, op->opA, metact, res);
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
static int metact_BGT(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact,
		      struct tcf_result *res)
{
	struct p4_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, metact, res);
	void *Aval = op->opA->fetch(skb, op->opA, metact, res);
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
static int metact_BGE(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact,
		      struct tcf_result *res)
{
	struct p4_type_ops *dst_ops = op->opA->oper_datatype->ops;
	struct p4_type_ops *src_ops = op->opB->oper_datatype->ops;
	void *Bval = op->opB->fetch(skb, op->opB, metact, res);
	void *Aval = op->opA->fetch(skb, op->opA, metact, res);
	int res_cmp;

	if (!Aval || !Bval)
		return TC_ACT_OK;

	res_cmp = p4t_cmp(op->opA->oper_mask_shift, dst_ops, Aval,
			  op->opB->oper_mask_shift, src_ops, Bval);
	if (!res_cmp || res_cmp > 0)
		return op->ctl1;

	return op->ctl2;
}

int validate_BRN(struct net *net, struct tca_meta_operand *A,
		 struct tca_meta_operand *B, struct tca_meta_operand *C,
		 struct netlink_ext_ack *extack)
{
	int err = 0;

	if (A->oper_type == METACT_OPER_CONST && B &&
	    B->oper_type == METACT_OPER_CONST) {
		NL_SET_ERR_MSG_MOD(extack, "Branch: A and B can't both be constant\n");
		return -EINVAL;
	}

	if (C) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid branch operation with C\n");
		return -EINVAL;
	}

	if ((A && !is_unsigned(A->oper_datatype->typeid)) ||
	    (B && !is_unsigned(B->oper_datatype->typeid))) {
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

static void free_op_BRN(struct tca_meta_operate *ope,
			struct netlink_ext_ack *extack)
{
	struct tca_meta_operand *A = ope->opA;
	struct tca_meta_operand *B = ope->opB;
	struct tca_meta_operand *C = ope->opC;

	return _free_operation(ope, A, B, C, extack);
}

static void free_op_PRINT(struct tca_meta_operate *ope,
			  struct netlink_ext_ack *extack)
{
	struct tca_meta_operand *A = ope->opA;

	return _free_operation(ope, A, NULL, NULL, extack);
}

static void free_op_TBLAPP(struct tca_meta_operate *ope,
			   struct netlink_ext_ack *extack)
{

	struct tca_meta_operand *A = ope->opA;

	return _free_operation(ope, A, NULL, NULL, extack);
}

static void free_op_SNDPORTEGR(struct tca_meta_operate *ope,
			       struct netlink_ext_ack *extack)
{

	struct tca_meta_operand *A = ope->opA;
	struct net_device *dev = A->priv;

	netdev_put(dev, NULL);

	return _free_operation(ope, A, NULL, NULL, extack);
}

static struct metact_cmd_s metact_cmds[] = {
	{ METACT_OP_SET, validate_SET, free_op_SET, metact_SET },
	{ METACT_OP_ACT, validate_ACT, free_op_ACT, metact_ACT },
	{ METACT_OP_BEQ, validate_BRN, free_op_BRN, metact_BEQ },
	{ METACT_OP_BNE, validate_BRN, free_op_BRN, metact_BNE },
	{ METACT_OP_BGT, validate_BRN, free_op_BRN, metact_BGT },
	{ METACT_OP_BLT, validate_BRN, free_op_BRN, metact_BLT },
	{ METACT_OP_BGE, validate_BRN, free_op_BRN, metact_BGE },
	{ METACT_OP_BLE, validate_BRN, free_op_BRN, metact_BLE },
	{ METACT_OP_PRINT, validate_PRINT, free_op_PRINT, metact_PRINT },
	{ METACT_OP_TBLAPP, validate_TBLAPP, free_op_TBLAPP, metact_TBLAPP },
	{ METACT_OP_SNDPORTEGR, validate_SNDPORTEGR, free_op_SNDPORTEGR,
	  metact_SNDPORTEGR },
	{ METACT_OP_MIRPORTEGR, validate_SNDPORTEGR, free_op_SNDPORTEGR,
	  metact_MIRPORTEGR },
};

static struct metact_cmd_s *get_cmd_byid(u16 cmdid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(metact_cmds); i++) {
		if (cmdid == metact_cmds[i].cmdid)
			return &metact_cmds[i];
	}

	return NULL;
}

/* Operands */
static const struct nla_policy metact_policy_oper[TCAA_METACT_OPND_MAX + 1] = {
	[TCAA_METACT_OPND_INFO] = {.len = sizeof(struct tca_u_meta_operand) },
	[TCAA_METACT_OPND_PATH] = {.type = NLA_BINARY,
				   .len = METACT_MAX_OPER_PATH_LEN },
};

/*
 * XXX: METACT_POLICY is used to disable overwriting extacks downstream
 * Could we use error pointers instead of this METACT_POLICY trickery?
 */
#define METACT_POLICY 12345
static int metact_process_opnd(struct nlattr *nla,
			       struct tca_meta_operand *kopnd,
			       struct netlink_ext_ack *extack)
{
	u32 wantbits = 0;
	int oper_sz = 0;
	int err = 0;
	struct nlattr *tb[TCAA_METACT_OPND_MAX + 1];
	struct tca_u_meta_operand *uopnd;

	err = nla_parse_nested_deprecated(tb, TCAA_METACT_OPND_MAX,
					  nla, metact_policy_oper, extack);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "parse error: TCAA_METACT_OPND_\n");
		return -EINVAL;
	}

	if (!tb[TCAA_METACT_OPND_INFO]) {
		NL_SET_ERR_MSG_MOD(extack, "operand information is mandatory");
		return -EINVAL;
	}

	uopnd = nla_data(tb[TCAA_METACT_OPND_INFO]);

	if (uopnd->oper_type == METACT_OPER_META) {
		kopnd->fetch = fetch_metadata;
	} else if (uopnd->oper_type == METACT_OPER_CONST) {
		kopnd->fetch = fetch_constant;
	} else if (uopnd->oper_type == METACT_OPER_ACTID) {
		kopnd->fetch = NULL;
	} else if (uopnd->oper_type == METACT_OPER_TBL) {
		kopnd->fetch = fetch_table;
	} else if (uopnd->oper_type == METACT_OPER_KEY) {
		kopnd->fetch = fetch_key;
	} else if (uopnd->oper_type == METACT_OPER_RES) {
		kopnd->fetch = fetch_result;
	} else if (uopnd->oper_type == METACT_OPER_HDRFIELD) {
		kopnd->fetch = fetch_hdrfield;
	} else if (uopnd->oper_type == METACT_OPER_PARAM) {
		kopnd->fetch = fetch_param;
	} else if (uopnd->oper_type == METACT_OPER_DEV) {
		kopnd->fetch = fetch_dev;
	} else {
		NL_SET_ERR_MSG_MOD(extack, "Unknown operand type");
		return -EINVAL;
	}

	wantbits = 1 + uopnd->oper_endbit - uopnd->oper_startbit;
	if (uopnd->oper_type != METACT_OPER_ACTID &&
	    uopnd->oper_type != METACT_OPER_TBL &&
	    uopnd->oper_cbitsize < wantbits) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Start and end bit dont fit in space");
		return -EINVAL;
	}

	err = copy_u2k_operand(uopnd, kopnd, extack);
	if (err < 0)
		return err;

	if (tb[TCAA_METACT_OPND_PATH])
		oper_sz = nla_len(tb[TCAA_METACT_OPND_PATH]);

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

	err = nla_memcpy(kopnd->path_or_value, tb[TCAA_METACT_OPND_PATH],
			 oper_sz);
	if (unlikely(err != oper_sz)) {
		NL_SET_ERR_MSG_MOD(extack, "Malformed operand path data");
		kfree(kopnd->path_or_value);
		return -EINVAL;
	}

	return 0;
}

/* Operation */
static const struct nla_policy metact_ops_policy[TCAA_METACT_OPER_MAX + 1] = {
	[TCAA_METACT_OPERATION] = {.len = sizeof(struct tca_u_meta_operate) },
	[TCAA_METACT_OPER_A] = {.type = NLA_NESTED },
	[TCAA_METACT_OPER_B] = {.type = NLA_NESTED },
	[TCAA_METACT_OPER_C] = {.type = NLA_NESTED },
};

static struct tca_meta_operate *uope_to_kope(struct tca_u_meta_operate *uope)
{
	struct tca_meta_operate *ope;

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

static int metact_process_ops(struct net *net, struct nlattr *nla,
			      struct tca_meta_operate **op_entry,
			      struct netlink_ext_ack *extack)
{
	struct tca_meta_operand *opndA = NULL;
	struct tca_meta_operand *opndB = NULL;
	struct tca_meta_operand *opndC = NULL;
	struct tca_meta_operate *ope = NULL;
	int err = 0, tbits = 0;
	struct nlattr *tb[TCAA_METACT_OPER_MAX + 1];
	struct metact_cmd_s *cmd_t;

	err = nla_parse_nested_deprecated(tb, TCAA_METACT_OPER_MAX, nla,
					  metact_ops_policy, extack);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "parse error: TCAA_METACT_OPER_\n");
		return METACT_POLICY;
	}

	ope = uope_to_kope(nla_data(tb[TCAA_METACT_OPERATION]));
	if (!ope)
		return -ENOMEM;

	cmd_t = get_cmd_byid(ope->op_id);
	if (!cmd_t) {
		NL_SET_ERR_MSG_MOD(extack, "Unknown operation ID\n");
		kfree(ope);
		return -EINVAL;
	}

	if (tb[TCAA_METACT_OPER_A]) {
		opndA = kzalloc(sizeof(*opndA), GFP_KERNEL);
		if (!opndA)
			return -ENOMEM;

		err = metact_process_opnd(tb[TCAA_METACT_OPER_A], opndA,
					  extack);
		if (err < 0) {
			//XXX: think about getting rid of this METACT_POLICY
			err =  METACT_POLICY;
			goto set_results;
		}

		tbits = opndA->oper_bitsize;
	}

	if (tb[TCAA_METACT_OPER_B]) {
		opndB = kzalloc(sizeof(*opndB), GFP_KERNEL);
		if (!opndB) {
			err =  -ENOMEM;
			goto set_results;
		}

		err = metact_process_opnd(tb[TCAA_METACT_OPER_B], opndB,
					  extack);
		if (err < 0) {
			//XXX: think about getting rid of this METACT_POLICY
			err =  METACT_POLICY;
			goto set_results;
		}

		tbits = opndB->oper_bitsize;
	}

	if (tb[TCAA_METACT_OPER_C]) {
		opndC = kzalloc(sizeof(*opndC), GFP_KERNEL);
		if (!opndC) {
			err =  -ENOMEM;
			goto set_results;
		}

		err = metact_process_opnd(tb[TCAA_METACT_OPER_C], opndC,
					  extack);
		if (err < 0) {
			//XXX: think about getting rid of this METACT_POLICY
			err =  METACT_POLICY;
			goto set_results;
		}

		tbits = opndC->oper_bitsize;
	}

	if (cmd_t->validate_operands(net, opndA, opndB, opndC, extack)) {
		//XXX: think about getting rid of this METACT_POLICY
		err =  METACT_POLICY;
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
	if (cmdid == METACT_OP_BEQ || cmdid == METACT_OP_BNE ||
	    cmdid == METACT_OP_BLT || cmdid == METACT_OP_BLE ||
	    cmdid == METACT_OP_BGT || cmdid == METACT_OP_BGE)
		return 1;

	return 0;
}

static int metact_brn_validate(struct tca_meta_operate *oplist[], int cnt,
			       struct netlink_ext_ack *extack)
{
	int inscnt = cnt - 1;
	int i;

	for (i = 1; i < inscnt; i++) {
		struct tca_meta_operate *ope = oplist[i - 1];
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

static const struct nla_policy metact_policy[TCA_METACT_MAX + 1] = {
	[TCA_METACT_PARMS] = {.len = sizeof(struct tc_metact) },
	[TCA_METACT_LIST] = {.type = NLA_NESTED },	/*Max=TCA_METACT_LIST_MAX */
};

static void metact_ops_pass_to_list(struct tca_meta_operate **oplist,
				    struct list_head *meta_operations)
{
	int i;

	for (i = 0; i < TCA_METACT_LIST_MAX && oplist[i]; i++) {
		struct tca_meta_operate *ope = oplist[i];

		list_add_tail(&ope->meta_operations, meta_operations);
	}
}

static void metact_ops_del_list(struct list_head *meta_operations)
{
	struct tca_meta_operate *ope, *tmp;

	list_for_each_entry_safe(ope, tmp, meta_operations, meta_operations) {
		list_del(&ope->meta_operations);
		kfree_opentry(ope);
	}
}

static int metact_copy_opnd(struct tca_meta_operand **new_kopnd,
			    struct tca_meta_operand *kopnd,
			    struct netlink_ext_ack *extack)
{
	struct p4_type_mask_shift *mask_shift = NULL;
	struct tca_meta_operand *_new_kopnd;

	_new_kopnd = kzalloc(sizeof(*_new_kopnd), GFP_KERNEL);
	if (!_new_kopnd)
		return -ENOMEM;

	memcpy(_new_kopnd, kopnd, sizeof(*_new_kopnd));

	if (kopnd->oper_type == METACT_OPER_CONST) {
		mask_shift = create_constant_bitops(kopnd,
						    kopnd->oper_datatype,
						    extack);
		if (IS_ERR(mask_shift))
			return -EINVAL;
	} else if (kopnd->oper_type == METACT_OPER_META) {
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

static int metact_copy_ops(struct tca_meta_operate **new_op_entry,
			   struct tca_meta_operate *op_entry,
			   struct netlink_ext_ack *extack)
{
	struct tca_meta_operand *opndA = NULL;
	struct tca_meta_operand *opndB = NULL;
	struct tca_meta_operand *opndC = NULL;
	struct tca_meta_operate *_new_op_entry;
	int err;

	_new_op_entry = kzalloc(sizeof(*_new_op_entry), GFP_KERNEL);
	if (!_new_op_entry)
		return -ENOMEM;

	if (op_entry->opA) {
		err = metact_copy_opnd(&opndA, op_entry->opA, extack);
		if (err < 0)
			goto set_results;
	}

	if (op_entry->opB) {
		err = metact_copy_opnd(&opndB, op_entry->opB, extack);
		if (err < 0)
			goto set_results;
	}

	if (op_entry->opC) {
		err = metact_copy_opnd(&opndC, op_entry->opC, extack);
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

static int tcf_metact_copy_cmds(struct list_head *new_meta_operations,
				struct list_head *meta_operations,
				bool delete_old, struct netlink_ext_ack *extack)
{
	struct tca_meta_operate *oplist[TCA_METACT_LIST_MAX] = {NULL};
	int i = 0;
	struct tca_meta_operate *op;
	int err;

	if (delete_old)
		metact_ops_del_list(new_meta_operations);

	list_for_each_entry(op, meta_operations, meta_operations) {
		err = metact_copy_ops(&oplist[i], op, extack);
		if (err < 0)
			goto free_oplist;

		i++;
	}

	metact_ops_pass_to_list(oplist, new_meta_operations);

	return 0;

free_oplist:
	kfree_tmp_oplist(oplist);
	return err;
}

#define SEPARATOR "/"

int tcf_p4_metact_init(struct net *net, struct nlattr *nla,
		       struct nlattr *est, struct tc_action **a,
		       struct tcf_proto *tp, struct tc_action_ops *a_o,
		       u32 flags, struct netlink_ext_ack *extack)
{
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct tcf_chain *goto_ch = NULL;
	bool exists = false;
	int ret = 0;
	struct nlattr *tb[P4TC_ACT_MAX + 1];
	char *act_name_clone, *act_name;
	struct tcf_p4act_params *params;
	struct p4tc_pipeline *pipeline;
	struct tcf_metact_info *p;
	struct tc_action_net *tn;
	struct tc_act_dyna *parm;
	struct p4tc_act *act;
	char *p_name;
	u32 index;
	int err;

	if (!nla) {
		pr_err("Has no nla\n");
		return -EINVAL;
	}

	err = nla_parse_nested_deprecated(tb, P4TC_ACT_MAX, nla, NULL,
					  NULL);
	if (err < 0) {
		pr_err("Failed parsing\n");
		return err;
	}

	if (!tb[P4TC_ACT_OPT]) {
		pr_err("Has no ACT_OPT\n");
		return -EINVAL;
	}

	parm = nla_data(tb[P4TC_ACT_OPT]);
	index = parm->index;

	act_name_clone = act_name = kstrdup(a_o->kind, GFP_KERNEL);
	if (!act_name)
		return -ENOMEM;

	p_name = strsep(&act_name, SEPARATOR);
	pipeline = tcf_pipeline_find_byany(p_name, 0, NULL);
	act = tcf_action_find_byname(act_name, pipeline);
	if (!act->active) {
		pr_err("Is not active\n");
		kfree(act_name_clone);
		return -EINVAL;
	}

	kfree(act_name_clone);

	tn = net_generic(net, a_o->net_id);
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;

	exists = err;
	if (!exists) {
		ret = tcf_idr_create(tn, index, est, a,
				     a_o, bind, false, flags);
		if (ret) {
			tcf_idr_cleanup(tn, index);
			return ret;
		}

		/* dyn_ref here should never be 0, because if we are here, it
		 * means that a template action of this kind was created. Thus
		 * dyn_ref should be at least 1. Also since this operation and
		 * others that add or delete action templates run with
		 * rtnl_lock held, we cannot do this op and a deletion op in
		 * parallel.
		 */
		WARN_ON(!refcount_inc_not_zero(&a_o->dyn_ref));
		/* p_ref here should never be 0, because if we are here, it
		 * means that a template action of this kind was created. Thus
		 * p_ref should be at least 1. Also since this operation and
		 * others that add or delete pipelines and action templates run
		 * with rtnl_lock held, we cannot do this op and a deletion op
		 * in parallel.
		 */
		WARN_ON(!refcount_inc_not_zero(&pipeline->p_ref));
		ret = ACT_P_CREATED;
	} else {
		if (bind) /* dont override defaults */
			return 0;
		if (!(flags & TCA_ACT_FLAGS_REPLACE)) {
			tcf_idr_cleanup(tn, index);
			return -EEXIST;
		}
	}

	p = to_metact(*a);
	p->p_id = pipeline->common.p_id;
	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto release_idr;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params) {
		err = -ENOMEM;
		goto release_idr;
	}

	INIT_LIST_HEAD(&p->meta_operations);
	idr_init(&params->params_idr);
	if (tb[P4TC_ACT_PARMS]) {
		err = tcf_p4_act_init_params(net, params, act,
					     tb[P4TC_ACT_PARMS], extack);
		if (err < 0)
			goto release_params;
	} else {
		if (!idr_is_empty(&act->params_idr)) {
			pr_err("Must specify action parameters\n");
			err = -EINVAL;
			goto release_params;
		}
	}

	p->p_id = pipeline->common.p_id;

	if (exists)
		spin_lock_bh(&p->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);

	err = tcf_metact_copy_cmds(&p->meta_operations, &act->meta_operations,
				   exists, extack);
	if (err < 0)
		goto release_params;

	params = rcu_replace_pointer(p->params, params, 1);
	if (exists)
		spin_unlock_bh(&p->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	if (params)
		call_rcu(&params->rcu, tcf_p4_act_params_destroy_rcu);

	return ret;

release_params:
	tcf_p4_act_params_destroy(params);

release_idr:
	tcf_idr_release(*a, bind);
	return err;
}

int tcf_metact_parse_cmds(struct net *net,
			  struct list_head *meta_operations,
			  struct nlattr *nla, bool ovr,
			  struct netlink_ext_ack *extack)
{
	/* XXX: oplist and oplist_attr
	 * could bloat the stack depending on TCA_METACT_LIST_MAX
	 */
	struct tca_meta_operate *oplist[TCA_METACT_LIST_MAX] = {NULL};
	struct nlattr *oplist_attr[TCA_METACT_LIST_MAX + 1];
	int err;
	int i;

	err = nla_parse_nested_deprecated(oplist_attr, TCA_METACT_LIST_MAX,
					  nla, NULL, extack);
	if (err < 0)
		return err;

	for (i = 1; i < TCA_METACT_LIST_MAX && oplist_attr[i]; i++) {
		struct tca_meta_operate *o = oplist[i - 1];

		err =
		    metact_process_ops(net, oplist_attr[i], &oplist[i - 1],
				       extack);
		o = oplist[i - 1];
		if (err) {
			kfree_tmp_oplist(oplist);

			if (err == METACT_POLICY)
				err = -EINVAL;

			return err;
		}
	}

	err = metact_brn_validate(oplist, i, extack);
	if (err < 0) {
		kfree_tmp_oplist(oplist);
		return err;
	}

	if (ovr)
		metact_ops_del_list(meta_operations);

	/*XXX: At this point we have all the cmds and they are valid */
	metact_ops_pass_to_list(oplist, meta_operations);

	return 0;
}

static unsigned int metact_net_id;
static struct tc_action_ops act_metact_ops;

static int tcf_metact_init(struct net *net, struct nlattr *nla,
			   struct nlattr *est, struct tc_action **a,
			   struct tcf_proto *tp, u32 flags,
			   struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, metact_net_id);
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	bool ovr = flags & TCA_ACT_FLAGS_REPLACE;
	struct tcf_chain *goto_ch = NULL;
	int err = 0, ret = 0;
	struct nlattr *tb[TCA_METACT_MAX + 1];
	struct tcf_metact_info *m;
	struct tc_metact *parm;
	u32 index;

	if (!nla) {
		NL_SET_ERR_MSG_MOD(extack, "attributes MUST be provided");
		return -EINVAL;
	}

	if (ovr && !bind) {
		NL_SET_ERR_MSG_MOD(extack, "updates are not allowed\n");
		return -EOPNOTSUPP;
	}

	err = nla_parse_nested_deprecated(tb, TCA_METACT_MAX, nla,
					  metact_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_METACT_PARMS]) {
		NL_SET_ERR_MSG_MOD(extack, "params MUST be provided");
		return -EINVAL;
	}

	parm = nla_data(tb[TCA_METACT_PARMS]);

	index = parm->index;

	/*XXX: tcf_idr_check_alloc returns 0 if action doesn't
	 * exist and also prevents concurrent users from inserting
	 * actions with  the same params. i.e exists is not true when
	 * we get 0 back..
	 * Undocumented: tcf_idr_check_alloc can return < 0 for other
	 * errors
	 */
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (!err) {		/*!exists */
		ret = tcf_idr_create_from_flags(tn, index, est, a,
						&act_metact_ops, bind, flags);
		if (ret) {
			tcf_idr_cleanup(tn, index);
			return ret;
		}

		ret = ACT_P_CREATED;
	} else if (err > 0) {
		if (bind)
			return 0;

		/*exists and not bound should have been caught earlier in:
		 * if(ovr && !bind) check. If we allow override then
		 * we will have to remove that earlier check then
		 */
		if (!ovr) {	/* no explicit request to override */
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
	} else {
		NL_SET_ERR_MSG_MOD(extack,
				   "Please report the config for this error");
		return err;
	}

	/* XXX: we moved the initialization here because we want
	 * tcf_metact_cleanup() to find a valid list even if we didn't
	 * put anything on it because of failure in processing cmds
	 */
	m = to_metact(*a);
	INIT_LIST_HEAD(&m->meta_operations);

	/* does not exist at this point, we expect the instruction list */
	if (!tb[TCA_METACT_LIST]) {
		NL_SET_ERR_MSG_MOD(extack, "instructions MUST be provided");
		tcf_idr_release(*a, bind);
		return -EINVAL;
	}

	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0) {		//XXX: extack?
		tcf_idr_release(*a, bind);
		return err;
	}

	if (ovr)
		spin_lock_bh(&m->tcf_lock);

	err = tcf_metact_parse_cmds(net, &m->meta_operations,
				    tb[TCA_METACT_LIST], ovr, extack);
	if (err < 0) {
		tcf_idr_release(*a, bind);
		return err;
	}

	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
	if (ovr)
		spin_unlock_bh(&m->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);

	return ret;
}

int tcf_metact_dump(struct sk_buff *skb, struct tc_action *a, int bind,
		    int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_metact_info *metact = to_metact(a);
	struct tc_metact opt = {
		.index = metact->tcf_index,
		.refcnt = refcount_read(&metact->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&metact->tcf_bindcnt) - bind,
	};
	int i = 1;
	struct tcf_p4act_params *params;
	struct p4tc_act_param *parm;
	struct nlattr *nest_parms;
	struct nlattr *nest;
	struct tcf_t t;
	int id;

	spin_lock_bh(&metact->tcf_lock);

	opt.action = metact->tcf_action;
	if (nla_put(skb, TCA_METACT_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	nest = nla_nest_start_noflag(skb, TCA_METACT_LIST);
	if (fillup_metact_cmds(skb, &metact->meta_operations))
		goto nla_put_failure;
	nla_nest_end(skb, nest);

	if (nla_put_string(skb, TCA_METACT_ACT_NAME, a->ops->kind))
		goto nla_put_failure;

	tcf_tm_dump(&t, &metact->tcf_tm);
	if (nla_put_64bit(skb, TCA_METACT_TM, sizeof(t), &t, TCA_METACT_PAD))
		goto nla_put_failure;

	nest_parms = nla_nest_start_noflag(skb, TCA_METACT_ACT_PARMS);
	if (!nest_parms)
		goto nla_put_failure;

	params = rcu_dereference(metact->params);
	if (params) {
		idr_for_each_entry(&params->params_idr, parm, id) {
			struct p4tc_act_param_ops *op;
			struct nlattr *nest_count;

			nest_count = nla_nest_start_noflag(skb, i);
			if (!nest_count)
				goto nla_put_failure;

			if (nla_put_string(skb, P4TC_ACT_PARAMS_NAME, parm->name))
				goto nla_put_failure;

			if (nla_put_u32(skb, P4TC_ACT_PARAMS_ID, parm->id))
				goto nla_put_failure;

			op = (struct p4tc_act_param_ops *)&param_ops[parm->type];
			if (op->dump_value) {
				if (op->dump_value(skb, op, parm) < 0)
					goto nla_put_failure;
			} else {
				struct p4_type *type;

				type = p4type_find_byid(parm->type);
				if (generic_dump_param_value(skb, type, parm))
					goto nla_put_failure;
			}

			if (nla_put_u32(skb, P4TC_ACT_PARAMS_TYPE, parm->type))
				goto nla_put_failure;

			nla_nest_end(skb, nest_count);
			i++;
		}
	}
	nla_nest_end(skb, nest_parms);

	spin_unlock_bh(&metact->tcf_lock);

	return skb->len;

nla_put_failure:
	spin_unlock_bh(&metact->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static void *fetch_constant(struct sk_buff *skb, struct tca_meta_operand *op,
			    struct tcf_metact_info *metact,
			    struct tcf_result *res)
{
	if (op->oper_flags & DATA_IS_IMMEDIATE)
		return &op->immedv;

	if (op->path_or_value_sz)
		return op->path_or_value;

	return NULL;
}

static void *fetch_table(struct sk_buff *skb, struct tca_meta_operand *op,
			 struct tcf_metact_info *metact,
			 struct tcf_result *res)
{
	return op->oper_value_ops->fetch(skb, op->oper_value_ops);
}

static void *fetch_result(struct sk_buff *skb, struct tca_meta_operand *op,
			  struct tcf_metact_info *metact,
			  struct tcf_result *res)
{
	if (op->immedv == METACT_RESULTS_HIT)
		return &res->hit;
	else
		return &res->miss;
}

static void *fetch_hdrfield(struct sk_buff *skb, struct tca_meta_operand *op,
			    struct tcf_metact_info *metact,
			    struct tcf_result *res)
{
	return op->oper_value_ops->fetch(skb, op->oper_value_ops);
}

static void *fetch_param(struct sk_buff *skb, struct tca_meta_operand *op,
			 struct tcf_metact_info *metact,
			 struct tcf_result *res)
{
	struct tcf_p4act_params *params;
	struct p4tc_act_param *param;

	params = rcu_dereference(metact->params);
	param = idr_find(&params->params_idr, op->immedv2);

	return param->value;
}

static void *fetch_key(struct sk_buff *skb, struct tca_meta_operand *op,
		       struct tcf_metact_info *metact,
		       struct tcf_result *res)
{
	struct p4tc_skb_ext *p4tc_skb_ext;

	p4tc_skb_ext = skb_ext_find(skb, P4TC_SKB_EXT);
	if (unlikely(!p4tc_skb_ext))
		return NULL;

	return p4tc_skb_ext->p4tc_ext->key;
}

static void *fetch_dev(struct sk_buff *skb, struct tca_meta_operand *op,
		       struct tcf_metact_info *metact,
		       struct tcf_result *res)
{
	return op->priv;
}

static void *fetch_metadata(struct sk_buff *skb, struct tca_meta_operand *op,
			    struct tcf_metact_info *metact,
			    struct tcf_result *res)
{
	return op->oper_value_ops->fetch(skb, op->oper_value_ops);
}

/* SET A B  - A is set from B
 *
 * Assumes everything has been vetted - meaning no checks here
 *
 */
static int metact_SET(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact, struct tcf_result *res)
{
	void *src = op->opB->fetch(skb, op->opB, metact, res);
	void *dst = op->opA->fetch(skb, op->opA, metact, res);
	struct p4_type *dst_t = op->opA->oper_datatype;
	struct p4_type *src_t = op->opB->oper_datatype;
	struct p4_type_ops *dst_ops = dst_t->ops;
	struct p4_type_ops *src_ops = src_t->ops;
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
static int metact_ACT(struct sk_buff *skb, struct tca_meta_operate *op,
		      struct tcf_metact_info *metact, struct tcf_result *res)
{
	const struct tc_action *action = op->opA->action;

	return action->ops->act(skb, action, res);
}

static int metact_PRINT(struct sk_buff *skb, struct tca_meta_operate *op,
			struct tcf_metact_info *metact, struct tcf_result *res)
{
	struct tca_meta_operand *A = op->opA;
	struct p4_type *val_t = A->oper_datatype;
	void *val = A->fetch(skb, A, metact, res);
	char name[(TEMPLATENAMSZ * 4)];

	if (!val)
		return TC_ACT_OK;

	/* This is a debug function, so performance is not a priority */
	if (A->oper_type == METACT_OPER_META) {
		struct p4tc_pipeline *pipeline = NULL;
		char *path = (char *)A->path_or_value;
		struct p4tc_metadata *meta;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		meta = tcf_meta_find_byid(pipeline, A->immedv);

		if (A->path_or_value_sz)
			snprintf(name,
				 (TEMPLATENAMSZ << 1) + METACT_MAX_OPER_PATH_LEN,
				 "%s %s.%s", path, pipeline->common.name,
				 meta->common.name);
		else
			snprintf(name, TEMPLATENAMSZ << 1, "%s.%s",
				 pipeline->common.name, meta->common.name);

		val_t->ops->print(name, val);
	} else if (A->oper_type == METACT_OPER_HDRFIELD) {
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
	} else if (A->oper_type == METACT_OPER_KEY) {
		struct p4tc_table_class *tclass;
		struct p4tc_pipeline *pipeline;

		pipeline = tcf_pipeline_find_byid(A->pipeid);
		tclass = tcf_tclass_find_byid(pipeline, A->immedv);
		snprintf(name, TEMPLATENAMSZ * 3, "key.%s.%s.%u",
			 pipeline->common.name, tclass->common.name,
			 A->immedv2);
		val_t->ops->print(name, val);
	} else if (A->oper_type == METACT_OPER_PARAM) {
		val_t->ops->print("param", val);
	} else if (A->oper_type == METACT_OPER_RES) {
		if (A->immedv == METACT_RESULTS_HIT)
			val_t->ops->print("res.hit", val);
		else if (A->immedv == METACT_RESULTS_MISS)
			val_t->ops->print("res.miss", val);
	} else {
		pr_info("Unsupported operand for print\n");
	}

	return op->ctl1;
}

#define REDIRECT_RECURSION_LIMIT    4
static DEFINE_PER_CPU(unsigned int, redirect_rec_level);

static int metact_SNDPORTEGR(struct sk_buff *skb, struct tca_meta_operate *op,
			     struct tcf_metact_info *metact,
			     struct tcf_result *res)
{
	struct tca_meta_operand *A = op->opA;
	struct net_device *dev = A->fetch(skb, A, metact, res);
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

static int metact_MIRPORTEGR(struct sk_buff *skb, struct tca_meta_operate *op,
			     struct tcf_metact_info *metact,
			     struct tcf_result *res)
{
	struct tca_meta_operand *A = op->opA;
	struct net_device *dev = A->fetch(skb, A, metact, res);
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

static int metact_TBLAPP(struct sk_buff *skb, struct tca_meta_operate *op,
			 struct tcf_metact_info *metact,
			 struct tcf_result *res)
{
	struct tca_meta_operand *A = op->opA;
	struct p4tc_table_class *tclass = A->fetch(skb, A, metact, res);
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

	if (res->hit && entry->acts) {
		ret = tcf_action_exec(skb, entry->acts, entry->num_acts, res);
		if (ret != TC_ACT_PIPE)
			return ret;
	}

	return tcf_action_exec(skb, tclass->tbc_postacts,
			       tclass->tbc_num_postacts, res);
}

int tcf_metact_act(struct sk_buff *skb, const struct tc_action *a,
		   struct tcf_result *res)
{
	struct tcf_metact_info *metact = to_metact(a);
	int ret = 0;
	int jmp_cnt = 0;
	struct tca_meta_operate *op;


	tcf_lastuse_update(&metact->tcf_tm);
	tcf_action_update_bstats(&metact->common, skb);

	spin_lock(&metact->tcf_lock);
	list_for_each_entry(op, &metact->meta_operations, meta_operations) {
		if (jmp_cnt > 0) {
			jmp_cnt--;
			continue;
		}

		ret = op->cmd->run(skb, op, metact, res);
		if (TC_ACT_EXT_CMP(ret, TC_ACT_JUMP)) {
			jmp_cnt = ret & TC_ACT_EXT_VAL_MASK;
			continue;
		} else if (ret != TC_ACT_PIPE) {
			break;
		}
	}
	spin_unlock(&metact->tcf_lock);

	if (ret == TC_ACT_SHOT)
		tcf_action_inc_drop_qstats(&metact->common);

	if (ret == TC_ACT_STOLEN ||
	    ret == TC_ACT_TRAP)
		ret = TC_ACT_CONSUMED;

	if (ret == TC_ACT_OK)
		ret = metact->tcf_action;

	return ret;
}

static int tcf_metact_walker(struct net *net, struct sk_buff *skb,
			     struct netlink_callback *cb, int type,
			     const struct tc_action_ops *ops,
			     struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, metact_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_metact_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, metact_net_id);
	u32 ret;

	ret = tcf_idr_search(tn, a, index);

	return ret;
}

void tcf_metact_cleanup(struct tc_action *a)
{
	struct tc_action_ops *ops = (struct tc_action_ops *)a->ops;
	struct tcf_metact_info *m = to_metact(a);
	struct tcf_p4act_params *params;
	struct p4tc_pipeline *pipeline;

	pipeline = m->p_id ? tcf_pipeline_find_byid(m->p_id) : NULL;
	params = rcu_dereference_protected(m->params, 1);

	if (refcount_read(&ops->dyn_ref) > 1)
		refcount_dec(&ops->dyn_ref);
	if (pipeline)
		WARN_ON(!refcount_dec_not_one(&pipeline->p_ref));

	spin_lock_bh(&m->tcf_lock);
	release_ope_list(&m->meta_operations);
	/* XXX: Need to do this correctly */
	if (params)
		call_rcu(&params->rcu, tcf_p4_act_params_destroy_rcu);
	spin_unlock_bh(&m->tcf_lock);
}

static struct tc_action_ops act_metact_ops = {
	.kind = "metact",
	.id = TCA_ID_METACT,
	.owner = THIS_MODULE,
	.act = tcf_metact_act,
	.dump = tcf_metact_dump,
	.cleanup = tcf_metact_cleanup,
	.init = tcf_metact_init,
	.walk = tcf_metact_walker,
	.lookup = tcf_metact_search,
	.size = sizeof(struct tcf_metact_info),
};

static __net_init int metact_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, metact_net_id);

	return tc_action_net_init(net, tn, &act_metact_ops);
}

static void __net_exit metact_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, metact_net_id);
}

static struct pernet_operations metact_net_ops = {
	.init = metact_init_net,
	.exit_batch = metact_exit_net,
	.id = &metact_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init metact_init_module(void)
{
	return tcf_register_action(&act_metact_ops, &metact_net_ops);
}

static void __exit metact_cleanup_module(void)
{
	tcf_unregister_action(&act_metact_ops, &metact_net_ops);
}

module_init(metact_init_module);
module_exit(metact_cleanup_module);

MODULE_AUTHOR("Jamal Hadi Salim");
MODULE_AUTHOR("Victor Nogueira");
MODULE_AUTHOR("Pedro Tammela");
MODULE_DESCRIPTION("The TC metact Action");
MODULE_LICENSE("GPL");
