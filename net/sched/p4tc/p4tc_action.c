// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_action.c	P4 TC ACTION TEMPLATES
 *
 * Copyright (c) 2022-2023, Mojatatu Networks
 * Copyright (c) 2022-2023, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/flow_offload.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/sch_generic.h>
#include <net/sock.h>

#include <net/tc_act/p4tc.h>

static LIST_HEAD(dynact_list);

#define SEPARATOR "/"

static void set_param_indices(struct idr *params_idr)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;
	int i = 0;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		param->index = i;
		i++;
	}
}

#define P4TC_ACT_CREATED 1
#define P4TC_ACT_PREALLOC 2
#define P4TC_ACT_PREALLOC_UNINIT 3

static int __tcf_p4_dyna_init(struct net *net, struct nlattr *est,
			      struct p4tc_act *act, struct tc_act_dyna *parm,
			      struct tc_action **a, struct tcf_proto *tp,
			      struct tc_action_ops *a_o,
			      struct tcf_chain **goto_ch, u32 flags,
			      struct netlink_ext_ack *extack)
{
	bool from_p4tc = flags & TCA_ACT_FLAGS_FROM_P4TC;
	bool prealloc = flags & TCA_ACT_FLAGS_PREALLOC;
	bool replace = flags & TCA_ACT_FLAGS_REPLACE;
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct p4tc_pipeline *pipeline;
	struct tcf_p4act *p4act;
	u32 index = parm->index;
	bool exists = false;
	int ret = 0;
	int err;

	if ((from_p4tc && !prealloc && !replace && !index)) {
		p4act = tcf_p4_get_next_prealloc_act(act);

		if (p4act) {
			tcf_p4_set_init_flags(p4act);
			*a = &p4act->common;
			return P4TC_ACT_PREALLOC_UNINIT;
		}
	}

	err = tcf_idr_check_alloc(act->tn, &index, a, bind);
	if (err < 0)
		return err;

	exists = err;
	if (!exists) {
		struct tcf_p4act *p;

		if (bind) {
			NL_SET_ERR_MSG(extack,
				       "Must create action instances before binding");
			tcf_idr_cleanup(act->tn, index);
			return -EINVAL;
		}

		ret = tcf_idr_create(act->tn, index, est, a, a_o, bind, true,
				     flags);
		if (ret) {
			tcf_idr_cleanup(act->tn, index);
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

		pipeline = act->pipeline;

		p = to_p4act(*a);
		p->p_id = pipeline->common.p_id;
		p->act_id = act->a_id;

		p->common.tcfa_flags |= TCA_ACT_FLAGS_PREALLOC;
		if (!prealloc)
			list_add_tail(&p->node, &act->prealloc_list);

		ret = P4TC_ACT_CREATED;
	} else {
		if (bind) {
			if (((*a)->tcfa_flags & TCA_ACT_FLAGS_PREALLOC)) {
				if ((*a)->tcfa_flags & TCA_ACT_FLAGS_UNREFERENCED) {
					p4act = to_p4act(*a);
					tcf_p4_set_init_flags(p4act);
					return P4TC_ACT_PREALLOC_UNINIT;
				}

				return P4TC_ACT_PREALLOC;
			}

			return 0;
		}

		if (replace) {
			if (((*a)->tcfa_flags & TCA_ACT_FLAGS_PREALLOC)) {
				if ((*a)->tcfa_flags & TCA_ACT_FLAGS_UNREFERENCED) {
					p4act = to_p4act(*a);
					tcf_p4_set_init_flags(p4act);
					ret = P4TC_ACT_PREALLOC_UNINIT;
				} else {
					ret = P4TC_ACT_PREALLOC;
				}
			}
		} else {
			NL_SET_ERR_MSG_FMT(extack,
					   "Action %s with index %u was already created",
					   (*a)->ops->kind, index);
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
	}

	err = tcf_action_check_ctrlact(parm->action, tp, goto_ch, extack);
	if (err < 0) {
		tcf_idr_release(*a, bind);
		return err;
	}

	return ret;
}

static void generic_free_param_value(struct p4tc_act_param *param)
{
	kfree(param->value);
	kfree(param->mask);
}

static const struct nla_policy p4tc_act_params_value_policy[P4TC_ACT_VALUE_PARAMS_MAX + 1] = {
	[P4TC_ACT_PARAMS_VALUE_RAW] = { .type = NLA_BINARY },
};

static const struct nla_policy p4tc_act_params_type_policy[P4TC_ACT_PARAMS_TYPE_MAX + 1] = {
	[P4TC_ACT_PARAMS_TYPE_BITEND] = { .type = NLA_U16 },
	[P4TC_ACT_PARAMS_TYPE_CONTAINER_ID] = { .type = NLA_U32 },
};

static int dev_init_param_value(struct net *net, struct p4tc_act_param_ops *op,
				struct p4tc_act_param *nparam,
				struct nlattr **tb,
				struct netlink_ext_ack *extack)
{
	struct nlattr *tb_value[P4TC_ACT_VALUE_PARAMS_MAX + 1];
	u32 value_len;
	u32 *ifindex;
	int err;

	if (!tb[P4TC_ACT_PARAMS_VALUE]) {
		NL_SET_ERR_MSG(extack, "Must specify param value");
		return -EINVAL;
	}
	err = nla_parse_nested(tb_value, P4TC_ACT_VALUE_PARAMS_MAX,
			       tb[P4TC_ACT_PARAMS_VALUE],
			       p4tc_act_params_value_policy, extack);
	if (err < 0)
		return err;

	value_len = nla_len(tb_value[P4TC_ACT_PARAMS_VALUE_RAW]);
	if (value_len != sizeof(u32)) {
		NL_SET_ERR_MSG(extack, "Value length differs from template's");
		return -EINVAL;
	}

	ifindex = nla_data(tb_value[P4TC_ACT_PARAMS_VALUE_RAW]);
	rcu_read_lock();
	if (!dev_get_by_index_rcu(net, *ifindex)) {
		NL_SET_ERR_MSG(extack, "Invalid ifindex");
		rcu_read_unlock();
		return -EINVAL;
	}
	rcu_read_unlock();

	nparam->value = kmemdup(ifindex, sizeof(*ifindex), GFP_KERNEL);
	if (!nparam->value)
		return -EINVAL;

	return 0;
}

static int dev_dump_param_value(struct sk_buff *skb,
				struct p4tc_act_param_ops *op,
				struct p4tc_act_param *param)
{
	const u32 *ifindex = param->value;
	struct nlattr *nest;
	int ret;

	nest = nla_nest_start(skb, P4TC_ACT_PARAMS_VALUE);
	if (nla_put_u32(skb, P4TC_ACT_PARAMS_VALUE_RAW, *ifindex)) {
		ret = -EINVAL;
		goto out_nla_cancel;
	}
	nla_nest_end(skb, nest);

	return 0;

out_nla_cancel:
	nla_nest_cancel(skb, nest);
	return ret;
}

static void dev_free_param_value(struct p4tc_act_param *param)
{
	kfree(param->value);
}

static const struct p4tc_act_param_ops param_ops[P4T_MAX + 1] = {
	[P4T_DEV] = {
		.init_value = dev_init_param_value,
		.dump_value = dev_dump_param_value,
		.free = dev_free_param_value,
	},
};

static void tcf_p4_act_params_destroy(struct tcf_p4act_params *params)
{
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(&params->params_idr, param, tmp, param_id) {
		struct p4tc_act_param_ops *op;

		idr_remove(&params->params_idr, param_id);
		op = (struct p4tc_act_param_ops *)&param_ops[param->type->typeid];
		if (op->free)
			op->free(param);
		else
			generic_free_param_value(param);
		kfree(param);
	}

	kfree(params->params_array);
	idr_destroy(&params->params_idr);

	kfree(params);
}

static void tcf_p4_act_params_destroy_rcu(struct rcu_head *head)
{
	struct tcf_p4act_params *params;

	params = container_of(head, struct tcf_p4act_params, rcu);
	tcf_p4_act_params_destroy(params);
}

static struct p4tc_table_entry_act_bpf_kern *
p4tc_create_act_bpf(struct tcf_p4act *p4act,
		    struct tcf_p4act_params *act_params,
		    struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *params[P4TC_ACT_MAX_NUM_PARAMS];
	struct p4tc_table_entry_act_bpf_kern *act_bpf;
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;
	size_t tot_params_sz = 0;
	u8 *params_cursor;
	int nparams = 0;
	int i;

	act_bpf = kzalloc(sizeof(*act_bpf), GFP_KERNEL);
	if (!act_bpf)
		return ERR_PTR(-ENOMEM);

	idr_for_each_entry_ul(&act_params->params_idr, param, tmp, param_id) {
		const struct p4tc_type *type = param->type;

		if (tot_params_sz > P4TC_MAX_PARAM_DATA_SIZE) {
			NL_SET_ERR_MSG(extack, "Maximum parameter byte size reached");
			kfree(act_bpf);
			return ERR_PTR(-EINVAL);
		}

		tot_params_sz += BITS_TO_BYTES(type->container_bitsz);
		params[nparams++] = param;
	}

	act_bpf->act_bpf.act_id = p4act->act_id;
	params_cursor = act_bpf->act_bpf.params;
	for (i = 0; i < nparams; i++) {
		const struct p4tc_act_param *param = params[i];
		const struct p4tc_type *type = param->type;
		const u32 type_bytesz = BITS_TO_BYTES(type->container_bitsz);

		memcpy(params_cursor, param->value, type_bytesz);
		params_cursor += type_bytesz;
	}

	return act_bpf;
}

static int __tcf_p4_dyna_init_set(struct p4tc_act *act, struct tc_action **a,
				  struct tcf_p4act_params *params,
				  struct tcf_chain *goto_ch,
				  struct tc_act_dyna *parm, bool exists,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_table_entry_act_bpf_kern *act_bpf = NULL, *act_bpf_old;
	struct tcf_p4act_params *params_old;
	struct tcf_p4act *p;

	p = to_p4act(*a);

	if (!((*a)->tcfa_flags & TCA_ACT_FLAGS_UNREFERENCED)) {
		act_bpf = p4tc_create_act_bpf(p, params, extack);
		if (IS_ERR(act_bpf))
			return PTR_ERR(act_bpf);
	}

	/* sparse is fooled by lock under conditionals.
	 * To avoid false positives, we are repeating these 3 lines in both
	 * branches of the if-statement
	 */
	if (exists) {
		spin_lock_bh(&p->tcf_lock);
		goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
		params_old = rcu_replace_pointer(p->params, params, 1);
		act_bpf_old = rcu_replace_pointer(p->act_bpf, act_bpf, 1);
		spin_unlock_bh(&p->tcf_lock);
	} else {
		goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
		params_old = rcu_replace_pointer(p->params, params, 1);
		act_bpf_old = rcu_replace_pointer(p->act_bpf, act_bpf, 1);
	}

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);

	if (params_old)
		call_rcu(&params_old->rcu, tcf_p4_act_params_destroy_rcu);

	if (act_bpf_old)
		kfree_rcu(act_bpf_old, rcu);

	return 0;
}

static int tcf_p4_dyna_template_init(struct net *net, struct tc_action **a,
				     struct p4tc_act *act,
				     struct idr *params_idr,
				     struct list_head *params_lst,
				     struct tc_act_dyna *parm, u32 flags,
				     struct netlink_ext_ack *extack);

static struct tcf_p4act_params *tcf_p4_act_params_init(struct p4tc_act *act)
{
	struct tcf_p4act_params *params;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return ERR_PTR(-ENOMEM);

	params->params_array = kcalloc(act->num_params,
				       sizeof(struct p4tc_act_param *),
				       GFP_KERNEL);
	if (!params->params_array) {
		kfree(params);
		return ERR_PTR(-ENOMEM);
	}

	return params;
}

static struct p4tc_act_param *
init_prealloc_param(struct p4tc_act *act, struct idr *params_idr,
		    struct p4tc_act_param *param,
		    unsigned long *param_id,
		    struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *nparam;
	void *value;

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam)
		return ERR_PTR(-ENOMEM);

	value = kzalloc(BITS_TO_BYTES(param->type->container_bitsz),
			GFP_KERNEL);
	if (!value) {
		kfree(nparam);
		return ERR_PTR(-ENOMEM);
	}

	strscpy(nparam->name, param->name, ACTPARAMNAMSIZ);
	nparam->id = *param_id;
	nparam->value = value;
	nparam->type = param->type;

	return nparam;
}

static void p4tc_param_put(struct p4tc_act_param *param)
{
	kfree(param);
}

static void free_intermediate_param(struct p4tc_act_param *param)
{
	kfree(param->value);
	p4tc_param_put(param);
}

static void free_intermediate_params_list(struct list_head *params_list)
{
	struct p4tc_act_param *nparam, *p;

	list_for_each_entry_safe(nparam, p, params_list, head) {
		free_intermediate_param(nparam);
	}
}

static int init_prealloc_params(struct p4tc_act *act,
				struct idr *params_idr,
				struct list_head *params_lst,
				struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *params[P4TC_MSGBATCH_SIZE] = { NULL };
	struct p4tc_act_param *param;
	unsigned long param_id = 0;
	unsigned long tmp;
	int i = 0;

	idr_for_each_entry_ul(params_idr, param, tmp, param_id) {
		struct p4tc_act_param *nparam;

		nparam = init_prealloc_param(act, params_idr, param, &param_id,
					     extack);
		if (IS_ERR(nparam))
			return PTR_ERR(nparam);

		params[i] = nparam;
		list_add_tail(&nparam->head, params_lst);
		i++;
	}

	return 0;
}

struct p4tc_act *p4tc_action_find_byid(struct p4tc_pipeline *pipeline,
				       const u32 a_id)
{
	return idr_find(&pipeline->p_act_idr, a_id);
}

static void tcf_p4_prealloc_list_add(struct p4tc_act *act_tmpl,
				     struct tc_action **acts,
				     u32 num_prealloc_acts)
{
	int i;

	for (i = 0; i < num_prealloc_acts; i++) {
		struct tcf_p4act *p4act = to_p4act(acts[i]);

		list_add_tail(&p4act->node, &act_tmpl->prealloc_list);
	}

	tcf_idr_insert_n(acts, num_prealloc_acts);
}

static int tcf_p4_prealloc_acts(struct net *net, struct p4tc_act *act,
				struct idr *params_idr,
				struct tc_action **acts,
				const u32 num_prealloc_acts,
				struct netlink_ext_ack *extack)
{
	int err;
	int i;

	for (i = 0; i < num_prealloc_acts; i++) {
		u32 flags = TCA_ACT_FLAGS_PREALLOC | TCA_ACT_FLAGS_UNREFERENCED;
		struct tc_action *a = acts[i];
		struct tc_act_dyna parm = {0};
		struct list_head params_lst;
		struct tcf_p4act *p4act;

		parm.index = i + 1;
		parm.action = TC_ACT_PIPE;

		INIT_LIST_HEAD(&params_lst);

		err = init_prealloc_params(act, params_idr, &params_lst,
					   extack);
		if (err < 0) {
			free_intermediate_params_list(&params_lst);
			goto destroy_acts;
		}

		err = tcf_p4_dyna_template_init(net, &a, act, params_idr,
						&params_lst, &parm, flags,
						extack);
		free_intermediate_params_list(&params_lst);
		if (err < 0)
			goto destroy_acts;

		acts[i] = a;
		p4act = to_p4act(a);
	}

	return 0;

destroy_acts:
	tcf_action_destroy(acts, false);

	return err;
}

/* Need to implement after preallocating */
struct tcf_p4act *
tcf_p4_get_next_prealloc_act(struct p4tc_act *act)
{
	struct tcf_p4act *p4_act;

	spin_lock_bh(&act->list_lock);
	p4_act = list_first_entry_or_null(&act->prealloc_list, struct tcf_p4act,
					  node);
	if (p4_act) {
		list_del_init(&p4_act->node);
		refcount_set(&p4_act->common.tcfa_refcnt, 1);
		atomic_set(&p4_act->common.tcfa_bindcnt, 1);
	}
	spin_unlock_bh(&act->list_lock);

	return p4_act;
}

void tcf_p4_set_init_flags(struct tcf_p4act *p4act)
{
	struct tc_action *a;

	a = (struct tc_action *)p4act;
	a->tcfa_flags &= ~TCA_ACT_FLAGS_UNREFERENCED;
}

static void __tcf_p4_put_prealloc_act(struct p4tc_act *act,
				      struct tcf_p4act *p4act)
{
	struct p4tc_table_entry_act_bpf_kern *act_bpf_old;
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;

	if (p4act->params) {
		idr_for_each_entry_ul(&p4act->params->params_idr, param, tmp,
				      param_id) {
			const struct p4tc_type *type = param->type;
			const u32 type_bytesz = BITS_TO_BYTES(type->container_bitsz);

			memset(param->value, 0, type_bytesz);
		}
	}
	p4act->common.tcfa_flags |= TCA_ACT_FLAGS_UNREFERENCED;

	act_bpf_old = rcu_replace_pointer(p4act->act_bpf, NULL, 1);
	if (act_bpf_old)
		kfree_rcu(act_bpf_old, rcu);

	spin_lock_bh(&act->list_lock);
	list_add_tail(&p4act->node, &act->prealloc_list);
	spin_unlock_bh(&act->list_lock);
}

void
tcf_p4_put_prealloc_act(struct p4tc_act *act, struct tcf_p4act *p4act)
{
	if (refcount_read(&p4act->common.tcfa_refcnt) == 1) {
		__tcf_p4_put_prealloc_act(act, p4act);
	} else {
		refcount_dec(&p4act->common.tcfa_refcnt);
		atomic_dec(&p4act->common.tcfa_bindcnt);
	}
}

static const struct nla_policy p4tc_act_params_policy[P4TC_ACT_PARAMS_MAX + 1] = {
	[P4TC_ACT_PARAMS_NAME] = { .type = NLA_STRING, .len = ACTPARAMNAMSIZ },
	[P4TC_ACT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_ACT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_ACT_PARAMS_MASK] = { .type = NLA_BINARY },
	[P4TC_ACT_PARAMS_TYPE] = { .type = NLA_NESTED },
};

static int generic_dump_param_value(struct sk_buff *skb, struct p4tc_type *type,
				    struct p4tc_act_param *param)
{
	const u32 bytesz = BITS_TO_BYTES(type->container_bitsz);
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nla_value;

	nla_value = nla_nest_start(skb, P4TC_ACT_PARAMS_VALUE);
	if (nla_put(skb, P4TC_ACT_PARAMS_VALUE_RAW, bytesz,
		    param->value))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nla_value);

	if (param->mask &&
	    nla_put(skb, P4TC_ACT_PARAMS_MASK, bytesz, param->mask))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int generic_init_param_value(struct p4tc_act_param *nparam,
				    struct p4tc_type *type, struct nlattr **tb,
				    struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(type->container_bitsz);
	struct nlattr *tb_value[P4TC_ACT_VALUE_PARAMS_MAX + 1];
	const u32 len = BITS_TO_BYTES(type->bitsz);
	void *value;
	int err;

	if (!tb[P4TC_ACT_PARAMS_VALUE]) {
		NL_SET_ERR_MSG(extack, "Must specify param value");
		return -EINVAL;
	}

	err = nla_parse_nested(tb_value, P4TC_ACT_VALUE_PARAMS_MAX,
			       tb[P4TC_ACT_PARAMS_VALUE],
			       p4tc_act_params_value_policy, extack);
	if (err < 0)
		return err;

	value = nla_data(tb_value[P4TC_ACT_PARAMS_VALUE_RAW]);
	if (type->ops->validate_p4t) {
		err = type->ops->validate_p4t(type, value, 0, nparam->bitend,
					      extack);
		if (err < 0)
			return err;
	}

	if (nla_len(tb_value[P4TC_ACT_PARAMS_VALUE_RAW]) != len)
		return -EINVAL;

	nparam->value = kzalloc(alloc_len, GFP_KERNEL);
	if (!nparam->value)
		return -ENOMEM;

	memcpy(nparam->value, value, len);

	if (tb[P4TC_ACT_PARAMS_MASK]) {
		const void *mask = nla_data(tb[P4TC_ACT_PARAMS_MASK]);

		if (nla_len(tb[P4TC_ACT_PARAMS_MASK]) != len) {
			NL_SET_ERR_MSG(extack,
				       "Mask length differs from template's");
			err = -EINVAL;
			goto free_value;
		}

		nparam->mask = kzalloc(alloc_len, GFP_KERNEL);
		if (!nparam->mask) {
			err = -ENOMEM;
			goto free_value;
		}

		memcpy(nparam->mask, mask, len);
	}

	return 0;

free_value:
	kfree(nparam->value);
	return err;
}

static struct p4tc_act_param *param_find_byname(struct idr *params_idr,
						const char *param_name)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		if (param == ERR_PTR(-EBUSY))
			continue;
		if (strncmp(param->name, param_name, ACTPARAMNAMSIZ) == 0)
			return param;
	}

	return NULL;
}

struct p4tc_act_param *tcf_param_find_byid(struct idr *params_idr,
					   const u32 param_id)
{
	return idr_find(params_idr, param_id);
}

struct p4tc_act_param *tcf_param_find_byany(struct p4tc_act *act,
					    const char *param_name,
					    const u32 param_id,
					    struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param;
	int err;

	if (param_id) {
		param = tcf_param_find_byid(&act->params_idr, param_id);
		if (!param) {
			NL_SET_ERR_MSG(extack, "Unable to find param by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (param_name) {
			param = param_find_byname(&act->params_idr, param_name);
			if (!param) {
				NL_SET_ERR_MSG(extack, "Param name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack, "Must specify param name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return param;

out:
	return ERR_PTR(err);
}

static struct p4tc_act_param *
tcf_param_find_byanyattr(struct p4tc_act *act, struct nlattr *name_attr,
			 const u32 param_id, struct netlink_ext_ack *extack)
{
	char *param_name = NULL;

	if (name_attr)
		param_name = nla_data(name_attr);

	return tcf_param_find_byany(act, param_name, param_id, extack);
}

static int __p4_init_param_type(struct p4tc_act_param *param,
				struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ACT_PARAMS_TYPE_MAX + 1];
	struct p4tc_type *type;
	u16 bitend;
	u32 container_id;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ACT_PARAMS_TYPE_MAX, nla,
			       p4tc_act_params_type_policy, extack);
	if (ret < 0)
		return ret;

	if (tb[P4TC_ACT_PARAMS_TYPE_CONTAINER_ID]) {
		container_id =
			nla_get_u32(tb[P4TC_ACT_PARAMS_TYPE_CONTAINER_ID]);

		type = p4type_find_byid(container_id);
		if (!type) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Invalid container type id %u\n",
					   container_id);
			return -EINVAL;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify type container id");
		return -EINVAL;
	}

	if (tb[P4TC_ACT_PARAMS_TYPE_BITEND]) {
		bitend = nla_get_u16(tb[P4TC_ACT_PARAMS_TYPE_BITEND]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify bitend");
		return -EINVAL;
	}

	param->type = type;
	param->bitend = bitend;

	return 0;
}

static int tcf_p4_act_init_param(struct net *net,
				 struct tcf_p4act_params *params,
				 struct p4tc_act *act, struct nlattr *nla,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	struct p4tc_act_param *param, *nparam;
	struct p4tc_act_param_ops *op;
	u32 param_id = 0;
	int err;

	err = nla_parse_nested(tb, P4TC_ACT_PARAMS_MAX, nla,
			       p4tc_act_params_policy, extack);
	if (err < 0)
		return err;

	if (tb[P4TC_ACT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_ACT_PARAMS_ID]);

	param = tcf_param_find_byanyattr(act, tb[P4TC_ACT_PARAMS_NAME],
					 param_id, extack);
	if (IS_ERR(param))
		return PTR_ERR(param);

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam)
		return -ENOMEM;

	err = __p4_init_param_type(nparam, tb[P4TC_ACT_PARAMS_TYPE], extack);
	if (err < 0)
		goto free;

	if (nparam->type != param->type) {
		NL_SET_ERR_MSG(extack,
			       "Param type differs from template");
		err = -EINVAL;
		goto free;
	}

	if (nparam->bitend != param->bitend) {
		NL_SET_ERR_MSG(extack,
			       "Param bitend differs from template");
		err = -EINVAL;
		goto free;
	}

	strscpy(nparam->name, param->name, ACTPARAMNAMSIZ);

	op = (struct p4tc_act_param_ops *)&param_ops[param->type->typeid];
	if (op->init_value)
		err = op->init_value(net, op, nparam, tb, extack);
	else
		err = generic_init_param_value(nparam, nparam->type, tb, extack);

	if (err < 0)
		goto free;

	nparam->id = param->id;
	nparam->index = param->index;

	err = idr_alloc_u32(&params->params_idr, nparam, &nparam->id,
			    nparam->id, GFP_KERNEL);
	if (err < 0)
		goto free_val;

	params->params_array[param->index] = nparam;

	return 0;

free_val:
	if (op->free)
		op->free(nparam);
	else
		generic_free_param_value(nparam);

free:
	kfree(nparam);
	return err;
}

static int tcf_p4_act_init_params(struct net *net,
				  struct tcf_p4act_params *params,
				  struct p4tc_act *act, struct nlattr *nla,
				  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int err;
	int i;

	err = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, NULL);
	if (err < 0)
		return err;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		err = tcf_p4_act_init_param(net, params, act, tb[i], extack);
		if (err < 0)
			return err;
	}

	return 0;
}

static struct p4tc_act *p4tc_action_find_byname(const char *act_name,
						struct p4tc_pipeline *pipeline)
{
	char full_act_name[ACTPARAMNAMSIZ];
	unsigned long tmp, id;
	struct p4tc_act *act;

	snprintf(full_act_name, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);
	idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, id)
		if (strncmp(act->common.name, full_act_name, ACTNAMSIZ) == 0)
			return act;

	return NULL;
}

struct p4tc_act *tcf_p4_find_act(struct net *net,
				 const struct tc_action_ops *a_o)
{
	char *act_name_clone, *act_name, *p_name;
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;
	int err;

	act_name_clone = act_name = kstrdup(a_o->kind, GFP_KERNEL);
	if (!act_name)
		return ERR_PTR(-ENOMEM);

	p_name = strsep(&act_name, SEPARATOR);
	pipeline = p4tc_pipeline_find_byany(net, p_name, 0, NULL);
	if (IS_ERR(pipeline)) {
		err = -ENOENT;
		goto free_act_name;
	}

	act = p4tc_action_find_byname(act_name, pipeline);
	if (!act) {
		err = -ENOENT;
		goto free_act_name;
	}
	kfree(act_name_clone);

	return act;

free_act_name:
	kfree(act_name_clone);
	return ERR_PTR(err);
}

static int tcf_p4_dyna_init(struct net *net, struct nlattr *nla,
			    struct nlattr *est, struct tc_action **a,
			    struct tcf_proto *tp, struct tc_action_ops *a_o,
			    u32 flags, struct netlink_ext_ack *extack)
{
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct nlattr *tb[P4TC_ACT_MAX + 1];
	struct tcf_chain *goto_ch = NULL;
	struct tcf_p4act_params *params;
	struct tcf_p4act *prealloc_act;
	struct tc_act_dyna *parm;
	struct p4tc_act *act;
	bool exists = false;
	int ret = 0;
	int err;

	if (flags & TCA_ACT_FLAGS_BIND &&
	    !(flags & TCA_ACT_FLAGS_FROM_P4TC)) {
		NL_SET_ERR_MSG(extack,
			       "Can only bind to dynamic action from P4TC objects");
		return -EPERM;
	}

	if (unlikely(!nla)) {
		NL_SET_ERR_MSG(extack,
			       "Must specify action netlink attributes");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, P4TC_ACT_MAX, nla, NULL, extack);
	if (err < 0)
		return err;

	if (!tb[P4TC_ACT_OPT]) {
		NL_SET_ERR_MSG(extack,
			       "Must specify option netlink attributes");
		return -EINVAL;
	}

	act = tcf_p4_find_act(net, a_o);
	if (IS_ERR(act))
		return PTR_ERR(act);

	if (!act->active) {
		NL_SET_ERR_MSG(extack,
			       "Dynamic action must be active to create instance");
		return -EINVAL;
	}

	parm = nla_data(tb[P4TC_ACT_OPT]);

	ret = __tcf_p4_dyna_init(net, est, act, parm, a, tp, a_o, &goto_ch,
				 flags, extack);
	if (ret < 0)
		return ret;
	/* If trying to bind to unitialised preallocated action, must init below */
	if (bind && (!ret || ret == P4TC_ACT_PREALLOC))
		return 0;

	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto release_idr;

	params = tcf_p4_act_params_init(act);
	if (IS_ERR(params)) {
		err = PTR_ERR(params);
		goto release_idr;
	}

	idr_init(&params->params_idr);
	if (tb[P4TC_ACT_PARMS]) {
		err = tcf_p4_act_init_params(net, params, act,
					     tb[P4TC_ACT_PARMS], extack);
		if (err < 0)
			goto release_params;
	} else {
		if (!idr_is_empty(&act->params_idr)) {
			NL_SET_ERR_MSG(extack,
				       "Must specify action parameters");
			err = -EINVAL;
			goto release_params;
		}
	}

	exists = ret != P4TC_ACT_CREATED;
	err = __tcf_p4_dyna_init_set(act, a, params, goto_ch, parm, exists,
				     extack);
	if (err < 0)
		goto release_params;

	return ret;

release_params:
	tcf_p4_act_params_destroy(params);

release_idr:
	if (ret == P4TC_ACT_PREALLOC) {
		prealloc_act = to_p4act(*a);
		tcf_p4_put_prealloc_act(act, prealloc_act);
		(*a)->tcfa_flags |= TCA_ACT_FLAGS_UNREFERENCED;
	} else if (!exists && ((*a)->tcfa_flags & TCA_ACT_FLAGS_PREALLOC)) {
		prealloc_act = to_p4act(*a);
		list_del_init(&prealloc_act->node);
		tcf_idr_release(*a, bind);
	} else {
		tcf_idr_release(*a, bind);
	}

	return err;
}

static int tcf_p4_act_init_params_list(struct p4tc_act *act,
				       struct tcf_p4act_params *params,
				       struct list_head *params_lst)
{
	struct p4tc_act_param *nparam, *tmp;
	u32 tot_params_sz = 0;
	int err;

	list_for_each_entry_safe(nparam, tmp, params_lst, head) {
		err = idr_alloc_u32(&params->params_idr, nparam, &nparam->id,
				    nparam->id, GFP_KERNEL);
		if (err < 0)
			return err;
		list_del(&nparam->head);
		params->num_params++;
		tot_params_sz += nparam->type->container_bitsz;
	}
	/* Sum act_id */
	params->tot_params_sz = tot_params_sz + (sizeof(u32) << 3);

	return 0;
}

/* This is the action instantiation that is invoked from the template code,
 * specifically when initialising preallocated dynamic actions.
 * This functions is analogous to tcf_p4_dyna_init.
 */
static int tcf_p4_dyna_template_init(struct net *net, struct tc_action **a,
				     struct p4tc_act *act,
				     struct idr *params_idr,
				     struct list_head *params_lst,
				     struct tc_act_dyna *parm, u32 flags,
				     struct netlink_ext_ack *extack)
{
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct tc_action_ops *a_o = &act->ops;
	struct tcf_chain *goto_ch = NULL;
	struct tcf_p4act_params *params;
	struct tcf_p4act *prealloc_act;
	bool exists = false;
	int ret;
	int err;

	/* Don't need to check if action is active because we only call this
	 * when we are on our way to activating the action.
	 */
	ret = __tcf_p4_dyna_init(net, NULL, act, parm, a, NULL, a_o, &goto_ch,
				 flags, extack);
	if (ret < 0)
		return ret;

	params = tcf_p4_act_params_init(act);
	if (IS_ERR(params)) {
		err = PTR_ERR(params);
		goto release_idr;
	}

	idr_init(&params->params_idr);
	if (params_idr) {
		err = tcf_p4_act_init_params_list(act, params, params_lst);
		if (err < 0)
			goto release_params;
	} else {
		if (!idr_is_empty(&act->params_idr)) {
			NL_SET_ERR_MSG(extack,
				       "Must specify action parameters");
			err = -EINVAL;
			goto release_params;
		}
	}

	exists = ret != P4TC_ACT_CREATED;
	err = __tcf_p4_dyna_init_set(act, a, params, goto_ch, parm, exists,
				     extack);
	if (err < 0)
		goto release_params;

	return err;

release_params:
	tcf_p4_act_params_destroy(params);

release_idr:
	if (ret == P4TC_ACT_PREALLOC) {
		prealloc_act = to_p4act(*a);
		tcf_p4_put_prealloc_act(act, prealloc_act);
		(*a)->tcfa_flags |= TCA_ACT_FLAGS_UNREFERENCED;
	} else if (!exists && ((*a)->tcfa_flags & TCA_ACT_FLAGS_PREALLOC)) {
		prealloc_act = to_p4act(*a);
		list_del_init(&prealloc_act->node);
		tcf_idr_release(*a, bind);
	} else {
		tcf_idr_release(*a, bind);
	}

	return err;
}

static int tcf_p4_dyna_act(struct sk_buff *skb, const struct tc_action *a,
			   struct tcf_result *res)
{
	struct tcf_p4act *dynact = to_p4act(a);

	tcf_lastuse_update(&dynact->tcf_tm);
	tcf_action_update_bstats(&dynact->common, skb);

	return 0;
}

static int tcf_act_fill_param_type(struct sk_buff *skb,
				   struct p4tc_act_param *param)
{
	unsigned char *b = nlmsg_get_pos(skb);

	if (nla_put_u16(skb, P4TC_ACT_PARAMS_TYPE_BITEND, param->bitend))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_ACT_PARAMS_TYPE_CONTAINER_ID,
			param->type->typeid))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_p4_dyna_dump(struct sk_buff *skb, struct tc_action *a, int bind,
			    int ref)
{
	struct tcf_p4act *dynact = to_p4act(a);
	unsigned char *b = nlmsg_get_pos(skb);
	struct tc_act_dyna opt = {
		.index = dynact->tcf_index,
		.refcnt = refcount_read(&dynact->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&dynact->tcf_bindcnt) - bind,
	};
	struct tcf_p4act_params *params;
	struct p4tc_act_param *parm;
	struct nlattr *nest_parms;
	struct tcf_t t;
	int i = 1;
	int id;

	spin_lock_bh(&dynact->tcf_lock);

	opt.action = dynact->tcf_action;
	if (nla_put(skb, P4TC_ACT_OPT, sizeof(opt), &opt))
		goto nla_put_failure;

	if (nla_put_string(skb, P4TC_ACT_NAME, a->ops->kind))
		goto nla_put_failure;

	tcf_tm_dump(&t, &dynact->tcf_tm);
	if (nla_put_64bit(skb, P4TC_ACT_TM, sizeof(t), &t, P4TC_ACT_PAD))
		goto nla_put_failure;

	nest_parms = nla_nest_start(skb, P4TC_ACT_PARMS);
	if (!nest_parms)
		goto nla_put_failure;

	params = rcu_dereference_protected(dynact->params, 1);
	if (params) {
		idr_for_each_entry(&params->params_idr, parm, id) {
			struct p4tc_act_param_ops *op;
			struct nlattr *nest_count;
			struct nlattr *nest_type;

			nest_count = nla_nest_start(skb, i);
			if (!nest_count)
				goto nla_put_failure;

			if (nla_put_string(skb, P4TC_ACT_PARAMS_NAME,
					   parm->name))
				goto nla_put_failure;

			if (nla_put_u32(skb, P4TC_ACT_PARAMS_ID, parm->id))
				goto nla_put_failure;

			op = (struct p4tc_act_param_ops *)&param_ops[parm->type->typeid];
			if (op->dump_value) {
				if (op->dump_value(skb, op, parm) < 0)
					goto nla_put_failure;
			} else {
				if (generic_dump_param_value(skb, parm->type, parm))
					goto nla_put_failure;
			}

			nest_type = nla_nest_start(skb, P4TC_ACT_PARAMS_TYPE);
			if (!nest_type)
				goto nla_put_failure;

			tcf_act_fill_param_type(skb, parm);
			nla_nest_end(skb, nest_type);

			nla_nest_end(skb, nest_count);
			i++;
		}
	}
	nla_nest_end(skb, nest_parms);

	spin_unlock_bh(&dynact->tcf_lock);

	return skb->len;

nla_put_failure:
	spin_unlock_bh(&dynact->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_p4_dyna_lookup(struct net *net, const struct tc_action_ops *ops,
			      struct tc_action **a, u32 index)
{
	struct p4tc_act *act;
	int err;

	act = tcf_p4_find_act(net, ops);
	if (IS_ERR(act))
		return PTR_ERR(act);

	err = tcf_idr_search(act->tn, a, index);
	if (!err)
		return err;

	if ((*a)->tcfa_flags & TCA_ACT_FLAGS_UNREFERENCED)
		return false;

	return err;
}

static int tcf_p4_dyna_walker(struct net *net, struct sk_buff *skb,
			      struct netlink_callback *cb, int type,
			      const struct tc_action_ops *ops,
			      struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;

	act = tcf_p4_find_act(net, ops);
	if (IS_ERR(act))
		return PTR_ERR(act);

	return tcf_generic_walker(act->tn, skb, cb, type, ops, extack);
}

static void tcf_p4_dyna_cleanup(struct tc_action *a)
{
	struct tc_action_ops *ops = (struct tc_action_ops *)a->ops;
	struct p4tc_table_entry_act_bpf_kern *act_bpf;
	struct tcf_p4act *m = to_p4act(a);
	struct tcf_p4act_params *params;

	params = rcu_dereference_protected(m->params, 1);
	act_bpf = rcu_dereference_protected(m->act_bpf, 1);

	if (refcount_read(&ops->dyn_ref) > 1)
		refcount_dec(&ops->dyn_ref);

	if (params)
		call_rcu(&params->rcu, tcf_p4_act_params_destroy_rcu);

	if (act_bpf)
		kfree_rcu(act_bpf, rcu);
}

static struct p4tc_act *
p4tc_action_find_byany(struct p4tc_pipeline *pipeline,
		       const char *act_name, const u32 a_id,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;
	int err;

	if (a_id) {
		act = p4tc_action_find_byid(pipeline, a_id);
		if (!act) {
			NL_SET_ERR_MSG(extack, "Unable to find action by id");
			err = -ENOENT;
			goto out;
		}
	} else {
		if (act_name) {
			act = p4tc_action_find_byname(act_name, pipeline);
			if (!act) {
				NL_SET_ERR_MSG(extack, "Action name not found");
				err = -ENOENT;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify action name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return act;

out:
	return ERR_PTR(err);
}

struct p4tc_act *p4tc_action_find_get(struct p4tc_pipeline *pipeline,
				      const char *act_name, const u32 a_id,
				      struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;

	act = p4tc_action_find_byany(pipeline, act_name, a_id, extack);
	if (IS_ERR(act))
		return act;

	if (!refcount_inc_not_zero(&act->a_ref)) {
		NL_SET_ERR_MSG(extack, "Action is stale");
		return ERR_PTR(-EBUSY);
	}

	return act;
}

static struct p4tc_act *
p4tc_action_find_byanyattr(struct nlattr *act_name_attr, const u32 a_id,
			   struct p4tc_pipeline *pipeline,
			   struct netlink_ext_ack *extack)
{
	char *act_name = NULL;

	if (act_name_attr)
		act_name = nla_data(act_name_attr);

	return p4tc_action_find_byany(pipeline, act_name, a_id, extack);
}

static void p4_put_many_params(struct idr *params_idr)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id)
		p4tc_param_put(param);
}

static int p4_init_param_type(struct p4tc_act_param *param,
			      struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct p4tc_type *type;
	int ret;

	ret = __p4_init_param_type(param, nla, extack);
	if (ret < 0)
		return ret;

	type = param->type;
	ret = type->ops->validate_p4t(type, NULL, 0, param->bitend, extack);
	if (ret < 0)
		return ret;

	return 0;
}

static struct p4tc_act_param *p4_create_param(struct p4tc_act *act,
					      struct idr *params_idr,
					      struct nlattr **tb, u32 param_id,
					      struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param;
	char *name;
	int ret;

	if (tb[P4TC_ACT_PARAMS_NAME]) {
		name = nla_data(tb[P4TC_ACT_PARAMS_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param name");
		ret = -EINVAL;
		goto out;
	}

	param = kmalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	if (tcf_param_find_byid(&act->params_idr, param_id) ||
	    param_find_byname(&act->params_idr, name)) {
		NL_SET_ERR_MSG(extack, "Param already exists");
		ret = -EEXIST;
		goto free;
	}

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		ret = p4_init_param_type(param, tb[P4TC_ACT_PARAMS_TYPE],
					 extack);
		if (ret < 0)
			goto free;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}

	if (param_id) {
		ret = idr_alloc_u32(params_idr, param, &param_id,
				    param_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free;
		}
		param->id = param_id;
	} else {
		param->id = 1;

		ret = idr_alloc_u32(params_idr, param, &param->id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free;
		}
	}

	strscpy(param->name, name, ACTPARAMNAMSIZ);

	return param;

free:
	kfree(param);

out:
	return ERR_PTR(ret);
}

static struct p4tc_act_param *p4_update_param(struct p4tc_act *act,
					      struct nlattr **tb,
					      struct idr *params_idr,
					      u32 param_id,
					      struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param_old, *param;
	int ret;

	param_old = tcf_param_find_byanyattr(act, tb[P4TC_ACT_PARAMS_NAME],
					     param_id, extack);
	if (IS_ERR(param_old))
		return param_old;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	strscpy(param->name, param_old->name, ACTPARAMNAMSIZ);
	param->id = param_old->id;

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		ret = p4_init_param_type(param, tb[P4TC_ACT_PARAMS_TYPE],
					 extack);
		if (ret < 0)
			goto free;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}

	ret = idr_alloc_u32(params_idr, param, &param->id,
			    param->id, GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate param id");
		goto free;
	}

	return param;

free:
	kfree(param);
out:
	return ERR_PTR(ret);
}

static struct p4tc_act_param *p4_act_init_param(struct p4tc_act *act,
						struct nlattr *nla,
						struct idr *params_idr,
						bool update,
						struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	u32 param_id = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ACT_PARAMS_MAX, nla, NULL, extack);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (tb[P4TC_ACT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_ACT_PARAMS_ID]);

	if (update)
		return p4_update_param(act, tb, params_idr, param_id, extack);
	else
		return p4_create_param(act, params_idr, tb, param_id, extack);

out:
	return ERR_PTR(ret);
}

static int p4_act_init_params(struct p4tc_act *act, struct nlattr *nla,
			      struct idr *params_idr, bool update,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return -EINVAL;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_act_param *param;

		param = p4_act_init_param(act, tb[i], params_idr, update,
					  extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_del;
		}
	}

	return i - 1;

params_del:
	p4_put_many_params(params_idr);
	return ret;
}

static int p4_act_init(struct p4tc_act *act, struct nlattr *nla,
		       struct netlink_ext_ack *extack)
{
	int num_params = 0;
	int ret;

	idr_init(&act->params_idr);

	if (nla) {
		num_params =
			p4_act_init_params(act, nla, &act->params_idr, false,
					   extack);
		if (num_params < 0) {
			ret = num_params;
			goto idr_destroy;
		}
	}

	return num_params;

idr_destroy:
	p4_put_many_params(&act->params_idr);
	idr_destroy(&act->params_idr);
	return ret;
}

static const struct nla_policy p4tc_act_policy[P4TC_ACT_MAX + 1] = {
	[P4TC_ACT_NAME] = { .type = NLA_STRING, .len = ACTNAMSIZ },
	[P4TC_ACT_PARMS] = { .type = NLA_NESTED },
	[P4TC_ACT_OPT] = NLA_POLICY_EXACT_LEN(sizeof(struct tc_act_dyna)),
	[P4TC_ACT_NUM_PREALLOC] = NLA_POLICY_MIN(NLA_U32, 1),
	[P4TC_ACT_ACTIVE] = { .type = NLA_U8 },
};

static inline void p4tc_action_net_exit(struct tc_action_net *tn)
{
	tcf_idrinfo_destroy(tn->ops, tn->idrinfo);
	kfree(tn->idrinfo);
	kfree(tn);
}

static int __tcf_act_put(struct net *net, struct p4tc_pipeline *pipeline,
			 struct p4tc_act *act, bool teardown,
			 struct netlink_ext_ack *extack)
{
	struct tcf_p4act *p4act, *tmp_act;
	struct p4tc_act_param *act_param;
	unsigned long param_id, tmp;
	struct tc_action_net *tn;

	if (!teardown && (refcount_read(&act->ops.dyn_ref) > 1 ||
			  refcount_read(&act->a_ref) > 1)) {
		NL_SET_ERR_MSG(extack,
			       "Unable to delete referenced action template");
		return -EBUSY;
	}

	tn = net_generic(net, act->ops.net_id);

	idr_for_each_entry_ul(&act->params_idr, act_param, tmp, param_id) {
		idr_remove(&act->params_idr, param_id);
		kfree(act_param);
	}

	tcf_unregister_dyn_action(net, &act->ops);
	/* Free preallocated acts */
	list_for_each_entry_safe(p4act, tmp_act, &act->prealloc_list, node) {
		list_del_init(&p4act->node);
		if (p4act->common.tcfa_flags & TCA_ACT_FLAGS_UNREFERENCED)
			tcf_idr_release(&p4act->common, true);
	}
	p4tc_action_net_exit(act->tn);

	idr_remove(&pipeline->p_act_idr, act->a_id);

	list_del(&act->head);

	kfree(act);

	pipeline->num_created_acts--;

	return 0;
}

static int _tcf_act_fill_nlmsg(struct net *net, struct sk_buff *skb,
			       struct p4tc_act *act)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_act_param *param;
	struct nlattr *nest, *parms;
	unsigned long param_id, tmp;
	int i = 1;

	if (nla_put_u32(skb, P4TC_PATH, act->a_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_ACT_NAME, act->common.name))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_ACT_NUM_PREALLOC, act->num_prealloc_acts))
		goto out_nlmsg_trim;

	parms = nla_nest_start(skb, P4TC_ACT_PARMS);
	if (!parms)
		goto out_nlmsg_trim;

	idr_for_each_entry_ul(&act->params_idr, param, tmp, param_id) {
		struct nlattr *nest_count;
		struct nlattr *nest_type;

		nest_count = nla_nest_start(skb, i);
		if (!nest_count)
			goto out_nlmsg_trim;

		if (nla_put_string(skb, P4TC_ACT_PARAMS_NAME, param->name))
			goto out_nlmsg_trim;

		if (nla_put_u32(skb, P4TC_ACT_PARAMS_ID, param->id))
			goto out_nlmsg_trim;

		nest_type = nla_nest_start(skb, P4TC_ACT_PARAMS_TYPE);
		if (!nest_type)
			goto out_nlmsg_trim;

		tcf_act_fill_param_type(skb, param);
		nla_nest_end(skb, nest_type);

		nla_nest_end(skb, nest_count);
		i++;
	}
	nla_nest_end(skb, parms);

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_act_fill_nlmsg(struct net *net, struct sk_buff *skb,
			      struct p4tc_template_common *tmpl,
			      struct netlink_ext_ack *extack)
{
	return _tcf_act_fill_nlmsg(net, skb, to_act(tmpl));
}

static int tcf_act_flush(struct sk_buff *skb, struct net *net,
			 struct p4tc_pipeline *pipeline,
			 struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	unsigned long tmp, act_id;
	struct p4tc_act *act;
	int ret = 0;
	int i = 0;

	if (nla_put_u32(skb, P4TC_PATH, 0))
		goto out_nlmsg_trim;

	if (idr_is_empty(&pipeline->p_act_idr)) {
		NL_SET_ERR_MSG(extack,
			       "There are not action templates to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, act_id) {
		if (__tcf_act_put(net, pipeline, act, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any action template");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG_FMT(extack,
					   "Flushed only %u action templates",
					   i);
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_act_gd(struct net *net, struct sk_buff *skb, struct nlmsghdr *n,
		      struct nlattr *nla, struct p4tc_nl_pname *nl_pname,
		      u32 *ids, struct netlink_ext_ack *extack)
{
	const u32 pipeid = ids[P4TC_PID_IDX], a_id = ids[P4TC_AID_IDX];
	struct nlattr *tb[P4TC_ACT_MAX + 1] = { NULL };
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;
	int ret = 0;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline = p4tc_pipeline_find_byany_unsealed(net, nl_pname->data,
							     pipeid, extack);
	else
		pipeline = p4tc_pipeline_find_byany(net, nl_pname->data, pipeid,
						    extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_ACT_MAX, nla, p4tc_act_policy,
				       extack);
		if (ret < 0)
			return ret;
	}

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_act_flush(skb, net, pipeline, extack);

	act = p4tc_action_find_byanyattr(tb[P4TC_ACT_NAME], a_id, pipeline,
					 extack);
	if (IS_ERR(act))
		return PTR_ERR(act);

	if (_tcf_act_fill_nlmsg(net, skb, act) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for template action");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = __tcf_act_put(net, pipeline, act, false, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_act_put(struct p4tc_pipeline *pipeline,
		       struct p4tc_template_common *tmpl,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_act *act = to_act(tmpl);

	return __tcf_act_put(pipeline->net, pipeline, act, true, extack);
}

static void p4tc_params_replace_many(struct p4tc_act *act,
				     struct idr *params_idr)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		idr_remove(params_idr, param->id);
		param = idr_replace(&act->params_idr, param, param->id);
		p4tc_param_put(param);
	}
}

static struct p4tc_act *tcf_act_create(struct net *net, struct nlattr **tb,
				       struct p4tc_pipeline *pipeline, u32 *ids,
				       struct netlink_ext_ack *extack)
{
	u32 a_id = ids[P4TC_AID_IDX];
	struct p4tc_act *act;
	int num_params = 0;
	char *act_name;
	int ret = 0;

	if (tb[P4TC_ACT_NAME]) {
		act_name = nla_data(tb[P4TC_ACT_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must supply action name");
		return ERR_PTR(-EINVAL);
	}

	if ((p4tc_action_find_byname(act_name, pipeline))) {
		NL_SET_ERR_MSG(extack, "Action already exists with same name");
		return ERR_PTR(-EEXIST);
	}

	if (p4tc_action_find_byid(pipeline, a_id)) {
		NL_SET_ERR_MSG(extack, "Action already exists with same id");
		return ERR_PTR(-EEXIST);
	}

	act = kzalloc(sizeof(*act), GFP_KERNEL);
	if (!act)
		return ERR_PTR(-ENOMEM);

	act->ops.owner = THIS_MODULE;
	act->ops.act = tcf_p4_dyna_act;
	act->ops.dump = tcf_p4_dyna_dump;
	act->ops.cleanup = tcf_p4_dyna_cleanup;
	act->ops.init_ops = tcf_p4_dyna_init;
	act->ops.lookup = tcf_p4_dyna_lookup;
	act->ops.walk = tcf_p4_dyna_walker;
	act->ops.size = sizeof(struct tcf_p4act);
	INIT_LIST_HEAD(&act->head);

	act->tn = kzalloc(sizeof(*act->tn), GFP_KERNEL);
	if (!act->tn) {
		ret = -ENOMEM;
		goto free_act_ops;
	}

	ret = tc_action_net_init(net, act->tn, &act->ops);
	if (ret < 0) {
		kfree(act->tn);
		goto free_act_ops;
	}
	act->tn->ops = &act->ops;

	snprintf(act->ops.kind, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);

	if (a_id) {
		ret = idr_alloc_u32(&pipeline->p_act_idr, act, &a_id, a_id,
				    GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to alloc action id");
			goto free_action_net;
		}

		act->a_id = a_id;
	} else {
		act->a_id = 1;

		ret = idr_alloc_u32(&pipeline->p_act_idr, act, &act->a_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to alloc action id");
			goto free_action_net;
		}
	}

	/* We are only preallocating the instances once the action template is
	 * activated during update.
	 */
	if (tb[P4TC_ACT_NUM_PREALLOC]) {
		u32 *num_prealloc_acts = nla_data(tb[P4TC_ACT_NUM_PREALLOC]);

		if (*num_prealloc_acts > P4TC_MAX_TENTRIES) {
			ret = -EINVAL;
			NL_SET_ERR_MSG_FMT(extack,
					   "num_prealloc_acts can't be > %u",
					   P4TC_MAX_TENTRIES);
			goto idr_rm;
		}
		act->num_prealloc_acts = *num_prealloc_acts;
	} else {
		act->num_prealloc_acts = P4TC_DEFAULT_NUM_PREALLOC;
	}

	refcount_set(&act->ops.dyn_ref, 1);
	ret = tcf_register_dyn_action(net, &act->ops);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to register new action template");
		goto idr_rm;
	}

	num_params = p4_act_init(act, tb[P4TC_ACT_PARMS], extack);
	if (num_params < 0) {
		ret = num_params;
		goto unregister;
	}
	act->num_params = num_params;

	set_param_indices(&act->params_idr);

	act->pipeline = pipeline;

	pipeline->num_created_acts++;

	act->common.p_id = pipeline->common.p_id;
	snprintf(act->common.name, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);
	act->common.ops = (struct p4tc_template_ops *)&p4tc_act_ops;

	refcount_set(&act->a_ref, 1);

	list_add_tail(&act->head, &dynact_list);
	INIT_LIST_HEAD(&act->prealloc_list);
	spin_lock_init(&act->list_lock);

	return act;

unregister:
	rtnl_unlock();
	tcf_unregister_dyn_action(net, &act->ops);
	rtnl_lock();

idr_rm:
	idr_remove(&pipeline->p_act_idr, act->a_id);

free_action_net:
	p4tc_action_net_exit(act->tn);

free_act_ops:
	kfree(act);

	return ERR_PTR(ret);
}

static struct p4tc_act *tcf_act_update(struct net *net, struct nlattr **tb,
				       struct p4tc_pipeline *pipeline, u32 *ids,
				       u32 flags,
				       struct netlink_ext_ack *extack)
{
	const u32 a_id = ids[P4TC_AID_IDX];
	struct tc_action **prealloc_acts;
	bool updates_params = false;
	struct idr params_idr;
	u32 num_prealloc_acts;
	struct p4tc_act *act;
	int num_params = 0;
	s8 active = -1;
	int ret = 0;

	act = p4tc_action_find_byanyattr(tb[P4TC_ACT_NAME], a_id, pipeline,
					 extack);
	if (IS_ERR(act))
		return act;

	if (tb[P4TC_ACT_ACTIVE])
		active = nla_get_u8(tb[P4TC_ACT_ACTIVE]);

	if (act->active) {
		if (!active) {
			if (refcount_read(&act->ops.dyn_ref) > 1) {
				NL_SET_ERR_MSG(extack,
					       "Unable to inactivate action with instances");
				return ERR_PTR(-EINVAL);
			}
			act->active = false;
			return act;
		}
		NL_SET_ERR_MSG(extack, "Unable to update active action");

		ret = -EINVAL;
		goto out;
	}

	idr_init(&params_idr);
	if (tb[P4TC_ACT_PARMS]) {
		num_params = p4_act_init_params(act, tb[P4TC_ACT_PARMS],
						&params_idr, true, extack);
		if (num_params < 0) {
			ret = num_params;
			goto idr_destroy;
		}
		set_param_indices(&params_idr);
		updates_params = true;
	}

	if (tb[P4TC_ACT_NUM_PREALLOC]) {
		num_prealloc_acts = nla_get_u32(tb[P4TC_ACT_NUM_PREALLOC]);
		if (num_prealloc_acts > P4TC_MAX_TENTRIES) {
			ret = -EINVAL;
			NL_SET_ERR_MSG_FMT(extack,
					   "num_prealloc_acts can't be > %u",
					   P4TC_MAX_TENTRIES);
			goto params_del;
		}
	} else {
		num_prealloc_acts = act->num_prealloc_acts;
	}

	act->pipeline = pipeline;
	if (active == 1) {
		struct idr *chosen_idr = updates_params ?
			&params_idr : &act->params_idr;

		prealloc_acts = kcalloc(num_prealloc_acts,
					sizeof(*prealloc_acts),
					GFP_KERNEL);
		if (!prealloc_acts) {
			ret = -ENOMEM;
			goto params_del;
		}
		chosen_idr = updates_params ? &params_idr : &act->params_idr;

		ret = tcf_p4_prealloc_acts(pipeline->net, act, chosen_idr,
					   prealloc_acts, num_prealloc_acts,
					   extack);
		if (ret < 0)
			goto free_prealloc_acts;

		tcf_p4_prealloc_list_add(act, prealloc_acts,
					 num_prealloc_acts);

		kfree(prealloc_acts);

		act->active = true;
	} else if (!active) {
		NL_SET_ERR_MSG(extack, "Action is already inactive");
		ret = -EINVAL;
		goto params_del;
	}

	act->num_prealloc_acts = num_prealloc_acts;

	if (updates_params)
		p4tc_params_replace_many(act, &params_idr);

	idr_destroy(&params_idr);

	return act;

free_prealloc_acts:
	kfree(prealloc_acts);

params_del:
	p4_put_many_params(&params_idr);

idr_destroy:
	idr_destroy(&params_idr);

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_act_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	   struct p4tc_nl_pname *nl_pname, u32 *ids,
	   struct netlink_ext_ack *extack)
{
	const u32 pipeid = ids[P4TC_PID_IDX];
	struct nlattr *tb[P4TC_ACT_MAX + 1];
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;
	int ret;

	pipeline = p4tc_pipeline_find_byany_unsealed(net, nl_pname->data, pipeid,
						     extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ret = nla_parse_nested(tb, P4TC_ACT_MAX, nla, p4tc_act_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		act = tcf_act_create(net, tb, pipeline, ids, extack);
		break;
	case RTM_UPDATEP4TEMPLATE:
		act = tcf_act_update(net, tb, pipeline, ids, n->nlmsg_flags,
				     extack);
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (IS_ERR(act))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)act;
}

static int tcf_act_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			struct nlattr *nla, char **p_name, u32 *ids,
			struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = p4tc_pipeline_find_byany(net, *p_name,
						    ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = p4tc_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return p4tc_tmpl_generic_dump(skb, ctx, &pipeline->p_act_idr,
				      P4TC_AID_IDX, extack);
}

static int tcf_act_dump_1(struct sk_buff *skb,
			  struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_act *act = to_act(common);

	if (!param)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_ACT_NAME, act->common.name))
		goto out_nlmsg_trim;

	if (nla_put_u8(skb, P4TC_ACT_ACTIVE, act->active))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

const struct p4tc_template_ops p4tc_act_ops = {
	.init = NULL,
	.cu = tcf_act_cu,
	.put = tcf_act_put,
	.gd = tcf_act_gd,
	.fill_nlmsg = tcf_act_fill_nlmsg,
	.dump = tcf_act_dump,
	.dump_1 = tcf_act_dump_1,
};
