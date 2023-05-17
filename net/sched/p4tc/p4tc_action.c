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

#include <linux/indirect_call_wrapper.h>
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

#ifndef CONFIG_NET_P4_TC_KFUNCS
static u32 label_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_label_key *key = data;

	return jhash(key->label, key->labelsz, seed);
}

static int label_hash_cmp(struct rhashtable_compare_arg *arg, const void *ptr)
{
	const struct p4tc_label_key *label_arg = arg->key;
	const struct p4tc_label_node *node = ptr;

	return strncmp(label_arg->label, node->key.label, node->key.labelsz);
}

static u32 label_obj_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_label_node *node = data;

	return label_hash_fn(&node->key, 0, seed);
}

void p4tc_label_ht_destroy(void *ptr, void *arg)
{
	struct p4tc_label_node *node = ptr;

	kfree(node->key.label);
	kfree(node);
}

const struct rhashtable_params p4tc_label_ht_params = {
	.obj_cmpfn = label_hash_cmp,
	.obj_hashfn = label_obj_hash_fn,
	.hashfn = label_hash_fn,
	.head_offset = offsetof(struct p4tc_label_node, ht_node),
	.key_offset = offsetof(struct p4tc_label_node, key),
	.automatic_shrinking = true,
};
#endif

static void set_param_indices(struct p4tc_act *act)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;
	int i = 0;

	idr_for_each_entry_ul(&act->params_idr, param, tmp, id) {
		param->index = i;
		i++;
	}
}

static int __tcf_p4_dyna_init(struct net *net, struct nlattr *est,
			      struct p4tc_act *act, struct tc_act_dyna *parm,
			      struct tc_action **a, struct tcf_proto *tp,
			      struct tc_action_ops *a_o,
			      struct tcf_chain **goto_ch, u32 flags,
			      struct netlink_ext_ack *extack)
{
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	bool exists = false;
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	u32 index;
	int err;

	index = parm->index;

	err = tcf_idr_check_alloc(act->tn, &index, a, bind);
	if (err < 0)
		return err;

	exists = err;
	if (!exists) {
		struct tcf_p4act *p;

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
#ifndef CONFIG_NET_P4_TC_KFUNCS
		INIT_LIST_HEAD(&p->cmd_operations);
#endif

		ret = ACT_P_CREATED;
	} else {
		if (bind) /* dont override defaults */
			return 0;
		if (!(flags & TCA_ACT_FLAGS_REPLACE)) {
			tcf_idr_cleanup(act->tn, index);
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

static int __tcf_p4_dyna_init_set(struct p4tc_act *act, struct tc_action **a,
				  struct tcf_p4act_params *params,
				  struct tcf_chain *goto_ch,
				  struct tc_act_dyna *parm, bool exists,
				  struct netlink_ext_ack *extack)
{
	struct tcf_p4act_params *params_old;
	struct tcf_p4act *p;
	int err = 0;

	p = to_p4act(*a);

	if (exists)
		spin_lock_bh(&p->tcf_lock);

	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);

#ifndef CONFIG_NET_P4_TC_KFUNCS
	err = p4tc_cmds_copy(act, &p->cmd_operations, exists, extack);
	if (err < 0) {
		if (exists)
			spin_unlock_bh(&p->tcf_lock);

		return err;
	}
#endif

	params_old = rcu_replace_pointer(p->params, params, 1);
	if (exists)
		spin_unlock_bh(&p->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);

	if (params_old)
		call_rcu(&params_old->rcu, tcf_p4_act_params_destroy_rcu);

	return err;
}

static struct p4tc_act *tcf_p4_find_act(struct net *net,
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
	pipeline = tcf_pipeline_find_byany(net, p_name, 0, NULL);
	if (IS_ERR(pipeline)) {
		err = -ENOENT;
		goto free_act_name;
	}

	act = tcf_action_find_byname(act_name, pipeline);
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
	struct tcf_chain *goto_ch = NULL;
	bool exists = false;
	int ret = 0;
	struct nlattr *tb[P4TC_ACT_MAX + 1];
	struct tcf_p4act_params *params;
	struct tc_act_dyna *parm;
	struct p4tc_act *act;
	int err;

	if (flags & TCA_ACT_FLAGS_BIND &&
	    !(flags & TCA_ACT_FLAGS_FROM_P4TC)) {
		NL_SET_ERR_MSG(extack,
			       "Can only bind to dynamic action from P4TC objects");
		return -EPERM;
	}

	if (!nla) {
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
	if (bind && !ret)
		return 0;

	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto release_idr;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params) {
		err = -ENOMEM;
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

	exists = ret != ACT_P_CREATED;
	err = __tcf_p4_dyna_init_set(act, a, params, goto_ch, parm, exists,
				     extack);
	if (err < 0)
		goto release_params;

	return ret;

release_params:
	tcf_p4_act_params_destroy(params);

release_idr:
	tcf_idr_release(*a, bind);
	return err;
}

static const struct nla_policy p4tc_act_params_value_policy[P4TC_ACT_VALUE_PARAMS_MAX + 1] = {
	[P4TC_ACT_PARAMS_VALUE_RAW] = { .type = NLA_BINARY },
	[P4TC_ACT_PARAMS_VALUE_OPND] = { .type = NLA_NESTED },
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

	nparam->value = kzalloc(sizeof(*ifindex), GFP_KERNEL);
	if (!nparam->value)
		return -EINVAL;

	memcpy(nparam->value, ifindex, sizeof(*ifindex));

	return 0;
}

static int dev_dump_param_value(struct sk_buff *skb,
				struct p4tc_act_param_ops *op,
				struct p4tc_act_param *param)
{
	struct nlattr *nest;
	u32 *ifindex;
	int ret;

	nest = nla_nest_start(skb, P4TC_ACT_PARAMS_VALUE);
#ifdef CONFIG_NET_P4_TC_KFUNCS
	ifindex = (u32 *)param->value;
#else
	if (param->flags & P4TC_ACT_PARAM_FLAGS_ISDYN) {
		struct p4tc_cmd_operand *kopnd;
		struct nlattr *nla_opnd;

		nla_opnd = nla_nest_start(skb, P4TC_ACT_PARAMS_VALUE_OPND);
		kopnd = param->value;
		if (p4tc_cmds_fill_operand(skb, kopnd) < 0) {
			ret = -1;
			goto out_nla_cancel;
		}
		nla_nest_end(skb, nla_opnd);
	} else {
		ifindex = (u32 *)param->value;
#endif

		if (nla_put_u32(skb, P4TC_ACT_PARAMS_VALUE_RAW, *ifindex)) {
			ret = -EINVAL;
			goto out_nla_cancel;
		}
#ifndef CONFIG_NET_P4_TC_KFUNCS
	}
#endif
	nla_nest_end(skb, nest);

	return 0;

out_nla_cancel:
	nla_nest_cancel(skb, nest);
	return ret;
}

static void dev_free_param_value(struct p4tc_act_param *param)
{
#ifdef CONFIG_NET_P4_TC_KFUNCS
	kfree(param->value);
#else
	if (!(param->flags & P4TC_ACT_PARAM_FLAGS_ISDYN))
		kfree(param->value);
#endif
}

static int generic_init_param_value(struct p4tc_act_param *nparam,
				    struct p4tc_type *type, struct nlattr **tb,
				    struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(type->container_bitsz);
	const u32 len = BITS_TO_BYTES(type->bitsz);
	struct nlattr *tb_value[P4TC_ACT_VALUE_PARAMS_MAX + 1];
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
		err = type->ops->validate_p4t(type, value, 0, type->bitsz - 1,
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

const struct p4tc_act_param_ops param_ops[P4T_MAX + 1] = {
	[P4T_DEV] = {
		.init_value = dev_init_param_value,
		.dump_value = dev_dump_param_value,
		.free = dev_free_param_value,
	},
};

static void generic_free_param_value(struct p4tc_act_param *param)
{
#ifdef CONFIG_NET_P4_TC_KFUNCS
	kfree(param->value);
	kfree(param->mask);
#else
	if (!(param->flags & P4TC_ACT_PARAM_FLAGS_ISDYN)) {
		kfree(param->value);
		kfree(param->mask);
	}
#endif
}

static int tcf_p4_act_init_params_list(struct tcf_p4act_params *params,
				       struct list_head *params_list)
{
	struct p4tc_act_param *nparam, *tmp;
	int err;

	list_for_each_entry_safe(nparam, tmp, params_list, head) {
		err = idr_alloc_u32(&params->params_idr, nparam, &nparam->id,
				    nparam->id, GFP_KERNEL);
		if (err < 0)
			return err;
		list_del(&nparam->head);
		params->num_params++;
	}

	return 0;
}

/* This is the action instantiation that is invoked from the template code,
 * specifically when there is a command act with runtime parameters.
 * It is assumed that the action kind that is being instantiated here was
 * already created. This functions is analogous to tcf_p4_dyna_init.
 */
int tcf_p4_dyna_template_init(struct net *net, struct tc_action **a,
			      struct p4tc_act *act,
			      struct list_head *params_list,
			      struct tc_act_dyna *parm, u32 flags,
			      struct netlink_ext_ack *extack)
{
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct tc_action_ops *a_o = &act->ops;
	struct tcf_chain *goto_ch = NULL;
	bool exists = false;
	struct tcf_p4act_params *params;
	int ret;
	int err;

	if (!act->active) {
		NL_SET_ERR_MSG(extack,
			       "Dynamic action must be active to create instance");
		return -EINVAL;
	}

	ret = __tcf_p4_dyna_init(net, NULL, act, parm, a, NULL, a_o, &goto_ch,
				 flags, extack);
	if (ret < 0)
		return ret;

	err = tcf_action_check_ctrlact(parm->action, NULL, &goto_ch, extack);
	if (err < 0)
		goto release_idr;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params) {
		err = -ENOMEM;
		goto release_idr;
	}

	idr_init(&params->params_idr);
	if (params_list) {
		err = tcf_p4_act_init_params_list(params, params_list);
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

	exists = ret != ACT_P_CREATED;
	err = __tcf_p4_dyna_init_set(act, a, params, goto_ch, parm, exists,
				     extack);
	if (err < 0)
		goto release_params;

	return err;

release_params:
	tcf_p4_act_params_destroy(params);

release_idr:
	tcf_idr_release(*a, bind);
	return err;
}

INDIRECT_CALLABLE_SCOPE int tcf_p4_dyna_act(struct sk_buff *skb,
					    const struct tc_action *a,
					    struct tcf_result *res)
{
	struct tcf_p4act *dynact = to_p4act(a);
	int ret = 0;
#ifndef CONFIG_NET_P4_TC_KFUNCS
	int jmp_cnt = 0;
	struct p4tc_cmd_operate *op;
#endif

	tcf_lastuse_update(&dynact->tcf_tm);
	tcf_action_update_bstats(&dynact->common, skb);

#ifndef CONFIG_NET_P4_TC_KFUNCS
	list_for_each_entry(op, &dynact->cmd_operations, cmd_operations) {
		if (jmp_cnt-- > 0)
			continue;

		if (op->op_id == P4TC_CMD_OP_LABEL) {
			ret = TC_ACT_PIPE;
			continue;
		}

		ret = __p4tc_cmd_run(skb, op, dynact, res);
		if (TC_ACT_EXT_CMP(ret, TC_ACT_JUMP)) {
			jmp_cnt = ret & TC_ACT_EXT_VAL_MASK;
			continue;
		} else if (ret != TC_ACT_PIPE) {
			break;
		}
	}
#endif

	if (ret == TC_ACT_SHOT)
		tcf_action_inc_drop_qstats(&dynact->common);

	if (ret == TC_ACT_STOLEN || ret == TC_ACT_TRAP)
		ret = TC_ACT_CONSUMED;

	if (ret == TC_ACT_OK)
		ret = dynact->tcf_action;

	return ret;
}

static int tcf_p4_dyna_dump(struct sk_buff *skb, struct tc_action *a, int bind,
			    int ref)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct tcf_p4act *dynact = to_p4act(a);
	struct tc_act_dyna opt = {
		.index = dynact->tcf_index,
		.refcnt = refcount_read(&dynact->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&dynact->tcf_bindcnt) - bind,
	};
	int i = 1;
	struct tcf_p4act_params *params;
	struct p4tc_act_param *parm;
	struct nlattr *nest_parms;
#ifndef CONFIG_NET_P4_TC_KFUNCS
	struct nlattr *nest;
#endif
	struct tcf_t t;
	int id;

	spin_lock_bh(&dynact->tcf_lock);

	opt.action = dynact->tcf_action;
	if (nla_put(skb, P4TC_ACT_OPT, sizeof(opt), &opt))
		goto nla_put_failure;

#ifndef CONFIG_NET_P4_TC_KFUNCS
	nest = nla_nest_start(skb, P4TC_ACT_CMDS_LIST);
	if (p4tc_cmds_fillup(skb, &dynact->cmd_operations))
		goto nla_put_failure;
	nla_nest_end(skb, nest);
#endif

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

			if (nla_put_u32(skb, P4TC_ACT_PARAMS_TYPE, parm->type->typeid))
				goto nla_put_failure;

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

	act = tcf_p4_find_act(net, ops);
	if (IS_ERR(act))
		return PTR_ERR(act);

	return tcf_idr_search(act->tn, a, index);
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
	struct tcf_p4act *m = to_p4act(a);
	struct tcf_p4act_params *params;

	params = rcu_dereference_protected(m->params, 1);

	if (refcount_read(&ops->dyn_ref) > 1)
		refcount_dec(&ops->dyn_ref);

#ifndef CONFIG_NET_P4_TC_KFUNCS
	p4tc_cmds_release_ope_list(NULL, &m->cmd_operations, false);
#endif
	if (params)
		call_rcu(&params->rcu, tcf_p4_act_params_destroy_rcu);
}

int generic_dump_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     struct p4tc_act_param *param)
{
	const u32 bytesz = BITS_TO_BYTES(type->container_bitsz);
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nla_value;

	nla_value = nla_nest_start(skb, P4TC_ACT_PARAMS_VALUE);
#ifndef CONFIG_NET_P4_TC_KFUNCS
	if (param->flags & P4TC_ACT_PARAM_FLAGS_ISDYN) {
		struct p4tc_cmd_operand *kopnd;
		struct nlattr *nla_opnd;

		nla_opnd = nla_nest_start(skb, P4TC_ACT_PARAMS_VALUE_OPND);
		kopnd = param->value;
		if (p4tc_cmds_fill_operand(skb, kopnd) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, nla_opnd);
	} else {
#endif
		if (nla_put(skb, P4TC_ACT_PARAMS_VALUE_RAW, bytesz,
			    param->value))
			goto out_nlmsg_trim;
#ifndef CONFIG_NET_P4_TC_KFUNCS
	}
#endif
	nla_nest_end(skb, nla_value);

	if (param->mask &&
	    nla_put(skb, P4TC_ACT_PARAMS_MASK, bytesz, param->mask))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

void tcf_p4_act_params_destroy(struct tcf_p4act_params *params)
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

void tcf_p4_act_params_destroy_rcu(struct rcu_head *head)
{
	struct tcf_p4act_params *params;

	params = container_of(head, struct tcf_p4act_params, rcu);
	tcf_p4_act_params_destroy(params);
}

static const struct nla_policy p4tc_act_params_policy[P4TC_ACT_PARAMS_MAX + 1] = {
	[P4TC_ACT_PARAMS_NAME] = { .type = NLA_STRING, .len = ACTPARAMNAMSIZ },
	[P4TC_ACT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_ACT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_ACT_PARAMS_MASK] = { .type = NLA_BINARY },
	[P4TC_ACT_PARAMS_TYPE] = { .type = NLA_U32 },
};

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

static int tcf_p4_act_init_param(struct net *net,
				 struct tcf_p4act_params *params,
				 struct p4tc_act *act, struct nlattr *nla,
				 struct netlink_ext_ack *extack)
{
	u32 param_id = 0;
	struct nlattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	struct p4tc_act_param *param, *nparam;
	struct p4tc_act_param_ops *op;
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

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		u32 typeid = nla_get_u32(tb[P4TC_ACT_PARAMS_TYPE]);

		if (param->type->typeid != typeid) {
			NL_SET_ERR_MSG(extack,
				       "Param type differs from template");
			return -EINVAL;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		return -EINVAL;
	}

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam)
		return -ENOMEM;

	strscpy(nparam->name, param->name, ACTPARAMNAMSIZ);
	nparam->type = param->type;

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

int tcf_p4_act_init_params(struct net *net, struct tcf_p4act_params *params,
			   struct p4tc_act *act, struct nlattr *nla,
			   struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int err;
	int i;

	err = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, NULL);
	if (err < 0)
		return err;

	params->params_array = kcalloc(act->num_params,
				       sizeof(struct p4tc_act_param *),
				       GFP_KERNEL);
	if (!params->params_array)
		return -ENOMEM;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		err = tcf_p4_act_init_param(net, params, act, tb[i], extack);
		if (err < 0)
			return err;
	}

	return 0;
}

struct p4tc_act *tcf_action_find_byname(const char *act_name,
					struct p4tc_pipeline *pipeline)
{
	char full_act_name[ACTPARAMNAMSIZ];
	struct p4tc_act *act;
	unsigned long tmp, id;

	snprintf(full_act_name, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);
	idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, id)
		if (strncmp(act->common.name, full_act_name, ACTNAMSIZ) == 0)
			return act;

	return NULL;
}

struct p4tc_act *tcf_action_find_byid(struct p4tc_pipeline *pipeline,
				      const u32 a_id)
{
	return idr_find(&pipeline->p_act_idr, a_id);
}

struct p4tc_act *tcf_action_find_byany(struct p4tc_pipeline *pipeline,
				       const char *act_name, const u32 a_id,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;
	int err;

	if (a_id) {
		act = tcf_action_find_byid(pipeline, a_id);
		if (!act) {
			NL_SET_ERR_MSG(extack, "Unable to find action by id");
			err = -ENOENT;
			goto out;
		}
	} else {
		if (act_name) {
			act = tcf_action_find_byname(act_name, pipeline);
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

struct p4tc_act *tcf_action_get(struct p4tc_pipeline *pipeline,
				const char *act_name, const u32 a_id,
				struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;

	act = tcf_action_find_byany(pipeline, act_name, a_id, extack);
	if (IS_ERR(act))
		return act;

	WARN_ON(!refcount_inc_not_zero(&act->a_ref));
	return act;
}

void tcf_action_put(struct p4tc_act *act)
{
	WARN_ON(!refcount_dec_not_one(&act->a_ref));
}

static struct p4tc_act *
tcf_action_find_byanyattr(struct nlattr *act_name_attr, const u32 a_id,
			  struct p4tc_pipeline *pipeline,
			  struct netlink_ext_ack *extack)
{
	char *act_name = NULL;

	if (act_name_attr)
		act_name = nla_data(act_name_attr);

	return tcf_action_find_byany(pipeline, act_name, a_id, extack);
}

static void p4_put_param(struct idr *params_idr, struct p4tc_act_param *param)
{
	kfree(param);
}

void p4_put_many_params(struct idr *params_idr, struct p4tc_act_param *params[],
			int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4_put_param(params_idr, params[i]);
}

static struct p4tc_act_param *p4_create_param(struct p4tc_act *act,
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
		u32 typeid;

		typeid = nla_get_u32(tb[P4TC_ACT_PARAMS_TYPE]);
		param->type = p4type_find_byid(typeid);
		if (!param->type) {
			NL_SET_ERR_MSG(extack, "Param type is invalid");
			ret = -EINVAL;
			goto free;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}

	if (param_id) {
		ret = idr_alloc_u32(&act->params_idr, param, &param_id,
				    param_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free;
		}
		param->id = param_id;
	} else {
		param->id = 1;

		ret = idr_alloc_u32(&act->params_idr, param, &param->id,
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
					      const u32 param_id,
					      struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param_old, *param;
	int ret;

	param_old = tcf_param_find_byanyattr(act, tb[P4TC_ACT_PARAMS_NAME],
					     param_id, extack);
	if (IS_ERR(param_old))
		return param_old;

	param = kmalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	strscpy(param->name, param_old->name, ACTPARAMNAMSIZ);
	param->id = param_old->id;

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		u32 typeid;

		typeid = nla_get_u32(tb[P4TC_ACT_PARAMS_TYPE]);
		param->type = p4type_find_byid(typeid);
		if (!param->type) {
			NL_SET_ERR_MSG(extack, "Param type is invalid");
			ret = -EINVAL;
			goto free;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}

	return param;

free:
	kfree(param);
out:
	return ERR_PTR(ret);
}

static struct p4tc_act_param *p4_act_init_param(struct p4tc_act *act,
						struct nlattr *nla, bool update,
						struct netlink_ext_ack *extack)
{
	u32 param_id = 0;
	struct nlattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	int ret;

	ret = nla_parse_nested(tb, P4TC_ACT_PARAMS_MAX, nla, NULL, extack);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (tb[P4TC_ACT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_ACT_PARAMS_ID]);

	if (update)
		return p4_update_param(act, tb, param_id, extack);
	else
		return p4_create_param(act, tb, param_id, extack);

out:
	return ERR_PTR(ret);
}

int p4_act_init_params(struct p4tc_act *act, struct nlattr *nla,
		       struct p4tc_act_param *params[], bool update,
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

		param = p4_act_init_param(act, tb[i], update, extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_del;
		}
		params[i - 1] = param;
	}

	return i - 1;

params_del:
	p4_put_many_params(&act->params_idr, params, i - 1);
	return ret;
}

int p4_act_init(struct p4tc_act *act, struct nlattr *nla,
		struct p4tc_act_param *params[], struct netlink_ext_ack *extack)
{
	int num_params = 0;
	int ret;

	idr_init(&act->params_idr);

	if (nla) {
		num_params =
			p4_act_init_params(act, nla, params, false, extack);
		if (num_params < 0) {
			ret = num_params;
			goto idr_destroy;
		}
	}

	return num_params;

idr_destroy:
	p4_put_many_params(&act->params_idr, params, num_params);
	idr_destroy(&act->params_idr);
	return ret;
}

static const struct nla_policy p4tc_act_policy[P4TC_ACT_MAX + 1] = {
	[P4TC_ACT_NAME] = { .type = NLA_STRING, .len = ACTNAMSIZ },
	[P4TC_ACT_PARMS] = { .type = NLA_NESTED },
	[P4TC_ACT_OPT] = { .type = NLA_BINARY,
			   .len = sizeof(struct tc_act_dyna) },
	[P4TC_ACT_CMDS_LIST] = { .type = NLA_NESTED },
	[P4TC_ACT_ACTIVE] = { .type = NLA_U8 },
};

static inline void p4tc_action_net_exit(struct tc_action_net *tn)
{
	tcf_idrinfo_destroy(tn->ops, tn->idrinfo);
	kfree(tn->idrinfo);
	kfree(tn);
}

static int __tcf_act_put(struct net *net, struct p4tc_pipeline *pipeline,
			 struct p4tc_act *act, bool unconditional_purge,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *act_param;
	unsigned long param_id, tmp;
	struct tc_action_net *tn;
	int ret;

	if (!unconditional_purge && (refcount_read(&act->ops.dyn_ref) > 1 ||
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

#ifndef CONFIG_NET_P4_TC_KFUNCS
	p4tc_cmds_release_ope_list(net, &act->cmd_operations, true);
#endif

	ret = tcf_unregister_dyn_action(net, &act->ops);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to unregister new action template");
		return ret;
	}
	p4tc_action_net_exit(act->tn);

#ifndef CONFIG_NET_P4_TC_KFUNCS
	if (act->labels) {
		rhashtable_free_and_destroy(act->labels, p4tc_label_ht_destroy,
					    NULL);
		kfree(act->labels);
	}
#endif

	idr_remove(&pipeline->p_act_idr, act->a_id);

#ifndef CONFIG_NET_P4_TC_KFUNCS
	if (!unconditional_purge)
		tcf_pipeline_delete_from_dep_graph(pipeline, act);
#endif

	list_del(&act->head);

	kfree(act);

	pipeline->num_created_acts--;

	return 0;
}

static int _tcf_act_fill_nlmsg(struct net *net, struct sk_buff *skb,
			       struct p4tc_act *act)
{
	unsigned char *b = nlmsg_get_pos(skb);
	int i = 1;
	struct nlattr *nest, *parms;
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;
#ifndef CONFIG_NET_P4_TC_KFUNCS
	struct nlattr *cmds;
#endif

	if (nla_put_u32(skb, P4TC_PATH, act->a_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_ACT_NAME, act->common.name))
		goto out_nlmsg_trim;

	parms = nla_nest_start(skb, P4TC_ACT_PARMS);
	if (!parms)
		goto out_nlmsg_trim;

	idr_for_each_entry_ul(&act->params_idr, param, tmp, param_id) {
		struct nlattr *nest_count;

		nest_count = nla_nest_start(skb, i);
		if (!nest_count)
			goto out_nlmsg_trim;

		if (nla_put_string(skb, P4TC_ACT_PARAMS_NAME, param->name))
			goto out_nlmsg_trim;

		if (nla_put_u32(skb, P4TC_ACT_PARAMS_ID, param->id))
			goto out_nlmsg_trim;

		if (nla_put_u32(skb, P4TC_ACT_PARAMS_TYPE, param->type->typeid))
			goto out_nlmsg_trim;

		nla_nest_end(skb, nest_count);
		i++;
	}
	nla_nest_end(skb, parms);

#ifndef CONFIG_NET_P4_TC_KFUNCS
	cmds = nla_nest_start(skb, P4TC_ACT_CMDS_LIST);
	if (p4tc_cmds_fillup(skb, &act->cmd_operations))
		goto out_nlmsg_trim;
	nla_nest_end(skb, cmds);
#endif

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
	struct p4tc_act *act;
	unsigned long tmp, act_id;
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
			NL_SET_ERR_MSG(extack,
				       "Unable to flush all action templates");
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
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data,
							    pipeid, extack);
	else
		pipeline = tcf_pipeline_find_byany(net, nl_pname->data, pipeid,
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

	act = tcf_action_find_byanyattr(tb[P4TC_ACT_NAME], a_id, pipeline,
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

static int tcf_act_put(struct net *net, struct p4tc_template_common *tmpl,
		       bool unconditional_purge, struct netlink_ext_ack *extack)
{
	struct p4tc_act *act = to_act(tmpl);
	struct p4tc_pipeline *pipeline;

	pipeline = tcf_pipeline_find_byid(net, tmpl->p_id);

	return __tcf_act_put(net, pipeline, act, unconditional_purge, extack);
}

static void p4tc_params_replace_many(struct idr *params_idr,
				     struct p4tc_act_param *params[],
				     int params_count)
{
	int i;

	for (i = 0; i < params_count; i++) {
		struct p4tc_act_param *param = params[i];

		param = idr_replace(params_idr, param, param->id);
		kfree(param);
	}
}

static struct p4tc_act *tcf_act_create(struct net *net, struct nlattr **tb,
				       struct p4tc_pipeline *pipeline, u32 *ids,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *params[P4TC_MSGBATCH_SIZE] = { NULL };
	u32 a_id = ids[P4TC_AID_IDX];
	int num_params = 0;
	int ret = 0;
#ifndef CONFIG_NET_P4_TC_KFUNCS
	struct p4tc_act_dep_node *dep_node;
#endif
	struct p4tc_act *act;
	char *act_name;

	if (tb[P4TC_ACT_NAME]) {
		act_name = nla_data(tb[P4TC_ACT_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must supply action name");
		return ERR_PTR(-EINVAL);
	}

	if ((tcf_action_find_byname(act_name, pipeline))) {
		NL_SET_ERR_MSG(extack, "Action already exists with same name");
		return ERR_PTR(-EEXIST);
	}

	if (tcf_action_find_byid(pipeline, a_id)) {
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

#ifndef CONFIG_NET_P4_TC_KFUNCS
	dep_node = kzalloc(sizeof(*dep_node), GFP_KERNEL);
	if (!dep_node) {
		ret = -ENOMEM;
		goto idr_rm;
	}
	dep_node->act_id = act->a_id;
	INIT_LIST_HEAD(&dep_node->incoming_egde_list);
	list_add_tail(&dep_node->head, &pipeline->act_dep_graph);
#endif

	refcount_set(&act->ops.dyn_ref, 1);
	ret = tcf_register_dyn_action(net, &act->ops);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to register new action template");
#ifdef CONFIG_NET_P4_TC_KFUNCS
		goto idr_rm;
#else
		goto free_dep_node;
#endif
	}

	num_params = p4_act_init(act, tb[P4TC_ACT_PARMS], params, extack);
	if (num_params < 0) {
		ret = num_params;
		goto unregister;
	}
	act->num_params = num_params;

	set_param_indices(act);

#ifdef CONFIG_NET_P4_TC_KFUNCS
	if (tb[P4TC_ACT_CMDS_LIST]) {
		NL_SET_ERR_MSG(extack, "Commands not supported in kfuncs mode");
		ret = -EOPNOTSUPP;
		goto uninit;
	}
#else
	INIT_LIST_HEAD(&act->cmd_operations);
	act->pipeline = pipeline;
	if (tb[P4TC_ACT_CMDS_LIST]) {
		ret = p4tc_cmds_parse(net, act, tb[P4TC_ACT_CMDS_LIST], false,
				      extack);
		if (ret < 0)
			goto uninit;
	}
#endif

	pipeline->num_created_acts++;

#ifndef CONFIG_NET_P4_TC_KFUNCS
	ret = determine_act_topological_order(pipeline, true);
	if (ret < 0) {
		pipeline->num_created_acts--;
		goto release_cmds;
	}
#endif

	act->common.p_id = pipeline->common.p_id;
	snprintf(act->common.name, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);
	act->common.ops = (struct p4tc_template_ops *)&p4tc_act_ops;

	refcount_set(&act->a_ref, 1);

	list_add_tail(&act->head, &dynact_list);

	return act;

#ifndef CONFIG_NET_P4_TC_KFUNCS
release_cmds:
	if (tb[P4TC_ACT_CMDS_LIST])
		p4tc_cmds_release_ope_list(net, &act->cmd_operations, false);
#endif

uninit:
	p4_put_many_params(&act->params_idr, params, num_params);
	idr_destroy(&act->params_idr);

unregister:
	rtnl_unlock();
	tcf_unregister_dyn_action(net, &act->ops);
	rtnl_lock();

#ifndef CONFIG_NET_P4_TC_KFUNCS
free_dep_node:
	list_del(&dep_node->head);
	kfree(dep_node);
#endif

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
	struct p4tc_act_param *params[P4TC_MSGBATCH_SIZE] = { NULL };
	const u32 a_id = ids[P4TC_AID_IDX];
	int num_params = 0;
	s8 active = -1;
	int ret = 0;
	struct p4tc_act *act;

	act = tcf_action_find_byanyattr(tb[P4TC_ACT_NAME], a_id, pipeline,
					extack);
	if (IS_ERR(act))
		return act;

	if (tb[P4TC_ACT_ACTIVE])
		active = nla_get_u8(tb[P4TC_ACT_ACTIVE]);

	if (act->active) {
		if (!active) {
			if (refcount_read(&act->ops.dyn_ref) > 1) {
				NL_SET_ERR_MSG(extack,
					       "Unable to inactivate referenced action");
				return ERR_PTR(-EINVAL);
			}
			act->active = false;
			return act;
		}
		NL_SET_ERR_MSG(extack, "Unable to update active action");
		return ERR_PTR(-EINVAL);
	}

	if (tb[P4TC_ACT_PARMS]) {
		num_params = p4_act_init_params(act, tb[P4TC_ACT_PARMS], params,
						true, extack);
		if (num_params < 0) {
			ret = num_params;
			goto out;
		}
		set_param_indices(act);
	}

	act->pipeline = pipeline;
	if (active == 1) {
		act->active = true;
	} else if (!active) {
		NL_SET_ERR_MSG(extack, "Action is already inactive");
		ret = -EINVAL;
		goto params_del;
	}

#ifdef CONFIG_NET_P4_TC_KFUNCS
	if (tb[P4TC_ACT_CMDS_LIST]) {
		NL_SET_ERR_MSG(extack, "Commands not supported in kfuncs mode");
		ret = -EOPNOTSUPP;
		goto params_del;
	}
#else
	if (tb[P4TC_ACT_CMDS_LIST]) {
		ret = p4tc_cmds_parse(net, act, tb[P4TC_ACT_CMDS_LIST], true,
				      extack);
		if (ret < 0)
			goto params_del;

		ret = determine_act_topological_order(pipeline, true);
		if (ret < 0)
			goto release_cmds;
	}
#endif

	p4tc_params_replace_many(&act->params_idr, params, num_params);
	return act;

#ifndef CONFIG_NET_P4_TC_KFUNCS
release_cmds:
	p4tc_cmds_release_ope_list(net, &act->cmd_operations, false);
#endif

params_del:
	p4_put_many_params(&act->params_idr, params, num_params);

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
	struct p4tc_act *act;
	struct p4tc_pipeline *pipeline;
	int ret;

	pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data, pipeid,
						    extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ret = nla_parse_nested(tb, P4TC_ACT_MAX, nla, p4tc_act_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	if (n->nlmsg_flags & NLM_F_REPLACE)
		act = tcf_act_update(net, tb, pipeline, ids, n->nlmsg_flags,
				     extack);
	else
		act = tcf_act_create(net, tb, pipeline, ids, extack);
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
		pipeline = tcf_pipeline_find_byany(net, *p_name,
						   ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipeline->p_act_idr,
					P4TC_AID_IDX, extack);
}

static int tcf_act_dump_1(struct sk_buff *skb,
			  struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_act *act = to_act(common);
#ifndef CONFIG_NET_P4_TC_KFUNCS
	struct nlattr *nest;
#endif

	if (!param)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_ACT_NAME, act->common.name))
		goto out_nlmsg_trim;

#ifndef CONFIG_NET_P4_TC_KFUNCS
	nest = nla_nest_start(skb, P4TC_ACT_CMDS_LIST);
	if (p4tc_cmds_fillup(skb, &act->cmd_operations))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nest);
#endif

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
