// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_action.c	P4 TC ACTION TEMPLATES
 *
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
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
	char *act_name_clone, *act_name;
	struct tcf_p4act_params *params;
	struct p4tc_pipeline *pipeline;
	struct tcf_p4act *p;
	struct tc_action_net *tn;
	struct tc_act_dyna *parm;
	struct p4tc_act *act;
	char *p_name;
	u32 index;
	int err;

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

	parm = nla_data(tb[P4TC_ACT_OPT]);
	index = parm->index;

	act_name_clone = act_name = kstrdup(a_o->kind, GFP_KERNEL);
	if (!act_name)
		return -ENOMEM;

	p_name = strsep(&act_name, SEPARATOR);
	pipeline = tcf_pipeline_find_byany(p_name, 0, NULL);
	act = tcf_action_find_byname(act_name, pipeline);
	if (!act->active) {
		NL_SET_ERR_MSG(extack,
			       "Dynamic action must be active to create instance");
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

	p = to_p4act(*a);
	p->p_id = pipeline->common.p_id;
	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto release_idr;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params) {
		err = -ENOMEM;
		goto release_idr;
	}

	INIT_LIST_HEAD(&p->cmd_operations);
	idr_init(&params->params_idr);
	if (tb[P4TC_ACT_PARMS]) {
		err = tcf_p4_act_init_params(net, params, act,
					     tb[P4TC_ACT_PARMS], extack);
		if (err < 0)
			goto release_params;
	} else {
		if (!idr_is_empty(&act->params_idr)) {
			NL_SET_ERR_MSG(extack, "Must specify action parameters");
			err = -EINVAL;
			goto release_params;
		}
	}

	p->p_id = pipeline->common.p_id;

	if (exists)
		spin_lock_bh(&p->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);

	err = p4tc_cmds_copy(&p->cmd_operations, &act->cmd_operations, exists,
			     extack);
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

static int tcf_p4_dyna_act(struct sk_buff *skb, const struct tc_action *a,
			   struct tcf_result *res)
{
	struct tcf_p4act *dynact = to_p4act(a);
	int ret = 0;
	int jmp_cnt = 0;
	struct p4tc_cmd_operate *op;

	tcf_lastuse_update(&dynact->tcf_tm);
	tcf_action_update_bstats(&dynact->common, skb);

	/* We only need this lock because the operand's that are action
	 * parameters will be assigned at run-time, and thus will cause a write
	 * operation in the data path. If we had this structure as per-cpu, we'd
	 * possibly be able to get rid of this lock.
	 */
	spin_lock(&dynact->tcf_lock);
	list_for_each_entry(op, &dynact->cmd_operations, cmd_operations) {
		if (jmp_cnt > 0) {
			jmp_cnt--;
			continue;
		}

		ret = op->cmd->run(skb, op, dynact, res);
		if (TC_ACT_EXT_CMP(ret, TC_ACT_JUMP)) {
			jmp_cnt = ret & TC_ACT_EXT_VAL_MASK;
			continue;
		} else if (ret != TC_ACT_PIPE) {
			break;
		}
	}
	spin_unlock(&dynact->tcf_lock);

	if (ret == TC_ACT_SHOT)
		tcf_action_inc_drop_qstats(&dynact->common);

	if (ret == TC_ACT_STOLEN ||
	    ret == TC_ACT_TRAP)
		ret = TC_ACT_CONSUMED;

	if (ret == TC_ACT_OK)
		ret = dynact->tcf_action;

	return ret;
}

static int tcf_p4_dyna_dump(struct sk_buff *skb, struct tc_action *a, int bind,
			    int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
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
	struct nlattr *nest;
	struct tcf_t t;
	int id;

	spin_lock_bh(&dynact->tcf_lock);

	opt.action = dynact->tcf_action;
	if (nla_put(skb, P4TC_ACT_OPT, sizeof(opt), &opt))
		goto nla_put_failure;

	nest = nla_nest_start(skb, P4TC_ACT_CMDS_LIST);
	if (p4tc_cmds_fillup(skb, &dynact->cmd_operations))
		goto nla_put_failure;
	nla_nest_end(skb, nest);

	if (nla_put_string(skb, P4TC_ACT_NAME, a->ops->kind))
		goto nla_put_failure;

	tcf_tm_dump(&t, &dynact->tcf_tm);
	if (nla_put_64bit(skb, P4TC_ACT_TM, sizeof(t), &t, P4TC_ACT_PAD))
		goto nla_put_failure;

	nest_parms = nla_nest_start(skb, P4TC_ACT_PARMS);
	if (!nest_parms)
		goto nla_put_failure;

	params = rcu_dereference(dynact->params);
	if (params) {
		idr_for_each_entry(&params->params_idr, parm, id) {
			struct p4tc_act_param_ops *op;
			struct nlattr *nest_count;

			nest_count = nla_nest_start(skb, i);
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
				struct p4tc_type *type;

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

	spin_unlock_bh(&dynact->tcf_lock);

	return skb->len;

nla_put_failure:
	spin_unlock_bh(&dynact->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static void tcf_p4_dyna_cleanup(struct tc_action *a)
{
	struct tc_action_ops *ops = (struct tc_action_ops *)a->ops;
	struct tcf_p4act *m = to_p4act(a);
	struct tcf_p4act_params *params;
	struct p4tc_pipeline *pipeline;

	pipeline = m->p_id ? tcf_pipeline_find_byid(m->p_id) : NULL;
	params = rcu_dereference_protected(m->params, 1);

	if (refcount_read(&ops->dyn_ref) > 1)
		refcount_dec(&ops->dyn_ref);
	if (pipeline)
		WARN_ON(!refcount_dec_not_one(&pipeline->p_ref));

	spin_lock_bh(&m->tcf_lock);
	p4tc_cmds_release_ope_list(&m->cmd_operations);
	if (params)
		call_rcu(&params->rcu, tcf_p4_act_params_destroy_rcu);
	spin_unlock_bh(&m->tcf_lock);
}

static int dev_init_param_value(struct net *net, struct p4tc_act_param_ops *op,
				struct p4tc_act_param *nparam,
				struct nlattr **tb,
				struct netlink_ext_ack *extack)
{
	struct net_device *dev;

	if (tb[P4TC_ACT_PARAMS_VALUE]) {
		const u32 *ifindex = nla_data(tb[P4TC_ACT_PARAMS_VALUE]);

		if (nla_len(tb[P4TC_ACT_PARAMS_VALUE]) != sizeof(u32)) {
			NL_SET_ERR_MSG(extack, "Value length differs from template's");
			return -EINVAL;
		}

		dev = dev_get_by_index(net, *ifindex);
		if (!dev) {
			NL_SET_ERR_MSG(extack, "Invalid ifindex");
			return -EINVAL;
		}
		nparam->value = dev;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param value");
		return -EINVAL;
	}

	return 0;

}

static void dev_free_param_value(struct p4tc_act_param *param)
{
	struct net_device *dev = param->value;

	netdev_put(dev, NULL);
}

static int dev_dump_param_value(struct sk_buff *skb,
				struct p4tc_act_param_ops *op,
				struct p4tc_act_param *param)
{
	const struct net_device *dev = param->value;
	unsigned char *b = skb_tail_pointer(skb);

	if (nla_put_string(skb, P4TC_ACT_PARAMS_VALUE, dev->name)) {
		nlmsg_trim(skb, b);
		return -1;
	}

	return 0;
}

static int generic_init_param_value(struct p4tc_act_param *nparam,
				    struct p4tc_type *type,
				    struct nlattr **tb,
				    struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(type->container_bitsz);
	const u32 len = BITS_TO_BYTES(type->bitsz);
	int err;

	if (tb[P4TC_ACT_PARAMS_VALUE]) {
		void *value = nla_data(tb[P4TC_ACT_PARAMS_VALUE]);

		nparam->value = kzalloc(alloc_len, GFP_KERNEL);
		if (!nparam->value) {
			err = -ENOMEM;
			goto free_value;
		}

		if (nla_len(tb[P4TC_ACT_PARAMS_VALUE]) != len) {
			err = -EINVAL;
			goto free_value;
		}

		if (type->ops->validate_p4t) {
			err = type->ops->validate_p4t(type, value, 0,
						      type->bitsz - 1, extack);
			if (err < 0)
				goto free_value;
		}

		memcpy(nparam->value, value, len);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param value");
		err = -EINVAL;
		goto free_value;
	}

	if (tb[P4TC_ACT_PARAMS_MASK]) {
		const void *mask = nla_data(tb[P4TC_ACT_PARAMS_MASK]);

		nparam->mask = kzalloc(alloc_len, GFP_KERNEL);
		if (!nparam->mask) {
			err = -ENOMEM;
			goto free_value;
		}

		if (nla_len(tb[P4TC_ACT_PARAMS_MASK]) != len) {
			NL_SET_ERR_MSG(extack,
				       "Mask length differs from template's");
			err = -EINVAL;
			goto free_mask;
		}

		memcpy(nparam->mask, mask, len);
	}

	return 0;

free_mask:
	kfree(nparam->mask);

free_value:
	kfree(nparam->value);
	return err;
}

int generic_dump_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     struct p4tc_act_param *param)
{
	const u32 bytesz = BITS_TO_BYTES(type->container_bitsz);
	unsigned char *b = skb_tail_pointer(skb);

	if (nla_put(skb, P4TC_ACT_PARAMS_VALUE, bytesz, param->value)) {
		nlmsg_trim(skb, b);
		return -1;
	}

	if (param->mask &&
	    nla_put(skb, P4TC_ACT_PARAMS_MASK, bytesz, param->mask)) {
		nlmsg_trim(skb, b);
		return -1;
	}

	return 0;
}

static void generic_free_param_value(struct p4tc_act_param *param)
{
	kfree(param->value);
	kfree(param->mask);
}

const struct p4tc_act_param_ops param_ops[P4T_MAX + 1] = {
	[P4T_DEV] = {
		.init_value = dev_init_param_value,
		.dump_value = dev_dump_param_value,
		.free = dev_free_param_value,
	},
};

void tcf_p4_act_params_destroy(struct tcf_p4act_params *params)
{
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(&params->params_idr, param, tmp, param_id) {
		struct p4tc_act_param_ops *op;

		idr_remove(&params->params_idr, param_id);
		op = (struct p4tc_act_param_ops *)&param_ops[param->type];
		if (op->free)
			op->free(param);
		else
			generic_free_param_value(param);
		kfree(param);
	}

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
	[P4TC_ACT_PARAMS_VALUE] = { .type = NLA_BINARY },
	[P4TC_ACT_PARAMS_MASK] = { .type = NLA_BINARY },
	[P4TC_ACT_PARAMS_TYPE] = { .type = NLA_U32 },
};

static struct p4tc_act_param *
param_find_byname(struct idr *params_idr, struct nlattr *name_attr)
{
	const char *param_name = nla_data(name_attr);
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

static struct p4tc_act_param *
param_find(struct idr *params_idr, struct nlattr *name_attr, const u32 param_id,
	   struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param;
	int err;

	if (param_id) {
		param = tcf_param_find_byid(params_idr, param_id);
		if (!param) {
			NL_SET_ERR_MSG(extack, "Unable to find param by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (name_attr) {
			param = param_find_byname(params_idr, name_attr);
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

static int tcf_p4_act_init_param(struct net *net,
				 struct tcf_p4act_params *params,
				 struct p4tc_act *act,
				 struct nlattr *nla,
				 struct netlink_ext_ack *extack)
{
	u32 param_id = 0;
	struct nlattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	struct p4tc_act_param *param, *nparam;
	struct p4tc_act_param_ops *op;
	struct p4tc_type *type;
	int err;

	err = nla_parse_nested(tb, P4TC_ACT_PARAMS_MAX, nla,
			       p4tc_act_params_policy, extack);
	if (err < 0)
		return err;

	if (tb[P4TC_ACT_PARAMS_ID])
		param_id = *((u32 *)nla_data(tb[P4TC_ACT_PARAMS_ID]));

	param = param_find(&act->params_idr, tb[P4TC_ACT_PARAMS_NAME], param_id,
			   extack);
	if (IS_ERR(param))
		return PTR_ERR(param);

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		u32 *type = nla_data(tb[P4TC_ACT_PARAMS_TYPE]);

		if (param->type != *type) {
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

	type = p4type_find_byid(param->type);
	if (!type) {
		NL_SET_ERR_MSG(extack, "Invalid param type");
		err = -EINVAL;
		goto free;
	}

	op = (struct p4tc_act_param_ops *)&param_ops[param->type];
	if (op->init_value)
		err = op->init_value(net, op, nparam, tb, extack);
	else
		err = generic_init_param_value(nparam, type, tb, extack);

	if (err < 0)
		goto free;

	nparam->id = param->id;

	err = idr_alloc_u32(&params->params_idr, nparam, &nparam->id,
			    nparam->id, GFP_KERNEL);
	if (err < 0)
		goto free_val;

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

int tcf_p4_act_init_params(struct net *net,
			   struct tcf_p4act_params *params,
			   struct p4tc_act *act,
			   struct nlattr *nla,
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

struct p4tc_act *
tcf_action_find_byname(const char *act_name, struct p4tc_pipeline *pipeline)
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

struct p4tc_act *tcf_action_find_byany(struct nlattr *act_name_attr,
			     const u32 a_id,
			     struct p4tc_pipeline *pipeline,
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
		if (act_name_attr) {
			const char *act_name = nla_data(act_name_attr);

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

static void p4_put_param(struct idr *params_idr,
			 struct p4tc_act_param *param)
{
	kfree(param);
}

void p4_put_many_params(struct idr *params_idr,
			struct p4tc_act_param *params[],
			int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4_put_param(params_idr, params[i]);
}

static struct p4tc_act_param *
p4_create_param(struct p4tc_act *act, struct nlattr **tb,
		u32 param_id, struct netlink_ext_ack *extack)
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
	    param_find_byname(&act->params_idr, tb[P4TC_ACT_PARAMS_NAME])) {
		NL_SET_ERR_MSG(extack, "Param already exists");
		ret = -EEXIST;
		goto free;
	}

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		struct p4tc_type *type;

		param->type = *((u32 *)nla_data(tb[P4TC_ACT_PARAMS_TYPE]));
		type = p4type_find_byid(param->type);
		if (!type) {
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
		ret = idr_alloc_u32(&act->params_idr,
				    param, &param_id,
				    param_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free;
		}
		param->id = param_id;
	} else {
		param->id = 1;

		ret = idr_alloc_u32(&act->params_idr,
				    param, &param->id,
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

static struct p4tc_act_param *
p4_update_param(struct p4tc_act *act, struct nlattr **tb,
		const u32 param_id, struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param_old, *param;
	int ret;

	param_old = param_find(&act->params_idr, tb[P4TC_ACT_PARAMS_NAME],
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
		struct p4tc_type *type;

		param->type = *((u32 *)nla_data(tb[P4TC_ACT_PARAMS_TYPE]));
		type = p4type_find_byid(param->type);
		if (!type) {
			NL_SET_ERR_MSG(extack, "Param type is invalid");
			ret = -EINVAL;
			goto out;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto out;
	}

	return param;

out:
	return ERR_PTR(ret);
}

static struct p4tc_act_param *
p4_act_init_param(struct p4tc_act *act, struct nlattr *nla,
		  bool update, struct netlink_ext_ack *extack)
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
		param_id = *((u32 *)nla_data(tb[P4TC_ACT_PARAMS_ID]));

	if (update)
		return p4_update_param(act, tb, param_id, extack);
	else
		return p4_create_param(act, tb, param_id, extack);

out:
	return ERR_PTR(ret);
}

int p4_act_init_params(struct p4tc_act *act,
		       struct nlattr *nla,
		       struct p4tc_act_param *params[],
		       bool update,
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
		struct p4tc_act_param *params[],
		struct netlink_ext_ack *extack)
{
	int num_params = 0;
	int ret;

	idr_init(&act->params_idr);

	if (nla) {
		num_params = p4_act_init_params(act, nla, params, false,
						extack);
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

static int __tcf_act_put(struct net *net, struct p4tc_pipeline *pipeline,
			struct p4tc_act *act, struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *act_param;
	unsigned long param_id, tmp;
	int ret;

	if (refcount_read(&act->ops.dyn_ref) > 1) {
		NL_SET_ERR_MSG(extack,
			       "Unable to delete referenced action template");
		return -EBUSY;
	}

	idr_for_each_entry_ul(&act->params_idr, act_param, tmp, param_id) {
		idr_remove(&act->params_idr, param_id);
		kfree(act_param);
	}

	p4tc_cmds_release_ope_list(&act->cmd_operations);

	rtnl_unlock();
	ret = tcf_unregister_action(&act->ops, act->p4_net_ops);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to unregister new action template");
		rtnl_lock();
		return ret;
	}
	rtnl_lock();

	idr_remove(&pipeline->p_act_idr, act->a_id);

	list_del(&act->head);
	kfree(act->p4_net_ops);
	kfree(act);

	return 0;
}

static int _tcf_act_fill_nlmsg(struct net *net, struct sk_buff *skb,
			       struct p4tc_act *act)
{
	unsigned char *b = skb_tail_pointer(skb);
	int i = 1;
	struct nlattr *nest, *parms, *cmds;
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;

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

		if (nla_put_u32(skb, P4TC_ACT_PARAMS_TYPE, param->type))
			goto out_nlmsg_trim;

		nla_nest_end(skb, nest_count);
		i++;
	}
	nla_nest_end(skb, parms);

	cmds = nla_nest_start(skb, P4TC_ACT_CMDS_LIST);
	if (p4tc_cmds_fillup(skb, &act->cmd_operations))
		goto out_nlmsg_trim;
	nla_nest_end(skb, cmds);

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
	unsigned char *b = skb_tail_pointer(skb);
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
		if (__tcf_act_put(net, pipeline, act, extack) < 0) {
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
		      struct nlattr *nla, char **p_name, u32 *ids,
		      struct netlink_ext_ack *extack)
{
	const u32 pipeid = ids[P4TC_PID_IDX], a_id = ids[P4TC_AID_IDX];
	struct nlattr *tb[P4TC_ACT_MAX + 1] = {NULL};
	unsigned char *b = skb_tail_pointer(skb);
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline = tcf_pipeline_find_byany_unsealed(*p_name, pipeid, extack);
	else
		pipeline = tcf_pipeline_find_byany(*p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_ACT_MAX, nla, p4tc_act_policy,
				       extack);
		if (ret < 0)
			return ret;
	}

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_act_flush(skb, net, pipeline, extack);

	act = tcf_action_find_byany(tb[P4TC_ACT_NAME], a_id, pipeline, extack);
	if (IS_ERR(act))
		return PTR_ERR(act);

	if (_tcf_act_fill_nlmsg(net, skb, act) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for template action");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = __tcf_act_put(net, pipeline, act, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_act_put(struct net *net, struct p4tc_template_common *tmpl,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_act *act = to_act(tmpl);
	struct p4tc_pipeline *pipeline;

	pipeline = tcf_pipeline_find_byid(tmpl->p_id);

	return __tcf_act_put(net, pipeline, act, extack);
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

int p4tc_init_net_ops(struct net *net, unsigned int id)
{
	struct tc_action_net *tn = net_generic(net, id);
	struct p4tc_act *act;

	list_for_each_entry(act, &dynact_list, head) {
		if (act->ops.net_id == id)
			break;
	}

	return tc_action_net_init(net, tn, &act->ops);
}

void p4tc_exit_net_ops(struct list_head *net_list, unsigned int id)
{
	tc_action_net_exit(net_list, id);
}

static struct p4tc_act *
tcf_act_create(struct net *net, struct nlattr **tb,
	       struct p4tc_pipeline *pipeline, u32 *ids,
	       struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *params[P4TC_MSGBATCH_SIZE] = {NULL};
	u32 a_id = ids[P4TC_AID_IDX];
	int num_params = 0;
	int ret = 0;
	struct pernet_operations *p4_net_ops;
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
	act->ops.size = sizeof(struct tcf_p4act);
	INIT_LIST_HEAD(&act->head);

	p4_net_ops = kzalloc(sizeof(*p4_net_ops), GFP_KERNEL);
	if (!p4_net_ops) {
		ret = -ENOMEM;
		goto free_act_ops;
	}
	p4_net_ops->init_id = p4tc_init_net_ops;
	p4_net_ops->exit_batch_id = p4tc_exit_net_ops;
	p4_net_ops->size = sizeof(struct tc_action_net);
	p4_net_ops->id = &act->ops.net_id;

	snprintf(act->ops.kind, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);

	if (a_id) {
		ret = idr_alloc_u32(&pipeline->p_act_idr, act, &a_id,
				    a_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to alloc action id");
			goto free_net_ops;
		}

		act->a_id = a_id;
	} else {
		act->a_id = 1;

		ret = idr_alloc_u32(&pipeline->p_act_idr, act, &act->a_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to alloc action id");
			goto free_net_ops;
		}
	}

	refcount_set(&act->ops.dyn_ref, 1);
	rtnl_unlock();
	/* Increment module counter */
	/* Maybe we need to grab a lock before doing rtnl_unlock() */
	ret = tcf_register_action(&act->ops, p4_net_ops);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to register new action template");
		rtnl_lock();
		goto idr_rm;
	}
	rtnl_lock();

	act->p4_net_ops = p4_net_ops;
	num_params = p4_act_init(act, tb[P4TC_ACT_PARMS], params, extack);
	if (num_params < 0) {
		ret = num_params;
		goto unregister;
	}

	INIT_LIST_HEAD(&act->cmd_operations);
	if (tb[P4TC_ACT_CMDS_LIST]) {
		ret = p4tc_cmds_parse(net, &act->cmd_operations,
				      tb[P4TC_ACT_CMDS_LIST], false, extack);
		if (ret < 0)
			goto uninit;
	}

	act->common.p_id = pipeline->common.p_id;
	snprintf(act->common.name, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);
	act->common.ops = (struct p4tc_template_ops *)&p4tc_act_ops;

	list_add_tail(&act->head, &dynact_list);

	return act;

uninit:
	p4_put_many_params(&act->params_idr, params, num_params);
	idr_destroy(&act->params_idr);

unregister:
	rtnl_unlock();
	tcf_unregister_action(&act->ops, p4_net_ops);
	rtnl_lock();

idr_rm:
	idr_remove(&pipeline->p_act_idr, act->a_id);

free_net_ops:
	kfree(p4_net_ops);

free_act_ops:
	kfree(act);

	return ERR_PTR(ret);
}

static struct p4tc_act *
tcf_act_update(struct net *net, struct nlattr **tb,
	       struct p4tc_pipeline *pipeline, u32 *ids,
	       u32 flags, struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *params[P4TC_MSGBATCH_SIZE] = {NULL};
	const u32 a_id = ids[P4TC_AID_IDX];
	int num_params = 0;
	s8 active = -1;
	int ret = 0;
	struct p4tc_act *act;

	if (ret < 0)
		goto out;

	act = tcf_action_find_byany(tb[P4TC_ACT_NAME], a_id, pipeline, extack);
	if (IS_ERR(act))
		return act;

	if (tb[P4TC_ACT_ACTIVE])
		active = *((u8 *)nla_data(tb[P4TC_ACT_ACTIVE]));

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
		NL_SET_ERR_MSG(extack,
			       "Unable to update active action");
		return ERR_PTR(-EINVAL);
	}

	if (tb[P4TC_ACT_PARMS]) {
		num_params = p4_act_init_params(act, tb[P4TC_ACT_PARMS], params,
						true, extack);
		if (num_params < 0) {
			ret = num_params;
			goto out;
		}
	}

	if (tb[P4TC_ACT_CMDS_LIST]) {
		ret = p4tc_cmds_parse(net, &act->cmd_operations,
				      tb[P4TC_ACT_CMDS_LIST], true, extack);
		if (ret < 0)
			goto params_del;
	}

	if (active == 1) {
		act->active = true;
	} else if (!active) {
		NL_SET_ERR_MSG(extack, "Action is already inactive");
		ret = -EINVAL;
		goto params_del;
	}

	p4tc_params_replace_many(&act->params_idr, params, num_params);
	return act;

params_del:
	p4_put_many_params(&act->params_idr, params, num_params);

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_act_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	   char **p_name, u32 *ids, struct netlink_ext_ack *extack)
{
	const u32 pipeid = ids[P4TC_PID_IDX];
	struct nlattr *tb[P4TC_ACT_MAX + 1];
	struct p4tc_act *act;
	struct p4tc_pipeline *pipeline;
	int ret;

	pipeline = tcf_pipeline_find_byany_unsealed(*p_name, pipeid, extack);
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

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)act;
}

static int tcf_act_dump(struct sk_buff *skb,
			struct p4tc_dump_ctx *ctx,
			struct nlattr *nla,
			char **p_name, u32 *ids,
			struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = tcf_pipeline_find_byany(*p_name, ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(ctx->ids[P4TC_PID_IDX]);
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
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_act *act = to_act(common);
	struct nlattr *nest;

	if (!param)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_ACT_NAME, act->common.name))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_ACT_CMDS_LIST);
	if (p4tc_cmds_fillup(skb, &act->cmd_operations))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nest);

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
