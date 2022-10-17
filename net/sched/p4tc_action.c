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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/flow_offload.h>
#include <net/tc_act/p4tc.h>
#include <linux/netdevice.h>
#include <net/tc_act/tc_metact.h>

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
				    struct p4_type *type,
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
		pr_err("Must specify param value\n");
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
			pr_err("Mask length differs from template's\n");
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

int generic_dump_param_value(struct sk_buff *skb, struct p4_type *type,
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

static int tcf_p4_walker(struct net *net, struct sk_buff *skb,
			 struct netlink_callback *cb, int type,
			 const struct tc_action_ops *ops,
			 struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, ops->net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_p4_search(struct net *net, struct tc_action **a,
			 const struct tc_action_ops *ops, u32 index)
{
	struct tc_action_net *tn = net_generic(net, ops->net_id);

	return tcf_idr_search(tn, a, index);
}

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
			if (extack)
				NL_SET_ERR_MSG(extack, "Unable to find param by id");
			else
				pr_err("Unable to find param by id\n");

			err = -EINVAL;
			goto out;
		}
	} else {
		if (name_attr) {
			param = param_find_byname(params_idr, name_attr);
			if (!param) {
				if (extack)
					NL_SET_ERR_MSG(extack,
						       "Param name not found");
				else
					pr_err("Param name not found\n");

				err = -EINVAL;
				goto out;
			}
		} else {
			if (extack)
				NL_SET_ERR_MSG(extack,
					       "Must specify param name or id");
			else
				pr_err("Must specify param name or id\n");

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
	struct p4_type *type;
	int err;

	err = nla_parse_nested_deprecated(tb, P4TC_ACT_PARAMS_MAX, nla,
					  p4tc_act_params_policy, NULL);
	if (err < 0)
		return err;

	if (tb[P4TC_ACT_PARAMS_ID])
		param_id = *((u32 *)nla_data(tb[P4TC_ACT_PARAMS_ID]));

	param = param_find(&act->params_idr, tb[P4TC_ACT_PARAMS_NAME], param_id,
			   NULL);
	if (IS_ERR(param))
		return PTR_ERR(param);

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		u32 *type = nla_data(tb[P4TC_ACT_PARAMS_TYPE]);

		if (param->type != *type) {
			pr_err("Param type differs from template\n");
			return -EINVAL;
		}
	} else {
		pr_err("Must specify param type\n");
		return -EINVAL;
	}

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam)
		return -ENOMEM;

	strscpy(nparam->name, param->name, ACTPARAMNAMSIZ);
	nparam->type = param->type;

	type = p4type_find_byid(param->type);
	if (!type) {
		pr_err("Invalid param type %u\n", param->type);
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

	err = nla_parse_nested_deprecated(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
					  NULL);
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
		struct p4_type *type;

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
		struct p4_type *type;

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

	ret = nla_parse_nested_deprecated(tb, P4TC_ACT_PARAMS_MAX, nla,
					  NULL, extack);
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

	ret = nla_parse_nested_deprecated(tb, P4TC_MSGBATCH_SIZE, nla,
					  NULL, extack);
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
	[P4TC_ACT_NAME] = { .type = P4T_STRING, .len = ACTNAMSIZ },
	[P4TC_ACT_PARMS] = { .type = P4T_NESTED },
	[P4TC_ACT_OPT] = { .len = sizeof(struct tc_act_dyna) },
	[P4TC_ACT_METACT_LIST] = { .type = P4T_NESTED },
};

static int _tcf_act_put(struct net *net, struct p4tc_pipeline *pipeline,
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
	release_ope_list(&act->meta_operations);

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

		nest_count = nla_nest_start_noflag(skb, i);
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

	cmds = nla_nest_start_noflag(skb, P4TC_ACT_METACT_LIST);
	if (fillup_metact_cmds(skb, &act->meta_operations))
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
		if (_tcf_act_put(net, pipeline, act, extack) < 0) {
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
		ret = nla_parse_nested_deprecated(tb, P4TC_ACT_MAX, nla,
						  p4tc_act_policy, extack);
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
		ret = _tcf_act_put(net, pipeline, act, extack);
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

	pipeline = idr_find(&pipeline_idr, tmpl->p_id);

	return _tcf_act_put(net, pipeline, act, extack);
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
	unsigned long tmp, pipeid, actid;
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act = NULL;

	idr_for_each_entry_ul(&pipeline_idr, pipeline, tmp, pipeid) {
		idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, actid)
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
	act->ops.act = tcf_metact_act;
	act->ops.dump = tcf_metact_dump;
	act->ops.cleanup = tcf_metact_cleanup;
	act->ops.init_ops = tcf_p4_metact_init;
	act->ops.walk = tcf_p4_walker;
	act->ops.lookup_ops = tcf_p4_search;
	act->ops.size = sizeof(struct tcf_metact_info);

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

	INIT_LIST_HEAD(&act->meta_operations);
	if (tb[P4TC_ACT_METACT_LIST]) {
		ret = tcf_metact_parse_cmds(net, &act->meta_operations,
						 tb[P4TC_ACT_METACT_LIST],
						 false, extack);
		if (ret < 0)
			goto uninit;
	}

	act->common.p_id = pipeline->common.p_id;
	snprintf(act->common.name, ACTNAMSIZ, "%s/%s", pipeline->common.name,
		 act_name);
	act->common.ops = (struct p4tc_template_ops *)&p4tc_act_ops;
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

	if (tb[P4TC_ACT_METACT_LIST]) {
		ret = tcf_metact_parse_cmds(net, &act->meta_operations,
					    tb[P4TC_ACT_METACT_LIST],
					    true, extack);
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

	ret = nla_parse_nested_deprecated(tb, P4TC_ACT_MAX, nla, p4tc_act_policy,
					  extack);
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
		pipeline = idr_find(&pipeline_idr, ctx->ids[P4TC_PID_IDX]);
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
	nest = nla_nest_start_noflag(skb, TCA_METACT_LIST);
	if (fillup_metact_cmds(skb, &act->meta_operations))
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
	.cu = tcf_act_cu,
	.put = tcf_act_put,
	.gd = tcf_act_gd,
	.fill_nlmsg = tcf_act_fill_nlmsg,
	.dump = tcf_act_dump,
	.dump_1 = tcf_act_dump_1,
};
