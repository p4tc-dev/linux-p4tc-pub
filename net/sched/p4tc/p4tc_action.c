// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_action.c	P4 TC ACTION
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
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

static void p4a_parm_put(struct p4tc_act_param *param)
{
	kfree(param);
}

static const struct nla_policy p4a_parm_policy[P4TC_ACT_PARAMS_MAX + 1] = {
	[P4TC_ACT_PARAMS_NAME] = {
		.type = NLA_STRING,
		.len = P4TC_ACT_PARAM_NAMSIZ
	},
	[P4TC_ACT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_ACT_PARAMS_TYPE] = { .type = NLA_NESTED },
	[P4TC_ACT_PARAMS_FLAGS] =
		NLA_POLICY_RANGE(NLA_U8, 0,
				 BIT(P4TC_ACT_PARAMS_FLAGS_MAX + 1) - 1),
};

static struct p4tc_act_param *
p4a_parm_find_byname(struct idr *params_idr, const char *param_name)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		if (param == ERR_PTR(-EBUSY))
			continue;
		if (strncmp(param->name, param_name,
			    P4TC_ACT_PARAM_NAMSIZ) == 0)
			return param;
	}

	return NULL;
}

static struct p4tc_act_param *
p4a_parm_find_byid(struct idr *params_idr, const u32 param_id)
{
	return idr_find(params_idr, param_id);
}

static struct p4tc_act_param *
p4a_parm_find_byany(struct p4tc_act *act, const char *param_name,
		    const u32 param_id, struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param;
	int err;

	if (param_id) {
		param = p4a_parm_find_byid(&act->params_idr, param_id);
		if (!param) {
			NL_SET_ERR_MSG(extack, "Unable to find param by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (param_name) {
			param = p4a_parm_find_byname(&act->params_idr,
						     param_name);
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
p4a_parm_find_byanyattr(struct p4tc_act *act, struct nlattr *name_attr,
			const u32 param_id,
			struct netlink_ext_ack *extack)
{
	char *param_name = NULL;

	if (name_attr)
		param_name = nla_data(name_attr);

	return p4a_parm_find_byany(act, param_name, param_id, extack);
}

static const struct nla_policy
p4a_parm_type_policy[P4TC_ACT_PARAMS_TYPE_MAX + 1] = {
	[P4TC_ACT_PARAMS_TYPE_BITEND] = { .type = NLA_U16 },
	[P4TC_ACT_PARAMS_TYPE_CONTAINER_ID] = { .type = NLA_U32 },
};

static int
__p4a_parm_init_type(struct p4tc_act_param *param, struct nlattr *nla,
		     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ACT_PARAMS_TYPE_MAX + 1];
	struct p4tc_type *type;
	u32 container_id;
	u16 bitend;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ACT_PARAMS_TYPE_MAX, nla,
			       p4a_parm_type_policy, extack);
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

static struct p4tc_act *
p4a_tmpl_find_byname(const char *fullname, struct p4tc_pipeline *pipeline,
		     struct netlink_ext_ack *extack)
{
	unsigned long tmp, id;
	struct p4tc_act *act;

	idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, id)
		if (strncmp(act->fullname, fullname, ACTNAMSIZ) == 0)
			return act;

	return NULL;
}

static int p4a_parm_type_fill(struct sk_buff *skb, struct p4tc_act_param *param)
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

struct p4tc_act *p4a_tmpl_find_byid(struct p4tc_pipeline *pipeline,
				    const u32 a_id)
{
	return idr_find(&pipeline->p_act_idr, a_id);
}

static struct p4tc_act *
p4a_tmpl_find_byany(struct p4tc_pipeline *pipeline,
		    const char *act_name, const u32 a_id,
		    struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;
	int err;

	if (a_id) {
		act = p4a_tmpl_find_byid(pipeline, a_id);
		if (!act) {
			NL_SET_ERR_MSG(extack, "Unable to find action by id");
			err = -ENOENT;
			goto out;
		}
	} else {
		if (act_name) {
			act = p4a_tmpl_find_byname(act_name, pipeline,
						   extack);
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

struct p4tc_act *p4a_tmpl_get(struct p4tc_pipeline *pipeline,
			      const char *act_name, const u32 a_id,
			      struct netlink_ext_ack *extack)
{
	struct p4tc_act *act;

	act = p4a_tmpl_find_byany(pipeline, act_name, a_id, extack);
	if (IS_ERR(act))
		return act;

	if (!refcount_inc_not_zero(&act->a_ref)) {
		NL_SET_ERR_MSG(extack, "Action is stale");
		return ERR_PTR(-EBUSY);
	}

	return act;
}

static struct p4tc_act *
p4a_tmpl_find_byanyattr(struct nlattr *attr, const u32 a_id,
			struct p4tc_pipeline *pipeline,
			struct netlink_ext_ack *extack)
{
	char fullname[ACTNAMSIZ] = {};
	char *actname = NULL;

	if (attr) {
		actname = nla_data(attr);

		snprintf(fullname, ACTNAMSIZ, "%s/%s", pipeline->common.name,
			 actname);
	}

	return p4a_tmpl_find_byany(pipeline, fullname, a_id, extack);
}

static void p4a_tmpl_parms_put_many(struct idr *params_idr)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id)
		p4a_parm_put(param);
}

static int
p4a_parm_init_type(struct p4tc_act_param *param, struct nlattr *nla,
		   struct netlink_ext_ack *extack)
{
	struct p4tc_type *type;
	int ret;

	ret = __p4a_parm_init_type(param, nla, extack);
	if (ret < 0)
		return ret;

	type = param->type;
	ret = type->ops->validate_p4t(type, NULL, 0, param->bitend, extack);
	if (ret < 0)
		return ret;

	return 0;
}

static struct p4tc_act_param *
p4a_tmpl_parm_create(struct p4tc_act *act, struct idr *params_idr,
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

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	if (p4a_parm_find_byid(&act->params_idr, param_id) ||
	    p4a_parm_find_byname(&act->params_idr, name)) {
		NL_SET_ERR_MSG(extack, "Param already exists");
		ret = -EEXIST;
		goto free;
	}

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		ret = p4a_parm_init_type(param, tb[P4TC_ACT_PARAMS_TYPE],
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

	if (tb[P4TC_ACT_PARAMS_FLAGS])
		param->flags = nla_get_u8(tb[P4TC_ACT_PARAMS_FLAGS]);

	strscpy(param->name, name, P4TC_ACT_PARAM_NAMSIZ);

	return param;

free:
	kfree(param);

out:
	return ERR_PTR(ret);
}

static struct p4tc_act_param *
p4a_tmpl_parm_update(struct p4tc_act *act, struct nlattr **tb,
		     struct idr *params_idr, u32 param_id,
		     struct netlink_ext_ack *extack)
{
	struct p4tc_act_param *param_old, *param;
	u8 flags;
	int ret;

	param_old = p4a_parm_find_byanyattr(act, tb[P4TC_ACT_PARAMS_NAME],
					    param_id, extack);
	if (IS_ERR(param_old))
		return param_old;

	flags = param_old->flags;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	strscpy(param->name, param_old->name, P4TC_ACT_PARAM_NAMSIZ);
	param->id = param_old->id;

	if (tb[P4TC_ACT_PARAMS_TYPE]) {
		ret = p4a_parm_init_type(param, tb[P4TC_ACT_PARAMS_TYPE],
					 extack);
		if (ret < 0)
			goto free;
	} else {
		param->type = param_old->type;
		param->bitend = param_old->bitend;
	}

	ret = idr_alloc_u32(params_idr, param, &param->id,
			    param->id, GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate param id");
		goto free;
	}

	if (tb[P4TC_ACT_PARAMS_FLAGS])
		flags = nla_get_u8(tb[P4TC_ACT_PARAMS_FLAGS]);

	param->flags = flags;

	return param;

free:
	kfree(param);
out:
	return ERR_PTR(ret);
}

static struct p4tc_act_param *
p4a_tmpl_parm_init(struct p4tc_act *act, struct nlattr *nla,
		   struct idr *params_idr, bool update,
		   struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ACT_PARAMS_MAX + 1];
	u32 param_id = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ACT_PARAMS_MAX, nla, p4a_parm_policy,
			       extack);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (tb[P4TC_ACT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_ACT_PARAMS_ID]);

	if (update)
		return p4a_tmpl_parm_update(act, tb, params_idr, param_id,
					    extack);
	else
		return p4a_tmpl_parm_create(act, params_idr, tb, param_id,
					    extack);

out:
	return ERR_PTR(ret);
}

static int p4a_tmpl_parms_init(struct p4tc_act *act, struct nlattr *nla,
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

		param = p4a_tmpl_parm_init(act, tb[i], params_idr, update,
					   extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_del;
		}
	}

	return i - 1;

params_del:
	p4a_tmpl_parms_put_many(params_idr);
	return ret;
}

static int p4a_tmpl_init(struct p4tc_act *act, struct nlattr *nla,
			 struct netlink_ext_ack *extack)
{
	int num_params = 0;
	int ret;

	idr_init(&act->params_idr);

	if (nla) {
		num_params =
			p4a_tmpl_parms_init(act, nla, &act->params_idr, false,
					    extack);
		if (num_params < 0) {
			ret = num_params;
			goto idr_destroy;
		}
	}

	return num_params;

idr_destroy:
	p4a_tmpl_parms_put_many(&act->params_idr);
	idr_destroy(&act->params_idr);
	return ret;
}

static struct netlink_range_validation prealloc_range = {
	.min = 1,
	.max = P4TC_MAX_TENTRIES,
};

static const struct nla_policy p4a_tmpl_policy[P4TC_ACT_MAX + 1] = {
	[P4TC_ACT_NAME] = { .type = NLA_STRING, .len = P4TC_ACT_TMPL_NAMSZ },
	[P4TC_ACT_PARMS] = { .type = NLA_NESTED },
	[P4TC_ACT_OPT] = NLA_POLICY_EXACT_LEN(sizeof(struct tc_act_p4)),
	[P4TC_ACT_NUM_PREALLOC] =
		NLA_POLICY_FULL_RANGE(NLA_U32, &prealloc_range),
	[P4TC_ACT_ACTIVE] = { .type = NLA_U8 },
};

static void p4a_tmpl_parms_put(struct p4tc_act *act)
{
	struct p4tc_act_param *act_param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(&act->params_idr, act_param, tmp, param_id) {
		idr_remove(&act->params_idr, param_id);
		kfree(act_param);
	}
}

static int __p4a_tmpl_put(struct net *net, struct p4tc_pipeline *pipeline,
			  struct p4tc_act *act, bool teardown,
			  struct netlink_ext_ack *extack)
{
	struct tcf_p4act *p4act, *tmp_act;

	if (!teardown && refcount_read(&act->a_ref) > 1) {
		NL_SET_ERR_MSG(extack,
			       "Unable to delete referenced action template");
		return -EBUSY;
	}

	p4a_tmpl_parms_put(act);

	tcf_unregister_p4_action(net, &act->ops);
	/* Free preallocated acts */
	list_for_each_entry_safe(p4act, tmp_act, &act->prealloc_list, node) {
		list_del_init(&p4act->node);
		if (p4act->common.tcfa_flags & TCA_ACT_FLAGS_UNREFERENCED)
			tcf_idr_release(&p4act->common, true);
	}

	idr_remove(&pipeline->p_act_idr, act->a_id);

	list_del(&act->head);

	kfree(act);

	pipeline->num_created_acts--;

	return 0;
}

static int _p4a_tmpl_fill_nlmsg(struct net *net, struct sk_buff *skb,
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

	if (nla_put_string(skb, P4TC_ACT_NAME, act->fullname))
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

		p4a_parm_type_fill(skb, param);
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

static int p4a_tmpl_fill_nlmsg(struct net *net, struct sk_buff *skb,
			       struct p4tc_template_common *tmpl,
			       struct netlink_ext_ack *extack)
{
	return _p4a_tmpl_fill_nlmsg(net, skb, p4tc_to_act(tmpl));
}

static int p4a_tmpl_flush(struct sk_buff *skb, struct net *net,
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
		if (__p4a_tmpl_put(net, pipeline, act, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	if (nla_put_u32(skb, P4TC_COUNT, i))
		goto out_nlmsg_trim;

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

static int p4a_tmpl_gd(struct net *net, struct sk_buff *skb,
		       struct nlmsghdr *n, struct nlattr *nla,
		       struct p4tc_path_nlattrs *nl_path_attrs,
		       struct netlink_ext_ack *extack)
{
	u32 *ids = nl_path_attrs->ids;
	const u32 pipeid = ids[P4TC_PID_IDX], a_id = ids[P4TC_AID_IDX];
	struct nlattr *tb[P4TC_ACT_MAX + 1] = { NULL };
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;
	int ret = 0;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline =
			p4tc_pipeline_find_byany_unsealed(net,
							  nl_path_attrs->pname,
							  pipeid, extack);
	else
		pipeline = p4tc_pipeline_find_byany(net,
						    nl_path_attrs->pname,
						    pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_ACT_MAX, nla,
				       p4a_tmpl_policy, extack);
		if (ret < 0)
			return ret;
	}

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return p4a_tmpl_flush(skb, net, pipeline, extack);

	act = p4a_tmpl_find_byanyattr(tb[P4TC_ACT_NAME], a_id, pipeline,
				      extack);
	if (IS_ERR(act))
		return PTR_ERR(act);

	if (_p4a_tmpl_fill_nlmsg(net, skb, act) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for template action");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = __p4a_tmpl_put(net, pipeline, act, false, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4a_tmpl_put(struct p4tc_pipeline *pipeline,
			struct p4tc_template_common *tmpl,
			struct netlink_ext_ack *extack)
{
	struct p4tc_act *act = p4tc_to_act(tmpl);

	return __p4a_tmpl_put(pipeline->net, pipeline, act, true, extack);
}

static void p4a_tmpl_parm_idx_set(struct idr *params_idr)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;
	int i = 0;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		param->index = i;
		i++;
	}
}

static void p4a_tmpl_parms_replace_many(struct p4tc_act *act,
					struct idr *params_idr)
{
	struct p4tc_act_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		idr_remove(params_idr, param->id);
		param = idr_replace(&act->params_idr, param, param->id);
		p4a_parm_put(param);
	}
}

static const struct p4tc_template_ops p4tc_act_ops;

static struct p4tc_act *
p4a_tmpl_create(struct net *net, struct nlattr **tb,
		struct p4tc_pipeline *pipeline, u32 *ids,
		struct netlink_ext_ack *extack)
{
	u32 a_id = ids[P4TC_AID_IDX];
	char fullname[ACTNAMSIZ];
	struct p4tc_act *act;
	int num_params = 0;
	size_t nbytes;
	char *actname;
	int ret = 0;

	if (!tb[P4TC_ACT_NAME]) {
		NL_SET_ERR_MSG(extack, "Must supply action name");
		return ERR_PTR(-EINVAL);
	}

	actname = nla_data(tb[P4TC_ACT_NAME]);

	nbytes = snprintf(fullname, ACTNAMSIZ, "%s/%s", pipeline->common.name,
			  actname);
	if (nbytes == ACTNAMSIZ) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Full action name should fit in %u bytes",
				   ACTNAMSIZ);
		return ERR_PTR(-E2BIG);
	}

	if (p4a_tmpl_find_byname(fullname, pipeline, extack)) {
		NL_SET_ERR_MSG(extack, "Action already exists with same name");
		return ERR_PTR(-EEXIST);
	}

	if (p4a_tmpl_find_byid(pipeline, a_id)) {
		NL_SET_ERR_MSG(extack, "Action already exists with same id");
		return ERR_PTR(-EEXIST);
	}

	act = kzalloc(sizeof(*act), GFP_KERNEL);
	if (!act)
		return ERR_PTR(-ENOMEM);

	if (a_id) {
		ret = idr_alloc_u32(&pipeline->p_act_idr, act, &a_id, a_id,
				    GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to alloc action id");
			goto free_act;
		}

		act->a_id = a_id;
	} else {
		act->a_id = 1;

		ret = idr_alloc_u32(&pipeline->p_act_idr, act, &act->a_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to alloc action id");
			goto free_act;
		}
	}

	/* We are only preallocating the instances once the action template is
	 * activated during update.
	 */
	if (tb[P4TC_ACT_NUM_PREALLOC])
		act->num_prealloc_acts = nla_get_u32(tb[P4TC_ACT_NUM_PREALLOC]);
	else
		act->num_prealloc_acts = P4TC_DEFAULT_NUM_PREALLOC;

	num_params = p4a_tmpl_init(act, tb[P4TC_ACT_PARMS], extack);
	if (num_params < 0) {
		ret = num_params;
		goto idr_rm;
	}
	act->num_params = num_params;

	p4a_tmpl_parm_idx_set(&act->params_idr);

	act->pipeline = pipeline;

	pipeline->num_created_acts++;

	act->common.p_id = pipeline->common.p_id;

	strscpy(act->fullname, fullname, ACTNAMSIZ);
	strscpy(act->common.name, actname, P4TC_ACT_TMPL_NAMSZ);

	act->common.ops = (struct p4tc_template_ops *)&p4tc_act_ops;

	refcount_set(&act->a_ref, 1);

	INIT_LIST_HEAD(&act->prealloc_list);
	spin_lock_init(&act->list_lock);

	return act;

idr_rm:
	idr_remove(&pipeline->p_act_idr, act->a_id);

free_act:
	kfree(act);

	return ERR_PTR(ret);
}

static struct p4tc_act *
p4a_tmpl_update(struct net *net, struct nlattr **tb,
		struct p4tc_pipeline *pipeline, u32 *ids,
		u32 flags, struct netlink_ext_ack *extack)
{
	const u32 a_id = ids[P4TC_AID_IDX];
	bool updates_params = false;
	struct idr params_idr;
	u32 num_prealloc_acts;
	struct p4tc_act *act;
	int num_params = 0;
	s8 active = -1;
	int ret = 0;

	act = p4a_tmpl_find_byanyattr(tb[P4TC_ACT_NAME], a_id, pipeline,
				      extack);
	if (IS_ERR(act))
		return act;

	if (tb[P4TC_ACT_ACTIVE])
		active = nla_get_u8(tb[P4TC_ACT_ACTIVE]);

	if (act->active) {
		if (!active) {
			act->active = false;
			return act;
		}
		NL_SET_ERR_MSG(extack, "Unable to update active action");

		ret = -EINVAL;
		goto out;
	}

	idr_init(&params_idr);
	if (tb[P4TC_ACT_PARMS]) {
		num_params = p4a_tmpl_parms_init(act, tb[P4TC_ACT_PARMS],
						 &params_idr, true, extack);
		if (num_params < 0) {
			ret = num_params;
			goto idr_destroy;
		}
		p4a_tmpl_parm_idx_set(&params_idr);
		updates_params = true;
	}

	if (tb[P4TC_ACT_NUM_PREALLOC])
		num_prealloc_acts = nla_get_u32(tb[P4TC_ACT_NUM_PREALLOC]);
	else
		num_prealloc_acts = act->num_prealloc_acts;

	act->pipeline = pipeline;
	if (active == 1) {
		act->active = true;
	} else if (!active) {
		NL_SET_ERR_MSG(extack, "Action is already inactive");
		ret = -EINVAL;
		goto params_del;
	}

	act->num_prealloc_acts = num_prealloc_acts;

	if (updates_params)
		p4a_tmpl_parms_replace_many(act, &params_idr);

	idr_destroy(&params_idr);

	return act;

params_del:
	p4a_tmpl_parms_put_many(&params_idr);

idr_destroy:
	idr_destroy(&params_idr);

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4a_tmpl_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	    struct p4tc_path_nlattrs *nl_path_attrs,
	    struct netlink_ext_ack *extack)
{
	u32 *ids = nl_path_attrs->ids;
	const u32 pipeid = ids[P4TC_PID_IDX];
	struct nlattr *tb[P4TC_ACT_MAX + 1];
	struct p4tc_pipeline *pipeline;
	struct p4tc_act *act;
	int ret;

	pipeline = p4tc_pipeline_find_byany_unsealed(net, nl_path_attrs->pname,
						     pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ret = nla_parse_nested(tb, P4TC_ACT_MAX, nla, p4a_tmpl_policy,
			       extack);
	if (ret < 0)
		return ERR_PTR(ret);

	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		act = p4a_tmpl_create(net, tb, pipeline, ids, extack);
		break;
	case RTM_UPDATEP4TEMPLATE:
		act = p4a_tmpl_update(net, tb, pipeline, ids,
				      n->nlmsg_flags, extack);
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (IS_ERR(act))
		goto out;

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)act;
}

static int p4a_tmpl_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
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

static int p4a_tmpl_dump_1(struct sk_buff *skb,
			   struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_act *act = p4tc_to_act(common);

	if (!param)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_ACT_NAME, act->fullname))
		goto out_nlmsg_trim;

	if (nla_put_u8(skb, P4TC_ACT_ACTIVE, act->active))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static const struct p4tc_template_ops p4tc_act_ops = {
	.cu = p4a_tmpl_cu,
	.put = p4a_tmpl_put,
	.gd = p4a_tmpl_gd,
	.fill_nlmsg = p4a_tmpl_fill_nlmsg,
	.dump = p4a_tmpl_dump,
	.dump_1 = p4a_tmpl_dump_1,
	.obj_id = P4TC_OBJ_ACT,
};

static int __init p4tc_act_init(void)
{
	p4tc_tmpl_register_ops(&p4tc_act_ops);

	return 0;
}

subsys_initcall(p4tc_act_init);
