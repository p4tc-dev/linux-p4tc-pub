// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_pipeline.c	P4 TC PIPELINE
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
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
#include <net/p4tc_types.h>

static unsigned int pipeline_net_id;
static struct p4tc_pipeline *root_pipeline;

static __net_init int pipeline_init_net(struct net *net)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);

	idr_init(&pipe_net->pipeline_idr);

	return 0;
}

static int __p4tc_pipeline_put(struct p4tc_pipeline *pipeline,
			       struct p4tc_template_common *template,
			       struct netlink_ext_ack *extack);

static void __net_exit pipeline_exit_net(struct net *net)
{
	struct p4tc_pipeline_net *pipe_net;
	struct p4tc_pipeline *pipeline;
	unsigned long pipeid, tmp;

	rtnl_lock();
	pipe_net = net_generic(net, pipeline_net_id);
	idr_for_each_entry_ul(&pipe_net->pipeline_idr, pipeline, tmp, pipeid) {
		__p4tc_pipeline_put(pipeline, &pipeline->common, NULL);
	}
	idr_destroy(&pipe_net->pipeline_idr);
	rtnl_unlock();
}

static struct pernet_operations pipeline_net_ops = {
	.init = pipeline_init_net,
	.pre_exit = pipeline_exit_net,
	.id = &pipeline_net_id,
	.size = sizeof(struct p4tc_pipeline_net),
};

static const struct nla_policy tc_pipeline_policy[P4TC_PIPELINE_MAX + 1] = {
	[P4TC_PIPELINE_NUMTABLES] =
		NLA_POLICY_RANGE(NLA_U16, P4TC_MINTABLES_COUNT,
				 P4TC_MAXTABLES_COUNT),
	[P4TC_PIPELINE_STATE] = { .type = NLA_U8 },
};

static void p4tc_pipeline_destroy(struct p4tc_pipeline *pipeline)
{
	idr_destroy(&pipeline->p_act_idr);

	kfree(pipeline);
}

static void p4tc_pipeline_destroy_rcu(struct rcu_head *head)
{
	struct p4tc_pipeline *pipeline;
	struct net *net;

	pipeline = container_of(head, struct p4tc_pipeline, rcu);

	net = pipeline->net;
	p4tc_pipeline_destroy(pipeline);
	put_net(net);
}

static void p4tc_pipeline_teardown(struct p4tc_pipeline *pipeline,
				   struct netlink_ext_ack *extack)
{
	struct net *net = pipeline->net;
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);
	struct net *pipeline_net = maybe_get_net(net);
	unsigned long iter_act_id;
	struct p4tc_act *act;
	unsigned long tmp;

	idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, iter_act_id)
		act->common.ops->put(pipeline, &act->common, extack);

	/* If we are on netns cleanup we can't touch the pipeline_idr.
	 * On pre_exit we will destroy the idr but never call into teardown
	 * if filters are active which makes pipeline pointers dangle until
	 * the filters ultimately destroy them.
	 */
	if (pipeline_net) {
		idr_remove(&pipe_net->pipeline_idr, pipeline->common.p_id);
		call_rcu(&pipeline->rcu, p4tc_pipeline_destroy_rcu);
	} else {
		p4tc_pipeline_destroy(pipeline);
	}
}

static int __p4tc_pipeline_put(struct p4tc_pipeline *pipeline,
			       struct p4tc_template_common *template,
			       struct netlink_ext_ack *extack)
{
	/* The lifetime of the pipeline can be terminated in two cases:
	 * - netns cleanup (system driven)
	 * - pipeline delete (user driven)
	 *
	 * When the pipeline is referenced by one or more p4 classifiers we need
	 * to make sure the pipeline and its components are alive while the
	 * classifier is still visible by the datapath.
	 * In the netns cleanup, we cannot destroy the pipeline in our netns
	 * exit callback as the netdevs and filters are still visible in the
	 * datapath. In such case, it's the filter's job to destroy the
	 * pipeline.
	 *
	 * To accommodate such scenario, whichever put call reaches '0' first
	 * will destroy the pipeline and its components.
	 *
	 * On netns cleanup we guarantee no table entries operations are in
	 * flight.
	 */
	if (!refcount_dec_and_test(&pipeline->p_ctrl_ref)) {
		NL_SET_ERR_MSG(extack, "Can't delete referenced pipeline");
		return -EBUSY;
	}

	p4tc_pipeline_teardown(pipeline, extack);

	return 0;
}

static int pipeline_try_set_state_ready(struct p4tc_pipeline *pipeline,
					struct netlink_ext_ack *extack)
{
	if (pipeline->curr_tables != pipeline->num_tables) {
		NL_SET_ERR_MSG(extack,
			       "Must have all table defined to update state to ready");
		return -EINVAL;
	}

	pipeline->p_state = P4TC_STATE_READY;

	return true;
}

static bool p4tc_pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}

struct p4tc_pipeline *p4tc_pipeline_find_byid(struct net *net, const u32 pipeid)
{
	struct p4tc_pipeline_net *pipe_net;

	if (pipeid == P4TC_KERNEL_PIPEID)
		return root_pipeline;

	pipe_net = net_generic(net, pipeline_net_id);

	return idr_find(&pipe_net->pipeline_idr, pipeid);
}
EXPORT_SYMBOL_GPL(p4tc_pipeline_find_byid);

static struct p4tc_pipeline *p4tc_pipeline_find_byname(struct net *net,
						       const char *name)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);
	struct p4tc_pipeline *pipeline;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipe_net->pipeline_idr, pipeline, tmp, id) {
		/* Don't show kernel pipeline */
		if (id == P4TC_KERNEL_PIPEID)
			continue;
		if (strncmp(pipeline->common.name, name,
			    P4TC_PIPELINE_NAMSIZ) == 0)
			return pipeline;
	}

	return NULL;
}

static const struct p4tc_template_ops p4tc_pipeline_ops;

static struct p4tc_pipeline *
p4tc_pipeline_create(struct net *net, struct nlmsghdr *n,
		     struct nlattr *nla, const char *p_name,
		     u32 pipeid, struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);
	struct nlattr *tb[P4TC_PIPELINE_MAX + 1];
	struct p4tc_pipeline *pipeline;
	int ret = 0;

	ret = nla_parse_nested(tb, P4TC_PIPELINE_MAX, nla, tc_pipeline_policy,
			       extack);

	if (ret < 0)
		goto out;

	pipeline = p4tc_pipeline_find_byany(net, p_name, pipeid, NULL);
	if (pipeid != P4TC_KERNEL_PIPEID && !IS_ERR(pipeline)) {
		NL_SET_ERR_MSG(extack, "Pipeline exists");
		ret = -EEXIST;
		goto out;
	}

	pipeline = kzalloc(sizeof(*pipeline), GFP_KERNEL);
	if (unlikely(!pipeline))
		return ERR_PTR(-ENOMEM);

	if (!p_name || p_name[0] == '\0') {
		NL_SET_ERR_MSG(extack, "Must specify pipeline name");
		ret = -EINVAL;
		goto err;
	}

	strscpy(pipeline->common.name, p_name, P4TC_PIPELINE_NAMSIZ);

	if (pipeid) {
		ret = idr_alloc_u32(&pipe_net->pipeline_idr, pipeline, &pipeid,
				    pipeid, GFP_KERNEL);
	} else {
		pipeid = 1;
		ret = idr_alloc_u32(&pipe_net->pipeline_idr, pipeline, &pipeid,
				    UINT_MAX, GFP_KERNEL);
	}

	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate pipeline id");
		goto idr_rm;
	}

	pipeline->common.p_id = pipeid;

	if (tb[P4TC_PIPELINE_NUMTABLES])
		pipeline->num_tables =
			nla_get_u16(tb[P4TC_PIPELINE_NUMTABLES]);
	else
		pipeline->num_tables = P4TC_DEFAULT_NUM_TABLES;

	idr_init(&pipeline->p_act_idr);

	pipeline->num_created_acts = 0;

	pipeline->p_state = P4TC_STATE_NOT_READY;

	pipeline->net = net;

	refcount_set(&pipeline->p_ctrl_ref, 1);

	pipeline->common.ops = (struct p4tc_template_ops *)&p4tc_pipeline_ops;

	return pipeline;

idr_rm:
	idr_remove(&pipe_net->pipeline_idr, pipeid);

err:
	kfree(pipeline);

out:
	return ERR_PTR(ret);
}

struct p4tc_pipeline *p4tc_pipeline_find_byany(struct net *net,
					       const char *p_name,
					       const u32 pipeid,
					       struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = NULL;

	if (pipeid) {
		pipeline = p4tc_pipeline_find_byid(net, pipeid);
		if (!pipeline) {
			NL_SET_ERR_MSG(extack, "Unable to find pipeline by id");
			return ERR_PTR(-EINVAL);
		}
	} else {
		if (p_name) {
			pipeline = p4tc_pipeline_find_byname(net, p_name);
			if (!pipeline) {
				NL_SET_ERR_MSG(extack,
					       "Pipeline name not found");
				return ERR_PTR(-EINVAL);
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify pipeline name or id");
			return ERR_PTR(-EINVAL);
		}
	}

	return pipeline;
}

struct p4tc_pipeline *
p4tc_pipeline_find_get(struct net *net, const char *p_name,
		       const u32 pipeid, struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		p4tc_pipeline_find_byany(net, p_name, pipeid, extack);

	if (IS_ERR(pipeline))
		return pipeline;

	if (!p4tc_pipeline_get(pipeline)) {
		NL_SET_ERR_MSG(extack, "Pipeline is stale");
		return ERR_PTR(-EINVAL);
	}

	return pipeline;
}
EXPORT_SYMBOL_GPL(p4tc_pipeline_find_get);

void p4tc_pipeline_put(struct p4tc_pipeline *pipeline)
{
	__p4tc_pipeline_put(pipeline, &pipeline->common, NULL);
}
EXPORT_SYMBOL_GPL(p4tc_pipeline_put);

struct p4tc_pipeline *
p4tc_pipeline_find_byany_unsealed(struct net *net, const char *p_name,
				  const u32 pipeid,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		p4tc_pipeline_find_byany(net, p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return pipeline;

	if (p4tc_pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack, "Pipeline is sealed");
		return ERR_PTR(-EINVAL);
	}

	return pipeline;
}

static struct p4tc_pipeline *
p4tc_pipeline_update(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		     const char *p_name, const u32 pipeid,
		     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_PIPELINE_MAX + 1];
	struct p4tc_pipeline *pipeline;
	u16 num_tables = 0;
	int ret = 0;

	ret = nla_parse_nested(tb, P4TC_PIPELINE_MAX, nla, tc_pipeline_policy,
			       extack);

	if (ret < 0)
		goto out;

	pipeline =
		p4tc_pipeline_find_byany_unsealed(net, p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return pipeline;

	if (tb[P4TC_PIPELINE_NUMTABLES])
		num_tables = nla_get_u16(tb[P4TC_PIPELINE_NUMTABLES]);

	if (tb[P4TC_PIPELINE_STATE]) {
		ret = pipeline_try_set_state_ready(pipeline, extack);
		if (ret < 0)
			goto out;
	}

	if (num_tables)
		pipeline->num_tables = num_tables;

	return pipeline;

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_pipeline_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		 struct p4tc_path_nlattrs *nl_path_attrs,
		 struct netlink_ext_ack *extack)
{
	u32 *ids = nl_path_attrs->ids;
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;

	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		pipeline = p4tc_pipeline_create(net, n, nla,
						nl_path_attrs->pname,
						pipeid, extack);
		break;
	case RTM_UPDATEP4TEMPLATE:
		pipeline = p4tc_pipeline_update(net, n, nla,
						nl_path_attrs->pname,
						pipeid, extack);
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (IS_ERR(pipeline))
		goto out;

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)pipeline;
}

static int _p4tc_pipeline_fill_nlmsg(struct sk_buff *skb,
				     const struct p4tc_pipeline *pipeline)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nest;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;
	if (nla_put_u16(skb, P4TC_PIPELINE_NUMTABLES, pipeline->num_tables))
		goto out_nlmsg_trim;
	if (nla_put_u8(skb, P4TC_PIPELINE_STATE, pipeline->p_state))
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int p4tc_pipeline_fill_nlmsg(struct net *net, struct sk_buff *skb,
				    struct p4tc_template_common *template,
				    struct netlink_ext_ack *extack)
{
	const struct p4tc_pipeline *pipeline = to_pipeline(template);

	if (_p4tc_pipeline_fill_nlmsg(skb, pipeline) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for pipeline");
		return -EINVAL;
	}

	return 0;
}

static int p4tc_pipeline_del_one(struct p4tc_pipeline *pipeline,
				 struct netlink_ext_ack *extack)
{
	/* User driven pipeline put doesn't transfer the lifetime
	 * of the pipeline to other ref holders. In case of unlocked
	 * table entries, it shall never teardown the pipeline so
	 * need to do an atomic transition here.
	 *
	 * System driven put will serialize with rtnl_lock and
	 * table entries are guaranteed to not be in flight.
	 */
	if (!refcount_dec_if_one(&pipeline->p_ctrl_ref)) {
		NL_SET_ERR_MSG(extack, "Pipeline in use");
		return -EAGAIN;
	}

	p4tc_pipeline_teardown(pipeline, extack);

	return 0;
}

static int p4tc_pipeline_gd(struct net *net, struct sk_buff *skb,
			    struct nlmsghdr *n, struct nlattr *nla,
			    struct p4tc_path_nlattrs *nl_path_attrs,
			    struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_template_common *tmpl;
	struct p4tc_pipeline *pipeline;
	u32 *ids = nl_path_attrs->ids;
	u32 pipeid = ids[P4TC_PID_IDX];
	int ret = 0;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE &&
	    (n->nlmsg_flags & NLM_F_ROOT)) {
		NL_SET_ERR_MSG(extack, "Pipeline flush not supported");
		return -EOPNOTSUPP;
	}

	pipeline = p4tc_pipeline_find_byany(net, nl_path_attrs->pname, pipeid,
					    extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	tmpl = (struct p4tc_template_common *)pipeline;
	ret = p4tc_pipeline_fill_nlmsg(net, skb, tmpl, extack);
	if (ret < 0)
		return -1;

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = p4tc_pipeline_del_one(pipeline, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return ret;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4tc_pipeline_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			      struct nlattr *nla, char **p_name, u32 *ids,
			      struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline_net *pipe_net;

	pipe_net = net_generic(net, pipeline_net_id);

	return p4tc_tmpl_generic_dump(skb, ctx, &pipe_net->pipeline_idr,
				      P4TC_PID_IDX, extack);
}

static int p4tc_pipeline_dump_1(struct sk_buff *skb,
				struct p4tc_template_common *common)
{
	struct p4tc_pipeline *pipeline = to_pipeline(common);
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *param;

	/* Don't show kernel pipeline in dump */
	if (pipeline->common.p_id == P4TC_KERNEL_PIPEID)
		return 1;

	param = nla_nest_start(skb, P4TC_PARAMS);
	if (!param)
		goto out_nlmsg_trim;
	if (nla_put_string(skb, P4TC_PIPELINE_NAME, pipeline->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int register_pipeline_pernet(void)
{
	return register_pernet_subsys(&pipeline_net_ops);
}

static const struct p4tc_template_ops p4tc_pipeline_ops = {
	.cu = p4tc_pipeline_cu,
	.fill_nlmsg = p4tc_pipeline_fill_nlmsg,
	.gd = p4tc_pipeline_gd,
	.put = __p4tc_pipeline_put,
	.dump = p4tc_pipeline_dump,
	.dump_1 = p4tc_pipeline_dump_1,
	.obj_id = P4TC_OBJ_PIPELINE,
};

static int __p4tc_pipeline_init(void)
{
	int pipeid = P4TC_KERNEL_PIPEID;

	root_pipeline = kzalloc(sizeof(*root_pipeline), GFP_ATOMIC);
	if (unlikely(!root_pipeline)) {
		pr_err("Unable to register kernel pipeline\n");
		return -ENOMEM;
	}

	strscpy(root_pipeline->common.name, "kernel", P4TC_PIPELINE_NAMSIZ);

	root_pipeline->common.ops =
		(struct p4tc_template_ops *)&p4tc_pipeline_ops;

	root_pipeline->common.p_id = pipeid;

	root_pipeline->p_state = P4TC_STATE_READY;

	return 0;
}

static int __init p4tc_pipeline_init(void)
{
	if (register_pipeline_pernet() < 0) {
		pr_err("Failed to register per net pipeline IDR");
		return 0;
	}

	if (p4tc_register_types() < 0) {
		pr_err("Failed to register P4 types");
		goto unregister_pipeline_pernet;
	}

	if (__p4tc_pipeline_init() < 0)
		goto unregister_types;

	p4tc_tmpl_register_ops(&p4tc_pipeline_ops);

	return 0;

unregister_types:
	p4tc_unregister_types();

unregister_pipeline_pernet:
	unregister_pernet_subsys(&pipeline_net_ops);
	return 0;
}

subsys_initcall(p4tc_pipeline_init);
