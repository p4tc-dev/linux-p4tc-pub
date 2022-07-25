// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_pipeline.c	P4 TC PIPELINE
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

DEFINE_IDR(pipeline_idr);

static const struct nla_policy tc_pipeline_policy[P4TC_PIPELINE_MAX + 1] = {
	[P4TC_PIPELINE_MAXRULES] = P4T_POLICY_RANGE(P4T_U32, 1, P4TC_MAXRULES_LIMIT),
	[P4TC_PIPELINE_NUMTCLASSES] = P4T_POLICY_RANGE(P4T_U16, 1, P4TC_MAXTCLASSES_COUNT),
	[P4TC_PIPELINE_STATE] = { .type = P4T_U8 },
	[P4TC_PIPELINE_PREACTIONS] = { .type = P4T_NESTED },
	[P4TC_PIPELINE_POSTACTIONS] = { .type = P4T_NESTED },
};

static void tcf_pipeline_destroy(struct rcu_head *head)
{
	struct p4tc_pipeline *pipeline;

	pipeline = container_of(head, struct p4tc_pipeline, rcu);

	idr_destroy(&pipeline->p_tbc_idr);
	idr_destroy(&pipeline->p_meta_idr);
	idr_destroy(&pipeline->p_parser_idr);
	idr_destroy(&pipeline->p_act_idr);

	kfree(pipeline);
}

static int tcf_pipeline_put(struct net *net,
			    struct p4tc_template_common *template,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = to_pipeline(template);
	unsigned long tbc_id, m_id, parser_id, act_id, tmp;
	struct p4tc_table_class *tclass;
	struct p4tc_metadata *meta;
	struct p4tc_parser *parser;
	struct p4tc_act *act;

	if (!refcount_dec_if_one(&pipeline->p_ref)) {
		NL_SET_ERR_MSG(extack,
			       "Can't delete referenced pipeline");
		return -EBUSY;
	}

	idr_for_each_entry_ul(&pipeline->p_parser_idr, parser, tmp, parser_id)
		tcf_parser_del(pipeline, parser->parser_name,
			       parser->parser_inst_id, extack);

	idr_for_each_entry_ul(&pipeline->p_meta_idr, meta, tmp, m_id)
		meta->common.ops->put(net, &meta->common, extack);

	idr_for_each_entry_ul(&pipeline->p_tbc_idr, tclass, tmp, tbc_id)
		tclass->common.ops->put(net, &tclass->common, extack);

	idr_for_each_entry_ul(&pipeline->p_act_idr, act, tmp, act_id)
		act->common.ops->put(net, &act->common, extack);

	idr_remove(&pipeline_idr, pipeline->common.p_id);

	/* XXX: The action fields are only accessed in the control path
	 * since they will be copied to the filter, where the data path
	 * will use them. So there is no need to free them in the rcu
	 * callback. We can just free them here
	 */
	tcf_action_destroy(pipeline->preacts, TCA_ACT_UNBIND);
	kfree(pipeline->preacts);

	tcf_action_destroy(pipeline->postacts, TCA_ACT_UNBIND);
	kfree(pipeline->postacts);

	call_rcu(&pipeline->rcu, tcf_pipeline_destroy);

	return 0;
}

static inline bool pipeline_try_set_state_ready(struct p4tc_pipeline *pipeline)
{
	if (pipeline->curr_table_classes != pipeline->num_table_classes)
		return false;

	pipeline->p_state = P4TC_STATE_READY;
	return true;
}

static struct p4tc_pipeline *pipeline_find_name(const char *name)
{
	struct p4tc_pipeline *pipeline;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline_idr, pipeline, tmp, id) {
		if (strncmp(pipeline->common.name, name,
			    PIPELINENAMSIZ) == 0)
			return pipeline;
	}

	return NULL;
}

static struct p4tc_pipeline *
tcf_pipeline_create(struct net *net, struct nlmsghdr *n,
		    struct nlattr *nla, const char *p_name,
		    u32 pipeid, struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *tb[P4TC_PIPELINE_MAX + 1];
	struct p4tc_pipeline *pipeline;

	ret = nla_parse_nested_deprecated(tb, P4TC_PIPELINE_MAX,
					  nla, tc_pipeline_policy, extack);

	if (ret < 0)
		return ERR_PTR(ret);

	pipeline = kmalloc(sizeof(*pipeline), GFP_KERNEL);
	if (!pipeline)
		return ERR_PTR(-ENOMEM);

	if (!p_name || p_name[0] == '\0') {
		NL_SET_ERR_MSG(extack, "Must specify pipeline name");
		ret = -EINVAL;
		goto err;
	}

	if (pipeline_find_name(p_name) || idr_find(&pipeline_idr, pipeid)) {
		NL_SET_ERR_MSG(extack, "Pipeline was already created");
		ret = -EEXIST;
		goto err;
	}

	strscpy(pipeline->common.name, p_name, PIPELINENAMSIZ);

	if (pipeid) {
		ret = idr_alloc_u32(&pipeline_idr, pipeline, &pipeid, pipeid,
				    GFP_KERNEL);

		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate pipeline id");
			goto err;
		}

		pipeline->common.p_id = pipeid;
	} else {
		pipeline->common.p_id = 1;

		ret = idr_alloc_u32(&pipeline_idr, pipeline,
				    &pipeline->common.p_id, UINT_MAX,
				    GFP_KERNEL);

		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate pipeline id");
			goto err;
		}
	}

	if (tb[P4TC_PIPELINE_MAXRULES])
		pipeline->max_rules =
			*((u32 *)nla_data(tb[P4TC_PIPELINE_MAXRULES]));
	else
		pipeline->max_rules = P4TC_DEFAULT_MAX_RULES;

	if (tb[P4TC_PIPELINE_NUMTCLASSES])
		pipeline->num_table_classes =
			*((u16 *)nla_data(tb[P4TC_PIPELINE_NUMTCLASSES]));
	else
		pipeline->num_table_classes = P4TC_DEFAULT_NUM_TCLASSES;

	if (tb[P4TC_PIPELINE_PREACTIONS]) {
		pipeline->preacts = kcalloc(TCA_ACT_MAX_PRIO,
					    sizeof(struct tc_action *),
					    GFP_KERNEL);
		if (!pipeline->preacts) {
			ret = -ENOMEM;
			goto idr_rm;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_PREACTIONS],
				       pipeline->preacts, extack);
		if (ret < 0) {
			kfree(pipeline->preacts);
			goto idr_rm;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify pipeline preactions");
		ret = -EINVAL;
		goto idr_rm;
	}

	if (tb[P4TC_PIPELINE_POSTACTIONS]) {
		pipeline->postacts = kcalloc(TCA_ACT_MAX_PRIO,
					     sizeof(struct tc_action *),
					     GFP_KERNEL);
		if (!pipeline->postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_POSTACTIONS],
				       pipeline->postacts, extack);
		if (ret < 0) {
			kfree(pipeline->postacts);
			goto preactions_destroy;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify pipeline postactions");
		ret = -EINVAL;
		goto preactions_destroy;
	}

	idr_init(&pipeline->p_parser_idr);
	idr_init(&pipeline->p_act_idr);

	idr_init(&pipeline->p_tbc_idr);
	pipeline->curr_table_classes = 0;

	idr_init(&pipeline->p_meta_idr);
	pipeline->p_meta_offset = 0;

	pipeline->p_state = P4TC_STATE_NOT_READY;

	refcount_set(&pipeline->p_ref, 1);

	pipeline->common.ops = (struct p4tc_template_ops *)&p4tc_pipeline_ops;

	return pipeline;

preactions_destroy:
	tcf_action_destroy(pipeline->preacts, TCA_ACT_UNBIND);
	kfree(pipeline->preacts);

idr_rm:
	idr_remove(&pipeline_idr, pipeid);

err:
	kfree(pipeline);
	return ERR_PTR(ret);
}

static struct p4tc_pipeline *
__pipeline_find(const char *p_name, const u32 pipeid,
	      struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = NULL;
	int err;

	if (pipeid) {
		pipeline = idr_find(&pipeline_idr, pipeid);
		if (!pipeline) {
			NL_SET_ERR_MSG(extack, "Unable to find pipeline by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (p_name) {
			pipeline = pipeline_find_name(p_name);
			if (!pipeline) {
				NL_SET_ERR_MSG(extack, "Pipeline name not found");
				err = -EINVAL;
				goto out;
			}
		}
	}

	return pipeline;

out:
	return ERR_PTR(err);
}

struct p4tc_pipeline *
pipeline_find(const char *p_name, const u32 pipeid,
	      struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		__pipeline_find(p_name, pipeid, extack);
	if (!pipeline) {
		NL_SET_ERR_MSG(extack, "Must specify pipeline name or id");
		return ERR_PTR(-EINVAL);
	}

	return pipeline;
}

struct p4tc_pipeline *
pipeline_find_unsealed(const char *p_name, const u32 pipeid,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = pipeline_find(p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return pipeline;

	if (pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack, "Pipeline is sealed");
		return ERR_PTR(-EINVAL);
	}

	return pipeline;
}

static struct p4tc_pipeline *
tcf_pipeline_update(struct net *net, struct nlmsghdr *n,
		    struct nlattr *nla, const char *p_name,
		    const u32 pipeid, struct netlink_ext_ack *extack)
{
	struct tc_action **preacts = NULL;
	struct tc_action **postacts = NULL;
	u16 num_table_classes = 0;
	u16 max_rules = 0;
	int ret = 0;
	struct nlattr *tb[P4TC_PIPELINE_MAX + 1];
	struct p4tc_pipeline *pipeline;

	ret = nla_parse_nested_deprecated(tb, P4TC_PIPELINE_MAX,
					  nla, tc_pipeline_policy, extack);

	if (ret < 0)
		goto out;

	pipeline = pipeline_find_unsealed(p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return pipeline;

	if (tb[P4TC_PIPELINE_NUMTCLASSES])
		num_table_classes =
			*((u16 *)nla_data(tb[P4TC_PIPELINE_NUMTCLASSES]));

	if (tb[P4TC_PIPELINE_MAXRULES])
		max_rules = *((u32 *)nla_data(tb[P4TC_PIPELINE_MAXRULES]));

	if (tb[P4TC_PIPELINE_PREACTIONS]) {
		preacts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				  GFP_KERNEL);
		if (!preacts) {
			ret = -ENOMEM;
			goto out;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_PREACTIONS],
				       preacts, extack);
		if (ret < 0) {
			kfree(preacts);
			goto out;
		}
	}

	if (tb[P4TC_PIPELINE_POSTACTIONS]) {
		postacts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				   GFP_KERNEL);
		if (!postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_POSTACTIONS],
				       postacts, extack);
		if (ret < 0) {
			kfree(postacts);
			goto preactions_destroy;
		}
	}

	if (tb[P4TC_PIPELINE_STATE]) {
		if (!pipeline_try_set_state_ready(pipeline)) {
			NL_SET_ERR_MSG(extack,
				       "Must have all table classes defined to update state to ready");
			ret = -EINVAL;
			goto postactions_destroy;
		}
	}

	if (max_rules)
		pipeline->max_rules = max_rules;
	if (num_table_classes)
		pipeline->num_table_classes = num_table_classes;
	if (preacts) {
		tcf_action_destroy(pipeline->preacts, TCA_ACT_UNBIND);
		kfree(pipeline->preacts);
		pipeline->preacts = preacts;
	}
	if (postacts) {
		tcf_action_destroy(pipeline->postacts, TCA_ACT_UNBIND);
		kfree(pipeline->postacts);
		pipeline->postacts = postacts;
	}

	return pipeline;

postactions_destroy:
	if (postacts) {
		tcf_action_destroy(postacts, TCA_ACT_UNBIND);
		kfree(postacts);
	}

preactions_destroy:
	if (preacts) {
		tcf_action_destroy(preacts, TCA_ACT_UNBIND);
		kfree(preacts);
	}

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_pipeline_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		char **p_name, u32 *ids, struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		pipeline = tcf_pipeline_update(net, n, nla, *p_name, pipeid,
					       extack);
	else
		pipeline = tcf_pipeline_create(net, n, nla, *p_name, pipeid,
					       extack);

	if (IS_ERR(pipeline))
		goto out;

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)pipeline;
}

static int _tcf_pipeline_fill_nlmsg(struct sk_buff *skb,
				    const struct p4tc_pipeline *pipeline)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct nlattr *nest, *preacts, *postacts;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;
	if (nla_put_u32(skb, P4TC_PIPELINE_MAXRULES, pipeline->max_rules))
		goto out_nlmsg_trim;

	if (nla_put_u16(skb, P4TC_PIPELINE_NUMTCLASSES, pipeline->num_table_classes))
		goto out_nlmsg_trim;
	if (nla_put_u8(skb, P4TC_PIPELINE_STATE, pipeline->p_state))
		goto out_nlmsg_trim;

	preacts = nla_nest_start(skb, P4TC_PIPELINE_PREACTIONS);
	if (tcf_action_dump(skb, pipeline->preacts, 0, 0, false) < 0)
		goto out_nlmsg_trim;
	nla_nest_end(skb, preacts);

	postacts = nla_nest_start(skb, P4TC_PIPELINE_POSTACTIONS);
	if (tcf_action_dump(skb, pipeline->postacts, 0, 0, false) < 0)
		goto out_nlmsg_trim;
	nla_nest_end(skb, postacts);

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_pipeline_fill_nlmsg(struct net *net, struct sk_buff *skb,
				   struct p4tc_template_common *template,
				   struct netlink_ext_ack *extack)
{
	const struct p4tc_pipeline *pipeline = to_pipeline(template);

	if (_tcf_pipeline_fill_nlmsg(skb, pipeline) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for pipeline");
		return -EINVAL;
	}

	return 0;
}

static int tcf_pipeline_del_one(struct net *net,
				struct p4tc_template_common *tmpl,
				struct netlink_ext_ack *extack)
{
	return tcf_pipeline_put(net, tmpl, extack);
}

static int tcf_pipeline_gd(struct net *net, struct sk_buff *skb,
			   struct nlmsghdr *n, struct nlattr *nla,
			   char **p_name, u32 *ids,
			   struct netlink_ext_ack *extack)
{
	unsigned char *b = skb_tail_pointer(skb);
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_template_common *tmpl;
	struct p4tc_pipeline *pipeline;
	int ret;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE &&
	    (n->nlmsg_flags & NLM_F_ROOT)) {
		NL_SET_ERR_MSG(extack, "Pipeline flush not supported");
		return -EOPNOTSUPP;
	}

	pipeline = pipeline_find(*p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	tmpl = (struct p4tc_template_common *)pipeline;
	ret = tcf_pipeline_fill_nlmsg(net, skb, tmpl, extack);
	if (ret < 0)
		return -1;

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = tcf_pipeline_del_one(net, tmpl, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return ret;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_pipeline_dump(struct sk_buff *skb,
			     struct p4tc_dump_ctx *ctx,
			     struct nlattr *nla,
			     char **p_name, u32 *ids,
			     struct netlink_ext_ack *extack)
{
	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipeline_idr,
					P4TC_PID_IDX, extack);
}

static int tcf_pipeline_dump_1(struct sk_buff *skb,
			       struct p4tc_template_common *common)
{
	struct p4tc_pipeline *pipeline = to_pipeline(common);
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	unsigned char *b = skb_tail_pointer(skb);

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

const struct p4tc_template_ops p4tc_pipeline_ops = {
	.cu = tcf_pipeline_cu,
	.fill_nlmsg = tcf_pipeline_fill_nlmsg,
	.gd = tcf_pipeline_gd,
	.put = tcf_pipeline_put,
	.dump = tcf_pipeline_dump,
	.dump_1 = tcf_pipeline_dump_1,
};
