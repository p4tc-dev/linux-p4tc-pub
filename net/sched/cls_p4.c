// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/cls_p4.c - P4 Classifier
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu.h>

#include <net/sch_generic.h>
#include <net/pkt_cls.h>

#include <net/p4tc.h>

#include "p4tc/trace.h"

struct cls_p4_head {
	struct tcf_exts exts;
	struct tcf_result res;
	struct rcu_work rwork;
	struct p4tc_pipeline *pipeline;
	u32 handle;
};

static int p4_classify(struct sk_buff *skb, const struct tcf_proto *tp,
		       struct tcf_result *res)
{
	struct cls_p4_head *head = rcu_dereference_bh(tp->root);
	struct tcf_result p4res = {};
	int rc = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_skb_ext *p4tc_ext;

	if (unlikely(!head)) {
		pr_err("P4 classifier not found\n");
		return -1;
	}

	pipeline = head->pipeline;
	trace_p4_classify(skb, pipeline);

	p4tc_ext = skb_ext_find(skb, P4TC_SKB_EXT);
	if (!p4tc_ext) {
		p4tc_ext = p4tc_skb_ext_alloc(skb);
		if (WARN_ON_ONCE(!p4tc_ext))
			return TC_ACT_SHOT;
	}

	if (refcount_read(&pipeline->p_hdrs_used) > 1)
		rc = tcf_skb_parse(skb, p4tc_ext, pipeline->parser);

	if (rc > 0) {
		pr_warn("P4 parser error %d\n", rc);
		return TC_ACT_SHOT;
	}

	rc = tcf_action_exec(skb, pipeline->preacts, pipeline->num_preacts,
			     &p4res);
	if (rc != TC_ACT_PIPE)
		return rc;

	rc = tcf_action_exec(skb, pipeline->postacts, pipeline->num_postacts,
			     &p4res);
	if (rc != TC_ACT_PIPE)
		return rc;

	*res = head->res;

	return tcf_exts_exec(skb, &head->exts, res);
}

static int p4_init(struct tcf_proto *tp)
{
	return 0;
}

static void __p4_destroy(struct cls_p4_head *head)
{
	tcf_exts_destroy(&head->exts);
	tcf_exts_put_net(&head->exts);
	__tcf_pipeline_put(head->pipeline);
	kfree(head);
}

static void p4_destroy_work(struct work_struct *work)
{
	struct cls_p4_head *head =
		container_of(to_rcu_work(work), struct cls_p4_head, rwork);

	rtnl_lock();
	__p4_destroy(head);
	rtnl_unlock();
}

static void p4_destroy(struct tcf_proto *tp, bool rtnl_held,
		       struct netlink_ext_ack *extack)
{
	struct cls_p4_head *head = rtnl_dereference(tp->root);

	if (!head)
		return;

	tcf_unbind_filter(tp, &head->res);

	if (tcf_exts_get_net(&head->exts))
		tcf_queue_work(&head->rwork, p4_destroy_work);
	else
		__p4_destroy(head);
}

static void *p4_get(struct tcf_proto *tp, u32 handle)
{
	struct cls_p4_head *head = rtnl_dereference(tp->root);

	if (head && head->handle == handle)
		return head;

	return NULL;
}

static const struct nla_policy p4_policy[TCA_P4_MAX + 1] = {
	[TCA_P4_UNSPEC] = { .type = NLA_UNSPEC },
	[TCA_P4_CLASSID] = { .type = NLA_U32 },
	[TCA_P4_PNAME] = { .type = NLA_STRING },
};

static int p4_set_parms(struct net *net, struct tcf_proto *tp,
			struct cls_p4_head *head, unsigned long base,
			struct nlattr **tb, struct nlattr *est, u32 flags,
			struct netlink_ext_ack *extack)
{
	int err;

	err = tcf_exts_validate_ex(net, tp, tb, est, &head->exts, flags, 0,
				   extack);
	if (err < 0)
		return err;

	if (tb[TCA_P4_CLASSID]) {
		head->res.classid = nla_get_u32(tb[TCA_P4_CLASSID]);
		tcf_bind_filter(tp, &head->res, base);
	}

	return 0;
}

static int p4_change(struct net *net, struct sk_buff *in_skb,
		     struct tcf_proto *tp, unsigned long base, u32 handle,
		     struct nlattr **tca, void **arg, u32 flags,
		     struct netlink_ext_ack *extack)
{
	struct cls_p4_head *head = rtnl_dereference(tp->root);
	struct p4tc_pipeline *pipeline = NULL;
	char *pname = NULL;
	struct nlattr *tb[TCA_P4_MAX + 1];
	struct cls_p4_head *new;
	int err;

	if (!tca[TCA_OPTIONS]) {
		NL_SET_ERR_MSG(extack, "Must provide pipeline options");
		return -EINVAL;
	}

	if (head)
		return -EEXIST;

	err = nla_parse_nested_deprecated(tb, TCA_P4_MAX, tca[TCA_OPTIONS],
					  p4_policy, NULL);
	if (err < 0)
		return err;

	if (tb[TCA_P4_PNAME])
		pname = nla_data(tb[TCA_P4_PNAME]);

	if (pname) {
		pipeline = tcf_pipeline_get(net, pname, 0, extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
	} else {
		NL_SET_ERR_MSG(extack, "MUST provide pipeline name");
		return -EINVAL;
	}

	if (!pipeline_sealed(pipeline)) {
		err = -EINVAL;
		NL_SET_ERR_MSG(extack, "Pipeline must be sealed before use");
		goto pipeline_put;
	}

	if (refcount_read(&pipeline->p_hdrs_used) > 1 &&
	    !tcf_parser_is_callable(pipeline->parser)) {
		err = -EINVAL;
		NL_SET_ERR_MSG(extack, "Pipeline doesn't have callable parser");
		goto pipeline_put;
	}

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new) {
		err = -ENOMEM;
		goto pipeline_put;
	}

	err = tcf_exts_init(&new->exts, net, TCA_P4_ACT, 0);
	if (err)
		goto err_exts_init;

	if (!handle)
		handle = 1;

	new->handle = handle;

	err = p4_set_parms(net, tp, new, base, tb, tca[TCA_RATE], flags,
			   extack);
	if (err)
		goto err_set_parms;

	new->pipeline = pipeline;
	*arg = head;
	rcu_assign_pointer(tp->root, new);
	return 0;

err_set_parms:
	tcf_exts_destroy(&new->exts);
err_exts_init:
	kfree(new);
pipeline_put:
	__tcf_pipeline_put(pipeline);
	return err;
}

static int p4_delete(struct tcf_proto *tp, void *arg, bool *last,
		     bool rtnl_held, struct netlink_ext_ack *extack)
{
	*last = true;
	return 0;
}

static void p4_walk(struct tcf_proto *tp, struct tcf_walker *arg,
		    bool rtnl_held)
{
	struct cls_p4_head *head = rtnl_dereference(tp->root);

	if (arg->count < arg->skip)
		goto skip;

	if (!head)
		return;
	if (arg->fn(tp, head, arg) < 0)
		arg->stop = 1;
skip:
	arg->count++;
}

static int p4_dump(struct net *net, struct tcf_proto *tp, void *fh,
		   struct sk_buff *skb, struct tcmsg *t, bool rtnl_held)
{
	struct cls_p4_head *head = fh;
	struct nlattr *nest;

	if (!head)
		return skb->len;

	t->tcm_handle = head->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	if (nla_put_string(skb, TCA_P4_PNAME, head->pipeline->common.name))
		goto nla_put_failure;

	if (head->res.classid &&
	    nla_put_u32(skb, TCA_P4_CLASSID, head->res.classid))
		goto nla_put_failure;

	if (tcf_exts_dump(skb, &head->exts))
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	if (tcf_exts_dump_stats(skb, &head->exts) < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static void p4_bind_class(void *fh, u32 classid, unsigned long cl, void *q,
			  unsigned long base)
{
	struct cls_p4_head *head = fh;

	if (head && head->res.classid == classid) {
		if (cl)
			__tcf_bind_filter(q, &head->res, base);
		else
			__tcf_unbind_filter(q, &head->res);
	}
}

static struct tcf_proto_ops cls_p4_ops __read_mostly = {
	.kind		= "p4",
	.classify	= p4_classify,
	.init		= p4_init,
	.destroy	= p4_destroy,
	.get		= p4_get,
	.change		= p4_change,
	.delete		= p4_delete,
	.walk		= p4_walk,
	.dump		= p4_dump,
	.bind_class	= p4_bind_class,
	.owner		= THIS_MODULE,
};

static int __init cls_p4_init(void)
{
	return register_tcf_proto_ops(&cls_p4_ops);
}

static void __exit cls_p4_exit(void)
{
	unregister_tcf_proto_ops(&cls_p4_ops);
}

module_init(cls_p4_init);
module_exit(cls_p4_exit);

MODULE_AUTHOR("Mojatatu Networks");
MODULE_DESCRIPTION("P4 Classifier");
MODULE_LICENSE("GPL");
