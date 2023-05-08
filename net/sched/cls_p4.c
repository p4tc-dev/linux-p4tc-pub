// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/cls_p4.c - P4 Classifier
 * Copyright (c) 2022-2023, Mojatatu Networks
 * Copyright (c) 2022-2023, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include <net/sch_generic.h>
#include <net/pkt_cls.h>

#include <net/p4tc.h>

#include "p4tc/trace.h"

#define CLS_P4_PROG_NAME_LEN	256

struct p4tc_bpf_prog {
	struct bpf_prog *p4_prog;
	const char *p4_prog_name;
};

struct cls_p4_head {
	struct tcf_exts exts;
	struct tcf_result res;
	struct rcu_work rwork;
	struct p4tc_pipeline *pipeline;
	struct p4tc_bpf_prog *prog;
	u32 p4_prog_cookie;
	u32 handle;
};

static int p4_classify(struct sk_buff *skb, const struct tcf_proto *tp,
		       struct tcf_result *res)
{
	struct cls_p4_head *head = rcu_dereference_bh(tp->root);
	bool at_ingress = skb_at_tc_ingress(skb);
	int rc = TC_ACT_PIPE;
	struct p4tc_percpu_scratchpad *pad;
#ifndef CONFIG_NET_P4_TC_KFUNCS
	struct tcf_result p4res = {};
	struct p4tc_pipeline *pipeline;
#endif

	if (unlikely(!head)) {
		pr_err("P4 classifier not found\n");
		return -1;
	}

	pad = this_cpu_ptr(&p4tc_percpu_scratchpad);

	if (head->prog) {
		/* If eBPF program is loaded into TC */
		if (head->prog->p4_prog->type == BPF_PROG_TYPE_SCHED_ACT) {
			if (at_ingress) {
				/* It is safe to push/pull even if skb_shared() */
				__skb_push(skb, skb->mac_len);
				bpf_compute_data_pointers(skb);
				rc = bpf_prog_run(head->prog->p4_prog,
						  skb);
				__skb_pull(skb, skb->mac_len);
			} else {
				bpf_compute_data_pointers(skb);
				rc = bpf_prog_run(head->prog->p4_prog,
						  skb);
			}
		/* Potentially eBPF program was executed before at XDP and we
		 * need to check the cookie to see if that was the case.
		 */
		} else {
			if (head->p4_prog_cookie != pad->prog_cookie) {
				net_notice_ratelimited("prog_cookie doesn't match");
				return TC_ACT_SHOT;
			}
		}
	}

	if (rc != TC_ACT_PIPE)
		goto zero_pad;

#ifndef CONFIG_NET_P4_TC_KFUNCS
	pipeline = head->pipeline;
	trace_p4_classify(skb, pipeline);

	rc = tcf_action_exec(skb, pipeline->preacts, pipeline->num_preacts,
			     &p4res);
	if (rc != TC_ACT_PIPE)
		goto zero_pad;

	rc = tcf_action_exec(skb, pipeline->postacts, pipeline->num_postacts,
			     &p4res);
	if (rc != TC_ACT_PIPE)
		goto zero_pad;
#endif

	*res = head->res;

	rc = tcf_exts_exec(skb, &head->exts, res);

zero_pad:
	/* Pad will always be zero initialised after boot.
	 * Zero it at the end after all users are done with it.
	 */
	memset(pad, 0, sizeof(*pad));

	return rc;
}

static int p4_init(struct tcf_proto *tp)
{
	return 0;
}

static void p4_bpf_prog_destroy(struct p4tc_bpf_prog *prog)
{
	bpf_prog_put(prog->p4_prog);
	kfree(prog->p4_prog_name);
	kfree(prog);
}

static void __p4_destroy(struct cls_p4_head *head)
{
	tcf_exts_destroy(&head->exts);
	tcf_exts_put_net(&head->exts);
	if (head->prog)
		p4_bpf_prog_destroy(head->prog);
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
	[TCA_P4_ACT] = { .type = NLA_NESTED },
	[TCA_P4_PNAME] = { .type = NLA_STRING, .len = PIPELINENAMSIZ },
	[TCA_P4_PROG_FD] = { .type = NLA_U32},
	[TCA_P4_PROG_NAME] = { .type = NLA_STRING, .len = CLS_P4_PROG_NAME_LEN },
	[TCA_P4_PROG_TYPE] = { .type = NLA_U32},
	[TCA_P4_PROG_COOKIE] = { .type = NLA_U32 }
};

static int cls_p4_prog_from_efd(struct nlattr **tb,
				struct p4tc_bpf_prog *prog, u32 flags,
				struct netlink_ext_ack *extack)
{
	struct bpf_prog *fp;
	u32 prog_type;
	bool skip_sw;
	char *name;
	u32 bpf_fd;

	bpf_fd = nla_get_u32(tb[TCA_P4_PROG_FD]);
	prog_type = nla_get_u32(tb[TCA_P4_PROG_TYPE]);
	skip_sw = flags & TCA_CLS_FLAGS_SKIP_SW;

	if (prog_type != BPF_PROG_TYPE_XDP &&
	    prog_type != BPF_PROG_TYPE_SCHED_ACT) {
		NL_SET_ERR_MSG(extack,
			       "BPF prog type must be BPF_PROG_TYPE_SCHED_ACT or BPF_PROG_TYPE_XDP");
		return -EINVAL;
	}

	fp = bpf_prog_get_type_dev(bpf_fd, prog_type, skip_sw);
	if (IS_ERR(fp))
		return PTR_ERR(fp);

	name = nla_memdup(tb[TCA_P4_PROG_NAME], GFP_KERNEL);
	if (!name) {
		bpf_prog_put(fp);
		return -ENOMEM;
	}

	prog->p4_prog_name = name;
	prog->p4_prog = fp;

	return 0;
}

static int p4_set_parms(struct net *net, struct tcf_proto *tp,
			struct cls_p4_head *head, unsigned long base,
			struct nlattr **tb, struct nlattr *est, u32 flags,
			struct netlink_ext_ack *extack)
{
	bool load_bpf_prog = tb[TCA_P4_PROG_NAME] && tb[TCA_P4_PROG_FD] &&
			     tb[TCA_P4_PROG_TYPE];
	struct p4tc_bpf_prog *prog = NULL;
	int err;

	err = tcf_exts_validate_ex(net, tp, tb, est, &head->exts, flags, 0,
				   extack);
	if (err < 0)
		return err;

	if (load_bpf_prog) {
		prog = kzalloc(GFP_KERNEL, sizeof(*prog));
		if (!prog) {
			err = -ENOMEM;
			goto exts_destroy;
		}

		err = cls_p4_prog_from_efd(tb, prog, flags, extack);
		if (err < 0) {
			kfree(prog);
			goto exts_destroy;
		}
	}

	if (tb[TCA_P4_PROG_COOKIE]) {
		struct p4tc_bpf_prog *prog_aux = prog ?: head->prog;
		u32 *p4_prog_cookie;

		if (!prog_aux) {
			err = -EINVAL;
			NL_SET_ERR_MSG(extack,
				       "Must have a BPF program to specify xdp prog_cookie");
			goto prog_put;
		}

		if (prog_aux->p4_prog->type != BPF_PROG_TYPE_XDP) {
			err = -EINVAL;
			NL_SET_ERR_MSG(extack,
				       "Program must be attached to XDP to specify prog_cookie");
			goto prog_put;
		}

		p4_prog_cookie = nla_data(tb[TCA_P4_PROG_COOKIE]);
		head->p4_prog_cookie = *p4_prog_cookie;
	} else {
		struct p4tc_bpf_prog *prog_aux = prog ?: head->prog;

		if (prog_aux && prog_aux->p4_prog->type == BPF_PROG_TYPE_XDP &&
		    !head->p4_prog_cookie) {
			NL_SET_ERR_MSG(extack,
				       "MUST provide prog_cookie when loading into XDP");
			err = -EINVAL;
			goto prog_put;
		}
	}

	if (tb[TCA_P4_CLASSID]) {
		head->res.classid = nla_get_u32(tb[TCA_P4_CLASSID]);
		tcf_bind_filter(tp, &head->res, base);
	}

	if (head->prog) {
		pr_notice("cls_p4: Substituting old BPF program with id %u with new one with id %u\n",
			  head->prog->p4_prog->aux->id, prog->p4_prog->aux->id);
		p4_bpf_prog_destroy(head->prog);
	}
	head->prog = prog;

	return 0;

prog_put:
	if (prog)
		p4_bpf_prog_destroy(prog);
exts_destroy:
	tcf_exts_destroy(&head->exts);
	return err;
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

	err = nla_parse_nested(tb, TCA_P4_MAX, tca[TCA_OPTIONS], p4_policy,
			       extack);
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

static int p4_prog_dump(struct sk_buff *skb, struct p4tc_bpf_prog *prog,
			u32 prog_cookie)
{
	unsigned char *b = nlmsg_get_pos(skb);

	if (nla_put_u32(skb, TCA_P4_PROG_ID, prog->p4_prog->aux->id))
		goto nla_put_failure;

	if (nla_put_string(skb, TCA_P4_PROG_NAME, prog->p4_prog_name))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_P4_PROG_TYPE, prog->p4_prog->type))
		goto nla_put_failure;

	if (prog_cookie &&
	    nla_put_u32(skb, TCA_P4_PROG_COOKIE, prog_cookie))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
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

	if (head->prog && p4_prog_dump(skb, head->prog, head->p4_prog_cookie))
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
