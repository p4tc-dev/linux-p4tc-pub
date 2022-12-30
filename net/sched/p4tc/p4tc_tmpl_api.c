// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_api.c	P4 TC API
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

const struct nla_policy p4tc_root_policy[P4TC_ROOT_MAX + 1] = {
	[P4TC_ROOT] = { .type = NLA_NESTED },
	[P4TC_ROOT_PNAME] = { .type = NLA_STRING, .len = PIPELINENAMSIZ },
};

const struct nla_policy p4tc_policy[P4TC_MAX + 1] = {
	[P4TC_PATH] = { .type = NLA_BINARY,
			.len = P4TC_PATH_MAX * sizeof(u32) },
	[P4TC_PARAMS] = { .type = NLA_NESTED },
};

static bool obj_is_valid(u32 obj)
{
	switch (obj) {
	case P4TC_OBJ_PIPELINE:
		return true;
	default:
		return false;
	}
}

static const struct p4tc_template_ops *p4tc_ops[P4TC_OBJ_MAX] = {
	[P4TC_OBJ_PIPELINE] = &p4tc_pipeline_ops,
};

int tcf_p4_tmpl_generic_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			     struct idr *idr, int idx,
			     struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	unsigned long id = 0;
	int i = 0;
	struct p4tc_template_common *common;
	unsigned long tmp;

	id = ctx->ids[idx];

	idr_for_each_entry_continue_ul(idr, common, tmp, id) {
		struct nlattr *count;
		int ret;

		if (i == P4TC_MSGBATCH_SIZE)
			break;

		count = nla_nest_start(skb, i + 1);
		if (!count)
			goto out_nlmsg_trim;
		ret = common->ops->dump_1(skb, common);
		if (ret < 0) {
			goto out_nlmsg_trim;
		} else if (ret) {
			nla_nest_cancel(skb, count);
			continue;
		}
		nla_nest_end(skb, count);

		i++;
	}

	if (i == 0) {
		if (!ctx->ids[idx])
			NL_SET_ERR_MSG(extack,
				       "There are no pipeline components");
		return 0;
	}

	ctx->ids[idx] = id;

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int tc_ctl_p4_tmpl_gd_1(struct net *net, struct sk_buff *skb,
			       struct nlmsghdr *n, struct nlattr *arg,
			       struct p4tc_nl_pname *nl_pname,
			       struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	u32 ids[P4TC_PATH_MAX] = {};
	struct nlattr *tb[P4TC_MAX + 1];
	struct p4tc_template_ops *op;
	int ret;

	if (!obj_is_valid(t->obj)) {
		NL_SET_ERR_MSG(extack, "Invalid object type");
		return -EINVAL;
	}

	ret = nla_parse_nested(tb, P4TC_MAX, arg, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	ids[P4TC_PID_IDX] = t->pipeid;

	if (tb[P4TC_PATH]) {
		if ((nla_len(tb[P4TC_PATH])) >
		    (P4TC_PATH_MAX - 1) * sizeof(u32)) {
			NL_SET_ERR_MSG(extack, "Path is too big");
			return -E2BIG;
		}
	}

	op = (struct p4tc_template_ops *)p4tc_ops[t->obj];

	ret = op->gd(net, skb, n, tb[P4TC_PARAMS], nl_pname, ids, extack);
	if (ret < 0)
		return ret;

	if (!t->pipeid)
		t->pipeid = ids[P4TC_PID_IDX];

	return ret;
}

static int tc_ctl_p4_tmpl_gd_n(struct sk_buff *skb, struct nlmsghdr *n,
			       char *p_name, struct nlattr *nla, int event,
			       struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	int ret = 0;
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_nl_pname nl_pname;
	struct sk_buff *new_skb;
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *pnatt;
	struct nlattr *root;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return ret;

	new_skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!new_skb)
		return -ENOMEM;

	nlh = nlmsg_put(new_skb, portid, n->nlmsg_seq, event, sizeof(*t),
			n->nlmsg_flags);
	if (!nlh) {
		ret = -ENOMEM;
		goto out;
	}

	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;

	pnatt = nla_reserve(new_skb, P4TC_ROOT_PNAME, PIPELINENAMSIZ);
	if (!pnatt) {
		ret = -ENOMEM;
		goto out;
	}

	nl_pname.data = nla_data(pnatt);
	if (!p_name) {
		/* Filled up by the operation or forced failure */
		memset(nl_pname.data, 0, PIPELINENAMSIZ);
		nl_pname.passed = false;
	} else {
		strscpy(nl_pname.data, p_name, PIPELINENAMSIZ);
		nl_pname.passed = true;
	}

	root = nla_nest_start(new_skb, P4TC_ROOT);
	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct nlattr *nest = nla_nest_start(new_skb, i);

		ret = tc_ctl_p4_tmpl_gd_1(net, new_skb, nlh, tb[i], &nl_pname,
					  extack);
		if (n->nlmsg_flags & NLM_F_ROOT && event == RTM_DELP4TEMPLATE) {
			if (ret <= 0)
				goto out;
		} else {
			if (ret < 0)
				goto out;
		}
		nla_nest_end(new_skb, nest);
	}
	nla_nest_end(new_skb, root);

	nlmsg_end(new_skb, nlh);

	if (event == RTM_GETP4TEMPLATE)
		return rtnl_unicast(new_skb, net, portid);

	return rtnetlink_send(new_skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
out:
	kfree_skb(new_skb);
	return ret;
}

static int tc_ctl_p4_tmpl_get(struct sk_buff *skb, struct nlmsghdr *n,
			      struct netlink_ext_ack *extack)
{
	char *p_name = NULL;
	struct nlattr *p4tc_attr[P4TC_ROOT_MAX + 1];
	int ret;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), p4tc_attr, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (!p4tc_attr[P4TC_ROOT]) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	if (p4tc_attr[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tc_attr[P4TC_ROOT_PNAME]);

	return tc_ctl_p4_tmpl_gd_n(skb, n, p_name, p4tc_attr[P4TC_ROOT],
				   RTM_GETP4TEMPLATE, extack);
}

static int tc_ctl_p4_tmpl_delete(struct sk_buff *skb, struct nlmsghdr *n,
				 struct netlink_ext_ack *extack)
{
	char *p_name = NULL;
	struct nlattr *p4tc_attr[P4TC_ROOT_MAX + 1];
	int ret;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), p4tc_attr, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (!p4tc_attr[P4TC_ROOT]) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	if (p4tc_attr[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tc_attr[P4TC_ROOT_PNAME]);

	return tc_ctl_p4_tmpl_gd_n(skb, n, p_name, p4tc_attr[P4TC_ROOT],
				   RTM_DELP4TEMPLATE, extack);
}

static struct p4tc_template_common *
tcf_p4_tmpl_cu_1(struct sk_buff *skb, struct net *net, struct nlmsghdr *n,
		 struct p4tc_nl_pname *nl_pname, struct nlattr *nla,
		 struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	u32 ids[P4TC_PATH_MAX] = {};
	struct nlattr *p4tc_attr[P4TC_MAX + 1];
	struct p4tc_template_common *tmpl;
	struct p4tc_template_ops *op;
	int ret;

	if (!obj_is_valid(t->obj)) {
		NL_SET_ERR_MSG(extack, "Invalid object type");
		ret = -EINVAL;
		goto out;
	}

	ret = nla_parse_nested(p4tc_attr, P4TC_MAX, nla, p4tc_policy, extack);
	if (ret < 0)
		goto out;

	if (!p4tc_attr[P4TC_PARAMS]) {
		NL_SET_ERR_MSG(extack, "Must specify object attributes");
		ret = -EINVAL;
		goto out;
	}

	ids[P4TC_PID_IDX] = t->pipeid;

	if (p4tc_attr[P4TC_PATH]) {
		if ((nla_len(p4tc_attr[P4TC_PATH])) >
		    (P4TC_PATH_MAX - 1) * sizeof(u32)) {
			NL_SET_ERR_MSG(extack, "Path is too big");
			ret = -E2BIG;
			goto out;
		}
	}

	op = (struct p4tc_template_ops *)p4tc_ops[t->obj];
	tmpl = op->cu(net, n, p4tc_attr[P4TC_PARAMS], nl_pname, ids, extack);
	if (IS_ERR(tmpl))
		return tmpl;

	ret = op->fill_nlmsg(net, skb, tmpl, extack);
	if (ret < 0)
		goto put;

	if (!t->pipeid)
		t->pipeid = ids[P4TC_PID_IDX];

	return tmpl;

put:
	op->put(net, tmpl, false, extack);

out:
	return ERR_PTR(ret);
}

static int tcf_p4_tmpl_cu_n(struct sk_buff *skb, struct nlmsghdr *n,
			    struct nlattr *nla, char *p_name,
			    struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	struct p4tc_template_common *tmpls[P4TC_MSGBATCH_SIZE];
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_nl_pname nl_pname;
	struct sk_buff *new_skb;
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *pnatt;
	struct nlattr *root;
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return ret;

	new_skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!new_skb)
		return -ENOMEM;

	nlh = nlmsg_put(new_skb, portid, n->nlmsg_seq, RTM_CREATEP4TEMPLATE,
			sizeof(*t), n->nlmsg_flags);
	if (!nlh)
		goto out;

	t_new = nlmsg_data(nlh);
	if (!t_new) {
		NL_SET_ERR_MSG(extack, "Message header is missing");
		ret = -EINVAL;
		goto out;
	}
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;

	pnatt = nla_reserve(new_skb, P4TC_ROOT_PNAME, PIPELINENAMSIZ);
	if (!pnatt) {
		ret = -ENOMEM;
		goto out;
	}

	nl_pname.data = nla_data(pnatt);
	if (!p_name) {
		/* Filled up by the operation or forced failure */
		memset(nl_pname.data, 0, PIPELINENAMSIZ);
		nl_pname.passed = false;
	} else {
		strscpy(nl_pname.data, p_name, PIPELINENAMSIZ);
		nl_pname.passed = true;
	}

	root = nla_nest_start(new_skb, P4TC_ROOT);
	if (!root) {
		ret = -ENOMEM;
		goto out;
	}

	/* XXX: See if we can use NLA_NESTED_ARRAY here */
	for (i = 0; i < P4TC_MSGBATCH_SIZE && tb[i + 1]; i++) {
		struct nlattr *nest = nla_nest_start(new_skb, i + 1);

		tmpls[i] = tcf_p4_tmpl_cu_1(new_skb, net, nlh, &nl_pname,
					    tb[i + 1], extack);
		if (IS_ERR(tmpls[i])) {
			ret = PTR_ERR(tmpls[i]);
			goto undo_prev;
		}

		nla_nest_end(new_skb, nest);
	}
	nla_nest_end(new_skb, root);

	if (!t_new->pipeid)
		t_new->pipeid = ret;

	nlmsg_end(new_skb, nlh);

	return rtnetlink_send(new_skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);

undo_prev:
	if (!(nlh->nlmsg_flags & NLM_F_REPLACE)) {
		while (--i > 0) {
			struct p4tc_template_common *tmpl = tmpls[i - 1];

			tmpl->ops->put(net, tmpl, false, extack);
		}
	}

out:
	kfree_skb(new_skb);
	return ret;
}

static int tc_ctl_p4_tmpl_cu(struct sk_buff *skb, struct nlmsghdr *n,
			     struct netlink_ext_ack *extack)
{
	char *p_name = NULL;
	int ret = 0;
	struct nlattr *p4tc_attr[P4TC_ROOT_MAX + 1];

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), p4tc_attr, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (!p4tc_attr[P4TC_ROOT]) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	if (p4tc_attr[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tc_attr[P4TC_ROOT_PNAME]);

	return tcf_p4_tmpl_cu_n(skb, n, p4tc_attr[P4TC_ROOT], p_name, extack);
}

static int tc_ctl_p4_tmpl_dump_1(struct sk_buff *skb, struct nlattr *arg,
				 char *p_name, struct netlink_callback *cb)
{
	struct p4tc_dump_ctx *ctx = (void *)cb->ctx;
	struct netlink_ext_ack *extack = cb->extack;
	u32 portid = NETLINK_CB(cb->skb).portid;
	const struct nlmsghdr *n = cb->nlh;
	u32 ids[P4TC_PATH_MAX] = {};
	struct nlattr *tb[P4TC_MAX + 1];
	struct p4tc_template_ops *op;
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *root;
	struct p4tcmsg *t;
	int ret;

	ret = nla_parse_nested_deprecated(tb, P4TC_MAX, arg, p4tc_policy,
					  extack);
	if (ret < 0)
		return ret;

	t = (struct p4tcmsg *)nlmsg_data(n);
	if (!obj_is_valid(t->obj)) {
		NL_SET_ERR_MSG(extack, "Invalid object type");
		return -EINVAL;
	}

	nlh = nlmsg_put(skb, portid, n->nlmsg_seq, RTM_GETP4TEMPLATE,
			sizeof(*t), n->nlmsg_flags);
	if (!nlh)
		return -ENOSPC;

	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;

	root = nla_nest_start(skb, P4TC_ROOT);

	ids[P4TC_PID_IDX] = t->pipeid;
	if (tb[P4TC_PATH]) {
		if ((nla_len(tb[P4TC_PATH])) >
		    (P4TC_PATH_MAX - 1) * sizeof(u32)) {
			NL_SET_ERR_MSG(extack, "Path is too big");
			return -E2BIG;
		}
	}

	op = (struct p4tc_template_ops *)p4tc_ops[t->obj];
	ret = op->dump(skb, ctx, tb[P4TC_PARAMS], &p_name, ids, extack);
	if (ret <= 0)
		goto out;
	nla_nest_end(skb, root);

	if (p_name) {
		if (nla_put_string(skb, P4TC_ROOT_PNAME, p_name)) {
			ret = -1;
			goto out;
		}
	}

	if (!t_new->pipeid)
		t_new->pipeid = ids[P4TC_PID_IDX];

	nlmsg_end(skb, nlh);

	return ret;

out:
	nlmsg_cancel(skb, nlh);
	return ret;
}

static int tc_ctl_p4_tmpl_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	char *p_name = NULL;
	struct nlattr *p4tc_attr[P4TC_ROOT_MAX + 1];
	int ret;

	ret = nlmsg_parse(cb->nlh, sizeof(struct p4tcmsg), p4tc_attr,
			  P4TC_ROOT_MAX, p4tc_root_policy, cb->extack);
	if (ret < 0)
		return ret;

	if (!p4tc_attr[P4TC_ROOT]) {
		NL_SET_ERR_MSG(cb->extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	if (p4tc_attr[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tc_attr[P4TC_ROOT_PNAME]);

	return tc_ctl_p4_tmpl_dump_1(skb, p4tc_attr[P4TC_ROOT], p_name, cb);
}

static int __init p4tc_template_init(void)
{
	u32 obj;

	rtnl_register(PF_UNSPEC, RTM_CREATEP4TEMPLATE, tc_ctl_p4_tmpl_cu, NULL,
		      0);
	rtnl_register(PF_UNSPEC, RTM_DELP4TEMPLATE, tc_ctl_p4_tmpl_delete, NULL,
		      0);
	rtnl_register(PF_UNSPEC, RTM_GETP4TEMPLATE, tc_ctl_p4_tmpl_get,
		      tc_ctl_p4_tmpl_dump, 0);

	for (obj = P4TC_OBJ_PIPELINE; obj < P4TC_OBJ_MAX; obj++) {
		const struct p4tc_template_ops *op = p4tc_ops[obj];

		if (!obj_is_valid(obj))
			continue;

		if (op->init)
			op->init();
	}

	return 0;
}

subsys_initcall(p4tc_template_init);
