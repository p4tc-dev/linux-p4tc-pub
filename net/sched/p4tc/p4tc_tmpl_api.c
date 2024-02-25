// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_tmpl_api.c	P4 TC TEMPLATE API
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

static const struct nla_policy p4tc_root_policy[P4TC_ROOT_MAX + 1] = {
	[P4TC_ROOT] = { .type = NLA_NESTED },
};

static const struct nla_policy p4tc_policy[P4TC_MAX + 1] = {
	[P4TC_PATH] = { .type = NLA_BINARY,
			.len = P4TC_PATH_MAX * sizeof(u32) },
	[P4TC_PARAMS] = { .type = NLA_NESTED },
};

static const struct p4tc_template_ops *p4tc_ops[P4TC_OBJ_MAX + 1] = {};

static bool obj_is_valid(u32 obj_id)
{
	if (obj_id > P4TC_OBJ_MAX)
		return false;

	return !!p4tc_ops[obj_id];
}

int p4tc_tmpl_generic_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			   struct idr *idr, int idx,
			   struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_template_common *common;
	unsigned long id = 0;
	unsigned long tmp;
	int i = 0;

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

static int p4tc_template_put(struct net *net,
			     struct p4tc_template_common *common,
			     struct netlink_ext_ack *extack)
{
	/* Every created template is bound to a pipeline */
	return common->ops->put(common, extack);
}

static int tc_ctl_p4_tmpl_1_send(struct sk_buff *skb, struct net *net,
				 struct nlmsghdr *n, u32 portid)
{
	if (n->nlmsg_type == RTM_GETP4TEMPLATE)
		return rtnl_unicast(skb, net, portid);

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static int tc_ctl_p4_tmpl_1(struct sk_buff *skb, struct nlmsghdr *n,
			    struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	struct p4tc_template_common *tmpl;
	struct p4tc_template_ops *obj_op;
	struct nlattr *tb[P4TC_MAX + 1];
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct sk_buff *nskb;
	struct nlattr *root;
	int ret;

	/* All checks will fail at this point because obj_is_valid will return
	 * false. The next patch will make this functional
	 */
	if (!obj_is_valid(t->obj)) {
		NL_SET_ERR_MSG(extack, "Invalid object type");
		return -EINVAL;
	}

	ret = nla_parse_nested(tb, P4TC_MAX, nla, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	nskb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!nskb)
		return -ENOMEM;

	nlh = nlmsg_put(nskb, portid, n->nlmsg_seq, n->nlmsg_type,
			sizeof(*t), n->nlmsg_flags);
	if (!nlh) {
		ret = -ENOMEM;
		goto free_skb;
	}

	t_new = nlmsg_data(nlh);
	t_new->obj = t->obj;

	root = nla_nest_start(nskb, P4TC_ROOT);
	if (!root) {
		ret = -ENOMEM;
		goto free_skb;
	}

	obj_op = (struct p4tc_template_ops *)p4tc_ops[t->obj];
	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
	case RTM_UPDATEP4TEMPLATE:
		if (NL_REQ_ATTR_CHECK(extack, nla, tb, P4TC_PARAMS)) {
			NL_SET_ERR_MSG(extack,
				       "Must specify object attributes");
			ret = -EINVAL;
			goto free_skb;
		}
		tmpl = obj_op->cu(net, n, tb[P4TC_PARAMS], extack);
		if (IS_ERR(tmpl)) {
			ret = PTR_ERR(tmpl);
			goto free_skb;
		}

		ret = obj_op->fill_nlmsg(net, nskb, tmpl, extack);
		if (ret < 0) {
			p4tc_template_put(net, tmpl, extack);
			goto free_skb;
		}
		break;
	case RTM_DELP4TEMPLATE:
	case RTM_GETP4TEMPLATE:
		ret = obj_op->gd(net, nskb, n, tb[P4TC_PARAMS], extack);
		if (ret < 0)
			goto free_skb;
		break;
	default:
		ret = -EINVAL;
		goto free_skb;
	}

	nlmsg_end(nskb, nlh);

	return tc_ctl_p4_tmpl_1_send(nskb, net, nlh, portid);

free_skb:
	kfree_skb(nskb);

	return ret;
}

static int tc_ctl_p4_tmpl_get(struct sk_buff *skb, struct nlmsghdr *n,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	int ret;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	return tc_ctl_p4_tmpl_1(skb, n, tb[P4TC_ROOT], extack);
}

static int tc_ctl_p4_tmpl_delete(struct sk_buff *skb, struct nlmsghdr *n,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	int ret;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	return tc_ctl_p4_tmpl_1(skb, n, tb[P4TC_ROOT], extack);
}

static int tc_ctl_p4_tmpl_cu(struct sk_buff *skb, struct nlmsghdr *n,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	int ret = 0;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	return tc_ctl_p4_tmpl_1(skb, n, tb[P4TC_ROOT], extack);
}

static int tc_ctl_p4_tmpl_dump_1(struct sk_buff *skb, struct nlattr *arg,
				 struct netlink_callback *cb)
{
	struct p4tc_dump_ctx *ctx = (void *)cb->ctx;
	struct netlink_ext_ack *extack = cb->extack;
	u32 portid = NETLINK_CB(cb->skb).portid;
	const struct nlmsghdr *n = cb->nlh;
	struct p4tc_template_ops *obj_op;
	struct nlattr *tb[P4TC_MAX + 1];
	u32 ids[P4TC_PATH_MAX] = {};
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
	/* All checks will fail at this point because obj_is_valid will return
	 * false. The next patch will make this functional
	 */
	if (!obj_is_valid(t->obj)) {
		NL_SET_ERR_MSG(extack, "Invalid object type");
		return -EINVAL;
	}

	nlh = nlmsg_put(skb, portid, n->nlmsg_seq, n->nlmsg_type,
			sizeof(*t), n->nlmsg_flags);
	if (!nlh)
		return -ENOSPC;

	t_new = nlmsg_data(nlh);
	t_new->obj = t->obj;

	root = nla_nest_start(skb, P4TC_ROOT);

	obj_op = (struct p4tc_template_ops *)p4tc_ops[t->obj];
	ret = obj_op->dump(skb, ctx, tb[P4TC_PARAMS], ids, extack);
	if (ret <= 0)
		goto out;
	nla_nest_end(skb, root);

	nlmsg_end(skb, nlh);

	return ret;

out:
	nlmsg_cancel(skb, nlh);
	return ret;
}

static int tc_ctl_p4_tmpl_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	int ret;

	ret = nlmsg_parse(cb->nlh, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, cb->extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(cb->extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(cb->extack,
			       "Netlink P4TC template attributes missing");
		return -EINVAL;
	}

	return tc_ctl_p4_tmpl_dump_1(skb, tb[P4TC_ROOT], cb);
}

static int __init p4tc_template_init(void)
{
	rtnl_register(PF_UNSPEC, RTM_CREATEP4TEMPLATE, tc_ctl_p4_tmpl_cu, NULL,
		      0);
	rtnl_register(PF_UNSPEC, RTM_UPDATEP4TEMPLATE, tc_ctl_p4_tmpl_cu, NULL,
		      0);
	rtnl_register(PF_UNSPEC, RTM_DELP4TEMPLATE, tc_ctl_p4_tmpl_delete, NULL,
		      0);
	rtnl_register(PF_UNSPEC, RTM_GETP4TEMPLATE, tc_ctl_p4_tmpl_get,
		      tc_ctl_p4_tmpl_dump, 0);
	return 0;
}

subsys_initcall(p4tc_template_init);
