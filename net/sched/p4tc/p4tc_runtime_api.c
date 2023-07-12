// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_runtime_api.c P4 TC RUNTIME API
 *
 * Copyright (c) 2022-2023, Mojatatu Networks
 * Copyright (c) 2022-2023, Intel Corporation.
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
#include <linux/bitmap.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/flow_offload.h>
#include <net/p4tc_ext_api.h>

static int tc_ctl_p4_root(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
			  struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	int ret;

	switch (t->obj) {
	case P4TC_OBJ_RUNTIME_TABLE: {
		struct net *net = sock_net(skb->sk);

		net = maybe_get_net(net);
		if (!net) {
			NL_SET_ERR_MSG(extack, "Net namespace is going down");
			return -EBUSY;
		}

		return p4tc_tbl_entry_doit(net, skb, n, cmd, extack);
	}
	case P4TC_OBJ_RUNTIME_EXTERN:
		rtnl_lock();
		ret = p4tc_ctl_extern(skb, n, cmd, extack);
		rtnl_unlock();
		return ret;
	default:
		NL_SET_ERR_MSG(extack, "Unknown P4 runtime object type");
		return -EOPNOTSUPP;
	}
}

static int tc_ctl_p4_get(struct sk_buff *skb, struct nlmsghdr *n,
			 struct netlink_ext_ack *extack)
{
	return tc_ctl_p4_root(skb, n, RTM_P4TC_GET, extack);
}

static int tc_ctl_p4_delete(struct sk_buff *skb, struct nlmsghdr *n,
			    struct netlink_ext_ack *extack)
{
	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	return tc_ctl_p4_root(skb, n, RTM_P4TC_DEL, extack);
}

static int tc_ctl_p4_cu(struct sk_buff *skb, struct nlmsghdr *n,
			struct netlink_ext_ack *extack)
{
	int ret;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = tc_ctl_p4_root(skb, n, RTM_P4TC_CREATE, extack);

	return ret;
}

static int tc_ctl_p4_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	char *p_name = NULL;
	struct p4tcmsg *t;
	int ret = 0;

	ret = nlmsg_parse(cb->nlh, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, cb->extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(cb->extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(cb->extack,
			       "Netlink P4TC Runtime attributes missing");
		return -EINVAL;
	}

	if (tb[P4TC_ROOT_PNAME])
		p_name = nla_data(tb[P4TC_ROOT_PNAME]);

	t = nlmsg_data(cb->nlh);

	switch (t->obj) {
	case P4TC_OBJ_RUNTIME_TABLE: {
		struct net *net = sock_net(skb->sk);

		net = maybe_get_net(net);
		if (!net) {
			NL_SET_ERR_MSG(cb->extack,
				       "Net namespace is going down");
			return -EBUSY;
		}

		return p4tc_tbl_entry_dumpit(net, skb, cb, tb[P4TC_ROOT],
					     p_name);
	}
	case P4TC_OBJ_RUNTIME_EXTERN:
		return p4tc_ctl_extern_dump(skb, cb, tb, p_name);
	default:
		NL_SET_ERR_MSG_FMT(cb->extack,
				   "Unknown p4 runtime object type %u\n",
				   t->obj);
		return -ENOENT;
	}
}

static int __init p4tc_tbl_init(void)
{
	rtnl_register(PF_UNSPEC, RTM_P4TC_CREATE, tc_ctl_p4_cu, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	rtnl_register(PF_UNSPEC, RTM_P4TC_DEL, tc_ctl_p4_delete, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	rtnl_register(PF_UNSPEC, RTM_P4TC_GET, tc_ctl_p4_get, tc_ctl_p4_dump,
		      RTNL_FLAG_DOIT_UNLOCKED);

	return 0;
}

subsys_initcall(p4tc_tbl_init);
