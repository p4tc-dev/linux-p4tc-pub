// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_runtime_api.c P4 TC RUNTIME API
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
#include <linux/bitmap.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/flow_offload.h>

static int tc_ctl_p4_root(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
			  struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);

	switch (t->obj) {
	case P4TC_OBJ_RUNTIME_TABLE: {
		struct net *net = sock_net(skb->sk);
		int ret;

		net = maybe_get_net(net);
		if (!net) {
			NL_SET_ERR_MSG(extack, "Net namespace is going down");
			return -EBUSY;
		}

		ret = p4tc_tbl_entry_root(net, skb, n, cmd, extack);

		put_net(net);

		return ret;
	}
	default:
		NL_SET_ERR_MSG(extack, "Unknown P4 runtime object type");
		return -EOPNOTSUPP;
	}
}

static int tc_ctl_p4_cu(struct sk_buff *skb, struct nlmsghdr *n,
			struct netlink_ext_ack *extack)
{
	int ret;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = tc_ctl_p4_root(skb, n, n->nlmsg_type, extack);

	return ret;
}

static int __init p4tc_tbl_init(void)
{
	rtnl_register(PF_UNSPEC, RTM_P4TC_CREATE, tc_ctl_p4_cu, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	rtnl_register(PF_UNSPEC, RTM_P4TC_UPDATE, tc_ctl_p4_cu, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);

	return 0;
}

subsys_initcall(p4tc_tbl_init);
