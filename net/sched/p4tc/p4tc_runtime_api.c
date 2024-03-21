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
#include <net/p4tc_ext_api.h>

static int tc_ctl_p4_root_subscribe(struct sk_buff *skb, struct nlmsghdr *n,
				    struct p4tc_path_nlattrs *nl_path_attrs,
				    struct nlattr *nla,
				    struct netlink_ext_ack *extack)

{
	struct nlattr *tb[P4TC_MAX + 1];
	u32 cmd = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_MAX, nla, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, nla, tb, P4TC_PATH)) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	return p4tc_tbl_entry_filter_sub(skb, nl_path_attrs, tb[P4TC_PARAMS],
					 cmd, extack);
}

static int tc_ctl_p4_root(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
			  struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct p4tc_path_nlattrs nl_path_attrs = { 0 };
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	u32 ids[P4TC_PATH_MAX] = { 0 };
	int ret;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (!tb[P4TC_ROOT] && !tb[P4TC_ROOT_SUBSCRIBE]) {
		NL_SET_ERR_MSG(extack,
			       "Must specify either P4TC_ROOT or P4TC_ROOT_SUBSCRIBE");
		return -EINVAL;
	}

	if (!!tb[P4TC_ROOT] != !tb[P4TC_ROOT_SUBSCRIBE]) {
		NL_SET_ERR_MSG(extack,
			       "P4TC_ROOT and P4TC_ROOT_SUBSCRIBE are mutually exclusive");
		return -EINVAL;
	}

	if (tb[P4TC_ROOT_SUBSCRIBE]) {
		if (tb[P4TC_ROOT_PNAME]) {
			nl_path_attrs.pname = nla_data(tb[P4TC_ROOT_PNAME]);
			nl_path_attrs.pname_passed = true;
		}
		ids[P4TC_PID_IDX] = t->pipeid;
		nl_path_attrs.ids = ids;

		return tc_ctl_p4_root_subscribe(skb, n, &nl_path_attrs,
						tb[P4TC_ROOT_SUBSCRIBE],
						extack);
	}

	switch (t->obj) {
	case P4TC_OBJ_RUNTIME_TABLE: {
		struct net *net = sock_net(skb->sk);

		net = maybe_get_net(net);
		if (!net) {
			NL_SET_ERR_MSG(extack, "Net namespace is going down");
			return -EBUSY;
		}

		ret = p4tc_tbl_entry_root(net, skb, n, tb, extack);

		put_net(net);

		return ret;
	}
	case P4TC_OBJ_RUNTIME_EXTERN:
		rtnl_lock();
		ret = p4tc_ctl_extern(skb, n, tb, extack);
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

	ret = tc_ctl_p4_root(skb, n, n->nlmsg_type, extack);

	return ret;
}

static int tc_ctl_p4_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	char *p_name = NULL;
	struct p4tcmsg *t;
	int ret = 0;

	/* Dump is always called with the nlk->cb_mutex held.
	 * In rtnl this mutex is set to rtnl_lock, which makes dump,
	 * even for table entries, to serialized over the rtnl_lock.
	 *
	 * For table entries, it guarantees the net namespace is alive.
	 * For externs, we don't need to lock the rtnl_lock.
	 */
	ASSERT_RTNL();

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
	case P4TC_OBJ_RUNTIME_TABLE:
		return p4tc_tbl_entry_dumpit(sock_net(skb->sk), skb, cb,
					     tb[P4TC_ROOT], p_name);
	case P4TC_OBJ_RUNTIME_EXTERN:
		return p4tc_ctl_extern_dump(skb, cb, tb, p_name);
	default:
		NL_SET_ERR_MSG_FMT(cb->extack,
				   "Unknown p4 runtime object type %u\n",
				   t->obj);
		return -ENOENT;
	}
}

static const struct rtnl_msg_handler p4tc_runt_rtnl_msg_handlers[] __initconst =
{
	{.msgtype = RTM_P4TC_CREATE, .doit = tc_ctl_p4_cu,
		.flags = RTNL_FLAG_DOIT_UNLOCKED},
	{.msgtype = RTM_P4TC_UPDATE, .doit = tc_ctl_p4_cu,
		.flags = RTNL_FLAG_DOIT_UNLOCKED},
	{.msgtype = RTM_P4TC_DEL, .doit = tc_ctl_p4_delete,
		.flags = RTNL_FLAG_DOIT_UNLOCKED},
	{.msgtype = RTM_P4TC_GET, .doit = tc_ctl_p4_get,
	 .dumpit = tc_ctl_p4_dump, .flags = RTNL_FLAG_DOIT_UNLOCKED},
};

static int __init p4tc_tbl_init(void)
{
	rtnl_register_many(p4tc_runt_rtnl_msg_handlers);

	p4tc_filter_sock_table_init();
	return 0;
}

subsys_initcall(p4tc_tbl_init);
