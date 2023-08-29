// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/externs/ext_is_net_or_host_port.c is_net/host_port externs implementation
 *
 * Copyright (c) 2023-2024, Mojatatu Networks
 * Copyright (c) 2023-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/p4tc.h>
#include <net/p4tc_ext_api.h>

enum
{
	P4TC_PORT_UNSPEC = 0,
	P4TC_PORT_FROM_HOST = 1,
	P4TC_PORT_FROM_NET = 2
};

#define EXTERN_IS_NET_PORT 0x10000000
#define EXTERN_IS_HOST_PORT 0x11000000

static struct net_device *get_dev_xdp(struct xdp_buff *xdp, const u32 ifindex)
{
	struct xdp_buff *ctx = (struct xdp_buff *)xdp;
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return dev_get_by_index_rcu(net, ifindex);
}

static struct net_device *get_dev_skb(struct sk_buff *skb, const u32 ifindex)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return dev_get_by_index_rcu(net, ifindex);
}

__bpf_kfunc_start_defs();

__bpf_kfunc bool
bpf_p4tc_is_net_port(struct sk_buff *skb, const u32 ifindex)
{
	struct net_device *dev;

	dev = get_dev_skb(skb, ifindex);
	if (!dev)
		return false;

	return dev->group == P4TC_PORT_FROM_NET;
}

__bpf_kfunc bool
bpf_p4tc_is_host_port(struct sk_buff *skb, const u32 ifindex)
{
	struct net_device *dev;

	dev = get_dev_skb(skb, ifindex);
	if (!dev)
		return false;

	return dev->group == P4TC_PORT_FROM_HOST;
}

__bpf_kfunc bool
xdp_p4tc_is_net_port(struct xdp_buff *xdp, const u32 ifindex)
{
	struct net_device *dev;

	dev = get_dev_xdp(xdp, ifindex);
	if (!dev)
		return false;

	return dev->group == P4TC_PORT_FROM_NET;
}

__bpf_kfunc bool
xdp_p4tc_is_host_port(struct xdp_buff *xdp, const u32 ifindex)
{
	struct net_device *dev;

	dev = get_dev_xdp(xdp, ifindex);
	if (!dev)
		return false;

	return dev->group == P4TC_PORT_FROM_HOST;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(p4tc_kfunc_check_ext_is_net_or_host_port_set)
BTF_ID_FLAGS(func, bpf_p4tc_is_net_port);
BTF_ID_FLAGS(func, bpf_p4tc_is_host_port);
BTF_ID_FLAGS(func, xdp_p4tc_is_host_port);
BTF_KFUNCS_END(p4tc_kfunc_check_ext_is_net_or_host_port_set)

static const struct btf_kfunc_id_set
p4tc_kfunc_ext_is_net_or_host_port_id_set = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_check_ext_is_net_or_host_port_set,
};

static struct p4tc_extern_ops ext_is_net_port_ops = {
	.kind		= "ext_is_net_port",
	.id		= EXTERN_IS_NET_PORT,
	.owner		= THIS_MODULE,
};

static struct p4tc_extern_ops ext_is_host_port_ops = {
	.kind		= "ext_is_host_port",
	.id		= EXTERN_IS_HOST_PORT,
	.owner		= THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("is_net/host_port extern");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ext_is_host_port");

static int __init counter_init_module(void)
{
	int ret = p4tc_register_extern(&ext_is_net_port_ops);

	if (ret < 0) {
		pr_info("Failed to register is_net_port TC extern");
		return ret;
	}

	ret = p4tc_register_extern(&ext_is_host_port_ops);
	if (ret < 0) {
		pr_info("Failed to register is_host_port TC kfuncs");
		goto unregister_is_net_port;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_is_net_or_host_port_id_set);
	if (ret < 0) {
		pr_info("Failed to register is_net/host_port TC kfuncs");
		goto unregister_is_host_port;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&p4tc_kfunc_ext_is_net_or_host_port_id_set);
	if (ret < 0) {
		pr_info("Failed to register is_net/host_port XDP kfuncs");
		goto unregister_is_host_port;
	}

	return ret;

unregister_is_host_port:
	p4tc_unregister_extern(&ext_is_host_port_ops);
unregister_is_net_port:
	p4tc_unregister_extern(&ext_is_net_port_ops);
	return ret;
}

static void __exit counter_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_is_net_port_ops);
	p4tc_unregister_extern(&ext_is_host_port_ops);
}

module_init(counter_init_module);
module_exit(counter_cleanup_module);
