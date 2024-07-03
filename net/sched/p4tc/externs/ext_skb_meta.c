// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/externs/ext_skb_meta.c SKB metadata extern
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
#include <net/p4tc_ext/ext_skb_meta.h>

BTF_ID_LIST(btf_p4tc_ext_skb_meta_ids)
BTF_ID(struct, p4tc_skb_meta_set)
BTF_ID(struct, p4tc_skb_meta_get)

#define EXTERN_SKB_META 0x12000000

__bpf_kfunc_start_defs();

__bpf_kfunc int
bpf_p4tc_skb_meta_set(struct sk_buff *skb,
		      struct p4tc_skb_meta_set *skb_meta_set,
		      u32 skb_meta_set__sz)
{
	if (!skb_meta_set)
		return -EINVAL;

	if (skb_meta_set__sz != P4TC_SKB_META_SET_SZ)
		return -EINVAL;

	if (skb_meta_set->bitmask & P4TC_SKB_META_SET_TSTAMP)
		skb->tstamp = skb_meta_set->tstamp;

	if (skb_meta_set->bitmask & P4TC_SKB_META_SET_MARK)
		skb->mark = skb_meta_set->mark;

	if (skb_meta_set->bitmask & P4TC_SKB_META_SET_CLASSID)
		qdisc_skb_cb(skb)->tc_classid = skb_meta_set->tc_classid;

#if defined(CONFIG_NET_SCHED) || defined(CONFIG_NET_XGRESS)
	if (skb_meta_set->bitmask & P4TC_SKB_META_SET_TC_INDEX)
		skb->tc_index = skb_meta_set->tc_index;
#endif

	if (skb_meta_set->bitmask & P4TC_SKB_META_SET_QMAP)
		skb->queue_mapping = skb_meta_set->queue_mapping;

	if (skb_meta_set->bitmask & P4TC_SKB_META_SET_PROTO)
		skb->protocol = skb_meta_set->protocol;

	return 0;
}

__bpf_kfunc int
bpf_p4tc_skb_meta_get(struct sk_buff *skb,
		      struct p4tc_skb_meta_get *skb_meta_get,
		      u32 skb_meta_get__sz)
{
	int err = 0;

	if (!skb_meta_get)
		return -EINVAL;

	if (skb_meta_get__sz != P4TC_SKB_META_SZ)
		return -EINVAL;

#ifdef CONFIG_NET_XGRESS
	if (skb_meta_get->bitmask & P4TC_SKB_META_GET_AT_INGRESS_BIT)
		skb_meta_get->tc_at_ingress = skb->tc_at_ingress;
#else
	if (skb_meta_get->bitmask & P4TC_SKB_META_GET_AT_INGRESS_BIT) {
		skb_meta_get->bitmask &= ~P4TC_SKB_META_GET_AT_INGRESS_BIT;
		err = -ENOTSUPP;
	}
#endif
#ifdef CONFIG_NET_REDIRECT
	if (skb_meta_get->bitmask & P4TC_SKB_META_GET_FROM_INGRESS_BIT)
		skb_meta_get->from_ingress = skb->from_ingress;
#else
	if (skb_meta_get->bitmask & P4TC_SKB_META_GET_FROM_INGRESS_BIT) {
		skb_meta_get->bitmask &= ~P4TC_SKB_META_GET_FROM_INGRESS_BIT;
		err = -ENOTSUPP;
	}
#endif

	return err;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(p4tc_kfunc_ext_skb_meta)
BTF_ID_FLAGS(func, bpf_p4tc_skb_meta_set);
BTF_ID_FLAGS(func, bpf_p4tc_skb_meta_get);
BTF_KFUNCS_END(p4tc_kfunc_ext_skb_meta)

static const struct btf_kfunc_id_set p4tc_kfunc_ext_skb_meta_set = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_ext_skb_meta,
};

static struct p4tc_extern_ops ext_skb_meta_ops = {
	.kind		= "ext_skb_meta",
	.id		= EXTERN_SKB_META,
	.owner		= THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("P4TC SKB Metadata extern");
MODULE_LICENSE("GPL");

static int __init skb_meta_init_module(void)
{
	int ret = p4tc_register_extern(&ext_skb_meta_ops);
	if (!ret)
		pr_info("SKB extern Loaded\n");

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_skb_meta_set);
	if (ret < 0) {
		p4tc_unregister_extern(&ext_skb_meta_ops);
		pr_info("Failed to register SKB extern kfuncs");
	}

	return ret;
}

static void __exit skb_meta_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_skb_meta_ops);
}

module_init(skb_meta_init_module);
module_exit(skb_meta_cleanup_module);
