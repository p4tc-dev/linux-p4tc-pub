// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2023, Mojatatu Networks
 * Copyright (c) 2022-2023, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/btf_ids.h>
#include <linux/net_namespace.h>
#include <net/p4tc.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/filter.h>

BTF_ID_LIST(btf_p4tc_ids)
BTF_ID(struct, p4tc_table_entry_act_bpf)
BTF_ID(struct, p4tc_table_entry_act_bpf_params)

#define ENTRY_KEY_OFFSET (offsetof(struct p4tc_table_entry_key, fa_key))

struct p4tc_table_entry_act_bpf *
__bpf_p4tc_tbl_read(struct net *caller_net,
		    struct p4tc_table_entry_act_bpf_params *params,
		    void *key, const u32 key__sz)
{
	struct p4tc_table_entry_key *entry_key = (struct p4tc_table_entry_key *)key;
	struct p4tc_table_entry_value *value;
	const u32 pipeid = params->pipeid;
	const u32 tblid = params->tblid;
	struct p4tc_table_entry *entry;
	struct p4tc_table *table;

	entry_key->keysz = (key__sz - ENTRY_KEY_OFFSET) << 3;

	table = p4tc_tbl_cache_lookup(caller_net, pipeid, tblid);
	if (!table)
		return NULL;

	entry = p4tc_table_entry_lookup_direct(table, entry_key);
	if (!entry) {
		struct p4tc_table_defact *defact;

		defact = rcu_dereference(table->tbl_default_missact);
		return defact ? defact->defact_bpf : NULL;
	}

	value = p4tc_table_entry_value(entry);

	return value->act_bpf;
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in vmlinux BTF");
__bpf_kfunc struct p4tc_table_entry_act_bpf *
bpf_skb_p4tc_tbl_read(struct __sk_buff *skb_ctx,
		      struct p4tc_table_entry_act_bpf_params *params,
		      void *key, const u32 key__sz)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct net *caller_net;

	caller_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_tbl_read(caller_net, params, key, key__sz);
}

__bpf_kfunc struct p4tc_table_entry_act_bpf *
bpf_xdp_p4tc_tbl_read(struct xdp_md *xdp_ctx,
		      struct p4tc_table_entry_act_bpf_params *params,
		      void *key, const u32 key__sz)
{
	struct xdp_buff *ctx = (struct xdp_buff *)xdp_ctx;
	struct net *caller_net;

	caller_net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_tbl_read(caller_net, params, key, key__sz);
}

__diag_pop();

BTF_SET8_START(p4tc_kfunc_check_tbl_set_skb)
BTF_ID_FLAGS(func, bpf_skb_p4tc_tbl_read, KF_RET_NULL);
BTF_SET8_END(p4tc_kfunc_check_tbl_set_skb)

static const struct btf_kfunc_id_set p4tc_kfunc_tbl_set_skb = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_check_tbl_set_skb,
};

BTF_SET8_START(p4tc_kfunc_check_tbl_set_xdp)
BTF_ID_FLAGS(func, bpf_xdp_p4tc_tbl_read, KF_RET_NULL);
BTF_SET8_END(p4tc_kfunc_check_tbl_set_xdp)

static const struct btf_kfunc_id_set p4tc_kfunc_tbl_set_xdp = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_check_tbl_set_xdp,
};

int register_p4tc_tbl_bpf(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_tbl_set_skb);
	if (ret < 0)
		return ret;

	/* There is no unregister_btf_kfunc_id_set function */
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					 &p4tc_kfunc_tbl_set_xdp);
}
