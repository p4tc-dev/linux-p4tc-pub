// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
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
#ifdef CONFIG_NET_P4_TC_KFUNCS
BTF_ID(struct, p4tc_table_entry_act_bpf)
BTF_ID(struct, p4tc_table_entry_act_bpf_params)
#else
BTF_ID(struct, p4tc_parser_buffer_act_bpf)
#endif

#ifdef CONFIG_NET_P4_TC_KFUNCS
#define ENTRY_KEY_OFFSET (offsetof(struct p4tc_table_entry_key, fa_key))

struct p4tc_table_entry_act_bpf *
__bpf_p4tc_tbl_lookup(struct net *caller_net,
		      struct p4tc_table_entry_act_bpf_params *params,
		      void *key, const u32 key__sz)
{
	struct p4tc_table_entry_key *entry_key = (struct p4tc_table_entry_key *)key;
	const u32 pipeid = params->pipeid;
	const u32 tblid = params->tblid;
	struct p4tc_table_entry_value *value;
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

struct p4tc_table_entry_act_bpf *
bpf_skb_p4tc_tbl_lookup(struct __sk_buff *skb_ctx,
			struct p4tc_table_entry_act_bpf_params *params,
			void *key, const u32 key__sz)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct net *caller_net;

	caller_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_tbl_lookup(caller_net, params, key, key__sz);
}

struct p4tc_table_entry_act_bpf *
bpf_xdp_p4tc_tbl_lookup(struct xdp_md *xdp_ctx,
			struct p4tc_table_entry_act_bpf_params *params,
			void *key, const u32 key__sz)
{
	struct xdp_buff *ctx = (struct xdp_buff *)xdp_ctx;
	struct net *caller_net;

	caller_net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_tbl_lookup(caller_net, params, key, key__sz);
}

#else
struct p4tc_parser_buffer_act_bpf *bpf_p4tc_get_parser_buffer(void)
{
	struct p4tc_percpu_scratchpad *pad;
	struct p4tc_parser_buffer_act_bpf *parser_buffer;

	pad = this_cpu_ptr(&p4tc_percpu_scratchpad);

	parser_buffer = (struct p4tc_parser_buffer_act_bpf *)&pad->hdrs;

	return parser_buffer;
}

int is_p4tc_kfunc(const struct bpf_reg_state *reg)
{
	const struct btf_type *p4tc_parser_type, *t;

	p4tc_parser_type = btf_type_by_id(reg->btf, btf_p4tc_ids[0]);

	t = btf_type_by_id(reg->btf, reg->btf_id);

	return p4tc_parser_type == t;
}
#endif

void bpf_p4tc_set_cookie(u32 cookie)
{
	struct p4tc_percpu_scratchpad *pad;

	pad = this_cpu_ptr(&p4tc_percpu_scratchpad);
	pad->prog_cookie = cookie;
}

BTF_SET8_START(p4tc_tbl_kfunc_set)
#ifdef CONFIG_NET_P4_TC_KFUNCS
BTF_ID_FLAGS(func, bpf_skb_p4tc_tbl_lookup, KF_RET_NULL);
BTF_ID_FLAGS(func, bpf_xdp_p4tc_tbl_lookup, KF_RET_NULL);
#else
BTF_ID_FLAGS(func, bpf_p4tc_get_parser_buffer, 0);
#endif
BTF_ID_FLAGS(func, bpf_p4tc_set_cookie, 0);
BTF_SET8_END(p4tc_tbl_kfunc_set)

static const struct btf_kfunc_id_set p4tc_table_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &p4tc_tbl_kfunc_set,
};

int register_p4tc_tbl_bpf(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_table_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					       &p4tc_table_kfunc_set);

	return ret;
}
