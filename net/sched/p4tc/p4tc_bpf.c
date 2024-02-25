// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/btf_ids.h>
#include <linux/net_namespace.h>
#include <net/p4tc.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/xdp.h>

BTF_ID_LIST(btf_p4tc_ids)
BTF_ID(struct, p4tc_table_entry_act_bpf)
BTF_ID(struct, p4tc_table_entry_act_bpf_params)
BTF_ID(struct, p4tc_table_entry_act_bpf)
BTF_ID(struct, p4tc_table_entry_create_bpf_params)

static struct p4tc_table_entry_act_bpf p4tc_no_action_hit_bpf = {
	.hit = 1,
};

static struct p4tc_table_entry_act_bpf *
__bpf_p4tc_tbl_read(struct net *caller_net,
		    struct p4tc_table_entry_act_bpf_params *params,
		    const u32 params__sz,
		    void *key, const u32 key__sz)
{
	struct p4tc_table_entry_key *entry_key = key;
	struct p4tc_table_defact *defact_hit;
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry *entry;
	struct p4tc_table *table;
	u32 pipeid;
	u32 tblid;

	if (!params || !key)
		return NULL;

	if (params__sz != P4TC_ENTRY_ACT_BPF_PARAMS_SZ)
		return NULL;

	pipeid = params->pipeid;
	tblid = params->tblid;

	if (key__sz != P4TC_ENTRY_KEY_SZ_BYTES(entry_key->keysz))
		return NULL;

	table = p4tc_tbl_cache_lookup(caller_net, pipeid, tblid);
	if (!table)
		return NULL;

	if (entry_key->keysz != table->tbl_keysz)
		return NULL;

	entry = p4tc_table_entry_lookup_direct(table, entry_key);
	if (!entry) {
		struct p4tc_table_defact *defact;

		defact = rcu_dereference(table->tbl_dflt_missact);
		return defact ? p4tc_table_entry_act_bpf(defact->acts[0]) :
				NULL;
	}

	value = p4tc_table_entry_value(entry);

	if (value->acts[0])
		return p4tc_table_entry_act_bpf(value->acts[0]);

	defact_hit = rcu_dereference(table->tbl_dflt_hitact);
	return defact_hit ? p4tc_table_entry_act_bpf(defact_hit->acts[0]) :
		&p4tc_no_action_hit_bpf;
}

__bpf_kfunc static struct p4tc_table_entry_act_bpf *
bpf_p4tc_tbl_read(struct sk_buff *skb,
		  struct p4tc_table_entry_act_bpf_params *params,
		  const u32 params__sz,
		  void *key, const u32 key__sz)
{
	struct net *caller_net;

	caller_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_tbl_read(caller_net, params, params__sz, key,
				   key__sz);
}

__bpf_kfunc static struct p4tc_table_entry_act_bpf *
xdp_p4tc_tbl_read(struct xdp_buff *ctx,
		  struct p4tc_table_entry_act_bpf_params *params,
		  const u32 params__sz,
		  void *key, const u32 key__sz)
{
	struct net *caller_net;

	caller_net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_tbl_read(caller_net, params, params__sz, key,
				   key__sz);
}

static int
__bpf_p4tc_entry_create(struct net *net,
			struct p4tc_table_entry_create_bpf_params *params,
			const u32 params__sz,
			void *key, const u32 key__sz,
			struct p4tc_table_entry_act_bpf *act_bpf)
{
	struct p4tc_table_entry_key *entry_key = key;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;

	if (!params || !key)
		return -EINVAL;
	if (key__sz != P4TC_ENTRY_KEY_SZ_BYTES(entry_key->keysz))
		return -EINVAL;

	if (params__sz != P4TC_ENTRY_CREATE_BPF_PARAMS_SZ)
		return -EINVAL;

	pipeline = p4tc_pipeline_find_byid(net, params->pipeid);
	if (!pipeline)
		return -ENOENT;

	table = p4tc_tbl_cache_lookup(net, params->pipeid, params->tblid);
	if (!table)
		return -ENOENT;

	if (entry_key->keysz != table->tbl_keysz)
		return -EINVAL;

	return p4tc_table_entry_create_bpf(pipeline, table, entry_key, act_bpf,
					   params->profile_id);
}

__bpf_kfunc static int
bpf_p4tc_entry_create(struct sk_buff *skb,
		      struct p4tc_table_entry_create_bpf_params *params,
		      const u32 params__sz,
		      void *key, const u32 key__sz)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_entry_create(net, params, params__sz, key, key__sz,
				       &params->act_bpf);
}

__bpf_kfunc static int
xdp_p4tc_entry_create(struct xdp_buff *ctx,
		      struct p4tc_table_entry_create_bpf_params *params,
		      const u32 params__sz,
		      void *key, const u32 key__sz)
{
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_entry_create(net, params, params__sz, key, key__sz,
				       &params->act_bpf);
}

__bpf_kfunc static int
bpf_p4tc_entry_create_on_miss(struct sk_buff *skb,
			      struct p4tc_table_entry_create_bpf_params *params,
			      const u32 params__sz,
			      void *key, const u32 key__sz)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_entry_create(net, params, params__sz, key, key__sz,
				       &params->act_bpf);
}

__bpf_kfunc static int
xdp_p4tc_entry_create_on_miss(struct xdp_buff *ctx,
			      struct p4tc_table_entry_create_bpf_params *params,
			      const u32 params__sz,
			      void *key, const u32 key__sz)
{
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_entry_create(net, params, params__sz, key, key__sz,
				       &params->act_bpf);
}

static int
__bpf_p4tc_entry_update(struct net *net,
			struct p4tc_table_entry_create_bpf_params *params,
			const u32 params__sz,
			void *key, const u32 key__sz,
			struct p4tc_table_entry_act_bpf *act_bpf)
{
	struct p4tc_table_entry_key *entry_key = key;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;

	if (!params || !key)
		return -EINVAL;

	if (key__sz != P4TC_ENTRY_KEY_SZ_BYTES(entry_key->keysz))
		return -EINVAL;

	if (params__sz != P4TC_ENTRY_CREATE_BPF_PARAMS_SZ)
		return -EINVAL;

	pipeline = p4tc_pipeline_find_byid(net, params->pipeid);
	if (!pipeline)
		return -ENOENT;

	table = p4tc_tbl_cache_lookup(net, params->pipeid, params->tblid);
	if (!table)
		return -ENOENT;

	if (entry_key->keysz != table->tbl_keysz)
		return -EINVAL;

	return p4tc_table_entry_update_bpf(pipeline, table, entry_key,
					  act_bpf, params->profile_id);
}

__bpf_kfunc static int
bpf_p4tc_entry_update(struct sk_buff *skb,
		      struct p4tc_table_entry_create_bpf_params *params,
		      const u32 params__sz,
		      void *key, const u32 key__sz)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_entry_update(net, params, params__sz, key, key__sz,
				       &params->act_bpf);
}

__bpf_kfunc static int
xdp_p4tc_entry_update(struct xdp_buff *ctx,
		      struct p4tc_table_entry_create_bpf_params *params,
		      const u32 params__sz,
		      void *key, const u32 key__sz)
{
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_entry_update(net, params, params__sz, key, key__sz,
				       &params->act_bpf);
}

static int
__bpf_p4tc_entry_delete(struct net *net,
			struct p4tc_table_entry_create_bpf_params *params,
			const u32 params__sz,
			void *key, const u32 key__sz)
{
	struct p4tc_table_entry_key *entry_key = key;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;

	if (!params || !key)
		return -EINVAL;

	if (key__sz != P4TC_ENTRY_KEY_SZ_BYTES(entry_key->keysz))
		return -EINVAL;

	if (params__sz != P4TC_ENTRY_CREATE_BPF_PARAMS_SZ)
		return -EINVAL;

	pipeline = p4tc_pipeline_find_byid(net, params->pipeid);
	if (!pipeline)
		return -ENOENT;

	table = p4tc_tbl_cache_lookup(net, params->pipeid, params->tblid);
	if (!table)
		return -ENOENT;

	if (entry_key->keysz != table->tbl_keysz)
		return -EINVAL;

	return p4tc_table_entry_del_bpf(pipeline, table, entry_key);
}

__bpf_kfunc static int
bpf_p4tc_entry_delete(struct sk_buff *skb,
		      struct p4tc_table_entry_create_bpf_params *params,
		      const u32 params__sz,
		      void *key, const u32 key__sz)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __bpf_p4tc_entry_delete(net, params, params__sz, key, key__sz);
}

__bpf_kfunc static int
xdp_p4tc_entry_delete(struct xdp_buff *ctx,
		      struct p4tc_table_entry_create_bpf_params *params,
		      const u32 params__sz,
		      void *key, const u32 key__sz)
{
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return __bpf_p4tc_entry_delete(net, params, params__sz, key, key__sz);
}

BTF_KFUNCS_START(p4tc_kfunc_check_tbl_set_skb)
BTF_ID_FLAGS(func, bpf_p4tc_tbl_read, KF_RET_NULL);
BTF_ID_FLAGS(func, bpf_p4tc_entry_create);
BTF_ID_FLAGS(func, bpf_p4tc_entry_create_on_miss);
BTF_ID_FLAGS(func, bpf_p4tc_entry_update);
BTF_ID_FLAGS(func, bpf_p4tc_entry_delete);
BTF_KFUNCS_END(p4tc_kfunc_check_tbl_set_skb)

static const struct btf_kfunc_id_set p4tc_kfunc_tbl_set_skb = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_check_tbl_set_skb,
};

BTF_KFUNCS_START(p4tc_kfunc_check_tbl_set_xdp)
BTF_ID_FLAGS(func, xdp_p4tc_tbl_read, KF_RET_NULL);
BTF_ID_FLAGS(func, xdp_p4tc_entry_create);
BTF_ID_FLAGS(func, xdp_p4tc_entry_create_on_miss);
BTF_ID_FLAGS(func, xdp_p4tc_entry_update);
BTF_ID_FLAGS(func, xdp_p4tc_entry_delete);
BTF_KFUNCS_END(p4tc_kfunc_check_tbl_set_xdp)

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
