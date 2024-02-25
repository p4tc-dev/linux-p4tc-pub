/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_ACT_P4_H
#define __NET_TC_ACT_P4_H

#include <net/pkt_cls.h>
#include <net/act_api.h>

struct tcf_p4act_params {
	struct idr params_idr;
	struct p4tc_act_param **params_array;
	struct rcu_head rcu;
	u32 num_params;
	u32 tot_params_sz;
};

#define P4TC_MAX_PARAM_DATA_SIZE 124

struct p4tc_table_entry_act_bpf {
	u32 act_id;
	u32 hit:1,
	    is_default_miss_act:1,
	    is_default_hit_act:1;
	u8 params[P4TC_MAX_PARAM_DATA_SIZE];
} __packed;

struct p4tc_table_entry_act_bpf_kern {
	struct rcu_head rcu;
	struct p4tc_table_entry_act_bpf act_bpf;
};

struct tcf_p4act {
	struct tc_action common;
	/* Params IDR reference passed during runtime */
	struct tcf_p4act_params __rcu *params;
	struct p4tc_table_entry_act_bpf_kern __rcu *act_bpf;
	u32 p_id;
	u32 act_id;
	struct list_head node;
	u32 num_runt_params;
};

#define to_p4act(a) ((struct tcf_p4act *)a)

static inline struct p4tc_table_entry_act_bpf *
p4tc_table_entry_act_bpf(struct tc_action *action)
{
	struct p4tc_table_entry_act_bpf_kern *act_bpf;
	struct tcf_p4act *p4act = to_p4act(action);

	act_bpf = rcu_dereference(p4act->act_bpf);

	return &act_bpf->act_bpf;
}

static inline int
p4tc_table_entry_act_bpf_change_flags(struct tc_action *action, u32 hit,
				      u32 dflt_miss, u32 dflt_hit)
{
	struct p4tc_table_entry_act_bpf_kern *act_bpf, *act_bpf_old;
	struct tcf_p4act *p4act = to_p4act(action);

	act_bpf = kzalloc(sizeof(*act_bpf), GFP_KERNEL);
	if (!act_bpf)
		return -ENOMEM;

	spin_lock_bh(&p4act->tcf_lock);
	act_bpf_old = rcu_dereference_protected(p4act->act_bpf, 1);
	act_bpf->act_bpf = act_bpf_old->act_bpf;
	act_bpf->act_bpf.hit = hit;
	act_bpf->act_bpf.is_default_hit_act = dflt_hit;
	act_bpf->act_bpf.is_default_miss_act = dflt_miss;
	rcu_replace_pointer(p4act->act_bpf, act_bpf, 1);
	kfree_rcu(act_bpf_old, rcu);
	spin_unlock_bh(&p4act->tcf_lock);

	return 0;
}

#endif /* __NET_TC_ACT_P4_H */
