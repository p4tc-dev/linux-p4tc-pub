/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_ACT_P4_H
#define __NET_TC_ACT_P4_H

#include <net/pkt_cls.h>
#include <net/act_api.h>

struct tcf_p4act_params {
	struct tcf_exts exts;
	struct idr params_idr;
	struct p4tc_act_param **params_array;
	struct rcu_head rcu;
	u32 num_params;
	u32 tot_params_sz;
};
#define P4TC_MAX_PARAM_DATA_SIZE 124

struct p4tc_table_entry_act_bpf {
	u32 act_id;
	u8 params[P4TC_MAX_PARAM_DATA_SIZE];
} __packed;

struct p4tc_table_entry_act_bpf_kern {
	struct rcu_head rcu;
	struct p4tc_table_entry_act_bpf act_bpf;
} __packed;


struct tcf_p4act {
	struct tc_action common;
	/* Params IDR reference passed during runtime */
	struct tcf_p4act_params __rcu *params;
	struct p4tc_table_entry_act_bpf_kern __rcu *act_bpf;
	u32 p_id;
	u32 act_id;
	struct list_head node;
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

#endif /* __NET_TC_ACT_P4_H */
