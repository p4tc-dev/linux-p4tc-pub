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

struct tcf_p4act {
	struct tc_action common;
	/* Params IDR reference passed during runtime */
	struct tcf_p4act_params __rcu *params;
	u32 p_id;
	u32 act_id;
	struct list_head node;
	u32 num_runt_params;
};

#define to_p4act(a) ((struct tcf_p4act *)a)

#endif /* __NET_TC_ACT_P4_H */
