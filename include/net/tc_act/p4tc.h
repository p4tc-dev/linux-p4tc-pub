/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_ACT_P4_H
#define __NET_TC_ACT_P4_H

#include <net/pkt_cls.h>
#include <net/act_api.h>

struct tcf_p4act_params {
	struct tcf_exts exts;
	struct idr params_idr;
	struct rcu_head rcu;
};

struct tcf_p4act {
	struct tc_action common;
	/* list of operations */
	struct list_head cmd_operations;
	/* Params IDR reference passed during runtime */
	struct tcf_p4act_params __rcu *params;
	u32 p_id;
	u32 act_id;
};
#define to_p4act(a) ((struct tcf_p4act *)a)

#endif /* __NET_TC_ACT_P4_H */
