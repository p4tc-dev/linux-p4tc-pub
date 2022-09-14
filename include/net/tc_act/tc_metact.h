/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_METACT_H
#define __NET_TC_METACT_H

#include <net/act_api.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <uapi/linux/tc_act/tc_metact.h>
#include <net/p4tc.h>
#include <net/tc_act/p4tc.h>

int tcf_p4_metact_init(struct net *net, struct nlattr *nla,
		       struct nlattr *est, struct tc_action **a,
		       struct tcf_proto *tp, struct tc_action_ops *a_o,
		       u32 flags, struct netlink_ext_ack *extack);
int tcf_metact_parse_cmds(struct net *net, struct list_head *meta_operations,
			  struct nlattr *nla, bool ovr,
			  struct netlink_ext_ack *extack);

int tcf_metact_act(struct sk_buff *skb, const struct tc_action *a,
		   struct tcf_result *res);
int tcf_metact_dump(struct sk_buff *skb, struct tc_action *a, int bind,
		    int ref);
void tcf_metact_cleanup(struct tc_action *a);
int fillup_metact_cmds(struct sk_buff *skb, struct list_head *meta_ops);
void release_ope_list(struct list_head *entries);

struct tca_meta_operate {
	struct list_head meta_operations;
	struct tca_meta_operand *opA;
	struct tca_meta_operand *opB;
	struct tca_meta_operand *opC;
	struct metact_cmd_s *cmd;
	u32 ctl1;
	u32 ctl2;
	u16 op_id;		/* METACT_OP_XXX */
	u8 op_flags;
	u8 op_cnt;
};

struct tcf_metact_info;
struct tca_meta_operand {
	struct tca_meta_value_ops *oper_value_ops;
	void *(*fetch)(struct sk_buff *skb, struct tca_meta_operand *op,
		       struct tcf_metact_info *metact, struct tcf_result *res);
	struct p4tc_type *oper_datatype; /* what is stored in path_or_value - P4T_XXX */
	struct p4tc_type_mask_shift *oper_mask_shift;
	struct tc_action *action;
	void *path_or_value;
	void *priv;
	u32 immedv;		/* one of: immediate value, metadata id, action id */
	u32 immedv2;		/* one of: action instance */
	u32 path_or_value_sz;
	u32 pipeid;		/* 0 for kernel */
	u8 oper_type;		/* METACT_OPER_XXX */
	u8 oper_cbitsize;	/* based on P4T_XXX container size */
	u8 oper_bitsize;	/* diff between bitend - oper_bitend */
	u8 oper_bitstart;
	u8 oper_bitend;
	u8 oper_flags;		/* TBA: DATA_IS_IMMEDIATE */
};

struct metact_cmd_s {
	int cmdid;
	int (*validate_operands)(struct net *net,
				 struct tca_meta_operand *A,
				 struct tca_meta_operand *B,
				 struct tca_meta_operand *C,
				 struct netlink_ext_ack *extack);
	void (*free_operation)(struct tca_meta_operate *op,
			       struct netlink_ext_ack *extack);
	int (*run)(struct sk_buff *skb, struct tca_meta_operate *op,
		   struct tcf_metact_info *metact, struct tcf_result *res);
};

struct tcf_metact_info {
	struct tc_action common;
	/* list of operations */
	struct list_head meta_operations;
	/* Params IDR reference passed during runtime */
	struct tcf_p4act_params __rcu *params;
	u32 p_id;
};
#define to_metact(a) ((struct tcf_metact_info *)a)

#endif /* __NET_TC_METACT_H */
