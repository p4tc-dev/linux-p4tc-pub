/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TC_H
#define __NET_P4TC_H

#include <uapi/linux/p4tc.h>
#include <linux/workqueue.h>
#include <net/sch_generic.h>
#include <net/net_namespace.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/rhashtable-types.h>

#define P4TC_DEFAULT_NUM_TCLASSES 1
#define P4TC_DEFAULT_MAX_RULES 1
#define P4TC_PATH_MAX 3

#define P4TC_PID_IDX 0

extern struct idr pipeline_idr;

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
};

struct p4tc_template_common;

/* Redefine these macros to avoid -Wenum-compare warnings */

#define __P4T_IS_UINT_TYPE(tp)						\
	(tp == P4T_U8 || tp == P4T_U16 || tp == P4T_U32 || tp == P4T_U64)

#define P4T_ENSURE_UINT_OR_BINARY_TYPE(tp)		\
	(__NLA_ENSURE(__P4T_IS_UINT_TYPE(tp) ||	\
		      tp == P4T_MSECS ||		\
		      tp == P4T_BINARY) + tp)

#define P4T_POLICY_RANGE(tp, _min, _max) {		\
	.type = P4T_ENSURE_UINT_OR_BINARY_TYPE(tp),	\
	.validation_type = NLA_VALIDATE_RANGE,		\
	.min = _min,					\
	.max = _max,					\
}

struct p4tc_template_ops {
	struct p4tc_template_common *
	(*cu)(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	      char **pname, u32 *ids, struct netlink_ext_ack *extack);
	int (*put)(struct p4tc_template_common *tmpl,
		   struct netlink_ext_ack *extack);
	/* XXX: Triple check to see if it's really ok not to have net as an argument */
	int (*gd)(struct sk_buff *skb, struct nlmsghdr *n, char **p_name,
		  u32 *ids, struct netlink_ext_ack *extack);
	int (*fill_nlmsg)(struct sk_buff *skb, struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack);
	int (*dump)(struct sk_buff *skb, struct p4tc_dump_ctx *ctx, struct netlink_ext_ack *extack);
	int (*dump_1)(struct sk_buff *skb, struct p4tc_template_common *common);
};

struct p4tc_template_common {
	char                     name[TEMPLATENAMSZ];
	struct p4tc_template_ops *ops;
	u32                      p_id;
	u32                      PAD0;
};

extern const struct p4tc_template_ops p4tc_pipeline_ops;

struct p4tc_pipeline {
	struct p4tc_template_common common;
	struct rcu_head             rcu;
	struct tc_action            **preacts;
	struct tc_action            **postacts;
	u32                         max_rules;
	refcount_t                  p_ref;
	u16                         num_table_classes;
	u16                         curr_table_classes;
	u8                          p_state;
};

int tcf_p4_tmpl_generic_dump(struct sk_buff *skb,
			     struct p4tc_dump_ctx *ctx,
			     struct idr *idr, int idx,
			     struct netlink_ext_ack *extack);

#define to_pipeline(t) ((struct p4tc_pipeline *)t)

#endif
