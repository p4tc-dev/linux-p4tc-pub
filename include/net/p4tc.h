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
#include <net/tc_act/p4tc.h>
#include <net/p4tc_types.h>

#define P4TC_DEFAULT_NUM_TABLES P4TC_MINTABLES_COUNT
#define P4TC_DEFAULT_MAX_RULES 1
#define P4TC_PATH_MAX 3
#define P4TC_MAX_TENTRIES 0x2000000

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_AID_IDX 1
#define P4TC_PARSEID_IDX 1

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
	struct rhashtable_iter *iter;
};

struct p4tc_template_common;

struct p4tc_path_nlattrs {
	char                     *pname;
	u32                      *ids;
	bool                     pname_passed;
};

struct p4tc_pipeline;
struct p4tc_template_ops {
	struct p4tc_template_common *(*cu)(struct net *net, struct nlmsghdr *n,
					   struct nlattr *nla,
					   struct p4tc_path_nlattrs *nl_pname,
					   struct netlink_ext_ack *extack);
	int (*put)(struct p4tc_pipeline *pipeline,
		   struct p4tc_template_common *tmpl,
		   struct netlink_ext_ack *extack);
	int (*gd)(struct net *net, struct sk_buff *skb, struct nlmsghdr *n,
		  struct nlattr *nla, struct p4tc_path_nlattrs *nl_pname,
		  struct netlink_ext_ack *extack);
	int (*fill_nlmsg)(struct net *net, struct sk_buff *skb,
			  struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack);
	int (*dump)(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
		    struct nlattr *nla, char **p_name, u32 *ids,
		    struct netlink_ext_ack *extack);
	int (*dump_1)(struct sk_buff *skb, struct p4tc_template_common *common);
	u32 obj_id;
};

struct p4tc_template_common {
	char                     name[P4TC_TMPL_NAMSZ];
	struct p4tc_template_ops *ops;
	u32                      p_id;
	u32                      __pad0;
};

struct p4tc_pipeline {
	struct p4tc_template_common common;
	struct idr                  p_act_idr;
	struct rcu_head             rcu;
	struct net                  *net;
	u32                         num_created_acts;
	/* Accounts for how many entities are referencing this pipeline.
	 * As for now only P4 filters can refer to pipelines.
	 */
	refcount_t                  p_ctrl_ref;
	u16                         num_tables;
	u16                         curr_tables;
	u8                          p_state;
};

struct p4tc_pipeline_net {
	struct idr pipeline_idr;
};

static inline bool p4tc_tmpl_msg_is_update(struct nlmsghdr *n)
{
	return n->nlmsg_type == RTM_UPDATEP4TEMPLATE;
}

int p4tc_tmpl_register_ops(const struct p4tc_template_ops *tmpl_ops);

int p4tc_tmpl_generic_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			   struct idr *idr, int idx,
			   struct netlink_ext_ack *extack);

struct p4tc_pipeline *p4tc_pipeline_find_byany(struct net *net,
					       const char *p_name,
					       const u32 pipeid,
					       struct netlink_ext_ack *extack);
struct p4tc_pipeline *p4tc_pipeline_find_byid(struct net *net,
					      const u32 pipeid);
struct p4tc_pipeline *
p4tc_pipeline_find_get(struct net *net, const char *p_name,
		       const u32 pipeid, struct netlink_ext_ack *extack);

static inline bool p4tc_pipeline_get(struct p4tc_pipeline *pipeline)
{
	return refcount_inc_not_zero(&pipeline->p_ctrl_ref);
}

void p4tc_pipeline_put(struct p4tc_pipeline *pipeline);
struct p4tc_pipeline *
p4tc_pipeline_find_byany_unsealed(struct net *net, const char *p_name,
				  const u32 pipeid,
				  struct netlink_ext_ack *extack);

struct p4tc_act_param {
	struct list_head head;
	struct rcu_head	rcu;
	void            *value;
	void            *mask;
	struct p4tc_type *type;
	u32             id;
	u32             index;
	u16             bitend;
	u8              flags;
	u8              __pad0;
	char            name[P4TC_ACT_PARAM_NAMSIZ];
};

struct p4tc_act_param_ops {
	int (*init_value)(struct net *net, struct p4tc_act_param_ops *op,
			  struct p4tc_act_param *nparam, struct nlattr **tb,
			  struct netlink_ext_ack *extack);
	int (*dump_value)(struct sk_buff *skb, struct p4tc_act_param_ops *op,
			  struct p4tc_act_param *param);
	void (*free)(struct p4tc_act_param *param);
	u32 len;
	u32 alloc_len;
};

struct p4tc_act {
	struct p4tc_template_common common;
	struct tc_action_ops        ops;
	struct tc_action_net        *tn;
	struct p4tc_pipeline        *pipeline;
	struct idr                  params_idr;
	struct tcf_exts             exts;
	struct list_head            head;
	struct list_head            prealloc_list;
	/* Locks the preallocated actions list.
	 * The list will be used whenever a table entry with an action or a
	 * table default action gets created, updated or deleted. Note that
	 * table entries may be added by both control and data path, so the
	 * list can be modified from both contexts.
	 */
	spinlock_t                  list_lock;
	u32                         a_id;
	u32                         num_params;
	u32                         num_prealloc_acts;
	/* Accounts for how many entities refer to this action. Usually just the
	 * pipeline it belongs to.
	 */
	refcount_t                  a_ref;
	bool                        active;
	char                        fullname[ACTNAMSIZ];
};

struct p4tc_act *p4a_tmpl_get(struct p4tc_pipeline *pipeline,
			      const char *act_name, const u32 a_id,
			      struct netlink_ext_ack *extack);
struct p4tc_act *p4a_tmpl_find_byid(struct p4tc_pipeline *pipeline,
				    const u32 a_id);

static inline bool p4tc_action_put_ref(struct p4tc_act *act)
{
	return refcount_dec_not_one(&act->a_ref);
}

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define p4tc_to_act(t) ((struct p4tc_act *)t)

#endif
