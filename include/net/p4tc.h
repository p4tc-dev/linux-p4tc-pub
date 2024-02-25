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

#define P4TC_DEFAULT_NUM_TABLES P4TC_MINTABLES_COUNT
#define P4TC_DEFAULT_MAX_RULES 1
#define P4TC_PATH_MAX 3

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
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
	struct rcu_head             rcu;
	struct net                  *net;
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

#define to_pipeline(t) ((struct p4tc_pipeline *)t)

#endif
