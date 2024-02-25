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
#define P4TC_DEFAULT_TENTRIES 256
#define P4TC_MAX_TMASKS 1024
#define P4TC_DEFAULT_TMASKS 8
#define P4TC_MAX_T_AGING_MS 864000000
#define P4TC_DEFAULT_T_AGING_MS 30000
#define P4TC_DEFAULT_NUM_TIMER_PROFILES 4
#define P4TC_MAX_NUM_TIMER_PROFILES P4TC_MSGBATCH_SIZE

#define P4TC_TIMER_PROFILE_ZERO_AGING_MS 30000
#define P4TC_DEFAULT_TIMER_PROFILE_ID 0

#define P4TC_MAX_PERMISSION (GENMASK(P4TC_PERM_MAX_BIT, 0))

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_TBLID_IDX 1
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
	struct idr                  p_tbl_idr;
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

struct p4tc_act *p4a_runt_find(struct net *net,
			       const struct tc_action_ops *a_o,
			       struct netlink_ext_ack *extack);
void
p4a_runt_prealloc_put(struct p4tc_act *act, struct tcf_p4act *p4_act);

static inline bool p4tc_pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}

static inline int p4tc_action_destroy(struct tc_action *acts[])
{
	struct tc_action *acts_non_prealloc[TCA_ACT_MAX_PRIO] = {NULL};
	struct tc_action *a;
	int ret = 0;
	int j = 0;
	int i;

	tcf_act_for_each_action(i, a, acts) {
		if (acts[i]->tcfa_flags & TCA_ACT_FLAGS_PREALLOC) {
			struct tcf_p4act *p4act;
			struct p4tc_act *act;
			struct net *net;

			p4act = (struct tcf_p4act *)acts[i];
			net = maybe_get_net(acts[i]->idrinfo->net);

			if (net) {
				const struct tc_action_ops *ops;

				ops = acts[i]->ops;
				act = p4a_runt_find(net, ops, NULL);
				p4a_runt_prealloc_put(act, p4act);
				put_net(net);
			} else {
				/* If net is coming down, template
				 * action will be deleted, so no need to
				 * remove from prealloc list, just decr
				 * refcounts.
				 */
				acts_non_prealloc[j] = acts[i];
				j++;
			}
		} else {
			acts_non_prealloc[j] = acts[i];
			j++;
		}
	}

	ret = tcf_action_destroy(acts_non_prealloc, TCA_ACT_UNBIND);

	return ret;
}

#define P4TC_CONTROL_PERMISSIONS (GENMASK(13, 7))
#define P4TC_DATA_PERMISSIONS (GENMASK(6, 0))

#define P4TC_TABLE_DEFAULT_PERMISSIONS                                   \
	((GENMASK(P4TC_CTRL_PERM_C_BIT, P4TC_CTRL_PERM_D_BIT)) | \
	 P4TC_CTRL_PERM_P | P4TC_CTRL_PERM_S | P4TC_DATA_PERM_R | \
	 P4TC_DATA_PERM_X)

#define P4TC_PERMISSIONS_UNINIT (1 << P4TC_PERM_MAX_BIT)

struct p4tc_table_defact {
	struct tc_action *acts[2];
	/* Will have two 7 bits blocks containing CRUDXPS (Create, read, update,
	 * delete, execute, publish and subscribe) permissions for control plane
	 * and data plane. The first 5 bits are for control and the next five
	 * are for data plane. |crudxpscrudxps| if we were to denote it as UNIX
	 * permission flags.
	 */
	__u16 perm;
	struct rcu_head  rcu;
};

struct p4tc_table_perm {
	__u16           permissions;
	struct rcu_head rcu;
};

struct p4tc_table {
	struct p4tc_template_common         common;
	struct list_head                    tbl_acts_list;
	struct idr                          tbl_masks_idr;
	struct ida                          tbl_prio_ida;
	struct xarray                       tbl_profiles_xa;
	struct rhltable                     tbl_entries;
	/* Mutex that protects tbl_profiles_xa */
	struct mutex                        tbl_profiles_xa_lock;
	struct p4tc_table_defact __rcu      *tbl_dflt_hitact;
	struct p4tc_table_defact __rcu      *tbl_dflt_missact;
	struct p4tc_table_perm __rcu        *tbl_permissions;
	struct p4tc_table_entry_mask __rcu  **tbl_masks_array;
	unsigned long __rcu                 *tbl_free_masks_bitmap;
	/* Locks the available masks IDR which will be used when adding and
	 * deleting table entries.
	 */
	spinlock_t                          tbl_masks_idr_lock;
	u32                                 tbl_keysz;
	u32                                 tbl_id;
	u32                                 tbl_max_entries;
	u32                                 tbl_max_masks;
	u32                                 tbl_curr_num_masks;
	atomic_t                            tbl_num_timer_profiles;
	/* Accounts for how many entities refer to this table. Usually just the
	 * pipeline it belongs to.
	 */
	refcount_t                          tbl_ctrl_ref;
	u16                                 tbl_type;
	u16                                 __pad0;
};

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
	atomic_t                    num_insts;
	bool                        active;
	char                        fullname[ACTNAMSIZ];
};

struct p4tc_table_act {
	struct list_head node;
	struct p4tc_act *act;
	u8     flags;
};

struct p4tc_table_timer_profile {
	struct rcu_head rcu;
	u64 aging_ms;
	u32 profile_id;
};

static inline int p4tc_action_init(struct net *net, struct nlattr *nla,
				   struct tc_action *acts[], u32 pipeid,
				   u32 flags, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[TCA_ACT_MAX_PRIO + 1] = {};
	int init_res[TCA_ACT_MAX_PRIO];
	struct tc_action *a;
	size_t attrs_size;
	size_t nacts = 0;
	int ret;
	int i;

	ret = nla_parse_nested_deprecated(tb, TCA_ACT_MAX_PRIO, nla, NULL,
					  extack);
	if (ret < 0)
		return ret;

	for (i = 1; i < TCA_ACT_MAX_PRIO + 1; i++)
		nacts += !!tb[i];

	if (nacts > 1) {
		NL_SET_ERR_MSG(extack, "Only one action is allowed");
		return -E2BIG;
	}

	/* If action was already created, just bind to existing one */
	flags |= TCA_ACT_FLAGS_BIND;
	flags |= TCA_ACT_FLAGS_FROM_P4TC;
	ret = tcf_action_init(net, NULL, nla, NULL, acts, init_res, &attrs_size,
			      flags, 0, extack);

	/* Check if we are trying to bind to dynamic action from different
	 * pipeline.
	 */
	tcf_act_for_each_action(i, a, acts) {
		struct tcf_p4act *p;

		if (a->ops->id <= TCA_ID_MAX)
			continue;

		p = to_p4act(a);
		if (p->p_id != pipeid) {
			NL_SET_ERR_MSG(extack,
				       "Unable to bind to dynact from different pipeline");
			ret = -EPERM;
			goto destroy_acts;
		}
	}

	return ret;

destroy_acts:
	p4tc_action_destroy(acts);
	return ret;
}

struct p4tc_act *p4a_tmpl_get(struct p4tc_pipeline *pipeline,
			      const char *act_name, const u32 a_id,
			      struct netlink_ext_ack *extack);
struct p4tc_act *p4a_tmpl_find_byid(struct p4tc_pipeline *pipeline,
				    const u32 a_id);

static inline bool p4tc_action_put_ref(struct p4tc_act *act)
{
	return refcount_dec_not_one(&act->a_ref);
}

struct p4tc_act_param *p4a_parm_find_byid(struct idr *params_idr,
					  const u32 param_id);
struct p4tc_act_param *
p4a_parm_find_byany(struct p4tc_act *act, const char *param_name,
		    const u32 param_id, struct netlink_ext_ack *extack);

struct p4tc_table *p4tc_table_find_byany(struct p4tc_pipeline *pipeline,
					 const char *tblname, const u32 tbl_id,
					 struct netlink_ext_ack *extack);
struct p4tc_table *p4tc_table_find_byid(struct p4tc_pipeline *pipeline,
					const u32 tbl_id);
int p4tc_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
				   struct netlink_ext_ack *extack);
void p4tc_table_put_mask_array(struct p4tc_pipeline *pipeline);
struct p4tc_table *p4tc_table_find_get(struct p4tc_pipeline *pipeline,
				       const char *tblname, const u32 tbl_id,
				       struct netlink_ext_ack *extack);

static inline bool p4tc_table_put_ref(struct p4tc_table *table)
{
	return refcount_dec_not_one(&table->tbl_ctrl_ref);
}

struct p4tc_table_defact_params {
	struct p4tc_table_defact *hitact;
	struct p4tc_table_defact *missact;
	struct nlattr *nla_hit;
	struct nlattr *nla_miss;
};

int p4tc_table_init_default_acts(struct net *net,
				 struct p4tc_table_defact_params *dflt,
				 struct p4tc_table *table,
				 struct list_head *acts_list,
				 struct netlink_ext_ack *extack);

static inline bool p4tc_table_act_is_noaction(struct p4tc_table_act *table_act)
{
	return !table_act->act->common.p_id && !table_act->act->a_id;
}

static inline bool p4tc_table_defact_is_noaction(struct tcf_p4act *p4_defact)
{
	return !p4_defact->p_id && !p4_defact->act_id;
}

static inline void p4tc_table_defacts_acts_copy(struct p4tc_table_defact *dst,
						struct p4tc_table_defact *src)
{
	dst->acts[0] = src->acts[0];
	dst->acts[1] = NULL;
}

void p4tc_table_replace_default_acts(struct p4tc_table *table,
				     struct p4tc_table_defact_params *dflt,
				     bool lock_rtnl);

struct p4tc_table_perm *
p4tc_table_init_permissions(struct p4tc_table *table, u16 permissions,
			    struct netlink_ext_ack *extack);
void p4tc_table_replace_permissions(struct p4tc_table *table,
				    struct p4tc_table_perm *tbl_perm,
				    bool lock_rtnl);

struct tcf_p4act *
p4a_runt_prealloc_get_next(struct p4tc_act *act);
void p4a_runt_prealloc_reference(struct p4tc_act *act, struct tcf_p4act *p4act);
void p4a_runt_parm_destroy(struct p4tc_act_param *parm);
struct p4tc_act_param *
p4a_runt_parm_init(struct net *net, struct p4tc_act *act,
		   struct nlattr *nla, struct netlink_ext_ack *extack);

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define p4tc_to_act(t) ((struct p4tc_act *)t)
#define p4tc_to_table(t) ((struct p4tc_table *)t)

#endif
