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
#define P4TC_MAX_TENTRIES (2 << 23)
#define P4TC_DEFAULT_TENTRIES 256
#define P4TC_MAX_TMASKS 1024
#define P4TC_DEFAULT_TMASKS 8

#define P4TC_MAX_PERMISSION (GENMASK(P4TC_PERM_MAX_BIT, 0))

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_TBLID_IDX 1
#define P4TC_AID_IDX 1
#define P4TC_PARSEID_IDX 1
#define P4TC_HDRFIELDID_IDX 2

#define P4TC_HDRFIELD_IS_VALIDITY_BIT 0x1

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
	struct rhashtable_iter *iter;
};

struct p4tc_template_common;

struct p4tc_nl_pname {
	char                     *data;
	bool                     passed;
};

struct p4tc_pipeline;
struct p4tc_template_ops {
	void (*init)(void);
	struct p4tc_template_common *(*cu)(struct net *net, struct nlmsghdr *n,
					   struct nlattr *nla,
					   struct p4tc_nl_pname *nl_pname,
					   u32 *ids,
					   struct netlink_ext_ack *extack);
	int (*put)(struct p4tc_pipeline *pipeline,
		   struct p4tc_template_common *tmpl,
		   struct netlink_ext_ack *extack);
	int (*gd)(struct net *net, struct sk_buff *skb, struct nlmsghdr *n,
		  struct nlattr *nla, struct p4tc_nl_pname *nl_pname, u32 *ids,
		  struct netlink_ext_ack *extack);
	int (*fill_nlmsg)(struct net *net, struct sk_buff *skb,
			  struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack);
	int (*dump)(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
		    struct nlattr *nla, char **p_name, u32 *ids,
		    struct netlink_ext_ack *extack);
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
	struct idr                  p_act_idr;
	struct idr                  p_tbl_idr;
	struct rcu_head             rcu;
	struct net                  *net;
	struct p4tc_parser          *parser;
	u32                         num_created_acts;
	refcount_t                  p_ctrl_ref;
	u16                         num_tables;
	u16                         curr_tables;
	u8                          p_state;
	refcount_t                  p_hdrs_used;
};

#define P4TC_PIPELINE_MAX_ARRAY 32

struct p4tc_table;

struct p4tc_tbl_cache_key {
	u32 pipeid;
	u32 tblid;
};

extern const struct rhashtable_params tbl_cache_ht_params;

int p4tc_tbl_cache_insert(struct net *net, u32 pipeid, struct p4tc_table *table);
void p4tc_tbl_cache_remove(struct net *net, struct p4tc_table *table);
struct p4tc_table *p4tc_tbl_cache_lookup(struct net *net, u32 pipeid, u32 tblid);

#define P4TC_TBLS_CACHE_SIZE 32

struct p4tc_pipeline_net {
	struct list_head  tbls_cache[P4TC_TBLS_CACHE_SIZE];
	struct idr        pipeline_idr;
};

int tcf_p4_tmpl_generic_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			     struct idr *idr, int idx,
			     struct netlink_ext_ack *extack);

struct p4tc_pipeline *tcf_pipeline_find_byany(struct net *net,
					      const char *p_name,
					      const u32 pipeid,
					      struct netlink_ext_ack *extack);
struct p4tc_pipeline *tcf_pipeline_find_byid(struct net *net, const u32 pipeid);
struct p4tc_pipeline *tcf_pipeline_find_get(struct net *net, const char *p_name,
					    const u32 pipeid,
					    struct netlink_ext_ack *extack);

static inline bool tcf_pipeline_get(struct p4tc_pipeline *pipeline)
{
	return refcount_inc_not_zero(&pipeline->p_ctrl_ref);
}

void tcf_pipeline_put(struct p4tc_pipeline *pipeline);
struct p4tc_pipeline *
tcf_pipeline_find_byany_unsealed(struct net *net, const char *p_name,
				 const u32 pipeid,
				 struct netlink_ext_ack *extack);

static inline bool pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}

static inline int p4tc_action_destroy(struct tc_action **acts)
{
	int ret = 0;

	if (acts) {
		ret = tcf_action_destroy(acts, TCA_ACT_UNBIND);
		kfree(acts);
	}

	return ret;
}

#define P4TC_CONTROL_PERMISSIONS (GENMASK(9, 5))
#define P4TC_DATA_PERMISSIONS (GENMASK(4, 0))

#define P4TC_TABLE_PERMISSIONS                                   \
	((GENMASK(P4TC_CTRL_PERM_C_BIT, P4TC_CTRL_PERM_D_BIT)) | \
	 P4TC_DATA_PERM_R | P4TC_DATA_PERM_X)

#define P4TC_PERMISSIONS_UNINIT (1 << P4TC_PERM_MAX_BIT)

#define P4TC_MAX_PARAM_DATA_SIZE 124

struct p4tc_table_entry_act_bpf {
	u32 act_id;
	u8 params[P4TC_MAX_PARAM_DATA_SIZE];
} __packed;

struct p4tc_table_defact {
	struct tc_action **default_acts;
	struct p4tc_table_entry_act_bpf *defact_bpf;
	/* Will have 2 5 bits blocks containing CRUDX (Create, read, update,
	 * delete, execute) permissions for control plane and data plane.
	 * The first 5 bits are for control and the next five are for data plane.
	 * |crudxcrudx| if we were to denote it as UNIX permission flags.
	 */
	__u16 permissions;
	struct rcu_head  rcu;
};

struct p4tc_table_perm {
	__u16           permissions;
	struct rcu_head rcu;
};

struct p4tc_table {
	struct p4tc_template_common         common;
	struct list_head                    tbl_cache_node;
	struct list_head                    tbl_acts_list;
	struct idr                          tbl_masks_idr;
	struct ida                          tbl_prio_idr;
	struct rhltable                     tbl_entries;
	struct p4tc_table_entry             *tbl_const_entry;
	struct p4tc_table_defact __rcu      *tbl_default_hitact;
	struct p4tc_table_defact __rcu      *tbl_default_missact;
	struct p4tc_table_perm __rcu        *tbl_permissions;
	struct p4tc_table_entry_mask __rcu  **tbl_masks_array;
	unsigned long __rcu                 *tbl_free_masks_bitmap;
	spinlock_t                          tbl_masks_idr_lock;
	u32                                 tbl_keysz;
	u32                                 tbl_id;
	u32                                 tbl_max_entries;
	u32                                 tbl_max_masks;
	u32                                 tbl_curr_num_masks;
	refcount_t                          tbl_entries_ref;
	refcount_t                          tbl_ctrl_ref;
	u16                                 tbl_type;
	u16                                 PAD0;
};

extern const struct p4tc_template_ops p4tc_table_ops;

struct p4tc_ipv4_param_value {
	u32 value;
	u32 mask;
};

struct p4tc_act_param {
	char            name[ACTPARAMNAMSIZ];
	struct list_head head;
	struct rcu_head	rcu;
	void            *value;
	void            *mask;
	struct p4tc_type *type;
	u32             id;
	u32             index;
	u8              flags;
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
	u32                         a_id;
	u32                         num_params;
	bool                        active;
	refcount_t                  a_ref;
};

struct p4tc_table_act {
	struct list_head node;
	struct tc_action_ops *ops;
	u8     flags;
};

extern const struct p4tc_template_ops p4tc_act_ops;

extern const struct rhashtable_params entry_hlt_params;

struct p4tc_table_entry_act_bpf_params {
	u32 pipeid;
	u32 tblid;
};

struct p4tc_table_entry;
struct p4tc_table_entry_work {
	struct work_struct   work;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
};

struct p4tc_table_entry_key {
	u32 keysz;
	/* Key start */
	u32 maskid;
	unsigned char fa_key[] __aligned(8);
};

struct p4tc_table_entry_value {
	u32                              prio;
	int                              num_acts;
	struct tc_action                 **acts;
	struct p4tc_table_entry_act_bpf  *act_bpf;
	refcount_t                       entries_ref;
	u32                              permissions;
	struct p4tc_table_entry_tm __rcu *tm;
	struct p4tc_table_entry_work     *entry_work;
};

struct p4tc_table_entry_mask {
	struct rcu_head	 rcu;
	u32              sz;
	u32              mask_index;
	refcount_t       mask_ref;
	u32              mask_id;
	unsigned char fa_value[] __aligned(8);
};

struct p4tc_table_entry {
	struct rcu_head rcu;
	struct rhlist_head ht_node;
	struct p4tc_table_entry_key key;
	/* fallthrough: key data + value */
};

#define P4TC_KEYSZ_BYTES(bits) (round_up(BITS_TO_BYTES(bits), 8))

static inline void *p4tc_table_entry_value(struct p4tc_table_entry *entry)
{
	return entry->key.fa_key + P4TC_KEYSZ_BYTES(entry->key.keysz);
}

static inline struct p4tc_table_entry_work *
p4tc_table_entry_work(struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_value *value = p4tc_table_entry_value(entry);

	return value->entry_work;
}

extern const struct nla_policy p4tc_root_policy[P4TC_ROOT_MAX + 1];
extern const struct nla_policy p4tc_policy[P4TC_MAX + 1];

struct p4tc_table_entry *
p4tc_table_entry_lookup_direct(struct p4tc_table *table,
			       struct p4tc_table_entry_key *key);


int __tcf_table_entry_del(struct p4tc_pipeline *pipeline,
			  struct p4tc_table *table,
			  struct p4tc_table_entry_key *key,
			  struct p4tc_table_entry_mask *mask, u32 prio);
struct p4tc_table_entry_act_bpf *
tcf_table_entry_create_act_bpf(struct tc_action *action,
			       struct netlink_ext_ack *extack);
int register_p4tc_tbl_bpf(void);

struct p4tc_parser {
	char parser_name[PARSERNAMSIZ];
	struct idr hdr_fields_idr;
	refcount_t parser_ref;
	u32 parser_inst_id;
};

struct p4tc_hdrfield {
	struct p4tc_template_common common;
	struct p4tc_parser          *parser;
	u32                         parser_inst_id;
	u32                         hdrfield_id;
	refcount_t                  hdrfield_ref;
	u16                         startbit;
	u16                         endbit;
	u8                          datatype; /* T_XXX */
	u8                          flags;  /* P4TC_HDRFIELD_FLAGS_* */
};

extern const struct p4tc_template_ops p4tc_hdrfield_ops;

static inline int p4tc_action_init(struct net *net, struct nlattr *nla,
				   struct tc_action *acts[], u32 pipeid,
				   u32 flags, struct netlink_ext_ack *extack)
{
	int init_res[TCA_ACT_MAX_PRIO];
	size_t attrs_size;
	int ret;
	int i;

	/* If action was already created, just bind to existing one*/
	flags |= TCA_ACT_FLAGS_BIND;
	flags |= TCA_ACT_FLAGS_FROM_P4TC;
	ret = tcf_action_init(net, NULL, nla, NULL, acts, init_res, &attrs_size,
			      flags, 0, extack);

	/* Check if we are trying to bind to dynamic action from different pipe */
	for (i = 0; i < TCA_ACT_MAX_PRIO && acts[i]; i++) {
		struct tc_action *a = acts[i];
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
	tcf_action_destroy(acts, TCA_ACT_FLAGS_BIND);
	return ret;
}

struct p4tc_act *tcf_action_find_byid(struct p4tc_pipeline *pipeline,
				      const u32 a_id);
struct p4tc_act *tcf_action_find_byname(const char *act_name,
					struct p4tc_pipeline *pipeline);
struct p4tc_act *tcf_action_find_byany(struct p4tc_pipeline *pipeline,
				       const char *act_name, const u32 a_id,
				       struct netlink_ext_ack *extack);
struct p4tc_act *tcf_action_find_get(struct p4tc_pipeline *pipeline,
				     const char *act_name, const u32 a_id,
				     struct netlink_ext_ack *extack);
void tcf_action_put(struct p4tc_act *act);
int tcf_p4_dyna_template_init(struct net *net, struct tc_action **a,
			      struct p4tc_act *act,
			      struct list_head *params_list,
			      struct tc_act_dyna *parm, u32 flags,
			      struct netlink_ext_ack *extack);
struct p4tc_act_param *tcf_param_find_byid(struct idr *params_idr,
					   const u32 param_id);
struct p4tc_act_param *tcf_param_find_byany(struct p4tc_act *act,
					    const char *param_name,
					    const u32 param_id,
					    struct netlink_ext_ack *extack);

struct p4tc_table *tcf_table_find_byany(struct p4tc_pipeline *pipeline,
					const char *tblname, const u32 tbl_id,
					struct netlink_ext_ack *extack);
struct p4tc_table *tcf_table_find_byid(struct p4tc_pipeline *pipeline,
				       const u32 tbl_id);
int tcf_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
				  struct netlink_ext_ack *extack);
struct p4tc_table *tcf_table_find_get(struct p4tc_pipeline *pipeline,
				      const char *tblname, const u32 tbl_id,
				      struct netlink_ext_ack *extack);
void tcf_table_put_ref(struct p4tc_table *table);

void tcf_table_entry_destroy_hash(void *ptr, void *arg);

struct p4tc_table_entry *
tcf_table_const_entry_cu(struct net *net, struct nlattr *arg,
			 struct p4tc_pipeline *pipeline,
			 struct p4tc_table *table,
			 struct netlink_ext_ack *extack);
int p4tc_tbl_entry_doit(struct net *net, struct sk_buff *skb,
			struct nlmsghdr *n, int cmd,
			struct netlink_ext_ack *extack);
int p4tc_tbl_entry_dumpit(struct net *net, struct sk_buff *skb,
			  struct netlink_callback *cb,
			  struct nlattr *arg, char *p_name);
int p4tc_tbl_entry_fill(struct sk_buff *skb, struct p4tc_table *table,
			struct p4tc_table_entry *entry, u32 tbl_id);

struct p4tc_parser *tcf_parser_create(struct p4tc_pipeline *pipeline,
				      const char *parser_name,
				      u32 parser_inst_id,
				      struct netlink_ext_ack *extack);

struct p4tc_parser *tcf_parser_find_byid(struct p4tc_pipeline *pipeline,
					 const u32 parser_inst_id);
struct p4tc_parser *tcf_parser_find_byany(struct p4tc_pipeline *pipeline,
					  const char *parser_name,
					  u32 parser_inst_id,
					  struct netlink_ext_ack *extack);
int tcf_parser_del(struct net *net, struct p4tc_pipeline *pipeline,
		   struct p4tc_parser *parser, struct netlink_ext_ack *extack);

struct p4tc_hdrfield *tcf_hdrfield_find_byid(struct p4tc_parser *parser,
					     const u32 hdrfield_id);
struct p4tc_hdrfield *tcf_hdrfield_find_byany(struct p4tc_parser *parser,
					      const char *hdrfield_name,
					      u32 hdrfield_id,
					      struct netlink_ext_ack *extack);
struct p4tc_hdrfield *tcf_hdrfield_get(struct p4tc_parser *parser,
				       const char *hdrfield_name,
				       u32 hdrfield_id,
				       struct netlink_ext_ack *extack);
void tcf_hdrfield_put_ref(struct p4tc_hdrfield *hdrfield);

int p4tc_init_net_ops(struct net *net, unsigned int id);
void p4tc_exit_net_ops(struct list_head *net_list, unsigned int id);
int tcf_p4_act_init_params(struct net *net, struct tcf_p4act_params *params,
			   struct p4tc_act *act, struct nlattr *nla,
			   struct netlink_ext_ack *extack);
void tcf_p4_act_params_destroy(struct tcf_p4act_params *params);
int p4_act_init(struct p4tc_act *act, struct nlattr *nla,
		struct p4tc_act_param *params[],
		struct netlink_ext_ack *extack);
void p4_put_many_params(struct idr *params_idr, struct p4tc_act_param *params[],
			int params_count);
void tcf_p4_act_params_destroy_rcu(struct rcu_head *head);
int p4_act_init_params(struct p4tc_act *act, struct nlattr *nla,
		       struct p4tc_act_param *params[], bool update,
		       struct netlink_ext_ack *extack);
extern const struct p4tc_act_param_ops param_ops[P4T_MAX + 1];
int generic_dump_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     struct p4tc_act_param *param);

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define to_hdrfield(t) ((struct p4tc_hdrfield *)t)
#define to_act(t) ((struct p4tc_act *)t)
#define to_table(t) ((struct p4tc_table *)t)

#endif
