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
#define P4TC_MAXMETA_OFFSET 512
#define P4TC_PATH_MAX 3

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_MID_IDX 1
#define P4TC_AID_IDX 1
#define P4TC_PARSEID_IDX 1
#define P4TC_HDRFIELDID_IDX 2

#define P4TC_HDRFIELD_IS_VALIDITY_BIT 0x1

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
	struct rhashtable_iter *iter;
};

struct p4tc_template_common;

/* Redefine these macros to avoid -Wenum-compare warnings */

#define __P4T_IS_UINT_TYPE(tp) \
	(tp == P4T_U8 || tp == P4T_U16 || tp == P4T_U32 || tp == P4T_U64)

#define P4T_ENSURE_UINT_OR_BINARY_TYPE(tp)                         \
	(__NLA_ENSURE(__P4T_IS_UINT_TYPE(tp) || tp == P4T_MSECS || \
		      tp == P4T_BINARY) +                          \
	 tp)

#define P4T_POLICY_RANGE(tp, _min, _max)                            \
	{                                                           \
		.type = P4T_ENSURE_UINT_OR_BINARY_TYPE(tp),         \
		.validation_type = NLA_VALIDATE_RANGE, .min = _min, \
		.max = _max,                                        \
	}

struct p4tc_nl_pname {
	char                     *data;
	bool                     passed;
};

struct p4tc_template_ops {
	void (*init)(void);
	struct p4tc_template_common *(*cu)(struct net *net, struct nlmsghdr *n,
					   struct nlattr *nla,
					   struct p4tc_nl_pname *nl_pname,
					   u32 *ids,
					   struct netlink_ext_ack *extack);
	int (*put)(struct net *net, struct p4tc_template_common *tmpl,
		   bool unconditional_purge, struct netlink_ext_ack *extack);
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

struct p4tc_act_dep_edge_node {
	struct list_head head;
	u32 act_id;
};

struct p4tc_act_dep_node {
	struct list_head incoming_egde_list;
	struct list_head head;
	u32 act_id;
};

struct p4tc_pipeline {
	struct p4tc_template_common common;
	struct idr                  p_meta_idr;
	struct idr                  p_act_idr;
	struct rcu_head             rcu;
	struct net                  *net;
	struct p4tc_parser          *parser;
	struct tc_action            **preacts;
	int                         num_preacts;
	struct tc_action            **postacts;
	int                         num_postacts;
	struct list_head            act_dep_graph;
	struct list_head            act_topological_order;
	u32                         max_rules;
	u32                         p_meta_offset;
	u32                         num_created_acts;
	refcount_t                  p_ref;
	refcount_t                  p_ctrl_ref;
	u16                         num_tables;
	u16                         curr_tables;
	u8                          p_state;
	refcount_t                  p_hdrs_used;
};

struct p4tc_pipeline_net {
	struct idr pipeline_idr;
};

int tcf_p4_tmpl_generic_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			     struct idr *idr, int idx,
			     struct netlink_ext_ack *extack);

struct p4tc_pipeline *tcf_pipeline_find_byany(struct net *net,
					      const char *p_name,
					      const u32 pipeid,
					      struct netlink_ext_ack *extack);
struct p4tc_pipeline *tcf_pipeline_find_byid(struct net *net, const u32 pipeid);
struct p4tc_pipeline *tcf_pipeline_get(struct net *net, const char *p_name,
				       const u32 pipeid,
				       struct netlink_ext_ack *extack);
void __tcf_pipeline_put(struct p4tc_pipeline *pipeline);
struct p4tc_pipeline *
tcf_pipeline_find_byany_unsealed(struct net *net, const char *p_name,
				 const u32 pipeid,
				 struct netlink_ext_ack *extack);

static inline int p4tc_action_destroy(struct tc_action **acts)
{
	int ret = 0;

	if (acts) {
		ret = tcf_action_destroy(acts, TCA_ACT_UNBIND);
		kfree(acts);
	}

	return ret;
}

static inline bool pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}
void tcf_pipeline_add_dep_edge(struct p4tc_pipeline *pipeline,
			       struct p4tc_act_dep_edge_node *edge_node,
			       u32 vertex_id);
bool tcf_pipeline_check_act_backedge(struct p4tc_pipeline *pipeline,
				     struct p4tc_act_dep_edge_node *edge_node,
				     u32 vertex_id);
int determine_act_topological_order(struct p4tc_pipeline *pipeline,
				    bool copy_dep_graph);

struct p4tc_act;
void tcf_pipeline_delete_from_dep_graph(struct p4tc_pipeline *pipeline,
					struct p4tc_act *act);

struct p4tc_metadata {
	struct p4tc_template_common common;
	struct rcu_head             rcu;
	u32                         m_id;
	u32                         m_skb_off;
	refcount_t                  m_ref;
	u16                         m_sz;
	u16                         m_startbit; /* Relative to its container */
	u16                         m_endbit; /* Relative to its container */
	u8                          m_datatype; /* T_XXX */
	bool                        m_read_only;
};

extern const struct p4tc_template_ops p4tc_meta_ops;

struct p4tc_ipv4_param_value {
	u32 value;
	u32 mask;
};

#define P4TC_ACT_PARAM_FLAGS_ISDYN BIT(0)

struct p4tc_act_param {
	char            name[ACTPARAMNAMSIZ];
	struct list_head head;
	struct rcu_head	rcu;
	void            *value;
	void            *mask;
	u32             type;
	u32             id;
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

struct p4tc_label_key {
	char *label;
	u32 labelsz;
};

struct p4tc_label_node {
	struct rhash_head ht_node;
	struct p4tc_label_key key;
	int cmd_offset;
};

struct p4tc_act {
	struct p4tc_template_common common;
	struct tc_action_ops        ops;
	struct rhashtable           *labels;
	struct list_head            cmd_operations;
	struct tc_action_net        *tn;
	struct p4tc_pipeline        *pipeline;
	struct idr                  params_idr;
	struct tcf_exts             exts;
	struct list_head            head;
	u32                         a_id;
	bool                        active;
	refcount_t                  a_ref;
};

extern const struct p4tc_template_ops p4tc_act_ops;
extern const struct rhashtable_params p4tc_label_ht_params;
extern const struct rhashtable_params acts_params;
void p4tc_label_ht_destroy(void *ptr, void *arg);

struct p4tc_parser {
	char parser_name[PARSERNAMSIZ];
	struct idr hdr_fields_idr;
#ifdef CONFIG_KPARSER
	const struct kparser_parser *kparser;
#endif
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

struct p4tc_metadata *tcf_meta_find_byid(struct p4tc_pipeline *pipeline,
					 u32 m_id);
void tcf_meta_fill_user_offsets(struct p4tc_pipeline *pipeline);
void tcf_meta_init(struct p4tc_pipeline *root_pipe);
struct p4tc_metadata *tcf_meta_get(struct p4tc_pipeline *pipeline,
				   const char *mname, const u32 m_id,
				   struct netlink_ext_ack *extack);
void tcf_meta_put_ref(struct p4tc_metadata *meta);
void *tcf_meta_fetch(struct sk_buff *skb, struct p4tc_metadata *meta);

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

		if (a->ops->id < TCA_ID_DYN)
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

static inline struct p4tc_skb_ext *p4tc_skb_ext_alloc(struct sk_buff *skb)
{
	struct p4tc_skb_ext *p4tc_skb_ext = skb_ext_add(skb, P4TC_SKB_EXT);

	if (!p4tc_skb_ext)
		return NULL;

	p4tc_skb_ext->p4tc_ext =
		kzalloc(sizeof(struct __p4tc_skb_ext), GFP_ATOMIC);
	if (!p4tc_skb_ext->p4tc_ext)
		return NULL;

	return p4tc_skb_ext;
}

struct p4tc_act *tcf_action_find_byid(struct p4tc_pipeline *pipeline,
				      const u32 a_id);
struct p4tc_act *tcf_action_find_byname(const char *act_name,
					struct p4tc_pipeline *pipeline);
struct p4tc_act *tcf_action_find_byany(struct p4tc_pipeline *pipeline,
				       const char *act_name, const u32 a_id,
				       struct netlink_ext_ack *extack);
struct p4tc_act *tcf_action_get(struct p4tc_pipeline *pipeline,
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
bool tcf_parser_is_callable(struct p4tc_parser *parser);
int tcf_skb_parse(struct sk_buff *skb, struct p4tc_skb_ext *p4tc_ext,
		  struct p4tc_parser *parser);

struct p4tc_hdrfield *tcf_hdrfield_find_byid(struct p4tc_parser *parser,
					     const u32 hdrfield_id);
struct p4tc_hdrfield *tcf_hdrfield_find_byany(struct p4tc_parser *parser,
					      const char *hdrfield_name,
					      u32 hdrfield_id,
					      struct netlink_ext_ack *extack);
bool tcf_parser_check_hdrfields(struct p4tc_parser *parser,
				struct p4tc_hdrfield *hdrfield);
void *tcf_hdrfield_fetch(struct sk_buff *skb, struct p4tc_hdrfield *hdrfield);
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
#define to_meta(t) ((struct p4tc_metadata *)t)
#define to_hdrfield(t) ((struct p4tc_hdrfield *)t)
#define to_act(t) ((struct p4tc_act *)t)

#endif
