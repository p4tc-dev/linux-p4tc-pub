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
#include <net/p4_types.h>

#define P4TC_DEFAULT_NUM_TCLASSES 1
#define P4TC_DEFAULT_MAX_RULES 1
#define P4TC_MAXMETA_OFFSET 512
#define P4TC_PATH_MAX 3
#define P4TC_DEFAULT_TCOUNT 64
#define P4TC_DEFAULT_TINST_COUNT 1
#define P4TC_MAX_TINSTS 512
#define P4TC_MAX_TENTRIES (2 << 23)
#define P4TC_DEFAULT_TENTRIES 256
#define P4TC_MAX_TMASKS 128
#define P4TC_DEFAULT_TMASKS 8
#define P4TC_MAX_TIENTRIES 512
#define P4TC_DEFAULT_TIENTRIES 128
#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_MID_IDX 1
#define P4TC_TBCID_IDX 1
#define P4TC_TIID_IDX 2
#define P4TC_AID_IDX 1
#define P4TC_PARSEID_IDX 1
#define P4TC_HDRFIELDID_IDX 2

extern struct idr pipeline_idr;

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
	struct rhashtable_iter *iter;
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
	void (*init)(void);
	struct p4tc_template_common *
	(*cu)(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	      char **pname, u32 *ids, struct netlink_ext_ack *extack);
	int (*put)(struct net *net, struct p4tc_template_common *tmpl,
		   struct netlink_ext_ack *extack);
	/* XXX: Triple check to see if it's really ok not to have net as an argument */
	int (*gd)(struct net *net, struct sk_buff *skb, struct nlmsghdr *n,
		  struct nlattr *nla,  char **p_name, u32 *ids,
		  struct netlink_ext_ack *extack);
	int (*fill_nlmsg)(struct net *net, struct sk_buff *skb,
			  struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack);
	int (*dump)(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
		    struct nlattr *nla, char **p_name,
		    u32 *ids, struct netlink_ext_ack *extack);
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
	struct idr                  p_meta_idr;
	struct idr                  p_tbc_idr;
	struct idr                  p_act_idr;
	struct rcu_head             rcu;
	struct p4tc_parser          *parser;
	struct tc_action            **preacts;
	int                         num_preacts;
	struct tc_action            **postacts;
	int                         num_postacts;
	u32                         max_rules;
	u32                         p_meta_offset;
	refcount_t                  p_ref;
	refcount_t                  p_ctrl_ref;
	u16                         num_table_classes;
	u16                         curr_table_classes;
	u8                          p_state;
};

int tcf_p4_tmpl_generic_dump(struct sk_buff *skb,
			     struct p4tc_dump_ctx *ctx,
			     struct idr *idr, int idx,
			     struct netlink_ext_ack *extack);

struct tca_meta_value_ops {
	void *(*fetch)(struct sk_buff *skb, void *value);
};

struct p4tc_metadata {
	struct p4tc_template_common common;
	struct rcu_head             rcu;
	struct tca_meta_value_ops   m_value_ops;
	u32                         m_id;
	u32                         m_skb_off;
	refcount_t                  m_ref;
	u16                         m_sz;
	u16                         m_startbit; /* Relative to its container */
	u16                         m_endbit; /* Relative to its container */
	u8                          m_datatype; /* T_XXX */
	u32                         PAD0;
};

extern const struct p4tc_template_ops p4tc_meta_ops;

struct p4tc_table_key {
	struct tc_action **key_acts;
	int              key_num_acts;
	u32              key_id;
};

struct p4tc_table_class {
	struct p4tc_template_common common;
	struct idr                  tbc_keys_idr;
	struct idr                  tbc_ti_idr;
	struct tca_meta_value_ops   tbc_value_ops;
	struct tc_action            **tbc_preacts;
	int                         tbc_num_preacts;
	struct tc_action            **tbc_postacts;
	int                         tbc_num_postacts;
	u32                         tbc_count;
	u32                         tbc_curr_count;
	u32                         tbc_keysz;
	u32                         tbc_id;
	u32                         tbc_keys_count;
	u32                         tbc_max_entries;
	u32                         tbc_max_masks;
	u32                         tbc_curr_used_entries;
	u32                         tbc_default_key;
	refcount_t                  tbc_ctrl_ref;
	refcount_t                  tbc_ref;
};

extern const struct p4tc_template_ops p4tc_tclass_ops;

struct p4tc_table_instance {
	struct p4tc_template_common common;
	struct rhash_head ht_node;
	struct rhltable   ti_entries;
	struct idr        ti_masks_idr;
	struct idr        ti_prio_idr;
	spinlock_t        ti_masks_idr_lock;
	spinlock_t        ti_prio_idr_lock;
	u32               tbc_id;
	u32               ti_id;
	u32               ti_max_entries;
	refcount_t        ti_ref;
	refcount_t        ti_ctrl_ref;
	refcount_t        ti_entries_ref;
};

extern struct p4tc_table_instance *
tcf_tinst_find_byany(struct nlattr *name_attr,
	   const u32 ti_id,
	   struct p4tc_pipeline *pipeline,
	   struct p4tc_table_class *tclass,
	   struct netlink_ext_ack *extack);

extern const struct p4tc_template_ops p4tc_tinst_ops;

struct p4tc_ipv4_param_value {
	u32 value;
	u32 mask;
};

struct p4tc_act_param {
	char            name[ACTPARAMNAMSIZ];
	void            *value;
	void            *mask;
	u32             type;
	u32             id;
	struct rcu_head	rcu;
};

struct p4tc_act_param_ops;

struct p4tc_act_param_ops {
	int (*init_value)(struct net *net, struct p4tc_act_param_ops *op,
			  struct p4tc_act_param *nparam,
			  struct nlattr **tb, struct netlink_ext_ack *extack);
	int (*dump_value)(struct sk_buff *skb, struct p4tc_act_param_ops *op,
			   struct p4tc_act_param *param);
	void (*free)(struct p4tc_act_param *param);
	u32 len;
	u32 alloc_len;
};

struct p4tc_act {
	struct p4tc_template_common common;
	struct tc_action_ops        ops;
	struct pernet_operations    *p4_net_ops;
	struct idr                  params_idr;
	struct tcf_exts             exts;
	u32                         a_id;
	bool                        active;
};
extern const struct p4tc_template_ops p4tc_act_ops;
extern const struct rhashtable_params acts_params;

extern const struct rhashtable_params entry_hlt_params;

struct p4tc_table_entry_key {
	u8  *value;
	u8  *unmasked_key;
	u16 keysz;
};

struct p4tc_table_entry_mask {
	struct rcu_head	 rcu;
	u32              sz;
	u32              mask_id;
	refcount_t       mask_ref;
	u8               *value;
};

struct p4tc_table_entry {
	struct p4tc_table_entry_key      key;
	struct p4tc_table_entry_tm __rcu *tm;
	u32                              prio;
	u32                              mask_id;
	struct tc_action                 **acts;
	int                              num_acts;
	struct rhlist_head               ht_node;
	struct list_head                 list;
	struct rcu_head                  rcu;
	refcount_t                       entries_ref;
	u16                              who_created;
	u16                              who_updated;
};

extern const struct nla_policy p4tc_root_policy[P4TC_ROOT_MAX + 1];
extern const struct nla_policy p4tc_policy[P4TC_MAX + 1];
struct p4tc_table_entry *
p4tc_table_entry_lookup(struct sk_buff *skb, struct p4tc_table_instance *tinst,
			u32 keysz);

struct p4tc_parser {
	char parser_name[PARSERNAMSIZ];
	struct idr hdr_fields_idr;
#ifdef CONFIG_KPARSER
	const struct kparser_parser *kparser;
#endif
	refcount_t parser_ref;
	u32 parser_inst_id;
};

struct p4tc_header_field {
	struct p4tc_template_common common;
	struct p4tc_parser          *parser;
	struct tca_meta_value_ops   h_value_ops;
	u32                         parser_inst_id;
	u32                         hdr_field_id;
	u16                         startbit;
	u16                         endbit;
	u8                          datatype; /* T_XXX */
};
extern const struct p4tc_template_ops p4tc_hdrfield_ops;

struct p4tc_pipeline *
tcf_pipeline_find_byany(const char *p_name, const u32 pipeid,
	      struct netlink_ext_ack *extack);
struct p4tc_pipeline *tcf_pipeline_find_byid(const u32 pipeid);
struct p4tc_pipeline *tcf_pipeline_get(const char *p_name, const u32 pipeid,
				       struct netlink_ext_ack *extack);
void __tcf_pipeline_put(struct p4tc_pipeline *pipeline);
struct p4tc_pipeline *
tcf_pipeline_find_byany_unsealed(const char *p_name, const u32 pipeid,
				 struct netlink_ext_ack *extack);
struct p4tc_metadata *
tcf_meta_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
		    const u32 m_id, struct netlink_ext_ack *extack);
struct p4tc_metadata *tcf_meta_find_byid(struct p4tc_pipeline *pipeline,
					 u32 m_id);
void tcf_meta_set_offsets(struct p4tc_pipeline *pipeline);

static inline bool pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}

static inline int p4tc_action_init(struct net *net, struct nlattr *nla,
				   struct tc_action *acts[], u32 flags,
				   struct netlink_ext_ack *extack)
{
	int init_res[TCA_ACT_MAX_PRIO];
	size_t attrs_size;
	int ret;

	/* If action was already created, just bind to existing one*/
	flags |= TCA_ACT_FLAGS_BIND;
	ret = tcf_action_init(net, NULL, nla, NULL, acts, init_res,
			      &attrs_size, flags, 0, extack);

	return ret;
}

static inline struct p4tc_skb_ext *p4tc_skb_ext_alloc(struct sk_buff *skb)
{
	struct p4tc_skb_ext *p4tc_skb_ext = skb_ext_add(skb, P4TC_SKB_EXT);

	if (!p4tc_skb_ext)
		return NULL;

	p4tc_skb_ext->p4tc_ext = kzalloc(sizeof(struct __p4tc_skb_ext),
					 GFP_ATOMIC);
	if (!p4tc_skb_ext->p4tc_ext)
		return NULL;

	return p4tc_skb_ext;
}

struct p4tc_table_class *
tcf_tclass_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
		      const u32 tbc_id, struct netlink_ext_ack *extack);
struct p4tc_table_class *tcf_tclass_find_byid(struct p4tc_pipeline *pipeline,
					      const u32 tbc_id);
struct p4tc_table_key *tcf_table_key_find(struct p4tc_table_class *tclass,
					  const u32 key_id);
void *tcf_tclass_fetch(struct sk_buff *skb, void *tbc_value_ops);

int p4tc_tinst_init(struct p4tc_table_instance *tinst,
		    struct p4tc_pipeline *pipeline,
		    const char *ti_name,
		    struct p4tc_table_class *tclass,
		    u32 max_entries);

void tcf_table_entry_destroy_hash(void *ptr, void *arg);

struct p4tc_parser *tcf_parser_create(struct p4tc_pipeline *pipeline,
				      const char *parser_name,
				      u32 parser_inst_id,
				      struct netlink_ext_ack *extack);
struct p4tc_parser *tcf_parser_find_byid(struct p4tc_pipeline *pipeline,
					 const u32 parser_inst_id);
struct p4tc_parser *tcf_parser_find_byany(struct p4tc_pipeline *pipeline,
					  struct nlattr *name_attr,
					  u32 parser_inst_id,
					  struct netlink_ext_ack *extack);
int tcf_parser_del(struct p4tc_pipeline *pipeline,
		   struct p4tc_parser *parser, struct netlink_ext_ack *extack);
bool tcf_parser_is_callable(struct p4tc_parser *parser);
int tcf_skb_parse(struct sk_buff *skb, struct p4tc_skb_ext *p4tc_ext,
		  struct p4tc_parser *parser);
struct p4tc_header_field *tcf_hdrfield_find_byid(struct p4tc_parser *parser,
						 const u32 hdrfield_id);
bool tcf_parser_check_hdrfields(struct p4tc_parser *parser,
				struct p4tc_header_field *hdrfield);

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define to_meta(t) ((struct p4tc_metadata *)t)
#define to_tclass(t) ((struct p4tc_table_class *)t)
#define to_tinst(t) ((struct p4tc_table_instance *)t)
#define to_act(t) ((struct p4tc_act *)t)
#define to_hdrfield(t) ((struct p4tc_header_field *)t)

#endif
