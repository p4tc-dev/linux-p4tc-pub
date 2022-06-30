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
#define P4TC_MAXMETA_OFFSET 512
#define P4TC_PATH_MAX 3
#define P4TC_DEFAULT_TCOUNT 64
#define P4TC_DEFAULT_TINST_COUNT 1
#define P4TC_MAX_KEYSZ 128
#define P4TC_MAX_TINSTS 512
#define P4TC_MAX_TENTRIES (2 << 23)
#define P4TC_DEFAULT_TENTRIES 256
#define P4TC_MAX_TMASKS 128
#define P4TC_DEFAULT_TMASKS 8

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_MID_IDX 1
#define P4TC_TBCID_IDX 1

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
	void (*init)(void);
	struct p4tc_template_common *
	(*cu)(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	      char **pname, u32 *ids, struct netlink_ext_ack *extack);
	int (*put)(struct p4tc_template_common *tmpl,
		   struct netlink_ext_ack *extack);
	/* XXX: Triple check to see if it's really ok not to have net as an argument */
	int (*gd)(struct sk_buff *skb, struct nlmsghdr *n, struct nlattr *nla,
		  char **p_name, u32 *ids, struct netlink_ext_ack *extack);
	int (*fill_nlmsg)(struct sk_buff *skb, struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack);
	int (*dump)(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
		    char **p_name, u32 *ids, struct netlink_ext_ack *extack);
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
	struct rcu_head             rcu;
	struct tc_action            **preacts;
	int                         num_preacts;
	struct tc_action            **postacts;
	int                         num_postacts;
	u32                         max_rules;
	u32                         p_meta_offset;
	refcount_t                  p_ref;
	u16                         num_table_classes;
	u16                         curr_table_classes;
	u8                          p_state;
};

int tcf_p4_tmpl_generic_dump(struct sk_buff *skb,
			     struct p4tc_dump_ctx *ctx,
			     struct idr *idr, int idx,
			     struct netlink_ext_ack *extack);

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

static inline bool pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}

struct tca_meta_value_ops {
	void *(*fetch)(struct sk_buff *skb, void *value);
};

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
	struct tca_meta_value_ops   tbc_value_ops;
	struct tc_action            **tbc_preacts;
	int                         tbc_num_preacts;
	struct tc_action            **tbc_postacts;
	int                         tbc_num_postacts;
	u32                         tbc_count;
	u32                         tbc_keysz;
	u32                         tbc_id;
	u32                         tbc_keys_count;
	u32                         tbc_max_entries;
	u32                         tbc_max_masks;
	u32                         tbc_default_key;
	refcount_t                  tbc_ref;
};

extern const struct p4tc_template_ops p4tc_tclass_ops;

struct p4tc_metadata *
tcf_meta_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
		    const u32 m_id, struct netlink_ext_ack *extack);
struct p4tc_metadata *tcf_meta_find_byid(struct p4tc_pipeline *pipeline,
					 u32 m_id);
void tcf_meta_fill_user_offsets(struct p4tc_pipeline *pipeline);

static inline int p4tc_action_init(struct net *net, struct nlattr *nla,
				   struct tc_action *acts[],
				   struct netlink_ext_ack *extack)
{
	int init_res[TCA_ACT_MAX_PRIO];
	size_t attrs_size;
	int ret;
	u32 flags;

	/* If action was already created, just bind to existing one*/
	flags = TCA_ACT_FLAGS_BIND;
	ret = tcf_action_init(net, NULL, nla, NULL, acts, init_res,
			      &attrs_size, flags, 0, extack);

	return ret;
}

struct p4tc_table_class *
tcf_tclass_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
		      const u32 tbc_id, struct netlink_ext_ack *extack);
struct p4tc_table_class *tcf_tclass_find_byid(struct p4tc_pipeline *pipeline,
					      const u32 tbc_id);
struct p4tc_table_key *tcf_table_key_find(struct p4tc_table_class *tclass,
					  const u32 key_id);
void *tcf_tclass_fetch(struct sk_buff *skb, void *tbc_value_ops);

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define to_meta(t) ((struct p4tc_metadata *)t)
#define to_tclass(t) ((struct p4tc_table_class *)t)

#endif
