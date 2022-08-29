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
#define P4TC_MAXMETA_OFFSET 512
#define P4TC_PATH_MAX 3

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_MID_IDX 1
#define P4TC_PARSEID_IDX 1
#define P4TC_HDRFIELDID_IDX 2

#define P4TC_HDRFIELD_IS_VALIDITY_BIT 0x1

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
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

struct p4tc_pipeline {
	struct p4tc_template_common common;
	struct idr                  p_meta_idr;
	struct rcu_head             rcu;
	struct net                  *net;
	struct p4tc_parser          *parser;
	struct tc_action            **preacts;
	int                         num_preacts;
	struct tc_action            **postacts;
	int                         num_postacts;
	u32                         max_rules;
	u32                         p_meta_offset;
	refcount_t                  p_ref;
	refcount_t                  p_ctrl_ref;
	u16                         num_tables;
	u16                         curr_tables;
	u8                          p_state;
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

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define to_meta(t) ((struct p4tc_metadata *)t)
#define to_hdrfield(t) ((struct p4tc_hdrfield *)t)

#endif
