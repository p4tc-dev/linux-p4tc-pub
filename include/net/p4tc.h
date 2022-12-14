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

#define P4TC_DEFAULT_NUM_TABLES 1
#define P4TC_DEFAULT_MAX_RULES 1
#define P4TC_MAXMETA_OFFSET 512
#define P4TC_PATH_MAX 3
#define P4TC_MAX_TENTRIES (2 << 23)
#define P4TC_DEFAULT_TENTRIES 256
#define P4TC_MAX_TMASKS 128
#define P4TC_DEFAULT_TMASKS 8

#define P4TC_MAX_PERMISSION (GENMASK(P4TC_PERM_MAX_BIT, 0))

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_MID_IDX 1
#define P4TC_TBLID_IDX 1
#define P4TC_AID_IDX 1
#define P4TC_PARSEID_IDX 1
#define P4TC_HDRFIELDID_IDX 2
#define P4TC_REGID_IDX 1

#define P4TC_HDRFIELD_IS_VALIDITY_BIT 0x1

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
	struct idr                  p_act_idr;
	struct idr                  p_tbl_idr;
	struct idr                  p_reg_idr;
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
	u16                         num_tables;
	u16                         curr_tables;
	u8                          p_state;
	refcount_t                  p_hdrs_used;
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

struct p4tc_table_key {
	struct tc_action **key_acts;
	int              key_num_acts;
	u32              key_id;
};

#define P4TC_CONTROL_PERMISSIONS (GENMASK(9, 5))
#define P4TC_DATA_PERMISSIONS (GENMASK(4, 0))

#define P4TC_TABLE_PERMISSIONS                                   \
	((GENMASK(P4TC_CTRL_PERM_C_BIT, P4TC_CTRL_PERM_D_BIT)) | \
	 P4TC_DATA_PERM_R | P4TC_DATA_PERM_X)

#define P4TC_PERMISSIONS_UNINIT (1 << P4TC_PERM_MAX_BIT)

struct p4tc_table_defact {
	struct tc_action **default_acts;
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
	struct idr                          tbl_keys_idr;
	struct idr                          tbl_masks_idr;
	struct idr                          tbl_prio_idr;
	struct rhltable                     tbl_entries;
	struct tc_action                    **tbl_preacts;
	struct tc_action                    **tbl_postacts;
	struct p4tc_table_entry             *tbl_const_entry;
	struct p4tc_table_defact __rcu      *tbl_default_hitact;
	struct p4tc_table_defact __rcu      *tbl_default_missact;
	struct p4tc_table_perm __rcu        *tbl_permissions;
	spinlock_t                          tbl_masks_idr_lock;
	spinlock_t                          tbl_prio_idr_lock;
	int                                 tbl_num_postacts;
	int                                 tbl_num_preacts;
	u32                                 tbl_count;
	u32                                 tbl_curr_count;
	u32                                 tbl_keysz;
	u32                                 tbl_id;
	u32                                 tbl_keys_count;
	u32                                 tbl_max_entries;
	u32                                 tbl_max_masks;
	u32                                 tbl_curr_used_entries;
	u32                                 tbl_default_key;
	refcount_t                          tbl_ctrl_ref;
	refcount_t                          tbl_ref;
	refcount_t                          tbl_entries_ref;
};

extern const struct p4tc_template_ops p4tc_table_ops;

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
	struct pernet_operations    *p4_net_ops;
	struct p4tc_pipeline        *pipeline;
	struct idr                  params_idr;
	struct tcf_exts             exts;
	struct list_head            head;
	u32                         a_id;
	bool                        active;
};
extern const struct p4tc_template_ops p4tc_act_ops;
extern const struct rhashtable_params p4tc_label_ht_params;
extern const struct rhashtable_params acts_params;
void p4tc_label_ht_destroy(void *ptr, void *arg);

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
	struct work_struct	         work;
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
	u16                              permissions;
};

extern const struct nla_policy p4tc_root_policy[P4TC_ROOT_MAX + 1];
extern const struct nla_policy p4tc_policy[P4TC_MAX + 1];
struct p4tc_table_entry *
p4tc_table_entry_lookup(struct sk_buff *skb, struct p4tc_table *table,
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
	u32                         parser_inst_id;
	u32                         hdr_field_id;
	u16                         startbit;
	u16                         endbit;
	u8                          datatype; /* T_XXX */
	u8                          flags;  /* P4TC_HDRFIELD_FLAGS_* */
};

extern const struct p4tc_template_ops p4tc_hdrfield_ops;

struct p4tc_register {
	struct p4tc_template_common common;
	spinlock_t                  reg_value_lock;
	struct p4tc_type            *reg_type;
	struct p4tc_type_mask_shift *reg_mask_shift;
	void                        *reg_value;
	u32                         reg_num_elems;
	u32                         reg_id;
	refcount_t                  reg_ref;
	u16                         reg_startbit; /* Relative to its container */
	u16                         reg_endbit; /* Relative to its container */
};

extern const struct p4tc_template_ops p4tc_register_ops;

struct p4tc_metadata *
tcf_meta_find_byany(struct p4tc_pipeline *pipeline, const char *mname,
		    const u32 m_id, struct netlink_ext_ack *extack);
struct p4tc_metadata *tcf_meta_find_byid(struct p4tc_pipeline *pipeline,
					 u32 m_id);
void tcf_meta_fill_user_offsets(struct p4tc_pipeline *pipeline);
void *tcf_meta_fetch(struct sk_buff *skb, struct p4tc_metadata *meta);

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

struct p4tc_act *tcf_action_find_byid(struct p4tc_pipeline *pipeline,
				      const u32 a_id);
struct p4tc_act *
tcf_action_find_byname(const char *act_name, struct p4tc_pipeline *pipeline);
struct p4tc_act *
tcf_action_find_byany(struct p4tc_pipeline *pipeline,
		      const char *act_name,
		      const u32 a_id,
		      struct netlink_ext_ack *extack);
int tcf_p4_dyna_template_init(struct net *net, struct tc_action **a,
			      struct p4tc_act *act,
			      struct list_head *params_list,
			      struct tc_act_dyna *parm, u32 flags,
			      struct netlink_ext_ack *extack);
struct p4tc_act_param *tcf_param_find_byid(struct idr *params_idr,
					   const u32 param_id);
struct p4tc_act_param *
tcf_param_find_byany(struct p4tc_act *act, const char *param_name,
		     const u32 param_id, struct netlink_ext_ack *extack);

struct p4tc_table *
tcf_table_find_byany(struct p4tc_pipeline *pipeline, const char *tblname,
		     const u32 tbl_id, struct netlink_ext_ack *extack);
struct p4tc_table *tcf_table_find_byid(struct p4tc_pipeline *pipeline,
					      const u32 tbl_id);
struct p4tc_table_key *tcf_table_key_find(struct p4tc_table *table,
					  const u32 key_id);
void *tcf_table_fetch(struct sk_buff *skb, void *tbl_value_ops);
int tcf_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
				   struct netlink_ext_ack *extack);

void tcf_table_entry_destroy_hash(void *ptr, void *arg);

int tcf_table_const_entry_cu(struct net *net, struct nlattr *arg,
			     struct p4tc_table_entry *entry,
			     struct p4tc_pipeline *pipeline,
			     struct p4tc_table *table,
			     struct netlink_ext_ack *extack);
int p4tca_table_get_entry_fill(struct sk_buff *skb,
			       struct p4tc_table *table,
			       struct p4tc_table_entry *entry,
			       u32 tbl_id);

struct p4tc_parser *tcf_parser_create(struct p4tc_pipeline *pipeline,
				      const char *parser_name,
				      u32 parser_inst_id,
				      struct netlink_ext_ack *extack);

struct p4tc_parser *tcf_parser_find_byid(struct p4tc_pipeline *pipeline,
					 const u32 parser_inst_id);
struct p4tc_parser *
tcf_parser_find_byany(struct p4tc_pipeline *pipeline, const char *parser_name,
		      u32 parser_inst_id, struct netlink_ext_ack *extack);
int tcf_parser_del(struct p4tc_pipeline *pipeline,
		   struct p4tc_parser *parser, struct netlink_ext_ack *extack);
bool tcf_parser_is_callable(struct p4tc_parser *parser);
int tcf_skb_parse(struct sk_buff *skb, struct p4tc_skb_ext *p4tc_ext,
		  struct p4tc_parser *parser);

struct p4tc_header_field *tcf_hdrfield_find_byid(struct p4tc_parser *parser,
						 const u32 hdrfield_id);
struct p4tc_header_field *
tcf_hdrfield_find_byany(struct p4tc_parser *parser, const char *hdrfield_name,
			u32 hdrfield_id, struct netlink_ext_ack *extack);
bool tcf_parser_check_hdrfields(struct p4tc_parser *parser,
				struct p4tc_header_field *hdrfield);
void *tcf_hdrfield_fetch(struct sk_buff *skb,
			 struct p4tc_header_field *hdrfield);

struct p4tc_register *tcf_register_find_byid(struct p4tc_pipeline *pipeline,
					     const u32 reg_id);
struct p4tc_register *
tcf_register_find_byany(struct p4tc_pipeline *pipeline,
			const char *regname, const u32 reg_id,
			struct netlink_ext_ack *extack);

void tcf_register_put_rcu(struct rcu_head *head);

int p4tc_init_net_ops(struct net *net, unsigned int id);
void p4tc_exit_net_ops(struct list_head *net_list, unsigned int id);
int tcf_p4_act_init_params(struct net *net,
			   struct tcf_p4act_params *params,
			   struct p4tc_act *act,
			   struct nlattr *nla, struct netlink_ext_ack *extack);
void tcf_p4_act_params_destroy(struct tcf_p4act_params *params);
int p4_act_init(struct p4tc_act *act, struct nlattr *nla,
		struct p4tc_act_param *params[],
		struct netlink_ext_ack *extack);
void p4_put_many_params(struct idr *params_idr,
			struct p4tc_act_param *params[],
			int params_count);
void tcf_p4_act_params_destroy_rcu(struct rcu_head *head);
int p4_act_init_params(struct p4tc_act *act,
		       struct nlattr *nla,
		       struct p4tc_act_param *params[],
		       bool update,
		       struct netlink_ext_ack *extack);
extern const struct p4tc_act_param_ops param_ops[P4T_MAX + 1];
int generic_dump_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     struct p4tc_act_param *param);

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define to_meta(t) ((struct p4tc_metadata *)t)
#define to_act(t) ((struct p4tc_act *)t)
#define to_hdrfield(t) ((struct p4tc_header_field *)t)
#define to_table(t) ((struct p4tc_table *)t)
#define to_register(t) ((struct p4tc_register *)t)

/* P4TC COMMANDS */
int p4tc_cmds_parse(struct net *net, struct p4tc_act *act,
		    struct nlattr *nla, bool ovr,
		    struct netlink_ext_ack *extack);
int p4tc_cmds_copy(struct p4tc_act *act, struct list_head *new_cmd_operations,
		   bool delete_old, struct netlink_ext_ack *extack);

int p4tc_cmds_fillup(struct sk_buff *skb, struct list_head *meta_ops);
void p4tc_cmds_release_ope_list(struct list_head *entries,
				bool called_from_template);
struct p4tc_cmd_operand;
int p4tc_cmds_fill_operand(struct sk_buff *skb, struct p4tc_cmd_operand *kopnd);

struct p4tc_cmd_operate {
	struct list_head cmd_operations;
	struct list_head operands_list;
	struct p4tc_cmd_s *cmd;
	char *label1;
	char *label2;
	u32 num_opnds;
	u32 ctl1;
	u32 ctl2;
	u16 op_id;		/* P4TC_CMD_OP_XXX */
	u32 cmd_offset;
	u8 op_flags;
	u8 op_cnt;
};

struct tcf_p4act;
struct p4tc_cmd_operand {
	struct list_head oper_list_node;
	void *(*fetch)(struct sk_buff *skb, struct p4tc_cmd_operand *op,
		       struct tcf_p4act *cmd, struct tcf_result *res);
	struct p4tc_type *oper_datatype; /* what is stored in path_or_value - P4T_XXX */
	struct p4tc_type_mask_shift *oper_mask_shift;
	struct tc_action *action;
	void *path_or_value;
	void *path_or_value_extra;
	void *print_prefix;
	void *priv;
	u64 immedv_large[BITS_TO_U64(P4T_MAX_BITSZ)];
	u32 immedv;		/* one of: immediate value, metadata id, action id */
	u32 immedv2;		/* one of: action instance */
	u32 path_or_value_sz;
	u32 path_or_value_extra_sz;
	u32 print_prefix_sz;
	u32 immedv_large_sz;
	u32 pipeid;		/* 0 for kernel */
	u8 oper_type;		/* P4TC_CMD_OPER_XXX */
	u8 oper_cbitsize;	/* based on P4T_XXX container size */
	u8 oper_bitsize;	/* diff between bitend - oper_bitend */
	u8 oper_bitstart;
	u8 oper_bitend;
	u8 oper_flags;		/* TBA: DATA_IS_IMMEDIATE */
};

struct p4tc_cmd_s {
	int cmdid;
	u32 num_opnds;
	int (*validate_operands)(struct net *net, struct p4tc_act *act,
				 struct p4tc_cmd_operate *ope, u32 cmd_num_opns,
				 struct netlink_ext_ack *extack);
	void (*free_operation)(struct p4tc_cmd_operate *op,
			       bool called_for_instance,
			       struct netlink_ext_ack *extack);
	int (*run)(struct sk_buff *skb, struct p4tc_cmd_operate *op,
		   struct tcf_p4act *cmd, struct tcf_result *res);
};

#endif
