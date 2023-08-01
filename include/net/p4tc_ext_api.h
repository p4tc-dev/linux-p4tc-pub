/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TC_EXT_API_H
#define __NET_P4TC_EXT_API_H

/*
 * Public extern P4TC_EXT API
 */

#include <uapi/linux/p4tc_ext.h>
#include <linux/refcount.h>
#include <net/flow_offload.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/p4tc.h>

struct p4tc_extern_ops;

struct p4tc_extern_params {
	struct idr params_idr;
	rwlock_t params_lock;
	u32 num_params;
	u32 PAD0;
};

struct p4tc_extern_common {
	struct list_head             node;
	struct p4tc_extern_params    *params;
	const struct p4tc_extern_ops *ops;
	struct p4tc_extern_inst      *inst;
	u32                          p4tc_ext_flags;
	u32                          p4tc_ext_key;
	refcount_t                   p4tc_ext_refcnt;
	u32                          PAD0;
};

struct p4tc_extern {
	struct p4tc_extern_common       common;
	struct idr			*elems_idr;
	struct rcu_head			rcu;
	size_t				attrs_size;
	/* Extern element lock */
	spinlock_t			p4tc_ext_lock;
};

/* Reserve 16 bits for user-space. See P4TC_EXT_FLAGS_NO_PERCPU_STATS. */
#define P4TC_EXT_FLAGS_USER_BITS 16
#define P4TC_EXT_FLAGS_USER_MASK 0xffff

struct p4tc_extern_ops {
	struct list_head head;
	size_t size;
	size_t elem_size;
	struct module *owner;
	struct p4tc_tmpl_extern *tmpl_ext;
	int (*exec)(struct p4tc_extern_common *common, void *priv);
	int (*construct)(struct p4tc_extern_inst **common,
			 struct p4tc_extern_params *params,
			 struct p4tc_extern_params *constr_params,
			 u32 max_num_elems, bool tbl_bindable,
			 struct netlink_ext_ack *extack);
	void (*deconstruct)(struct p4tc_extern_inst *common);
	int (*dump)(struct sk_buff *skb,
		    struct p4tc_extern_inst *common,
		    struct netlink_callback *cb);
	int (*rctrl)(int cmd, struct p4tc_extern_inst *inst,
		     struct p4tc_extern_common **e,
		     struct p4tc_extern_params *params,
		     void *key_u32, struct netlink_ext_ack *extack);
	u32 id; /* identifier should match kind */
	u32 PAD0;
	char kind[P4TC_EXT_NAMSIZ];
};

#define P4TC_EXT_P_CREATED 1
#define P4TC_EXT_P_DELETED 1

int p4tc_register_extern(struct p4tc_extern_ops *ext);
int p4tc_unregister_extern(struct p4tc_extern_ops *ext);

int p4tc_ctl_extern_dump(struct sk_buff *skb, struct netlink_callback *cb,
			 struct nlattr **tb, const char *pname);
void p4tc_ext_purge(struct idr *idr);
void p4tc_ext_inst_purge(struct p4tc_extern_inst *inst);

int p4tc_ctl_extern(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
		    struct netlink_ext_ack *extack);
struct p4tc_extern_param *
p4tc_ext_param_find_byanyattr(struct idr *params_idr,
			      struct nlattr *name_attr,
			      const u32 param_id,
			      struct netlink_ext_ack *extack);
struct p4tc_extern_param *
p4tc_ext_param_find_byid(struct idr *params_idr, const u32 param_id);

int p4tc_ext_param_value_init(struct net *net,
			      struct p4tc_extern_param *param,
			      struct nlattr **tb, u32 typeid,
			      bool value_required,
			      struct netlink_ext_ack *extack);
void p4tc_ext_param_value_free_tmpl(struct p4tc_extern_param *param);
int p4tc_ext_param_value_dump_tmpl(struct sk_buff *skb,
				   struct p4tc_extern_param *param);
int p4tc_extern_insts_init_elems(struct idr *user_ext_idr);
int p4tc_extern_inst_init_elems(struct p4tc_extern_inst *inst, u32 num_elems);

int p4tc_unregister_extern(struct p4tc_extern_ops *ext);

struct p4tc_extern_common *p4tc_ext_elem_next(struct p4tc_extern_inst *inst);
struct p4tc_extern_common *p4tc_ext_elem_get(struct p4tc_extern_common *e);
void p4tc_ext_elem_put_list(struct p4tc_extern_inst *inst,
			    struct p4tc_extern_common *e);

int p4tc_ext_elem_dump_1(struct sk_buff *skb, struct p4tc_extern_common *e);
void p4tc_ext_params_free(struct p4tc_extern_params *params, bool free_vals);

static inline struct p4tc_extern_param *
p4tc_extern_params_find_byid(struct p4tc_extern_params *params, u32 param_id)
{
	return idr_find(&params->params_idr, param_id);
}

int p4tc_ext_init_defval_params(struct p4tc_extern_inst *inst,
				struct p4tc_extern_common *common,
				struct idr *control_params_idr,
				struct netlink_ext_ack *extack);
struct p4tc_extern_params *p4tc_extern_params_init(void);

static inline bool p4tc_ext_inst_has_dump(const struct p4tc_extern_inst *inst)
{
	const struct p4tc_extern_ops *ops = inst->ops;

	return ops && ops->dump;
}

static inline bool p4tc_ext_has_rctrl(const struct p4tc_extern_ops *ops)
{
	return ops && ops->rctrl;
}

static inline bool p4tc_ext_has_exec(const struct p4tc_extern_ops *ops)
{
	return ops && ops->exec;
}

static inline bool p4tc_ext_has_construct(const struct p4tc_extern_ops *ops)
{
	return ops && ops->construct;
}

static inline bool
p4tc_ext_inst_has_construct(const struct p4tc_extern_inst *inst)
{
	const struct p4tc_extern_ops *ops = inst->ops;

	return p4tc_ext_has_construct(ops);
}

static inline bool
p4tc_ext_inst_has_rctrl(const struct p4tc_extern_inst *inst)
{
	const struct p4tc_extern_ops *ops = inst->ops;

	return p4tc_ext_has_rctrl(ops);
}

static inline bool
p4tc_ext_inst_has_exec(const struct p4tc_extern_inst *inst)
{
	const struct p4tc_extern_ops *ops = inst->ops;

	return p4tc_ext_has_exec(ops);
}

struct p4tc_extern *
p4tc_ext_elem_find(struct p4tc_extern_inst *inst,
		   struct p4tc_ext_bpf_params *params);

struct p4tc_extern_common *
p4tc_ext_common_elem_get(struct sk_buff *skb, struct p4tc_pipeline **pipeline,
			 struct p4tc_ext_bpf_params *params);
struct p4tc_extern_common *
p4tc_xdp_ext_common_elem_get(struct xdp_buff *ctx,
			     struct p4tc_pipeline **pipeline,
			     struct p4tc_ext_bpf_params *params);
void p4tc_ext_common_elem_put(struct p4tc_pipeline *pipeline,
			      struct p4tc_extern_common *common);

static inline void p4tc_ext_inst_inc_num_elems(struct p4tc_extern_inst *inst)
{
	atomic_inc(&inst->curr_num_elems);
}

static inline void p4tc_ext_inst_dec_num_elems(struct p4tc_extern_inst *inst)
{
	atomic_dec(&inst->curr_num_elems);
}

#endif
