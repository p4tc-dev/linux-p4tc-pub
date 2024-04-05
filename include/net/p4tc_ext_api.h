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

/* Reserve 16 bits for user-space. See P4TC_EXT_FLAGS_NO_PERCPU_STATS. */
#define P4TC_EXT_FLAGS_USER_BITS 16
#define P4TC_EXT_FLAGS_USER_MASK 0xffff

struct p4tc_extern_ops {
	struct list_head head;
	size_t size;
	size_t elem_size;
	struct module *owner;
	struct p4tc_tmpl_extern *tmpl_ext;
	int (*construct)(struct p4tc_extern_inst **common,
			 const struct p4tc_extern_ops *ops,
			 struct p4tc_extern_params *params,
			 struct p4tc_extern_params *constr_params,
			 u32 max_num_elems, bool tbl_bindable,
			 struct netlink_ext_ack *extack);
	void (*deconstruct)(struct p4tc_extern_inst *common);
	int (*dump)(struct sk_buff *skb,
		    struct p4tc_extern_inst *common,
		    struct netlink_callback *cb);
	int (*init_param_value)(struct p4tc_extern_inst *common,
				struct p4tc_extern_param *nparam,
				const void *value,
				struct netlink_ext_ack *extack);
	u32 id; /* identifier should match kind */
	u32 PAD0;
	char kind[P4TC_EXT_NAMSIZ];
};

struct p4tc_extern_inst *
p4tc_ext_inst_alloc(const struct p4tc_extern_ops *ops, const u32 max_num_elems,
		    bool tbl_bindable, char *ext_name);

int p4tc_register_extern(struct p4tc_extern_ops *ext);
int p4tc_unregister_extern(struct p4tc_extern_ops *ext);

static inline struct p4tc_extern_param *
p4tc_ext_param_find_byid(struct idr *params_idr, const u32 param_id)
{
	return idr_find(params_idr, param_id);
}

static inline struct p4tc_extern_tmpl_param *
p4tc_ext_tmpl_param_find_byid(struct idr *params_idr, const u32 param_id)
{
	return idr_find(params_idr, param_id);
}

void *
generic_parse_param_value(struct p4tc_type *type,
			  struct net *net, struct nlattr *nla,
			  struct p4tc_extern_tmpl_param_ops *param_validate,
			  bool value_required,
			  struct netlink_ext_ack *extack);
void p4tc_extern_put_param(struct p4tc_extern_param *param);

int p4tc_ext_param_value_init(struct net *net,
			      struct p4tc_extern_param *param,
			      struct nlattr **tb, bool value_required,
			      struct netlink_ext_ack *extack);
int
generic_dump_ext_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     const void *value);
int p4tc_unregister_extern(struct p4tc_extern_ops *ext);
void p4tc_ext_params_free(struct p4tc_extern_params *params);

static inline struct p4tc_extern_param *
p4tc_extern_params_find_byid(struct p4tc_extern_params *params, u32 param_id)
{
	return idr_find(&params->params_idr, param_id);
}

static inline struct p4tc_extern_params *p4tc_extern_params_init(void)
{
	struct p4tc_extern_params *params;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return NULL;

	idr_init(&params->params_idr);
	rwlock_init(&params->params_lock);

	return params;
}

static inline bool p4tc_ext_inst_has_dump(const struct p4tc_extern_inst *inst)
{
	const struct p4tc_extern_ops *ops = inst->ops;

	return ops && ops->dump;
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

static inline int
p4tc_ext_assign_param_ops(struct p4tc_extern_param *param,
			  struct p4tc_extern_param_ops *ops)
{
	if (!ops)
		return -EINVAL;

	if (!ops->init_value || !ops->default_value ||
	    !ops->dump_value || !ops->free)
		return -EINVAL;

	param->ops = ops;

	return 0;
}

#endif
