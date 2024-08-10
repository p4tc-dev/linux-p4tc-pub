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
#include <net/sock.h>
#include <net/xdp.h>

struct p4tc_extern_ops;

struct p4tc_extern_params {
	struct idr params_idr;
	spinlock_t params_lock;
	u32 num_params;
	u32 PAD0;
};

struct p4tc_ext_bpf_val_kern {
	struct rcu_head rcu;
	struct p4tc_ext_bpf_val val;
};

struct p4tc_extern_common {
	struct list_head			node;
	struct p4tc_extern_params		*params;
	const struct p4tc_extern_ops		*ops;
	struct p4tc_extern_inst			*inst;
	struct p4tc_ext_bpf_val_kern __rcu	*val_kern;
	atomic_t				hidden;
	u32					p4tc_ext_flags;
	u32					p4tc_ext_key;
	/* bpf extern param value structure lock */
	spinlock_t				p4tc_ext_bpf_val_lock;
	refcount_t				p4tc_ext_refcnt;
	u16					p4tc_ext_permissions;
	u16					PAD0;
};

struct p4tc_extern {
	struct p4tc_extern_common       common;
	size_t				attrs_size;
	/* Extern element lock */
	spinlock_t			p4tc_ext_lock;
};

/* Reserve 16 bits for user-space. See P4TC_EXT_FLAGS_NO_PERCPU_STATS. */
#define P4TC_EXT_FLAGS_USER_BITS 16
#define P4TC_EXT_FLAGS_USER_MASK 0xffff

#define P4TC_EXT_ELEM_PRIV_IDX 0

struct p4tc_extern_ops {
	struct list_head head;
	size_t size;
	size_t elem_size;
	struct module *owner;
	struct p4tc_tmpl_extern *tmpl_ext;
	int (*exec)(struct p4tc_extern_common *common, void *priv);
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
	int (*init)(struct p4tc_extern_common *common,
		    struct netlink_ext_ack *extack);
	int (*init_param_value)(struct p4tc_extern_inst *common,
				struct p4tc_extern_param *nparam,
				const void *value,
				struct netlink_ext_ack *extack);
	int (*rctrl)(int cmd, struct p4tc_extern_inst *inst,
		     struct p4tc_extern_common **e,
		     struct p4tc_extern_params *params,
		     u32 key, struct netlink_ext_ack *extack);
	u32 id; /* identifier should match kind */
	u32 PAD0;
	char kind[P4TC_EXT_NAMSIZ];
};

struct p4tc_extern_inst *
p4tc_ext_inst_alloc(const struct p4tc_extern_ops *ops, const u32 max_num_elems,
		    bool tbl_bindable, char *ext_name);

#define P4TC_EXT_P_DELETED 1

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
generic_param_value_parse(struct p4tc_extern_tmpl_param *tmpl_param,
			  struct net *net, struct nlattr *nla,
			  struct p4tc_extern_tmpl_param_ops *param_validate,
			  bool value_required,
			  struct netlink_ext_ack *extack);
int p4tc_ctl_extern_dump(struct sk_buff *skb, struct netlink_callback *cb,
			 struct nlattr **tb, const char *pname);
void p4tc_ext_purge(struct idr *idr);
void p4tc_ext_inst_purge(struct p4tc_extern_inst *inst);

int p4tc_ctl_extern(struct sk_buff *skb, struct nlmsghdr *n, struct nlattr **tb,
		    struct netlink_ext_ack *extack);
struct p4tc_extern_tmpl_param *
p4tc_ext_param_find_byanyattr(struct idr *params_idr,
			      struct nlattr *name_attr,
			      const u32 param_id,
			      struct netlink_ext_ack *extack);

int p4tc_ext_param_value_parse_and_init(struct net *net,
					struct p4tc_extern_param *param,
					struct nlattr **tb, bool value_required,
					struct netlink_ext_ack *extack);
int p4tc_extern_insts_init_elems(struct idr *user_ext_idr);
int p4tc_extern_inst_init_elems(struct p4tc_extern_inst *inst, u32 num_elems);

int p4tc_unregister_extern(struct p4tc_extern_ops *ext);

struct p4tc_extern_common *p4tc_ext_elem_next(struct p4tc_extern_inst *inst);

struct p4tc_extern_common *
p4tc_tbl_entry_meter_build(struct p4tc_pipeline *pipeline,
			  struct nlattr *nla, struct netlink_ext_ack *extack);
void p4tc_tbl_entry_meter_destroy(struct p4tc_extern_common *meter);
void p4tc_tbl_entry_meter_bind(struct p4tc_table_entry_value *value,
			       struct p4tc_extern_common *meter);

int p4tc_ext_elem_dump_1(struct sk_buff *skb, struct p4tc_extern_common *e,
			 bool params_lock);

int
generic_dump_ext_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     const void *value);

struct p4tc_extern *
p4tc_ext_elem_update(struct net *net, struct nlattr *nla,
		     struct p4tc_extern_inst *inst,
		     u32 key, u32 flags,
		     struct netlink_ext_ack *extack);

struct p4tc_extern_param *
p4tc_ext_init_param(struct net *net, struct idr *control_params_idr,
		    struct nlattr *nla, size_t *attrs_size,
		    struct netlink_ext_ack *extack);

static inline int
__p4tc_ext_runt_copy_bpf(u8 *params_cursor,
			 const struct p4tc_extern_param *param)
{
	u16 param_bytesz;

	param_bytesz = BITS_TO_BYTES(param->tmpl_param->bitsz);

	if (param->ops && param->ops->copy_value_bpf)
		param->ops->copy_value_bpf(params_cursor, param);
	else
		memcpy(params_cursor, param->value, param_bytesz);

	return param_bytesz;
}

static inline void
p4tc_ext_runt_array_copy_bpf(struct p4tc_ext_bpf_val_kern *val_kern,
			     struct p4tc_extern_param **params_arr,
			     u32 ext_id, u32 ext_key, u32 num_params)
{
	u8 *params_cursor = val_kern->val.out_params;
	const struct p4tc_extern_param *param;
	int i;

	for (i = 0; i < num_params; i++) {
		u16 param_bytesz;

		param = params_arr[i];
		param_bytesz = __p4tc_ext_runt_copy_bpf(params_cursor, param);
		params_cursor += param_bytesz;
	}

	val_kern->val.ext_id = ext_id;
	val_kern->val.index = ext_key;
}

static inline void
p4tc_ext_runt_copy_bpf(struct p4tc_ext_bpf_val_kern *val_kern,
		       struct idr *params_idr, u32 ext_id, u32 ext_key)
{
	u8 *params_cursor = val_kern->val.out_params;
	struct p4tc_extern_param *param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(params_idr, param, tmp, param_id) {
		u32 type_bytesz;

		type_bytesz = __p4tc_ext_runt_copy_bpf(params_cursor, param);
		params_cursor += type_bytesz;
	}

	val_kern->val.ext_id = ext_id;
	val_kern->val.index = ext_key;
}

/* Should only be called when all params in control_params_idr were previously
 * parsed and validated
 */
static inline int
p4tc_ext_copy_params_values(struct p4tc_extern_common *common,
			    struct idr *control_params_idr)
{
	struct p4tc_extern_params *params = common->params;
	struct p4tc_ext_bpf_val_kern *val_kern;
	struct p4tc_extern_param *param;
	unsigned long param_id, tmp;

	val_kern = kzalloc(sizeof(*val_kern), GFP_KERNEL);
	if (!val_kern)
		return -ENOMEM;

	spin_lock_bh(&common->params->params_lock);
	idr_for_each_entry_ul(control_params_idr, param, tmp, param_id) {
		struct p4tc_extern_param *orig_param =
			p4tc_ext_param_find_byid(&params->params_idr, param_id);
		const u16 param_bytesz =
			BITS_TO_BYTES(param->tmpl_param->bitsz);

		if (orig_param->ops && orig_param->ops->copy_value)
			orig_param->ops->copy_value(orig_param, param->value);
		else
			memcpy(orig_param->value, param->value, param_bytesz);
	}

	p4tc_ext_runt_copy_bpf(val_kern, &common->params->params_idr,
			       common->inst->ext_id, common->p4tc_ext_key);

	spin_lock_bh(&common->p4tc_ext_bpf_val_lock);
	val_kern = rcu_replace_pointer(common->val_kern, val_kern,
				       lockdep_is_held(&common->p4tc_ext_bpf_val_lock));
	spin_unlock_bh(&common->p4tc_ext_bpf_val_lock);
	spin_unlock_bh(&common->params->params_lock);

	if (val_kern)
		kfree_rcu(val_kern, rcu);

	return 0;
}

static inline void p4tc_ext_param_free(struct p4tc_extern_param *param)
{
	if (param->ops && param->ops->free)
		param->ops->free(param);
	else
		kfree(param->value);
	kfree(param);
}

static inline void p4tc_ext_params_free(struct p4tc_extern_params *params)
{
	struct p4tc_extern_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&params->params_idr, param, tmp, id) {
		p4tc_ext_param_free(param);
	}

	idr_destroy(&params->params_idr);
	kfree(params);
}

static inline void free_p4tc_ext(struct p4tc_extern_common *common)
{
	struct p4tc_ext_bpf_val_kern *val_kern;

	if (common->params)
		p4tc_ext_params_free(common->params);

	val_kern = rcu_dereference_protected(common->val_kern, 1);

	kfree_rcu(val_kern, rcu);
	kfree(common);
}

static inline void p4tc_extern_cleanup(struct p4tc_extern_common *common)
{
	free_p4tc_ext(common);
}

static inline int __p4tc_extern_put(struct p4tc_extern_common *common)
{
	if (refcount_dec_and_test(&common->p4tc_ext_refcnt)) {
		idr_remove(&common->inst->control_elems_idr,
			   common->p4tc_ext_key);

		p4tc_extern_cleanup(common);

		return 1;
	}

	return 0;
}

static inline int p4tc_extern_common_put(struct p4tc_extern_common *common)
{
	if (refcount_dec_and_test(&common->p4tc_ext_refcnt)) {
		p4tc_extern_cleanup(common);
		return 1;
	}

	return 0;
}

static inline int __p4tc_ext_idr_release(struct p4tc_extern_common *common)
{
	int ret = 0;

	if (common) {
		if (__p4tc_extern_put(common))
			ret = P4TC_EXT_P_DELETED;
	}

	return ret;
}

static inline int p4tc_ext_idr_release(struct p4tc_extern_common *common)
{
	return __p4tc_ext_idr_release(common);
}

static inline bool p4tc_ext_is_hidden(struct p4tc_extern_common *common)
{
	return atomic_read(&common->hidden);
}

static inline void p4tc_ext_hidden_set(struct p4tc_extern_common *common,
				       u32 val)
{
	atomic_set(&common->hidden, val);
}

static inline struct p4tc_extern_common *
p4tc_ext_elem_next_uninit(struct p4tc_extern_inst *inst)
{
	struct p4tc_extern_common *e;

	spin_lock_bh(&inst->available_list_lock);
	e = list_first_entry_or_null(&inst->unused_elems,
				     struct p4tc_extern_common, node);
	if (!e) {
		spin_unlock_bh(&inst->available_list_lock);
		return NULL;
	}

	list_del_init(&e->node);
	spin_unlock_bh(&inst->available_list_lock);
	refcount_set(&e->p4tc_ext_refcnt, 1);

	return e;
}

static inline void __p4tc_ext_elem_put_list(struct p4tc_extern_inst *inst,
					    struct p4tc_extern_common *e)
{
	spin_lock_bh(&inst->available_list_lock);
	list_add_tail(&e->node, &inst->unused_elems);
	spin_unlock_bh(&inst->available_list_lock);
}

static inline void p4tc_ext_elem_put_list(struct p4tc_extern_inst *inst,
					  struct p4tc_extern_common *e)
{
	if (refcount_dec_and_test(&e->p4tc_ext_refcnt)) {
		atomic_set(&e->hidden, 1);
		__p4tc_ext_elem_put_list(inst, e);
	}
}

static inline struct p4tc_extern_common *
p4tc_ext_elem_get(struct p4tc_extern_common *e)
{
	refcount_inc(&e->p4tc_ext_refcnt);
	return e;
}

static inline struct p4tc_extern_common *
p4tc_ext_idr_common_search(struct p4tc_extern_inst *inst, u32 key,
			   struct netlink_ext_ack *extack)
{
	struct idr *elems_idr = &inst->control_elems_idr;
	struct p4tc_extern_common *p;

	if (key == P4TC_EXT_ELEM_PRIV_IDX) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Elem of index %u cannot be accessed",
				   P4TC_EXT_ELEM_PRIV_IDX);
		return NULL;
	}

	p = idr_find(elems_idr, key);
	if (IS_ERR(p))
		return NULL;

	return p;
}

#define p4tc_ext_idr_search(inst, key, extack) \
	((struct p4tc_extern *)p4tc_ext_idr_common_search(inst, key, extack))

static inline struct p4tc_extern_common *
p4tc_ext_elem_get_bykey(struct p4tc_extern_inst *inst, u32 key,
			struct netlink_ext_ack *extack)
{
	struct p4tc_extern_common *common;

	common = p4tc_ext_idr_common_search(inst, key, extack);
	if (!common) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Elem with key %u not found",
				   key);
		return ERR_PTR(-EINVAL);
	}

	if (p4tc_ext_is_hidden(common)) {
		spin_lock_bh(&inst->available_list_lock);
		list_del_init(&common->node);
		spin_unlock_bh(&inst->available_list_lock);
		refcount_set(&common->p4tc_ext_refcnt, 1);
	} else {
		common = p4tc_ext_elem_get(common);
	}

	return common;
}


static inline struct p4tc_extern_common *
p4tc_ext_get_common(struct p4tc_extern_inst *inst, u32 key,
		    struct netlink_ext_ack *extack)
{
	struct p4tc_extern *e = NULL;
	int err;

	e = p4tc_ext_idr_search(inst, key, extack);
	if (!e) {
		err = -ENOENT;
		NL_SET_ERR_MSG(extack,
			       "TC extern with specified key not found");
		goto err_out;
	}

	if (!p4tc_ctrl_read_ok(e->common.p4tc_ext_permissions)) {
		NL_SET_ERR_MSG(extack, "Read permissions not set");
		err = -EPERM;
		goto err_out;
	}

	if (p4tc_ext_is_hidden(&e->common)) {
		NL_SET_ERR_MSG_FMT(extack, "Extern of index %u not accessible",
				   key);
		err = -ENOENT;
		goto err_out;
	}

	return &e->common;

err_out:
	return ERR_PTR(err);
}

static inline struct p4tc_extern_param *
p4tc_extern_params_find_byid(struct p4tc_extern_params *params, u32 param_id)
{
	return idr_find(&params->params_idr, param_id);
}

static inline struct p4tc_extern_params *p4tc_extern_params_init(gfp_t gfp_flags)
{
	struct p4tc_extern_params *params;

	params = kzalloc(sizeof(*params), gfp_flags);
	if (!params)
		return NULL;

	idr_init(&params->params_idr);
	spin_lock_init(&params->params_lock);

	return params;
}

int p4tc_ext_init_defval_params(struct p4tc_extern_inst *inst,
				struct p4tc_extern_common *common,
				struct idr *control_params_idr,
				struct netlink_ext_ack *extack);

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
p4tc_ext_has_init_param_value(const struct p4tc_extern_ops *ops)
{
	return ops && ops->init_param_value;
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

static inline void p4tc_ext_inst_inc_num_elems(struct p4tc_extern_inst *inst)
{
	atomic_inc(&inst->curr_num_elems);
}

static inline void p4tc_ext_inst_dec_num_elems(struct p4tc_extern_inst *inst)
{
	atomic_dec(&inst->curr_num_elems);
}

static inline struct p4tc_extern *
p4tc_ext_elem_find(struct p4tc_extern_inst *inst,
		   struct p4tc_ext_bpf_params *params)
{
	struct p4tc_extern *e;

	if (!params->index)
		return ERR_PTR(-EPERM);

	e = idr_find(&inst->control_elems_idr, params->index);
	if (!e)
		return ERR_PTR(-ENOENT);

	return e;
}

#define p4tc_ext_common_elem_find(common, params) \
	((struct p4tc_extern_common *)p4tc_ext_elem_find(common, params))

static inline struct p4tc_extern_common *
__p4tc_ext_common_elem_priv_get(struct net *net,
				struct p4tc_pipeline **pipeline,
				struct p4tc_ext_bpf_params *params)
{
	struct p4tc_extern_common *ext_common;
	struct p4tc_extern_inst *inst;
	int err;

	inst = p4tc_ext_inst_get_byids(net, pipeline, params);
	if (IS_ERR(inst)) {
		err = PTR_ERR(inst);
		goto put_pipe;
	}

	ext_common = idr_find(&inst->control_elems_idr, P4TC_EXT_ELEM_PRIV_IDX);
	if (!ext_common) {
		err = -ENOENT;
		goto put_pipe;
	}

	return ext_common;

put_pipe:
	p4tc_pipeline_put(*pipeline);
	return ERR_PTR(err);
}

static inline struct p4tc_extern_common *
__p4tc_ext_common_elem_get(struct net *net, struct p4tc_pipeline **pipeline,
			   struct p4tc_ext_bpf_params *params)
{
	struct p4tc_extern_common *ext_common;
	struct p4tc_extern_inst *inst;
	int err;

	inst = p4tc_ext_inst_get_byids(net, pipeline, params);
	if (IS_ERR(inst))
		return (struct p4tc_extern_common *)inst;

	ext_common = p4tc_ext_common_elem_find(inst, params);
	if (IS_ERR(ext_common)) {
		err = PTR_ERR(ext_common);
		goto put_pipe;
	}

	if (p4tc_ext_is_hidden(ext_common)) {
		err = -EPERM;
		goto put_pipe;
	}

	if (!refcount_inc_not_zero(&ext_common->p4tc_ext_refcnt)) {
		err = -EBUSY;
		goto put_pipe;
	}

	return ext_common;

put_pipe:
	p4tc_pipeline_put(*pipeline);
	return ERR_PTR(err);
}

/* This function should be paired with p4tc_ext_common_elem_put */
static inline struct p4tc_extern_common *
p4tc_ext_common_elem_get(struct sk_buff *skb, struct p4tc_pipeline **pipeline,
			 struct p4tc_ext_bpf_params *params)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __p4tc_ext_common_elem_get(net, pipeline, params);
}

/* This function should be paired with p4tc_ext_common_elem_put */
static inline struct p4tc_extern_common *
p4tc_ext_common_elem_priv_get(struct sk_buff *skb,
			      struct p4tc_pipeline **pipeline,
			      struct p4tc_ext_bpf_params *params)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __p4tc_ext_common_elem_priv_get(net, pipeline, params);
}

/* This function should be paired with p4tc_ext_common_elem_put */
static inline struct p4tc_extern_common *
p4tc_xdp_ext_common_elem_get(struct xdp_buff *ctx,
			     struct p4tc_pipeline **pipeline,
			     struct p4tc_ext_bpf_params *params)
{
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return __p4tc_ext_common_elem_get(net, pipeline, params);
}

static inline struct p4tc_extern_common *
p4tc_xdp_ext_common_elem_priv_get(struct xdp_buff *ctx,
				  struct p4tc_pipeline **pipeline,
				  struct p4tc_ext_bpf_params *params)
{
	struct net *net;

	net = dev_net(ctx->rxq->dev);

	return __p4tc_ext_common_elem_priv_get(net, pipeline, params);
}

static inline void p4tc_ext_common_elem_put(struct p4tc_pipeline *pipeline,
					    struct p4tc_extern_common *common)
{
	if (common->p4tc_ext_key != P4TC_EXT_ELEM_PRIV_IDX)
		refcount_dec(&common->p4tc_ext_refcnt);
	p4tc_pipeline_put(pipeline);
}

struct p4tc_ext_nlmsg_attrs {
	u32 pipeid;
	u32 portid;
	u32 seq;
	int cmd;
	u16 flags;
};

static inline int
tce_get_fill(struct sk_buff *skb, struct p4tc_pipeline *pipeline,
	     struct p4tc_extern_common *common,
	     struct p4tc_ext_nlmsg_attrs *nlmsg_attrs,
	     bool lock_params)
{
	const u32 portid = nlmsg_attrs->portid;
	const u32 pipeid = nlmsg_attrs->pipeid;
	unsigned char *b = nlmsg_get_pos(skb);
	const u16 flags = nlmsg_attrs->flags;
	const u32 seq = nlmsg_attrs->seq;
	const int cmd = nlmsg_attrs->cmd;
	struct nlattr *nest, *nest_count;
	struct nlmsghdr *nlh;
	struct p4tcmsg *t;
	int err;

	nlh = nlmsg_put(skb, portid, seq, cmd, sizeof(*t), flags);
	if (!nlh)
		goto out_nlmsg_trim;
	t = nlmsg_data(nlh);
	t->pipeid = pipeid;
	t->obj = P4TC_OBJ_RUNTIME_EXTERN;

	nest = nla_nest_start(skb, P4TC_ROOT);
	nest_count = nla_nest_start(skb, 1);
	if (!nest_count)
		goto out_nlmsg_trim;
	err = p4tc_ext_elem_dump_1(skb, common, lock_params);
	if (err < 0)
		goto out_nlmsg_trim;
	nla_nest_end(skb, nest_count);

	nla_nest_end(skb, nest);

	if (nla_put_string(skb, P4TC_ROOT_PNAME, pipeline->common.name))
		goto out_nlmsg_trim;

	nlh->nlmsg_len = (unsigned char *)nlmsg_get_pos(skb) - b;

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}


static inline bool
p4tc_extern_should_send(struct net *net,
			struct p4tc_ext_nlmsg_attrs *nlmsg_attrs)
{
	return (nlmsg_attrs->cmd != RTM_P4TC_UPDATE ||
		rtnl_has_listeners(net, RTNLGRP_P4TC) ||
		nlmsg_attrs->flags & NLM_F_ECHO);
}

static inline size_t p4tc_extern_full_attrs_size(size_t sz)
{
	return NLMSG_HDRLEN                     /* struct nlmsghdr */
		+ sizeof(struct p4tcmsg)
		+ nla_total_size(0)             /* P4TC_ROOT nested */
		+ sz;
}

static inline int
p4tc_extern_send(struct p4tc_pipeline *pipeline,
		 struct p4tc_extern_common *common,
		 struct p4tc_ext_nlmsg_attrs *nlmsg_attrs,
		 size_t attr_size, bool from_control,
		 struct netlink_ext_ack *extack)
{
	gfp_t alloc_flags = from_control ? GFP_KERNEL : GFP_ATOMIC;
	struct net *net = pipeline->net;
	struct sk_buff *skb;

	if (!p4tc_extern_should_send(net, nlmsg_attrs))
		return 0;

	if (from_control) {
		if (!p4tc_ctrl_pub_ok(common->p4tc_ext_permissions))
			return -EPERM;
	} else {
		if (!p4tc_data_pub_ok(common->p4tc_ext_permissions))
			return -EPERM;
	}

	attr_size = p4tc_extern_full_attrs_size(attr_size);
	skb = alloc_skb(attr_size <= NLMSG_GOODSIZE ?
			NLMSG_GOODSIZE : attr_size, alloc_flags);
	if (!skb)
		return -ENOBUFS;

	if (tce_get_fill(skb, pipeline, common, nlmsg_attrs,
			 from_control) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill netlink attributes while adding TC extern");
		kfree_skb(skb);
		return -EINVAL;
	}

	if (nlmsg_attrs->cmd == RTM_P4TC_UPDATE) {
		bool echo = nlmsg_attrs->flags & NLM_F_ECHO;

		return nlmsg_notify(net->rtnl, skb, nlmsg_attrs->portid,
				    RTNLGRP_P4TC, echo, alloc_flags);
	}

	return rtnl_unicast(skb, net, nlmsg_attrs->portid);
}
#endif
