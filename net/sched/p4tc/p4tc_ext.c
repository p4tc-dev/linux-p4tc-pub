// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_ext.c	P4 TC EXTERN API
 *
 * Copyright (c) 2022-2023, Mojatatu Networks
 * Copyright (c) 2022-2023, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/p4tc_types.h>
#include <net/p4tc_ext_api.h>
#include <net/netlink.h>
#include <net/flow_offload.h>
#include <net/tc_wrapper.h>
#include <uapi/linux/p4tc.h>

static inline bool p4tc_ext_param_ops_is_init(struct p4tc_extern_param_ops *ops)
{
	struct p4tc_extern_param_ops uninit_ops = {NULL};

	return memcmp(ops, &uninit_ops, sizeof(*ops));
}

static void p4tc_ext_put_param(struct p4tc_extern_param *param, bool free_val)
{
	struct p4tc_extern_param_ops *val_ops;

	if (p4tc_ext_param_ops_is_init(param->ops))
		val_ops = param->ops;
	else
		val_ops = param->mod_ops;

	if (free_val) {
		if (val_ops && val_ops->free)
			val_ops->free(param);
		else
			kfree(param->value);
	}

	if (param->mask_shift)
		p4t_release(param->mask_shift);
	kfree(param);
}

static void p4tc_ext_put_many_params(struct idr *params_idr,
				     struct p4tc_extern_param *params[],
				     int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4tc_ext_put_param(params[i], true);
}

static void p4tc_ext_insert_param(struct idr *params_idr,
				  struct p4tc_extern_param *param)
{
	struct p4tc_extern_param *param_old;

	param_old = idr_replace(params_idr, param, param->id);
	if (param_old != ERR_PTR(-EBUSY))
		p4tc_ext_put_param(param_old, true);
}

static void p4tc_ext_insert_many_params(struct idr *params_idr,
					struct p4tc_extern_param *params[],
					int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4tc_ext_insert_param(params_idr, params[i]);
}

static void __p4tc_ext_params_free(struct p4tc_extern_params *params,
				   bool free_vals)
{
	struct p4tc_extern_param *parm;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&params->params_idr, parm, tmp, id) {
		idr_remove(&params->params_idr, id);
		p4tc_ext_put_param(parm, free_vals);
	}
}

void p4tc_ext_params_free(struct p4tc_extern_params *params, bool free_vals)
{
	__p4tc_ext_params_free(params, free_vals);
	idr_destroy(&params->params_idr);
	kfree(params);
}
EXPORT_SYMBOL_GPL(p4tc_ext_params_free);

static void free_p4tc_ext(struct p4tc_extern *p)
{
	if (p->common.params)
		p4tc_ext_params_free(p->common.params, true);

	kfree(p);
}

static void free_p4tc_ext_rcu(struct rcu_head *rcu)
{
	struct p4tc_extern *p;

	p = container_of(rcu, struct p4tc_extern, rcu);

	free_p4tc_ext(p);
}

static void p4tc_extern_cleanup(struct p4tc_extern *p)
{
	free_p4tc_ext_rcu(&p->rcu);
}

static int __p4tc_extern_put(struct p4tc_extern *p)
{
	if (refcount_dec_and_test(&p->common.p4tc_ext_refcnt)) {
		idr_remove(p->elems_idr, p->common.p4tc_ext_key);

		p4tc_extern_cleanup(p);

		return 1;
	}

	return 0;
}

static int __p4tc_ext_idr_release(struct p4tc_extern *p)
{
	int ret = 0;

	if (p) {
		if (__p4tc_extern_put(p))
			ret = P4TC_EXT_P_DELETED;
	}

	return ret;
}

static int p4tc_ext_idr_release(struct p4tc_extern *e)
{
	return __p4tc_ext_idr_release(e);
}

static int p4tc_ext_idr_release_dec_num_elems(struct p4tc_extern *e)
{
	struct p4tc_extern_inst *inst = e->common.inst;
	int ret;

	ret = __p4tc_ext_idr_release(e);
	if (ret == P4TC_EXT_P_DELETED)
		p4tc_ext_inst_dec_num_elems(inst);

	return ret;
}

static size_t p4tc_extern_shared_attrs_size(void)
{
	return  nla_total_size(0) /* extern number nested */
		+ nla_total_size(EXTERNNAMSIZ)  /* P4TC_EXT_KIND */
		+ nla_total_size(EXTERNINSTNAMSIZ) /* P4TC_EXT_INST_NAME */
		+ nla_total_size(sizeof(struct nla_bitfield32)); /* P4TC_EXT_FLAGS */
}

static size_t p4tc_extern_full_attrs_size(size_t sz)
{
	return NLMSG_HDRLEN                     /* struct nlmsghdr */
		+ sizeof(struct p4tcmsg)
		+ nla_total_size(0)             /* P4TC_ROOT nested */
		+ sz;
}

static int
generic_dump_ext_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     struct p4tc_extern_param *param)
{
	const u32 bytesz = BITS_TO_BYTES(type->container_bitsz);
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nla_value;

	nla_value = nla_nest_start(skb, P4TC_EXT_PARAMS_VALUE);
	if (nla_put(skb, P4TC_EXT_PARAMS_VALUE_RAW, bytesz,
		    param->value))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nla_value);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static const struct nla_policy p4tc_extern_params_value_policy[P4TC_EXT_VALUE_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_VALUE_RAW] = { .type = NLA_BINARY },
};

static int dev_init_param_value(struct net *net,
				struct p4tc_extern_param *nparam,
				void *value,
				struct netlink_ext_ack *extack)
{
	u32 *ifindex = value;

	rcu_read_lock();
	if (!dev_get_by_index_rcu(net, *ifindex)) {
		NL_SET_ERR_MSG(extack, "Invalid ifindex");
		rcu_read_unlock();
		return -EINVAL;
	}
	rcu_read_unlock();

	nparam->value = kzalloc(sizeof(*ifindex), GFP_KERNEL);
	if (!nparam->value)
		return -EINVAL;

	memcpy(nparam->value, ifindex, sizeof(*ifindex));

	return 0;
}

static int dev_dump_param_value(struct sk_buff *skb,
				struct p4tc_extern_param_ops *op,
				struct p4tc_extern_param *param)
{
	struct nlattr *nest;
	u32 *ifindex;
	int ret;

	nest = nla_nest_start(skb, P4TC_EXT_PARAMS_VALUE);
	ifindex = (u32 *)param->value;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_VALUE_RAW, *ifindex)) {
		ret = -EINVAL;
		goto out_nla_cancel;
	}
	nla_nest_end(skb, nest);

	return 0;

out_nla_cancel:
	nla_nest_cancel(skb, nest);
	return ret;
}

static void dev_free_param_value(struct p4tc_extern_param *param)
{
	kfree(param->value);
}

static const struct p4tc_extern_param_ops ext_param_ops[P4T_MAX + 1] = {
	[P4T_DEV] = {
		.init_value = dev_init_param_value,
		.dump_value = dev_dump_param_value,
		.free = dev_free_param_value,
	},
};

static int p4tc_extern_elem_dump_param_noval(struct sk_buff *skb,
					     struct p4tc_extern_param *parm)
{
	unsigned char *b = nlmsg_get_pos(skb);

	if (nla_put_string(skb, P4TC_EXT_PARAMS_NAME,
			   parm->name))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_ID, parm->id))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_TYPE, parm->type->typeid))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int
p4tc_extern_elem_dump_params(struct sk_buff *skb, struct p4tc_extern_common *e)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_extern_param *parm;
	struct nlattr *nest_parms;
	int id;

	nest_parms = nla_nest_start(skb, P4TC_EXT_PARAMS);
	if (e->params) {
		int i = 1;

		idr_for_each_entry(&e->params->params_idr, parm, id) {
			struct p4tc_extern_param_ops *val_ops;
			struct nlattr *nest_count;

			nest_count = nla_nest_start(skb, i);
			if (!nest_count)
				goto nla_put_failure;

			if (p4tc_extern_elem_dump_param_noval(skb, parm) < 0)
				goto nla_put_failure;

			if (p4tc_ext_param_ops_is_init(parm->ops))
				val_ops = parm->ops;
			else
				val_ops = parm->mod_ops;

			read_lock_bh(&e->params->params_lock);
			if (val_ops && val_ops->dump_value) {
				if (val_ops->dump_value(skb, parm->ops, parm) < 0) {
					read_unlock_bh(&e->params->params_lock);
					goto nla_put_failure;
				}
			} else {
				if (generic_dump_ext_param_value(skb, parm->type, parm)) {
					read_unlock_bh(&e->params->params_lock);
					goto nla_put_failure;
				}
			}
			read_unlock_bh(&e->params->params_lock);

			if (nla_put_u32(skb, P4TC_EXT_PARAMS_FLAGS,
					parm->flags))
				goto nla_put_failure;

			nla_nest_end(skb, nest_count);
			i++;
		}
	}
	nla_nest_end(skb, nest_parms);

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

int
p4tc_ext_elem_dump_1(struct sk_buff *skb, struct p4tc_extern_common *e)
{
	const char *instname = e->inst->common.name;
	unsigned char *b = nlmsg_get_pos(skb);
	const char *kind = e->inst->ext_name;
	u32 flags = e->p4tc_ext_flags;
	u32 key = e->p4tc_ext_key;
	int err;

	if (nla_put_string(skb, P4TC_EXT_KIND, kind))
		goto nla_put_failure;

	if (nla_put_string(skb, P4TC_EXT_INST_NAME, instname))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_EXT_KEY, key))
		goto nla_put_failure;

	if (flags && nla_put_bitfield32(skb, P4TC_EXT_FLAGS,
					flags, flags))
		goto nla_put_failure;

	err = p4tc_extern_elem_dump_params(skb, e);
	if (err < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}
EXPORT_SYMBOL(p4tc_ext_elem_dump_1);

static int p4tc_ext_dump_walker(struct p4tc_extern_inst *inst,
				struct sk_buff *skb,
				struct netlink_callback *cb)
{
	struct idr *idr = &inst->control_elems_idr;
	int err = 0, s_i = 0, n_i = 0;
	u32 ext_flags = cb->args[2];
	struct p4tc_extern *p;
	unsigned long id = 1;
	struct nlattr *nest;
	unsigned long tmp;
	int key = -1;

	if (p4tc_ext_inst_has_dump(inst)) {
		n_i = inst->ops->dump(skb, inst, cb);
		if (n_i < 0)
			return n_i;
	} else {
		s_i = cb->args[0];

		idr_for_each_entry_ul(idr, p, tmp, id) {
			key++;
			if (key < s_i)
				continue;
			if (IS_ERR(p))
				continue;

			nest = nla_nest_start(skb, n_i);
			if (!nest) {
				key--;
				goto nla_put_failure;
			}

			err = p4tc_ext_elem_dump_1(skb, &p->common);
			if (err < 0) {
				key--;
				nlmsg_trim(skb, nest);
				goto done;
			}
			nla_nest_end(skb, nest);
			n_i++;
			if (!(ext_flags & P4TC_EXT_FLAG_LARGE_DUMP_ON) &&
			    n_i >= P4TC_MSGBATCH_SIZE)
				goto done;
		}
	}
done:
	if (key >= 0)
		cb->args[0] = key + 1;

	if (n_i) {
		if (ext_flags & P4TC_EXT_FLAG_LARGE_DUMP_ON)
			cb->args[1] = n_i;
	}
	return n_i;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	goto done;
}

static void __p4tc_ext_idr_purge(struct p4tc_extern *p)
{
	atomic_dec(&p->common.inst->curr_num_elems);
	p4tc_extern_cleanup(p);
}

static void p4tc_ext_idr_purge(struct p4tc_extern *p)
{
	idr_remove(p->elems_idr, p->common.p4tc_ext_key);
	__p4tc_ext_idr_purge(p);
}

/* Called when pipeline is being purged */
void p4tc_ext_purge(struct idr *idr)
{
	struct p4tc_extern *p;
	unsigned long tmp, id;

	idr_for_each_entry_ul(idr, p, tmp, id) {
		if (IS_ERR(p))
			continue;
		p4tc_ext_idr_purge(p);
	}
}

static int p4tc_ext_idr_search(struct p4tc_extern_inst *inst,
			       struct p4tc_extern **e, u32 key)
{
	struct idr *elems_idr = &inst->control_elems_idr;
	struct p4tc_extern *p;

	p = idr_find(elems_idr, key);
	if (IS_ERR(p))
		p = NULL;

	if (p) {
		*e = p;
		return true;
	}
	return false;
}

static int __p4tc_ext_idr_search(struct p4tc_extern_inst *inst,
				 struct p4tc_extern **e, u32 key)
{
	if (p4tc_ext_idr_search(inst, e, key)) {
		refcount_inc(&((*e)->common.p4tc_ext_refcnt));
		return true;
	}

	return false;
}

static int p4tc_ext_copy(struct p4tc_extern_inst *inst,
			 u32 key, struct p4tc_extern **e,
			 struct p4tc_extern *e_orig,
			 const struct p4tc_extern_ops *ops,
			 u32 flags)
{
	const u32 size = (ops && ops->elem_size) ? ops->elem_size : sizeof(**e);
	struct p4tc_extern *p = kzalloc(size, GFP_KERNEL);

	if (unlikely(!p))
		return -ENOMEM;

	spin_lock_init(&p->p4tc_ext_lock);
	p->common.p4tc_ext_key = key;
	p->common.p4tc_ext_flags = flags;
	refcount_set(&p->common.p4tc_ext_refcnt,
		     refcount_read(&e_orig->common.p4tc_ext_refcnt));

	p->elems_idr = e_orig->elems_idr;
	p->common.inst = inst;
	p->common.ops = ops;
	*e = p;
	return 0;
}

static int p4tc_ext_idr_create(struct p4tc_extern_inst *inst,
			       u32 key, struct p4tc_extern **e,
			       const struct p4tc_extern_ops *ops,
			       u32 flags)
{
	struct p4tc_extern *p = kzalloc(sizeof(*p), GFP_KERNEL);
	u32 max_num_elems = inst->max_num_elems;

	if (unlikely(!p))
		return -ENOMEM;

	if (atomic_read(&inst->curr_num_elems) == max_num_elems) {
		kfree(p);
		return -E2BIG;
	}

	p4tc_ext_inst_inc_num_elems(inst);

	refcount_set(&p->common.p4tc_ext_refcnt, 1);

	spin_lock_init(&p->p4tc_ext_lock);
	p->common.p4tc_ext_key = key;
	p->common.p4tc_ext_flags = flags;

	p->elems_idr = &inst->control_elems_idr;
	p->common.inst = inst;
	p->common.ops = ops;
	*e = p;
	return 0;
}

/* Check if extern with specified key exists. If externs is found, increments
 * its reference, and return 1. Otherwise insert temporary error pointer
 * (to prevent concurrent users from inserting externs with same key) and
 * return 0.
 */

static int p4tc_ext_idr_check_alloc(struct p4tc_extern_inst *inst,
				    u32 key, struct p4tc_extern **e,
				    struct netlink_ext_ack *extack)
{
	struct idr *elems_idr = &inst->control_elems_idr;
	struct p4tc_extern *p;
	int ret;

	p = idr_find(elems_idr, key);
	if (p) {
		refcount_inc(&p->common.p4tc_ext_refcnt);
		*e = p;
		ret = 1;
	} else {
		NL_SET_ERR_MSG_FMT(extack, "Unable to find element with key %u",
				   key);
		return -ENOENT;
	}

	return ret;
}

struct p4tc_extern *
p4tc_ext_elem_find(struct p4tc_extern_inst *inst,
		   struct p4tc_ext_bpf_params *params)
{
	struct p4tc_extern *e;

	e = idr_find(&inst->control_elems_idr, params->index);
	if (!e)
		return ERR_PTR(-ENOENT);

	return e;
}
EXPORT_SYMBOL(p4tc_ext_elem_find);

#define p4tc_ext_common_elem_find(common, params) \
	((struct p4tc_extern_common *)p4tc_ext_elem_find(common, params))

static struct p4tc_extern_common *
__p4tc_ext_common_elem_get(struct net *net, struct p4tc_pipeline **pipeline,
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

	ext_common = p4tc_ext_common_elem_find(inst, params);
	if (IS_ERR(ext_common)) {
		err = PTR_ERR(ext_common);
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
struct p4tc_extern_common *
p4tc_ext_common_elem_get(struct sk_buff *skb, struct p4tc_pipeline **pipeline,
			 struct p4tc_ext_bpf_params *params)
{
	struct net *net;

	net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);

	return __p4tc_ext_common_elem_get(net, pipeline, params);
}
EXPORT_SYMBOL(p4tc_ext_common_elem_get);

void p4tc_ext_common_elem_put(struct p4tc_pipeline *pipeline,
			      struct p4tc_extern_common *common)
{
	refcount_dec(&common->p4tc_ext_refcnt);
	p4tc_pipeline_put(pipeline);
}
EXPORT_SYMBOL(p4tc_ext_common_elem_put);

static inline bool p4tc_ext_param_is_writable(struct p4tc_extern_param *param)
{
	return param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY;
}

int __bpf_p4tc_extern_md_write(struct net *net,
			       struct p4tc_ext_bpf_params *params)
{
	u8 *params_data = params->in_params;
	struct p4tc_extern_param *param;
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_common *e;
	struct p4tc_type *type;
	int err = 0;

	e = __p4tc_ext_common_elem_get(net, &pipeline, params);
	if (IS_ERR(e))
		return PTR_ERR(e);

	param = idr_find(&e->params->params_idr, params->param_id);
	if (unlikely(!param)) {
		err = -EINVAL;
		goto put_pipe;
	}

	if (!p4tc_ext_param_is_writable(param)) {
		err = -EINVAL;
		goto put_pipe;
	}

	type = param->type;
	if (unlikely(!type->ops->host_read)) {
		err = -EINVAL;
		goto put_pipe;
	}

	if (unlikely(!type->ops->host_write)) {
		err = -EINVAL;
		goto put_pipe;
	}

	write_lock_bh(&e->params->params_lock);
	p4t_copy(param->mask_shift, type, param->value,
		 param->mask_shift, type, params_data);
	write_unlock_bh(&e->params->params_lock);

put_pipe:
	p4tc_ext_common_elem_put(pipeline, e);

	return err;
}

int __bpf_p4tc_extern_md_read(struct net *net,
			      struct p4tc_ext_bpf_res *res,
			      struct p4tc_ext_bpf_params *params)
{
	const struct p4tc_type_ops *ops;
	struct p4tc_extern_param *param;
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_common *e;
	int err = 0;

	e = __p4tc_ext_common_elem_get(net, &pipeline, params);
	if (IS_ERR(e))
		return PTR_ERR(e);

	param = idr_find(&e->params->params_idr, params->param_id);
	if (unlikely(!param)) {
		err = -ENOENT;
		goto refcount_dec;
	}

	ops = param->type->ops;
	if (unlikely(!ops->host_read)) {
		err = -ENOENT;
		goto refcount_dec;
	}

	read_lock_bh(&e->params->params_lock);
	ops->host_read(param->type, param->mask_shift, param->value,
		       res->out_params);
	read_unlock_bh(&e->params->params_lock);

refcount_dec:
	p4tc_ext_common_elem_put(pipeline, e);

	return err;
}

static int p4tc_extern_destroy(struct p4tc_extern *externs[])
{
	const struct p4tc_extern_ops *ops;
	struct p4tc_extern *e;
	int ret = 0, i;

	for (i = 0; i < P4TC_MSGBATCH_SIZE && externs[i]; i++) {
		e = externs[i];
		externs[i] = NULL;
		ops = e->common.ops;
		free_p4tc_ext_rcu(&e->rcu);
	}
	return ret;
}

static int p4tc_extern_put(struct p4tc_extern *p)
{
	return __p4tc_extern_put(p);
}

/* Put all externs in this array, skip those NULL's. */
static void p4tc_extern_put_many(struct p4tc_extern *externs[])
{
	int i;

	for (i = 0; i < P4TC_MSGBATCH_SIZE; i++) {
		struct p4tc_extern *e = externs[i];
		const struct p4tc_extern_ops *ops;

		if (!e)
			continue;
		ops = e->common.ops;
		p4tc_extern_put(e);
	}
}

static int p4tc_extern_elem_dump(struct sk_buff *skb,
				 struct p4tc_extern *externs[],
				 int ref)
{
	struct p4tc_extern *e;
	int err = -EINVAL, i;
	struct nlattr *nest;

	for (i = 0; i < P4TC_MSGBATCH_SIZE && externs[i]; i++) {
		e = externs[i];
		nest = nla_nest_start_noflag(skb, i + 1);
		if (!nest)
			goto nla_put_failure;
		err = p4tc_ext_elem_dump_1(skb, &e->common);
		if (err < 0)
			goto errout;
		nla_nest_end(skb, nest);
	}

	return 0;

nla_put_failure:
	err = -EINVAL;
errout:
	nla_nest_cancel(skb, nest);
	return err;
}

static void generic_free_param_value(struct p4tc_extern_param *param)
{
	kfree(param->value);
}

static void *generic_parse_param_value(struct p4tc_extern_param *nparam,
				       struct p4tc_type *type,
				       struct nlattr *nla, bool value_required,
				       struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(type->container_bitsz);
	struct nlattr *tb_value[P4TC_EXT_VALUE_PARAMS_MAX + 1];
	void *value;
	int err;

	if (!nla) {
		if (value_required) {
			NL_SET_ERR_MSG(extack, "Must specify param value");
			return ERR_PTR(-EINVAL);
		} else {
			return NULL;
		}
	}

	err = nla_parse_nested(tb_value, P4TC_EXT_VALUE_PARAMS_MAX,
			       nla, p4tc_extern_params_value_policy,
			       extack);
	if (err < 0)
		return ERR_PTR(err);

	value = nla_data(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]);
	if (type->ops->validate_p4t) {
		err = type->ops->validate_p4t(type, value, 0, type->bitsz - 1,
					      extack);
		if (err < 0)
			return ERR_PTR(err);
	}

	if (nla_len(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]) != alloc_len)
		return ERR_PTR(-EINVAL);

	return value;
}

static int generic_init_param_value(struct net *net,
				    struct p4tc_extern_param *nparam,
				    struct nlattr **tb,
				    u32 byte_sz, bool value_required,
				    struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(nparam->type->container_bitsz);
	struct p4tc_extern_param_ops *ops;
	void *value;

	if (p4tc_ext_param_ops_is_init(nparam->ops))
		ops = nparam->ops;
	else
		ops = nparam->mod_ops;

	value = generic_parse_param_value(nparam, nparam->type,
					  tb[P4TC_EXT_PARAMS_VALUE],
					  value_required, extack);
	if (IS_ERR_OR_NULL(value))
		return PTR_ERR(value);

	if (ops && ops->init_value)
		return ops->init_value(net, nparam, value, extack);

	nparam->value = kzalloc(alloc_len, GFP_KERNEL);
	if (!nparam->value)
		return -ENOMEM;

	memcpy(nparam->value, value, byte_sz);

	return 0;
}

static const struct nla_policy p4tc_extern_policy[P4TC_EXT_MAX + 1] = {
	[P4TC_EXT_INST_NAME] = {
		.type = NLA_STRING,
		.len = EXTERNINSTNAMSIZ
	},
	[P4TC_EXT_KIND]		= { .type = NLA_STRING },
	[P4TC_EXT_PARAMS]	= { .type = NLA_NESTED },
	[P4TC_EXT_KEY]		= { .type = NLA_NESTED },
	[P4TC_EXT_FLAGS]	= { .type = NLA_BITFIELD32 },
};

static const struct nla_policy p4tc_extern_params_policy[P4TC_EXT_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_NAME] = { .type = NLA_STRING, .len = EXTPARAMNAMSIZ },
	[P4TC_EXT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_EXT_PARAMS_TYPE] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_BITSZ] = { .type = NLA_U16 },
	[P4TC_EXT_PARAMS_FLAGS] = { .type = NLA_U8 },
};

int p4tc_ext_param_value_init(struct net *net,
			      struct p4tc_extern_param *param,
			      struct nlattr **tb, u32 typeid,
			      bool value_required,
			      struct netlink_ext_ack *extack)
{
	u32 byte_sz = BITS_TO_BYTES(param->bitsz);
	int err;

	if (!param->ops) {
		struct p4tc_extern_param_ops *ops;

		ops = (struct p4tc_extern_param_ops *)&ext_param_ops[typeid];
		param->ops = ops;
	}

	err = generic_init_param_value(net, param, tb,
				       byte_sz, value_required,
				       extack);

	return err;
}

void p4tc_ext_param_value_free_tmpl(struct p4tc_extern_param *param)
{
	if (param->ops->free)
		return param->ops->free(param);

	return generic_free_param_value(param);
}

int p4tc_ext_param_value_dump_tmpl(struct sk_buff *skb,
				   struct p4tc_extern_param *param)
{
	if (param->ops && param->ops->dump_value)
		return param->ops->dump_value(skb, param->ops, param);

	return generic_dump_ext_param_value(skb, param->type, param);
}

static struct p4tc_extern_param *
p4tc_ext_create_param(struct net *net, struct p4tc_extern_params *params,
		      struct idr *control_params_idr,
		      struct nlattr **tb, size_t *attrs_size,
		      bool init_param, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param, *nparam;
	u32 param_id = 0;
	int err = 0;

	if (tb[P4TC_EXT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_EXT_PARAMS_ID]);
	*attrs_size += nla_total_size(sizeof(u32));

	param = p4tc_ext_param_find_byanyattr(control_params_idr,
					      tb[P4TC_EXT_PARAMS_NAME],
					      param_id, extack);
	if (IS_ERR(param))
		return param;

	if (tb[P4TC_EXT_PARAMS_TYPE]) {
		u32 typeid = nla_get_u32(tb[P4TC_EXT_PARAMS_TYPE]);

		if (param->type->typeid != typeid) {
			NL_SET_ERR_MSG(extack,
				       "Param type differs from template");
			return ERR_PTR(-EINVAL);
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		return ERR_PTR(-EINVAL);
	}
	*attrs_size += nla_total_size(sizeof(u32));

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam)
		return ERR_PTR(-ENOMEM);

	strscpy(nparam->name, param->name, EXTPARAMNAMSIZ);
	nparam->type = param->type;
	nparam->bitsz = param->bitsz;

	if (init_param) {
		err = p4tc_ext_param_value_init(net, nparam, tb,
						param->type->typeid, true,
						extack);
	} else {
		void *value;

		value = generic_parse_param_value(nparam, nparam->type,
						  tb[P4TC_EXT_PARAMS_VALUE],
						  true, extack);
		if (IS_ERR(value))
			err = PTR_ERR(value);
		else
			nparam->value = value;
	}

	if (err < 0)
		goto free;

	*attrs_size += nla_total_size(BITS_TO_BYTES(param->type->container_bitsz));
	nparam->id = param->id;

	err = idr_alloc_u32(&params->params_idr, ERR_PTR(-EBUSY), &nparam->id,
			    nparam->id, GFP_KERNEL);
	if (err < 0)
		goto free_val;

	return nparam;

free_val:
	if (param->ops && param->ops->free)
		param->ops->free(nparam);
	else
		generic_free_param_value(nparam);

free:
	kfree(nparam);

	return ERR_PTR(err);
}

static struct p4tc_extern_param *
p4tc_ext_init_param(struct net *net, struct idr *control_params_idr,
		    struct p4tc_extern_params *params, struct nlattr *nla,
		    size_t *attrs_size, bool init_value,
		    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (err < 0)
		return ERR_PTR(err);

	return p4tc_ext_create_param(net, params, control_params_idr, tb,
				     attrs_size, init_value, extack);
}

static int p4tc_ext_get_key_param_value(struct nlattr *nla,
					u32 *key, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_VALUE_PARAMS_MAX];
	u32 *value;
	int err;

	if (!nla) {
		NL_SET_ERR_MSG(extack, "Must specify key param value");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, P4TC_EXT_VALUE_PARAMS_MAX,
			       nla, p4tc_extern_params_value_policy, extack);
	if (err < 0)
		return err;

	if (!tb[P4TC_EXT_PARAMS_VALUE_RAW]) {
		NL_SET_ERR_MSG(extack, "Must specify raw value attr");
		return -EINVAL;
	}

	if (nla_len(tb[P4TC_EXT_PARAMS_VALUE_RAW]) > sizeof(*key)) {
		NL_SET_ERR_MSG(extack,
			       "Param value is bigger than 32 bits");
		return -EINVAL;
	}

	value = nla_data(tb[P4TC_EXT_PARAMS_VALUE_RAW]);

	*key = *value;

	return 0;
}

static int p4tc_ext_get_nonscalar_key_param(struct idr *params_idr,
					    struct nlattr *nla, u32 *key,
					    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	struct p4tc_extern_param *index_param;
	char *param_name;
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (err < 0)
		return err;

	if (!tb[P4TC_EXT_PARAMS_NAME]) {
		NL_SET_ERR_MSG(extack, "Must specify key param name");
		return -EINVAL;
	}
	param_name = nla_data(tb[P4TC_EXT_PARAMS_NAME]);

	index_param = p4tc_ext_param_find_byanyattr(params_idr,
						    tb[P4TC_EXT_PARAMS_NAME],
						    0, extack);
	if (IS_ERR(index_param)) {
		NL_SET_ERR_MSG(extack, "Key param name not found");
		return -EINVAL;
	}

	if (!(index_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)) {
		NL_SET_ERR_MSG_FMT(extack, "%s is not the key param name",
				   param_name);
		return -EINVAL;
	}

	err = p4tc_ext_get_key_param_value(tb[P4TC_EXT_PARAMS_VALUE], key,
					   extack);
	if (err < 0)
		return err;

	return index_param->id;
}

static int p4tc_ext_get_key_param_scalar(struct p4tc_extern_inst *inst,
					 struct nlattr *nla, u32 *key,
					 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (err < 0)
		return err;

	return p4tc_ext_get_key_param_value(tb[P4TC_EXT_PARAMS_VALUE], key,
					    extack);
}

struct p4tc_extern_params *p4tc_extern_params_init(void)
{
	struct p4tc_extern_params *params;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return NULL;

	idr_init(&params->params_idr);
	rwlock_init(&params->params_lock);

	return params;
}

static int __p4tc_ext_init_params(struct net *net,
				  struct idr *control_params_idr,
				  struct p4tc_extern_params **params,
				  struct nlattr *nla, size_t *attrs_size,
				  bool init_values,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *params_backup[P4TC_MSGBATCH_SIZE] = { NULL };
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int err;
	int i;

	if (!*params) {
		*params = p4tc_extern_params_init();
		if (!*params)
			return -ENOMEM;
	}

	err = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (err < 0) {
		kfree(*params);
		*params = NULL;
		return err;
	}

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_param *param;

		param = p4tc_ext_init_param(net, control_params_idr, *params,
					    tb[i], attrs_size, init_values,
					    extack);
		if (IS_ERR(param)) {
			err = PTR_ERR(param);
			goto params_del;
		}
		params_backup[i - 1] = param;
		*attrs_size = nla_total_size(0);  /* params array element nested */
	}

	p4tc_ext_insert_many_params(&((*params)->params_idr), params_backup,
				    i - 1);
	return 0;

params_del:
	p4tc_ext_put_many_params(&((*params)->params_idr), params_backup,
				 i - 1);
	kfree(*params);
	*params = NULL;
	return err;
}

#define p4tc_ext_init_params(net, control_params_idr, params, nla, atrrs_size, extack) \
	(__p4tc_ext_init_params(net, control_params_idr, params, \
				nla, &(attrs_size), true, extack))

#define p4tc_ext_parse_params(net, control_params_idr, params, nla, attrs_size, extack) \
	(__p4tc_ext_init_params(net, control_params_idr, params, \
				nla, &(attrs_size), false, extack))

void p4tc_ext_elem_put_list(struct p4tc_extern_inst *inst,
			    struct p4tc_extern_common *e)
{
	struct p4tc_extern_param *param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(&e->params->params_idr, param, tmp, param_id) {
		const struct p4tc_type *type = param->type;
		const u32 type_bytesz = BITS_TO_BYTES(type->container_bitsz);

		if (param->mod_ops)
			param->mod_ops->default_value(param);
		else
			memset(param->value, 0, type_bytesz);
	}

	spin_lock(&inst->available_list_lock);
	list_add_tail(&e->node, &inst->unused_elems);
	refcount_dec(&e->p4tc_ext_refcnt);
	spin_unlock(&inst->available_list_lock);
}

struct p4tc_extern_common *p4tc_ext_elem_get(struct p4tc_extern_inst *inst)
{
	struct p4tc_extern_common *e;

	spin_lock(&inst->available_list_lock);
	e = list_first_entry_or_null(&inst->unused_elems,
				     struct p4tc_extern_common, node);
	if (e) {
		refcount_inc(&e->p4tc_ext_refcnt);
		list_del_init(&e->node);
	}

	spin_unlock(&inst->available_list_lock);

	return e;
}

static void p4tc_ext_idr_insert_many(struct p4tc_extern *externs[])
{
	int i;

	for (i = 0; i < P4TC_MSGBATCH_SIZE; i++) {
		struct p4tc_extern *e = externs[i];
		struct p4tc_extern_inst *inst;
		struct p4tc_extern *old_e;

		if (!e)
			continue;

		inst = e->common.inst;
		/* Replace ERR_PTR(-EBUSY) allocated by p4tc_ext_idr_check_alloc
		 * if it is just created. If it's updated, free previous extern.
		 */
		spin_lock(&inst->available_list_lock);
		old_e = idr_replace(e->elems_idr, e, e->common.p4tc_ext_key);
		if (old_e != ERR_PTR(-EBUSY)) {
			if (inst->tbl_bindable)
				list_del(&old_e->common.node);
			call_rcu(&old_e->rcu, free_p4tc_ext_rcu);
		}
		if (inst->tbl_bindable)
			list_add(&e->common.node, &inst->unused_elems);
		spin_unlock(&inst->available_list_lock);
	}
}

static const char *
p4tc_ext_get_kind(struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_MAX + 1];
	struct nlattr *kind;
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_MAX, nla,
			       p4tc_extern_policy, extack);
	if (err < 0)
		return ERR_PTR(err);
	err = -EINVAL;
	kind = tb[P4TC_EXT_KIND];
	if (!kind) {
		NL_SET_ERR_MSG(extack, "TC extern name must be specified");
		return ERR_PTR(err);
	}

	return nla_data(kind);
}

static struct p4tc_extern *
p4tc_ext_init(struct net *net, struct nlattr *nla,
	      struct p4tc_extern_inst *inst,
	      u32 key, u32 flags,
	      struct netlink_ext_ack *extack)
{
	struct idr *control_params_idr = &inst->params->params_idr;
	const struct p4tc_extern_ops *e_o = inst->ops;
	struct p4tc_extern_params *params = NULL;
	struct p4tc_extern *e_orig = NULL;
	size_t attrs_size = 0;
	struct p4tc_extern *e;
	int err = 0;

	if (!nla) {
		NL_SET_ERR_MSG(extack, "Must specify extern params");
		err =  -EINVAL;
		goto out;
	}

	if (p4tc_ext_has_rctrl(e_o)) {
		err = p4tc_ext_parse_params(net, control_params_idr, &params,
					    nla, attrs_size, extack);
		if (err < 0)
			goto out;

		err = e_o->rctrl(RTM_P4TC_UPDATE, inst,
				 (struct p4tc_extern_common **)&e, params, &key,
				 extack);
		p4tc_ext_params_free(params, false);
		if (err < 0)
			goto out;

		return e;
	}

	err = p4tc_ext_idr_check_alloc(inst, key, &e_orig, extack);
	if (err < 0)
		goto out;

	err = p4tc_ext_copy(inst, key, &e, e_orig, e_o, flags);
	if (err < 0)
		goto out;

	err = p4tc_ext_init_params(net, control_params_idr, &params,
				   nla, &attrs_size, extack);
	if (err < 0)
		goto release_idr;
	attrs_size += nla_total_size(0) + p4tc_extern_shared_attrs_size();
	e->attrs_size = attrs_size;

	e->common.params = params;

	return e;

release_idr:
	p4tc_ext_idr_release(e);

out:
	return ERR_PTR(err);
}

static struct p4tc_extern_param *find_key_param(struct idr *params_idr)
{
	struct p4tc_extern_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		if (param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)
			return param;
	}

	return NULL;
}

static struct p4tc_extern_param *
p4tc_ext_init_defval_param(struct p4tc_extern_param *param,
			   struct netlink_ext_ack *extack)
{
	const u32 bytesz = BITS_TO_BYTES(param->type->container_bitsz);
	struct p4tc_extern_param_ops *val_ops;
	struct p4tc_extern_param *nparam;
	int err;

	if (p4tc_ext_param_ops_is_init(param->ops))
		val_ops = param->ops;
	else
		val_ops = param->mod_ops;

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam) {
		err = -ENOMEM;
		goto out;
	}

	strscpy(nparam->name, param->name, EXTPARAMNAMSIZ);
	nparam->type = param->type;
	nparam->id = param->id;

	if (val_ops) {
		if (!val_ops->default_value) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Param %s should have default_value op",
					   param->name);
			err = -EINVAL;
			goto free_param;
		}
		err = val_ops->init_value(NULL, nparam, param->value, extack);
		if (err < 0)
			goto free_param;
	} else {
		nparam->value = kzalloc(bytesz, GFP_KERNEL);
		if (!nparam->value) {
			err = -ENOMEM;
			goto free_param;
		}

		if (param->value)
			memcpy(nparam->value, param->value, bytesz);
	}
	nparam->ops = param->ops;
	nparam->mod_ops = param->mod_ops;

	return nparam;

free_param:
	kfree(nparam);
out:
	return ERR_PTR(err);
}

struct p4tc_extern_params *
p4tc_ext_params_copy(struct p4tc_extern_params *params_orig)
{
	struct p4tc_extern_param *nparam = NULL;
	struct p4tc_extern_params *params_copy;
	const struct p4tc_extern_param *param;
	unsigned long tmp, id;
	int err;

	params_copy = p4tc_extern_params_init();
	if (!params_copy) {
		err = -ENOMEM;
		goto err_out;
	}

	idr_for_each_entry_ul(&params_orig->params_idr, param, tmp, id) {
		struct p4tc_type *param_type = param->type;
		u32 alloc_len = BITS_TO_BYTES(param_type->container_bitsz);
		struct p4tc_type_mask_shift *mask_shift = NULL;

		nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
		if (!nparam) {
			err = -ENOMEM;
			goto free_params;
		}
		nparam->ops = param->ops;
		nparam->mod_ops = param->mod_ops;
		nparam->type = param->type;

		if (param->value) {
			nparam->value = kzalloc(alloc_len, GFP_KERNEL);
			if (!nparam->value) {
				err = -ENOMEM;
				goto free_param;
			}
			memcpy(nparam->value, param->value, alloc_len);
		}

		if (param_type->ops && param_type->ops->create_bitops) {
			const u32 bitsz = param->bitsz;

			mask_shift = param_type->ops->create_bitops(bitsz, 0,
								    bitsz - 1,
								    NULL);
			if (IS_ERR(mask_shift)) {
				err = PTR_ERR(mask_shift);
				goto free_param_value;
			}
			nparam->mask_shift = mask_shift;
		}

		nparam->id = param->id;
		err = idr_alloc_u32(&params_copy->params_idr, nparam,
				    &nparam->id, nparam->id, GFP_KERNEL);
		if (err < 0)
			goto free_mask_shift;

		memcpy(&nparam->index, &param->index,
		       sizeof(*nparam) - offsetof(struct p4tc_extern_param, index));
		params_copy->num_params++;
	}

	return params_copy;

free_mask_shift:
	if (nparam->mask_shift)
		p4t_release(nparam->mask_shift);
free_param_value:
	kfree(nparam->value);
free_param:
	kfree(nparam);
free_params:
	p4tc_ext_params_free(params_copy, true);
err_out:
	return ERR_PTR(err);
}
EXPORT_SYMBOL(p4tc_ext_params_copy);

int p4tc_ext_init_defval_params(struct p4tc_extern_inst *inst,
				struct p4tc_extern_common *common,
				struct idr *control_params_idr,
				struct netlink_ext_ack *extack)
{
	struct p4tc_extern_params *params = NULL;
	struct p4tc_extern_param *param;
	unsigned long tmp, id;
	int err;

	params = p4tc_extern_params_init();
	if (!params)
		return -ENOMEM;

	idr_for_each_entry_ul(control_params_idr, param, tmp, id) {
		struct p4tc_extern_param *nparam;

		if (param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)
			/* Skip key param */
			continue;

		nparam = p4tc_ext_init_defval_param(param, extack);
		if (IS_ERR(nparam)) {
			err = PTR_ERR(nparam);
			goto free_params;
		}

		err = idr_alloc_u32(&params->params_idr, nparam, &nparam->id,
				    nparam->id, GFP_KERNEL);
		if (err < 0) {
			kfree(nparam);
			goto free_params;
		}
		params->num_params++;
	}

	common->params = params;
	common->inst = inst;
	common->ops = inst->ops;
	refcount_set(&common->p4tc_ext_refcnt, 1);
	if (inst->tbl_bindable)
		list_add(&common->node, &inst->unused_elems);

	return 0;

free_params:
	p4tc_ext_params_free(params, true);
	return err;
}
EXPORT_SYMBOL_GPL(p4tc_ext_init_defval_params);

static int p4tc_ext_init_defval(struct p4tc_extern **e,
				struct p4tc_extern_inst *inst,
				u32 key, struct netlink_ext_ack *extack)
{
	const struct p4tc_extern_ops *e_o = inst->ops;
	int err;

	if (!inst->is_scalar) {
		struct p4tc_extern_param *key_param;

		key_param = find_key_param(&inst->params->params_idr);
		if (!key_param) {
			NL_SET_ERR_MSG(extack, "Unable to find key param");
			return -ENOENT;
		}
	}

	err = p4tc_ext_idr_create(inst, key, e, e_o, 0);
	if (err < 0)
		return err;

	/* We already store it in the IDR, because, when we arrive here, the
	 * pipeline is still not sealed, and so no runtime command or data
	 * path thread will be able to access the control_elems_idr yet. Also,
	 * we arrive here with rtnl_lock, so this code is never accessed
	 * concurrently from the template pipeline sealing command.
	 */
	err = idr_alloc_u32(&inst->control_elems_idr, *e, &key,
			    key, GFP_KERNEL);
	if (err < 0) {
		__p4tc_ext_idr_purge(*e);
		return err;
	}

	err = p4tc_ext_init_defval_params(inst, &((*e)->common),
					  &inst->params->params_idr, extack);
	if (err < 0)
		goto release_idr;

	return 0;

release_idr:
	p4tc_ext_idr_release_dec_num_elems(*e);

	return err;
}

static void p4tc_extern_inst_destroy_elems(struct idr *insts_idr)
{
	struct p4tc_extern_inst *inst;
	unsigned long tmp, id;

	idr_for_each_entry_ul(insts_idr, inst, tmp, id) {
		unsigned long tmp2, elem_id;
		struct p4tc_extern *e;

		idr_for_each_entry_ul(&inst->control_elems_idr, e,
				      tmp2, elem_id) {
			p4tc_ext_idr_purge(e);
		}
	}
}

static void p4tc_user_pipe_ext_destroy_elems(struct idr *user_ext_idr)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	unsigned long tmp, id;

	idr_for_each_entry_ul(user_ext_idr, pipe_ext, tmp, id) {
		if (p4tc_ext_has_construct(pipe_ext->tmpl_ext->ops))
			continue;

		p4tc_extern_inst_destroy_elems(&pipe_ext->e_inst_idr);
	}
}

static int
___p4tc_extern_inst_init_elems(struct p4tc_extern_inst *inst, u32 num_elems)
{
	int err = 0;
	int i;

	for (i = 0; i < num_elems; i++) {
		struct p4tc_extern *e = NULL;

		err = p4tc_ext_init_defval(&e, inst, i + 1, NULL);
		if (err)
			return err;
	}

	return 0;
}

static int
__p4tc_extern_inst_init_elems(struct idr *insts_idr)
{
	struct p4tc_extern_inst *inst;
	unsigned long tmp, id;
	int err = 0;

	idr_for_each_entry_ul(insts_idr, inst, tmp, id) {
		u32 max_num_elems = inst->max_num_elems;

		err = ___p4tc_extern_inst_init_elems(inst, max_num_elems);
		if (err < 0)
			return err;
	}

	return 0;
}

/* Called before sealing the pipeline */
int p4tc_extern_inst_init_elems(struct idr *user_ext_idr)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	unsigned long tmp, id;
	int err;

	idr_for_each_entry_ul(user_ext_idr, pipe_ext, tmp, id) {
		/* We assume the module construct will create the initial elems
		 * by itself.
		 * We only initialise after sealing if we don't have construct.
		 */
		if (p4tc_ext_has_construct(pipe_ext->tmpl_ext->ops))
			continue;

		err = __p4tc_extern_inst_init_elems(&pipe_ext->e_inst_idr);
		if (err < 0)
			goto destroy_ext_inst_elems;
	}

	return 0;

destroy_ext_inst_elems:
	p4tc_user_pipe_ext_destroy_elems(user_ext_idr);
	return err;
}

static struct p4tc_extern *
p4tc_extern_init_1(struct p4tc_pipeline *pipeline,
		   struct p4tc_extern_inst *inst,
		   struct nlattr *nla, u32 key, u32 flags,
		   struct netlink_ext_ack *extack)
{
	return p4tc_ext_init(pipeline->net, nla, inst, key,
			     flags, extack);
}

static int tce_get_fill(struct sk_buff *skb, struct p4tc_extern *externs[],
			u32 portid, u32 seq, u16 flags, u32 pipeid, int cmd,
			int ref, struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlmsghdr *nlh;
	struct nlattr *nest;
	struct p4tcmsg *t;

	nlh = nlmsg_put(skb, portid, seq, cmd, sizeof(*t), flags);
	if (!nlh)
		goto out_nlmsg_trim;
	t = nlmsg_data(nlh);
	t->pipeid = pipeid;
	t->obj = P4TC_OBJ_RUNTIME_EXTERN;

	nest = nla_nest_start(skb, P4TC_ROOT);
	if (p4tc_extern_elem_dump(skb, externs, ref) < 0)
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	nlh->nlmsg_len = (unsigned char *)nlmsg_get_pos(skb) - b;

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int
p4tc_extern_get_respond(struct net *net, u32 portid, struct nlmsghdr *n,
			struct p4tc_extern *externs[], u32 pipeid,
			size_t attr_size, struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;

	skb = alloc_skb(attr_size <= NLMSG_GOODSIZE ? NLMSG_GOODSIZE : attr_size,
			GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;
	if (tce_get_fill(skb, externs, portid, n->nlmsg_seq, 0, pipeid,
			 RTM_P4TC_GET, 1, NULL) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill netlink attributes while adding TC extern");
		kfree_skb(skb);
		return -EINVAL;
	}

	return rtnl_unicast(skb, net, portid);
}

static struct p4tc_extern *
p4tc_extern_get_1(struct p4tc_extern_inst *inst,
		  struct nlattr *nla, const char *kind, struct nlmsghdr *n,
		  u32 key, u32 portid, struct netlink_ext_ack *extack)
{
	struct p4tc_extern *e;
	int err;

	if (p4tc_ext_inst_has_rctrl(inst)) {
		err = inst->ops->rctrl(n->nlmsg_type, inst,
				       (struct p4tc_extern_common **)&e,
				       NULL, &key, extack);
		if (err < 0)
			return ERR_PTR(err);

		return e;
	}

	if (__p4tc_ext_idr_search(inst, &e, key) == 0) {
		err = -ENOENT;
		NL_SET_ERR_MSG(extack, "TC extern with specified key not found");
		goto err_out;
	}

	return e;

err_out:
	return ERR_PTR(err);
}

static int
p4tc_extern_add_notify(struct net *net, struct nlmsghdr *n,
		       struct p4tc_extern *externs[], u32 portid, u32 pipeid,
		       size_t attr_size, struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;

	skb = alloc_skb(attr_size <= NLMSG_GOODSIZE ? NLMSG_GOODSIZE : attr_size,
			GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tce_get_fill(skb, externs, portid, n->nlmsg_seq, n->nlmsg_flags,
			 pipeid, n->nlmsg_type, 0, extack) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill netlink attributes while adding TC extern");
		kfree_skb(skb);
		return -EINVAL;
	}

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static int p4tc_ext_get_key_param(struct p4tc_extern_inst *inst,
				  struct nlattr *nla,
				  struct idr *params_idr, u32 *key,
				  struct netlink_ext_ack *extack)
{
	int err = 0;

	if (inst->is_scalar) {
		if (nla) {
			err = p4tc_ext_get_key_param_scalar(inst, nla, key,
							    extack);
			if (err < 0)
				return err;

			if (*key != 1) {
				NL_SET_ERR_MSG(extack,
					       "Key of scalar must be 1");
				return -EINVAL;
			}
		} else {
			*key = 1;
		}
	} else {
		if (nla) {
			err = p4tc_ext_get_nonscalar_key_param(params_idr, nla,
							       key, extack);
			if (err < 0)
				return -EINVAL;
		}

		if (!key) {
			NL_SET_ERR_MSG(extack, "Must specify extern key");
			return -EINVAL;
		}
	}

	return err;
}

static struct p4tc_extern *
__p4tc_ctl_extern_1(struct p4tc_pipeline *pipeline,
		    struct nlattr *nla, struct nlmsghdr *n,
		    u32 portid, u32 flags, bool rctrl_allowed,
		    struct netlink_ext_ack *extack)
{
	const char *kind = p4tc_ext_get_kind(nla, extack);
	struct nlattr *tb[P4TC_EXT_MAX + 1];
	struct p4tc_extern_inst *inst;
	struct nlattr *params_attr;
	struct p4tc_extern *e;
	char *instname;
	u32 key;
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_MAX, nla,
			       p4tc_extern_policy, extack);
	if (err < 0)
		return ERR_PTR(err);

	if (IS_ERR(kind))
		return (struct p4tc_extern *)kind;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_INST_NAME)) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		return ERR_PTR(-EINVAL);
	}
	instname = nla_data(tb[P4TC_EXT_INST_NAME]);

	err = -EINVAL;
	inst = p4tc_ext_inst_find_bynames(pipeline->net, pipeline, kind,
					  instname, extack);
	if (IS_ERR(inst))
		return (struct p4tc_extern *)inst;

	if (!rctrl_allowed && p4tc_ext_has_rctrl(inst->ops)) {
		NL_SET_ERR_MSG(extack,
			       "Runtime message may only have one extern with rctrl op");
		return ERR_PTR(-EINVAL);
	}

	err = p4tc_ext_get_key_param(inst, tb[P4TC_EXT_KEY],
				     &inst->params->params_idr, &key,
				     extack);
	if (err < 0)
		return ERR_PTR(err);

	params_attr = tb[P4TC_EXT_PARAMS];

	switch (n->nlmsg_type) {
	case RTM_P4TC_CREATE:
		NL_SET_ERR_MSG(extack,
			       "Create command is not supported");
		return ERR_PTR(-EOPNOTSUPP);
	case RTM_P4TC_UPDATE: {
		struct nla_bitfield32 userflags = { 0, 0 };

		if (tb[P4TC_EXT_FLAGS])
			userflags = nla_get_bitfield32(tb[P4TC_EXT_FLAGS]);

		flags = userflags.value | flags;
		e = p4tc_extern_init_1(pipeline, inst, params_attr, key,
				       flags, extack);
		break;
	}
	case RTM_P4TC_DEL:
		NL_SET_ERR_MSG(extack,
			       "Delete command is not supported");
		return ERR_PTR(-EOPNOTSUPP);
	case RTM_P4TC_GET: {
		e = p4tc_extern_get_1(inst, params_attr, kind, n, key, portid,
				      extack);
		break;
	}
	default:
		NL_SET_ERR_MSG_FMT(extack, "Unknown extern command #%u",
				   n->nlmsg_type);
		return ERR_PTR(-EOPNOTSUPP);
	}

	return e;
}

static int __p4tc_ctl_extern(struct p4tc_pipeline *pipeline,
			     struct nlattr *nla, struct nlmsghdr *n,
			     u32 portid, u32 flags,
			     struct netlink_ext_ack *extack)
{
	struct p4tc_extern *externs[P4TC_MSGBATCH_SIZE] = {};
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	bool processed_rctrl_extern = false;
	struct p4tc_extern *ext;
	size_t attr_size = 0;
	bool has_one_element;
	int i, ret;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
			       extack);
	if (ret < 0)
		return ret;

	/* We only allow 1 batched element in case of a module extern element */
	has_one_element = !tb[2];
	ext = __p4tc_ctl_extern_1(pipeline, tb[1], n, portid,
				  flags, has_one_element, extack);
	if (IS_ERR(ext))
		return PTR_ERR(ext);

	externs[0] = ext;
	if (p4tc_ext_has_rctrl(ext->common.ops)) {
		processed_rctrl_extern = true;
		goto notify;
	} else {
		attr_size += ext->attrs_size;
	}

	for (i = 2; i <= P4TC_MSGBATCH_SIZE && tb[i]; i++) {
		ext = __p4tc_ctl_extern_1(pipeline, tb[i], n, portid,
					  flags, false, extack);
		if (IS_ERR(ext)) {
			ret = PTR_ERR(ext);
			goto err;
		}

		attr_size += ext->attrs_size;
		/* Only add to externs array, extern modules that don't
		 * implement rctrl callback.
		 */
		externs[i - 1] = ext;
	}

notify:
	attr_size = p4tc_extern_full_attrs_size(attr_size);

	if (n->nlmsg_type == RTM_P4TC_UPDATE) {
		int listeners = rtnl_has_listeners(pipeline->net, RTNLGRP_TC);
		int echo = n->nlmsg_flags & NLM_F_ECHO;

		if (!processed_rctrl_extern)
			p4tc_ext_idr_insert_many(externs);

		if (echo || listeners)
			p4tc_extern_add_notify(pipeline->net, n, externs,
					       portid, pipeline->common.p_id,
					       attr_size, extack);
	} else if (n->nlmsg_type == RTM_P4TC_GET) {
		p4tc_extern_get_respond(pipeline->net, portid, n, externs,
					pipeline->common.p_id, attr_size,
					extack);
	}

	return 0;

err:
	if (n->nlmsg_type == RTM_P4TC_UPDATE)
		p4tc_extern_destroy(externs);
	else if (n->nlmsg_type == RTM_P4TC_GET)
		p4tc_extern_put_many(externs);

	return ret;
}

static int parse_dump_ext_attrs(struct nlattr *nla,
				struct nlattr **tb2)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];

	if (nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
			     NULL) < 0)
		return -EINVAL;

	if (!tb[1])
		return -EINVAL;
	if (nla_parse_nested(tb2, P4TC_EXT_MAX, tb[1],
			     p4tc_extern_policy, NULL) < 0)
		return -EINVAL;

	if (!tb2[P4TC_EXT_KIND])
		return -EINVAL;

	if (!tb2[P4TC_EXT_INST_NAME])
		return -EINVAL;

	return 0;
}

int p4tc_ctl_extern_dump(struct sk_buff *skb, struct netlink_callback *cb,
			 struct nlattr **tb, const char *pname)
{
	struct netlink_ext_ack *extack = cb->extack;
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *tb2[P4TC_EXT_MAX + 1];
	struct net *net = sock_net(skb->sk);
	struct nlattr *count_attr = NULL;
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;
	char *kind_str, *instname;
	struct nla_bitfield32 bf;
	struct nlmsghdr *nlh;
	struct nlattr *nest;
	u32 ext_count = 0;
	struct p4tcmsg *t;
	int ret = 0;

	pipeline = p4tc_pipeline_find_byany(net, pname, 0, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Pipeline must be sealed for extern runtime ops");
		return -EINVAL;
	}

	ret = parse_dump_ext_attrs(tb[P4TC_ROOT], tb2);
	if (ret < 0)
		return ret;

	kind_str = nla_data(tb2[P4TC_EXT_KIND]);
	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_KIND)) {
		NL_SET_ERR_MSG(extack,
			       "TC extern kind name must be specified");
		return -EINVAL;
	}

	instname = nla_data(tb2[P4TC_EXT_INST_NAME]);
	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_INST_NAME)) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		return -EINVAL;
	}

	inst = p4tc_ext_inst_find_bynames(pipeline->net, pipeline, kind_str,
					  instname, extack);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

	cb->args[2] = 0;
	if (tb[P4TC_ROOT_FLAGS]) {
		bf = nla_get_bitfield32(tb[P4TC_ROOT_FLAGS]);
		cb->args[2] = bf.value;
	}

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, sizeof(*t), 0);
	if (!nlh)
		goto err_out;

	t = nlmsg_data(nlh);
	t->pipeid = pipeline->common.p_id;
	t->obj = P4TC_OBJ_RUNTIME_EXTERN;
	count_attr = nla_reserve(skb, P4TC_ROOT_COUNT, sizeof(u32));
	if (!count_attr)
		goto err_out;

	nest = nla_nest_start_noflag(skb, P4TC_ROOT);
	if (!nest)
		goto err_out;

	ret = p4tc_ext_dump_walker(inst, skb, cb);
	if (ret < 0)
		goto err_out;

	if (ret > 0) {
		nla_nest_end(skb, nest);
		ret = skb->len;
		ext_count = cb->args[1];
		memcpy(nla_data(count_attr), &ext_count, sizeof(u32));
		cb->args[1] = 0;
	} else {
		nlmsg_trim(skb, b);
	}

	nlh->nlmsg_len = (unsigned char *)nlmsg_get_pos(skb) - b;
	if (NETLINK_CB(cb->skb).portid && ret)
		nlh->nlmsg_flags |= NLM_F_MULTI;
	return skb->len;

err_out:
	nlmsg_trim(skb, b);
	return skb->len;
}

int p4tc_ctl_extern(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
		    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	struct p4tc_pipeline *pipeline;
	struct nlattr *root;
	char *pname = NULL;
	u32 flags = 0;
	int ret = 0;

	if (cmd != RTM_P4TC_GET && !netlink_capable(skb, CAP_NET_ADMIN)) {
		NL_SET_ERR_MSG(extack, "Need CAP_NET_ADMIN to do CRU ops");
		return -EPERM;
	}

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (tb[P4TC_ROOT_PNAME])
		pname = nla_data(tb[P4TC_ROOT_PNAME]);

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(extack, "Netlink P4TC extern attributes missing");
		return -EINVAL;
	}

	root = tb[P4TC_ROOT];

	pipeline = p4tc_pipeline_find_byany(net, pname, 0, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Pipeline must be sealed for extern runtime ops");
		return -EPERM;
	}

	return __p4tc_ctl_extern(pipeline, root, n, portid, flags, extack);
}
