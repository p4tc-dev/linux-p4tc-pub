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

static void p4tc_ext_put_param(struct p4tc_extern_param *param)
{
	kfree(param->value);
	kfree(param);
}

static void p4tc_ext_put_many_params(struct idr *params_idr,
				     struct p4tc_extern_param *params[],
				     int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4tc_ext_put_param(params[i]);
}

static void p4tc_ext_insert_param(struct idr *params_idr,
				  struct p4tc_extern_param *param)
{
	struct p4tc_extern_param *param_old;

	param_old = idr_replace(params_idr, param, param->id);
	if (param_old != ERR_PTR(-EBUSY))
		p4tc_ext_put_param(param_old);
}

static void p4tc_ext_insert_many_params(struct idr *params_idr,
					struct p4tc_extern_param *params[],
					int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4tc_ext_insert_param(params_idr, params[i]);
}

static void free_p4tc_ext_params(struct p4tc_extern_params *params)
{
	struct p4tc_extern_param *parm;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&params->params_idr, parm, tmp, id) {
		idr_remove(&params->params_idr, id);
		p4tc_ext_put_param(parm);
	}

	kfree(params);
}

static void free_p4tc_ext(struct p4tc_extern *p)
{
	if (p->params)
		free_p4tc_ext_params(p->params);
	refcount_dec(&p->inst->inst_ref);

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
	if (refcount_dec_and_test(&p->p4tc_ext_refcnt)) {
		idr_remove(p->elems_idr, p->p4tc_ext_key);

		refcount_dec(&p->inst->curr_num_elems);
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
			ret = ACT_P_DELETED;
	}

	return ret;
}

static int p4tc_ext_idr_release(struct p4tc_extern *e)
{
	const struct p4tc_extern_ops *ops = e->ops;
	struct p4tc_extern_inst *inst = e->inst;
	int ret;

	ret = __p4tc_ext_idr_release(e);
	if (ret == ACT_P_DELETED) {
		refcount_dec(&inst->curr_num_elems);
		p4tc_extern_ops_put(ops);
	}

	return ret;
}

static size_t p4tc_extern_shared_attrs_size(const struct p4tc_extern *ext)
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

static size_t p4tc_extern_fill_size(const struct p4tc_extern *ext)
{
	size_t sz = p4tc_extern_shared_attrs_size(ext);

	return sz;
}

struct p4tc_extern_param_ops {
	int (*init_value)(struct net *net, struct p4tc_extern_param_ops *op,
			  struct p4tc_extern_param *nparam, struct nlattr **tb,
			  struct netlink_ext_ack *extack);
	int (*dump_value)(struct sk_buff *skb, struct p4tc_extern_param_ops *op,
			  struct p4tc_extern_param *param);
	void (*free)(struct p4tc_extern_param *param);
	u32 len;
	u32 alloc_len;
};

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

static int dev_init_param_value(struct net *net, struct p4tc_extern_param_ops *op,
				struct p4tc_extern_param *nparam,
				struct nlattr **tb,
				struct netlink_ext_ack *extack)
{
	struct nlattr *tb_value[P4TC_EXT_VALUE_PARAMS_MAX + 1];
	u32 value_len;
	u32 *ifindex;
	int err;

	if (!tb[P4TC_EXT_PARAMS_VALUE]) {
		NL_SET_ERR_MSG(extack, "Must specify param value");
		return -EINVAL;
	}
	err = nla_parse_nested(tb_value, P4TC_EXT_VALUE_PARAMS_MAX,
			       tb[P4TC_EXT_PARAMS_VALUE],
			       p4tc_extern_params_value_policy, extack);
	if (err < 0)
		return err;

	value_len = nla_len(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]);
	if (value_len != sizeof(u32)) {
		NL_SET_ERR_MSG(extack, "Value length differs from template's");
		return -EINVAL;
	}

	ifindex = nla_data(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]);
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

static int
p4tc_extern_dump_1(struct sk_buff *skb, struct p4tc_extern *e, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_extern_param *parm;
	struct nlattr *nest_parms;
	u32 flags;
	int id;

	if (nla_put_string(skb, P4TC_EXT_KIND, e->ops->kind))
		goto nla_put_failure;

	flags = e->p4tc_ext_flags & P4TC_EXT_FLAGS_USER_MASK;
	if (flags &&
	    nla_put_bitfield32(skb, P4TC_EXT_FLAGS,
			       flags, flags))
		goto nla_put_failure;

	nest_parms = nla_nest_start(skb, P4TC_EXT_PARAMS);
	if (e->params) {
		int i = 1;

		idr_for_each_entry(&e->params->params_idr, parm, id) {
			struct p4tc_extern_param_ops *op;
			struct nlattr *nest_count;

			nest_count = nla_nest_start(skb, i);
			if (!nest_count)
				goto nla_put_failure;

			if (nla_put_string(skb, P4TC_EXT_PARAMS_NAME,
					   parm->name))
				goto nla_put_failure;

			if (nla_put_u32(skb, P4TC_EXT_PARAMS_ID, parm->id))
				goto nla_put_failure;

			op = (struct p4tc_extern_param_ops *)&ext_param_ops[parm->type->typeid];
			spin_lock(&e->params->params_lock);
			if (op->dump_value) {
				if (op->dump_value(skb, op, parm) < 0) {
					spin_unlock(&e->params->params_lock);
					goto nla_put_failure;
				}
			} else {
				if (generic_dump_ext_param_value(skb, parm->type, parm)) {
					spin_unlock(&e->params->params_lock);
					goto nla_put_failure;
				}
			}
			spin_unlock(&e->params->params_lock);

			if (nla_put_u32(skb, P4TC_EXT_PARAMS_TYPE, parm->type->typeid))
				goto nla_put_failure;

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

static int p4tc_ext_dump_walker(struct p4tc_extern_inst *inst,
				struct sk_buff *skb,
				struct netlink_callback *cb)
{
	struct idr *idr = &inst->inst_common->control_elems_idr;
	int err = 0, s_i = 0, n_i = 0;
	u32 ext_flags = cb->args[2];
	unsigned long id = 1;
	struct p4tc_extern *p;
	struct nlattr *nest;
	unsigned long tmp;
	int key = -1;

	s_i = cb->args[0];

	idr_for_each_entry_ul(idr, p, tmp, id) {
		key++;
		if (key < s_i)
			continue;
		if (IS_ERR(p))
			continue;

		nest = nla_nest_start_noflag(skb, n_i);
		if (!nest) {
			key--;
			goto nla_put_failure;
		}

		err = p4tc_extern_dump_1(skb, p, 0);
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

static void p4tc_ext_idr_purge(struct p4tc_extern *p)
{
	idr_remove(p->elems_idr, p->p4tc_ext_key);
	p4tc_extern_ops_put(p->ops);
	refcount_dec(&p->inst->curr_num_elems);
	p4tc_extern_cleanup(p);
}

static int p4tc_ext_idr_release_unsafe(struct p4tc_extern *p)
{
	if (refcount_dec_and_test(&p->p4tc_ext_refcnt)) {
		idr_remove(p->elems_idr, p->p4tc_ext_key);
		p4tc_extern_cleanup(p);
		return ACT_P_DELETED;
	}

	return 0;
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

static int p4tc_ext_del_walker(struct p4tc_extern_inst *inst,
			       struct sk_buff *skb,
			       const struct p4tc_extern_ops *ops,
			       struct netlink_ext_ack *extack)
{
	struct idr *idr = &inst->inst_common->control_elems_idr;
	unsigned long id = 1;
	int ret = -EINVAL;
	int n_i = 0;
	struct p4tc_extern *p;
	struct nlattr *nest;
	unsigned long tmp;

	nest = nla_nest_start_noflag(skb, 0);
	if (!nest)
		goto nla_put_failure;
	if (nla_put_string(skb, P4TC_EXT_KIND, ops->kind))
		goto nla_put_failure;

	ret = 0;
	idr_for_each_entry_ul(idr, p, tmp, id) {
		if (IS_ERR(p))
			continue;
		ret = p4tc_ext_idr_release_unsafe(p);
		if (ret == ACT_P_DELETED) {
			refcount_dec(&inst->curr_num_elems);
			p4tc_extern_ops_put(ops);
		} else if (ret < 0) {
			break;
		}
		n_i++;
	}
	if (ret < 0) {
		if (n_i)
			NL_SET_ERR_MSG(extack, "Unable to flush all TC externs");
		else
			goto nla_put_failure;
	}

	ret = nla_put_u32(skb, P4TC_EXT_FCNT, n_i);
	if (ret)
		goto nla_put_failure;
	nla_nest_end(skb, nest);

	return n_i;
nla_put_failure:
	nla_nest_cancel(skb, nest);
	return ret;
}

static int p4tc_ext_generic_walker(struct p4tc_extern_inst *inst,
				   struct sk_buff *skb,
				   struct netlink_callback *cb, int type,
				   const struct p4tc_extern_ops *ops,
				   struct netlink_ext_ack *extack)
{
	if (type == RTM_P4TC_DEL)
		return p4tc_ext_del_walker(inst, skb, ops, extack);
	else if (type == RTM_P4TC_GET)
		return p4tc_ext_dump_walker(inst, skb, cb);

	WARN(1, "%s: unknown command %d\n", __func__, type);
	NL_SET_ERR_MSG_FMT(extack, "%s: unknown command", __func__);
	return -EINVAL;
}

static int p4tc_ext_idr_search(struct p4tc_extern_inst *inst,
			       struct p4tc_extern **e, u32 key)
{
	struct idr *elems_idr = &inst->inst_common->control_elems_idr;
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

static int __p4tc_ext_generic_walker(struct sk_buff *skb,
				     struct netlink_callback *cb, int type,
				     struct p4tc_extern_inst *inst,
				     const struct p4tc_extern_ops *ops,
				     struct netlink_ext_ack *extack)
{
	return p4tc_ext_generic_walker(inst, skb, cb, type, ops, extack);
}

static int __p4tc_ext_idr_search(struct p4tc_extern_inst *inst,
				 struct p4tc_extern **e, u32 key)
{
	if (p4tc_ext_idr_search(inst, e, key)) {
		refcount_inc(&((*e)->p4tc_ext_refcnt));
		return true;
	}

	return false;
}

static int p4tc_ext_idr_delete_key(struct idr *elems_idr, u32 key)
{
	struct p4tc_extern *p;
	int ret = 0;

	p = idr_find(elems_idr, key);
	if (!p)
		return -ENOENT;

	if (refcount_dec_and_test(&p->p4tc_ext_refcnt)) {
		WARN_ON(p != idr_remove(elems_idr, p->p4tc_ext_key));

		refcount_dec(&p->inst->curr_num_elems);
		p4tc_extern_ops_put(p->ops);
		p4tc_extern_cleanup(p);
		return 0;
	}

	return ret;
}

static int p4tc_ext_copy(struct p4tc_extern_inst *inst,
			 u32 key, struct p4tc_extern **e,
			 struct p4tc_extern *e_orig,
			 const struct p4tc_extern_ops *ops,
			 u32 flags)
{
	struct p4tc_extern *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (unlikely(!p))
		return -ENOMEM;

	spin_lock_init(&p->p4tc_ext_lock);
	p->p4tc_ext_key = key;
	spin_lock(&e_orig->p4tc_ext_lock);
	spin_unlock(&e_orig->p4tc_ext_lock);
	p->p4tc_ext_flags = flags;
	refcount_set(&p->p4tc_ext_refcnt,
		     refcount_read(&e_orig->p4tc_ext_refcnt));

	p->elems_idr = e_orig->elems_idr;
	refcount_inc(&inst->inst_ref);
	p->inst = inst;
	p->ops = ops;
	*e = p;
	return 0;
}

static int p4tc_ext_idr_create(struct p4tc_extern_inst *inst,
			       u32 key, struct p4tc_extern **e,
			       const struct p4tc_extern_ops *ops,
			       u32 flags)
{
	struct p4tc_extern *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (unlikely(!p))
		return -ENOMEM;

	if (refcount_read(&inst->curr_num_elems) - 1 == inst->max_num_elems) {
		kfree(p);
		return -E2BIG;
	}

	refcount_inc(&inst->curr_num_elems);

	refcount_set(&p->p4tc_ext_refcnt, 1);

	spin_lock_init(&p->p4tc_ext_lock);
	p->p4tc_ext_key = key;
	p->p4tc_ext_flags = flags;

	p->elems_idr = &inst->inst_common->control_elems_idr;
	__module_get(ops->owner);
	inst->ops = ops;
	refcount_inc(&inst->inst_ref);
	p->inst = inst;
	p->ops = ops;
	*e = p;
	return 0;
}

/* Cleanup idr key that was allocated but not initialized. */

static void p4tc_ext_idr_cleanup(struct p4tc_extern_inst_common *inst_common,
				 u32 key)
{
	/* Remove ERR_PTR(-EBUSY) allocated by p4tc_ext_idr_check_alloc */
	WARN_ON(!IS_ERR(idr_remove(&inst_common->control_elems_idr, key)));
}

/* Check if extern with specified key exists. If externs is found, increments
 * its reference, and return 1. Otherwise insert temporary error pointer
 * (to prevent concurrent users from inserting externs with same key) and
 * return 0.
 */

static int p4tc_ext_idr_check_alloc(struct p4tc_extern_inst *inst,
				    u32 *key, struct p4tc_extern **e)
{
	struct idr *elems_idr = &inst->inst_common->control_elems_idr;
	struct p4tc_extern *p;
	int ret;

again:
	if (*key) {
		p = idr_find(elems_idr, *key);
		if (IS_ERR(p)) {
			/* This means that another process allocated
			 * key but did not assign the pointer yet.
			 */
			goto again;
		}

		if (p) {
			refcount_inc(&p->p4tc_ext_refcnt);
			*e = p;
			ret = 1;
		} else {
			*e = NULL;
			ret = idr_alloc_u32(elems_idr, NULL, key,
					    *key, GFP_KERNEL);
			if (!ret)
				idr_replace(elems_idr,
					    ERR_PTR(-EBUSY), *key);
		}
	} else {
		*key = 1;
		*e = NULL;
		ret = idr_alloc_u32(elems_idr, NULL, key, UINT_MAX,
				    GFP_KERNEL);
		if (!ret)
			idr_replace(elems_idr, ERR_PTR(-EBUSY), *key);
	}
	return ret;
}

static inline void *read_control_value(struct idr *params_idr, const u32 index)
{
	struct p4tc_extern_param *param = idr_find(params_idr, index);

	return param->value;
}

static int p4tc_extern_exec_write(struct p4tc_extern *e,
				  struct p4tc_ext_bpf_params *params)
{
	u8 *params_data = params->in_params;
	struct p4tc_extern_param *param;
	struct p4tc_type *type;

	/* When it's method P4TC_EXT_FLAGS_CONTROL_WRITE, we assume the first
	 * parameter is the index and the second is the value we wish to write
	 * to.
	 */
	spin_lock(&e->params->params_lock);

	param = idr_find(&e->params->params_idr, 2);
	type = param->type;

	p4t_copy(param->mask_shift, type, param->value,
		 param->mask_shift, type, params_data);

	spin_unlock(&e->params->params_lock);

	return 0;
}

static int p4tc_extern_exec_read(struct p4tc_extern *e,
				 struct p4tc_ext_bpf_res *res, u32 index)
{
	int ret = 0;
	struct p4tc_extern_param *param;
	const struct p4tc_type_ops *ops;

	/* When it's method P4TC_EXT_FLAGS_CONTROL_READ, we assume the first
	 * parameter is the index and the second is the value we want to read.
	 */
	spin_lock(&e->params->params_lock);
	param = idr_find(&e->params->params_idr, 2);
	ops = param->type->ops;

	if (unlikely(!ops->host_read)) {
		ret = -EINVAL;
		goto unlock;
	}

	ops->host_read(param->type, param->mask_shift, param->value,
		       res->out_params);

unlock:
	spin_unlock(&e->params->params_lock);

	return ret;
}

int
p4tc_extern_exec_bpf(struct sk_buff *skb, struct p4tc_ext_bpf_params *params,
		     struct p4tc_ext_bpf_res *res)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	struct p4tc_ext_bpf_params_exec exec_params = {0};
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;
	struct p4tc_extern *e;
	int ret;

	inst = p4tc_ext_inst_get_byids(net, &pipeline, params->pipe_id,
				       &pipe_ext, params->ext_id,
				       params->inst_id);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

	e = idr_find(&inst->inst_common->control_elems_idr, params->index);
	if (!e)
		return -ENOENT;

	if (params->flags & P4TC_EXT_FLAGS_CONTROL_READ) {
		ret = p4tc_extern_exec_read(e, res, params->index);
	} else if (params->flags & P4TC_EXT_FLAGS_CONTROL_WRITE) {
		ret = p4tc_extern_exec_write(e, params);
	} else {
		exec_params.data = (u8 *)params->in_params;
		exec_params.method_id = params->method_id;
		ret = inst->ops->exec(skb, inst->inst_common, e, &exec_params,
				      res);
	}

	refcount_dec(&inst->inst_ref);
	refcount_dec(&pipe_ext->ext_ref);
	refcount_dec(&pipeline->p_ref);

	return ret;
}

static int p4tc_extern_destroy(struct p4tc_extern *externs[], int init_res[])
{
	const struct p4tc_extern_ops *ops;
	struct p4tc_extern *e;
	int ret = 0, i;

	for (i = 0; i < P4TC_MSGBATCH_SIZE && externs[i]; i++) {
		e = externs[i];
		externs[i] = NULL;
		ops = e->ops;
		if (init_res[i] == P4TC_EXT_P_CREATED) {
			struct p4tc_extern_inst *inst = e->inst;

			ret = __p4tc_ext_idr_release(e);
			if (ret == ACT_P_DELETED) {
				refcount_dec(&inst->curr_num_elems);
				p4tc_extern_ops_put(ops);
			} else if (ret < 0) {
				return ret;
			}
		} else {
			p4tc_extern_ops_put(ops);
			free_p4tc_ext_rcu(&e->rcu);
		}
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
		ops = e->ops;
		if (p4tc_extern_put(e))
			p4tc_extern_ops_put(ops);
	}
}

static int p4tc_extern_dump(struct sk_buff *skb, struct p4tc_extern *externs[],
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
		err = p4tc_extern_dump_1(skb, e, ref);
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

static int generic_init_param_value(struct p4tc_extern_param *nparam,
				    struct p4tc_type *type, struct nlattr **tb,
				    struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(type->container_bitsz);
	const u32 len = BITS_TO_BYTES(type->bitsz);
	struct nlattr *tb_value[P4TC_EXT_VALUE_PARAMS_MAX + 1];
	void *value;
	int err;

	if (!tb[P4TC_EXT_PARAMS_VALUE]) {
		NL_SET_ERR_MSG(extack, "Must specify param value");
		return -EINVAL;
	}

	err = nla_parse_nested(tb_value, P4TC_EXT_VALUE_PARAMS_MAX,
			       tb[P4TC_EXT_PARAMS_VALUE],
			       p4tc_extern_params_value_policy, extack);
	if (err < 0)
		return err;

	value = nla_data(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]);
	if (type->ops->validate_p4t) {
		err = type->ops->validate_p4t(type, value, 0, type->bitsz - 1,
					      extack);
		if (err < 0)
			return err;
	}

	if (nla_len(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]) != len)
		return -EINVAL;

	nparam->value = kzalloc(alloc_len, GFP_KERNEL);
	if (!nparam->value)
		return -ENOMEM;

	memcpy(nparam->value, value, len);

	return 0;
}

static const struct nla_policy p4tc_extern_policy[P4TC_EXT_MAX + 1] = {
	[P4TC_EXT_KIND]		= { .type = NLA_STRING },
	[P4TC_EXT_PARAMS]	= { .type = NLA_NESTED },
	[P4TC_EXT_FLAGS]	= { .type = NLA_BITFIELD32 },
	[P4TC_EXT_INST_NAME]	= {
		.type = NLA_STRING,
		.len = EXTERNINSTNAMSIZ
	},
};

static const struct nla_policy p4tc_extern_params_policy[P4TC_EXT_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_NAME] = { .type = NLA_STRING, .len = EXTPARAMNAMSIZ },
	[P4TC_EXT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_EXT_PARAMS_TYPE] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_BITSZ] = { .type = NLA_U16 },
	[P4TC_EXT_PARAMS_FLAGS] = { .type = NLA_U8 },
};

static struct p4tc_extern_param *
p4tc_ext_create_param(struct net *net, struct p4tc_extern_params *params,
		      struct p4tc_extern_inst_common *inst_common,
		      struct nlattr **tb, size_t *attrs_size,
		      struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &inst_common->control_params_idr;
	u32 param_id = 0;
	struct p4tc_extern_param *param, *nparam;
	struct p4tc_extern_param_ops *op;
	int err;

	if (tb[P4TC_EXT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_EXT_PARAMS_ID]);
	*attrs_size += nla_total_size(sizeof(u32));

	param = p4tc_extern_param_find_byanyattr(params_idr,
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

	op = (struct p4tc_extern_param_ops *)&ext_param_ops[param->type->typeid];
	if (op->init_value)
		err = op->init_value(net, op, nparam, tb, extack);
	else
		err = generic_init_param_value(nparam, nparam->type, tb, extack);
	*attrs_size += nla_total_size(BITS_TO_BYTES(param->type->container_bitsz));

	if (err < 0)
		goto free;

	nparam->id = param->id;

	err = idr_alloc_u32(&params->params_idr, ERR_PTR(-EBUSY), &nparam->id,
			    nparam->id, GFP_KERNEL);
	if (err < 0)
		goto free_val;

	return nparam;

free_val:
	if (op->free)
		op->free(nparam);
	else
		generic_free_param_value(nparam);

free:
	kfree(nparam);
	return ERR_PTR(err);
}

static struct p4tc_extern_param *
p4tc_ext_init_param(struct net *net, struct p4tc_extern_inst *inst,
		    struct p4tc_extern_params *params, struct nlattr *nla,
		    size_t *attrs_size, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst_common *inst_common = inst->inst_common;
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (err < 0)
		return ERR_PTR(err);

	return p4tc_ext_create_param(net, params, inst_common, tb, attrs_size,
				     extack);
}

static int __p4tc_ext_get_key_param(struct p4tc_extern_inst *inst,
				    struct nlattr *nla, u32 *key,
				    struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &inst->inst_common->control_params_idr;
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	struct p4tc_extern_param *index_param;
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (err < 0)
		return err;

	if (!tb[P4TC_EXT_PARAMS_NAME]) {
		NL_SET_ERR_MSG(extack, "Must specify key param name");
		return -EINVAL;
	}

	if (!tb[P4TC_EXT_PARAMS_VALUE]) {
		NL_SET_ERR_MSG(extack, "Must specify key param value");
		return -EINVAL;
	}

	index_param = p4tc_extern_param_find_byanyattr(params_idr,
						       tb[P4TC_EXT_PARAMS_NAME],
						       0, extack);
	if (IS_ERR(index_param)) {
		NL_SET_ERR_MSG(extack, "Key param name not found");
		return -EINVAL;
	}

	if (index_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		struct nlattr *tb2[P4TC_EXT_VALUE_PARAMS_MAX];
		u32 *value;
		int err;

		err = nla_parse_nested(tb2, P4TC_EXT_VALUE_PARAMS_MAX,
				       tb[P4TC_EXT_PARAMS_VALUE], NULL, extack);
		if (err < 0)
			return err;

		if (!tb2[P4TC_EXT_PARAMS_VALUE_RAW]) {
			NL_SET_ERR_MSG(extack, "Must specify raw value attr");
			return -EINVAL;
		}

		if (nla_len(tb2[P4TC_EXT_PARAMS_VALUE_RAW]) > sizeof(*key)) {
			NL_SET_ERR_MSG(extack,
				       "Param value is bigger than 64 bits");
			return -EINVAL;
		}

		value = nla_data(tb2[P4TC_EXT_PARAMS_VALUE_RAW]);

		*key = *value;

		return 0;
	}

	return -ENOENT;
}

static int p4tc_ext_get_key_param(struct p4tc_extern_inst *inst,
				  struct nlattr *nla, u32 *key,
				  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1] = {NULL};
	int err = -EINVAL;
	int i;

	err = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (!tb[1]) {
		NL_SET_ERR_MSG(extack, "Must specify at least one parameter");
		return -EINVAL;
	}

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		err = __p4tc_ext_get_key_param(inst, tb[i], key, extack);
		if (!err)
			return err;
	}

	return err;
}

static int p4tc_ext_init_params(struct net *net, struct p4tc_extern_inst *inst,
				struct p4tc_extern_params **params,
				struct nlattr *nla, size_t *attrs_size,
				struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *params_array[P4TC_MSGBATCH_SIZE] = { NULL };
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int err;
	int i;

	if (!*params) {
		*params = kzalloc(sizeof(*(*params)), GFP_KERNEL);
		if (!*params)
			return -ENOMEM;

		idr_init(&((*params)->params_idr));
		spin_lock_init(&((*params)->params_lock));
	}

	err = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (err < 0) {
		kfree(*params);
		*params = NULL;
		return err;
	}

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_param *param;

		param = p4tc_ext_init_param(net, inst, *params, tb[i],
					    attrs_size, extack);
		if (IS_ERR(param)) {
			err = PTR_ERR(param);
			goto params_del;
		}
		params_array[i - 1] = param;
		*attrs_size = nla_total_size(0);  /* params array element nested */
	}

	p4tc_ext_insert_many_params(&((*params)->params_idr), params_array,
				    i - 1);
	return 0;

params_del:
	p4tc_ext_put_many_params(&((*params)->params_idr), params_array, i - 1);
	kfree(*params);
	*params = NULL;
	return err;
}

static void p4tc_ext_idr_insert_many(struct p4tc_extern *externs[])
{
	int i;

	for (i = 0; i < P4TC_MSGBATCH_SIZE; i++) {
		struct p4tc_extern *e = externs[i];

		if (!e)
			continue;
		/* Replace ERR_PTR(-EBUSY) allocated by p4tc_ext_idr_check_alloc
		 * if it is just created. If it's updated, free previous extern.
		 */
		e = idr_replace(e->elems_idr, e, e->p4tc_ext_key);
		if (e != ERR_PTR(-EBUSY))
			call_rcu(&e->rcu, free_p4tc_ext_rcu);
	}
}

static struct p4tc_extern_ops *
p4tc_ext_load_ops(struct net *net, struct nlattr *nla,
		  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_MAX + 1];
	struct p4tc_extern_ops *a_o;
	char ext_name[EXTERNNAMSIZ];
	struct nlattr *kind;
	int err;

	err = nla_parse_nested_deprecated(tb, P4TC_EXT_MAX, nla,
					  p4tc_extern_policy, extack);
	if (err < 0)
		return ERR_PTR(err);
	err = -EINVAL;
	kind = tb[P4TC_EXT_KIND];
	if (!kind) {
		NL_SET_ERR_MSG(extack, "TC extern must be specified");
		return ERR_PTR(err);
	}
	if (nla_strscpy(ext_name, kind, EXTERNNAMSIZ) < 0) {
		NL_SET_ERR_MSG(extack, "TC extern name too long");
		return ERR_PTR(err);
	}

	a_o = p4tc_extern_ops_get(ext_name);
	if (!a_o) {
#ifdef CONFIG_MODULES
		rtnl_unlock();
		request_module("ext_%s", ext_name);
		rtnl_lock();

		a_o = p4tc_extern_ops_get(ext_name);

		/* We dropped the RTNL semaphore in order to
		 * perform the module load.  So, even if we
		 * succeeded in loading the module we have to
		 * tell the caller to replay the request.  We
		 * indicate this using -EAGAIN.
		 */
		if (a_o) {
			p4tc_extern_ops_put(a_o);
			return ERR_PTR(-EAGAIN);
		}
#endif
		NL_SET_ERR_MSG(extack, "Failed to load TC extern module");
		return ERR_PTR(-ENOENT);
	}

	return a_o;
}

static int p4tc_ext_init(struct net *net, struct nlattr **tb,
			 struct p4tc_extern **e,
			 struct p4tc_extern_inst *inst,
			 u32 flags, size_t *attrs_size,
			 struct netlink_ext_ack *extack)
{
	const struct p4tc_extern_ops *e_o = inst->ops;
	struct p4tc_extern_params *params = NULL;
	struct p4tc_extern *e_orig = NULL;
	bool exists = false;
	int ret = 0, err;
	u32 key;

	if (tb[P4TC_EXT_PARAMS]) {
		err = p4tc_ext_get_key_param(inst, tb[P4TC_EXT_PARAMS], &key,
					     extack);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify extern params");
		return -EINVAL;
	}

	if (err < 0) {
		if (err == -ENOENT)
			NL_SET_ERR_MSG(extack, "Unable to find key param");
		return err;
	}

	err = p4tc_ext_idr_check_alloc(inst, &key, &e_orig);
	if (err < 0)
		return err;

	exists = err;

	if (!exists) {
		err = p4tc_ext_idr_create(inst, key, e, e_o, flags);
		if (err < 0) {
			p4tc_ext_idr_cleanup(inst->inst_common, key);
			return err;
		}

		ret = P4TC_EXT_P_CREATED;
	} else {
		err = p4tc_ext_copy(inst, key, e, e_orig, e_o, flags);
		if (err < 0)
			return err;

		if (!(flags & P4TC_EXT_FLAGS_REPLACE)) {
			err = -EEXIST;
			goto release_idr;
		}
	}

	err = p4tc_ext_init_params(net, inst, &params, tb[P4TC_EXT_PARAMS],
				   attrs_size, extack);
	if (err < 0)
		goto release_idr;
	*attrs_size = nla_total_size(0);  /* P4TC_EXT_PARAMS nested */

	(*e)->params = params;

	return ret;

release_idr:
	p4tc_ext_idr_release(*e);
	return err;
}

static struct p4tc_extern_inst *
__p4tc_ext_inst_find_bynames(struct net *net, struct p4tc_pipeline *pipeline,
			     const char *modextname, const char *instname,
			     struct netlink_ext_ack *extack)
{
	const char *extname = &modextname[4];

	return p4tc_ext_inst_find_bynames(net, pipeline, extname, instname,
					  extack);
}

static struct p4tc_extern *
p4tc_extern_init_1(struct net *net, struct p4tc_pipeline *pipeline,
		   struct nlattr *nla, struct p4tc_extern_ops *a_o,
		   int *init_res, u32 flags, size_t *attrs_size,
		   struct netlink_ext_ack *extack)
{
	struct nla_bitfield32 userflags = { 0, 0 };
	struct nlattr *tb[P4TC_EXT_MAX + 1];
	struct p4tc_extern_inst *inst;
	struct p4tc_extern *e;
	char *instname;
	int err;

	err = nla_parse_nested_deprecated(tb, P4TC_EXT_MAX, nla,
					  p4tc_extern_policy, extack);
	if (err < 0)
		return ERR_PTR(err);
	if (tb[P4TC_EXT_FLAGS])
		userflags = nla_get_bitfield32(tb[P4TC_EXT_FLAGS]);

	if (!tb[P4TC_EXT_INST_NAME]) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		return ERR_PTR(-EINVAL);
	}
	instname = nla_data(tb[P4TC_EXT_INST_NAME]);

	inst = __p4tc_ext_inst_find_bynames(net, pipeline, a_o->kind, instname,
					    extack);
	if (IS_ERR(inst))
		return (void *)inst;

	inst->ops = a_o;

	err = p4tc_ext_init(net, tb, &e, inst, userflags.value | flags,
			    attrs_size, extack);
	*init_res = err;

	if (err < 0)
		return ERR_PTR(err);

	return e;
}

/* Returns numbers of initialized externs or negative error. */
static int p4tc_extern_init(struct net *net, struct p4tc_pipeline *pipeline,
			    struct nlattr *nla, struct p4tc_extern *externs[],
			    int init_res[], size_t *attrs_size, u32 flags,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_extern_ops *ops[P4TC_MSGBATCH_SIZE] = {};
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_extern *ext;
	size_t sz = 0;
	int err;
	int i;

	err = nla_parse_nested_deprecated(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
					  extack);
	if (err < 0)
		return err;

	for (i = 1; i <= P4TC_MSGBATCH_SIZE && tb[i]; i++) {
		struct p4tc_extern_ops *a_o;

		a_o = p4tc_ext_load_ops(net, tb[i], extack);
		if (IS_ERR(a_o)) {
			err = PTR_ERR(a_o);
			goto err_mod;
		}
		ops[i - 1] = a_o;
	}

	for (i = 1; i <= P4TC_MSGBATCH_SIZE && tb[i]; i++) {
		size_t attrs_size_before = *attrs_size;
		size_t extern_fill_size;

		ext = p4tc_extern_init_1(net, pipeline, tb[i], ops[i - 1],
					 &init_res[i - 1], flags, attrs_size,
					 extack);
		if (IS_ERR(ext)) {
			err = PTR_ERR(ext);
			goto err;
		}
		extern_fill_size = p4tc_extern_fill_size(ext);
		ext->attrs_size = *attrs_size - attrs_size_before + extern_fill_size;
		sz += extern_fill_size;
		/* Start from key 0 */
		externs[i - 1] = ext;
	}

	/* We have to commit them all together, because if any error happened in
	 * between, we could not handle the failure gracefully.
	 */
	p4tc_ext_idr_insert_many(externs);

	*attrs_size = p4tc_extern_full_attrs_size(sz);
	err = i - 1;
	goto err_mod;

err:
	p4tc_extern_destroy(externs, init_res);
err_mod:
	for (i = 0; i < P4TC_MSGBATCH_SIZE; i++) {
		if (ops[i])
			p4tc_extern_ops_put(ops[i]);
	}
	return err;
}

static int tce_get_fill(struct sk_buff *skb, struct p4tc_extern *externs[],
			u32 portid, u32 seq, u16 flags, u32 pipeid, int cmd,
			int ref, struct netlink_ext_ack *extack)
{
	unsigned char *b = skb_tail_pointer(skb);
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
	if (p4tc_extern_dump(skb, externs, ref) < 0)
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	nlh->nlmsg_len = skb_tail_pointer(skb) - b;

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int
p4tc_extern_get_respond(struct net *net, u32 portid, struct nlmsghdr *n,
			struct p4tc_extern *externs[], u32 pipeid, int cmd,
			size_t attr_size, struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;

	skb = alloc_skb(attr_size <= NLMSG_GOODSIZE ? NLMSG_GOODSIZE : attr_size,
			GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;
	if (tce_get_fill(skb, externs, portid, n->nlmsg_seq, 0, pipeid, cmd,
			 1, NULL) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill netlink attributes while adding TC extern");
		kfree_skb(skb);
		return -EINVAL;
	}

	return rtnl_unicast(skb, net, portid);
}

static struct p4tc_extern *
p4tc_extern_get_1(struct net *net, struct p4tc_pipeline *pipeline,
		  struct nlattr *nla, struct nlmsghdr *n, u32 portid,
		  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_MAX + 1];
	const struct p4tc_extern_ops *ops;
	struct p4tc_extern_inst *inst;
	char *kind, *instname;
	struct p4tc_extern *e;
	u32 key;
	int err;

	err = nla_parse_nested_deprecated(tb, P4TC_EXT_MAX, nla,
					  p4tc_extern_policy, extack);
	if (err < 0)
		goto err_out;

	if (!tb[P4TC_EXT_KIND]) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		err = -EINVAL;
		goto err_out;
	}
	kind = nla_data(tb[P4TC_EXT_KIND]);

	if (!tb[P4TC_EXT_INST_NAME]) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		return ERR_PTR(-EINVAL);
	}
	instname = nla_data(tb[P4TC_EXT_INST_NAME]);

	err = -EINVAL;
	ops = p4tc_extern_ops_get(kind);
	if (!ops) { /* could happen in batch of externs */
		NL_SET_ERR_MSG(extack, "Specified TC extern kind not found");
		goto err_out;
	}

	inst = __p4tc_ext_inst_find_bynames(net, pipeline, ops->kind, instname,
					    extack);
	if (IS_ERR(inst)) {
		err = PTR_ERR(inst);
		goto err_mod;
	}
	if (tb[P4TC_EXT_PARAMS]) {
		err = p4tc_ext_get_key_param(inst, tb[P4TC_EXT_PARAMS], &key,
					     extack);
		if (err < 0)
			goto err_mod;
	} else {
		/* Assume key 1 when none is specified */
		key = 1;
	}

	if (__p4tc_ext_idr_search(inst, &e, key) == 0) {
		err = -ENOENT;
		NL_SET_ERR_MSG(extack, "TC extern with specified key not found");
		goto err_mod;
	}

	p4tc_extern_ops_put(ops);
	return e;

err_mod:
	p4tc_extern_ops_put(ops);
err_out:
	return ERR_PTR(err);
}

static int p4tc_extern_flush(struct net *net, struct p4tc_pipeline *pipeline,
			     struct nlattr *nla, struct nlmsghdr *n,
			     u32 portid, struct netlink_ext_ack *extack)
{
	int err = -ENOMEM;
	struct nlattr *tb[P4TC_EXT_MAX + 1];
	const struct p4tc_extern_ops *ops;
	struct p4tc_extern_inst *inst;
	struct netlink_callback dcb;
	char *kind, *instname;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	struct nlattr *nest;
	struct p4tcmsg *t;
	unsigned char *b;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return err;

	b = skb_tail_pointer(skb);

	err = nla_parse_nested_deprecated(tb, P4TC_EXT_MAX, nla,
					  p4tc_extern_policy, extack);
	if (err < 0)
		goto err_out;

	err = -EINVAL;
	if (!tb[P4TC_EXT_KIND]) {
		NL_SET_ERR_MSG(extack,
			       "TC extern name must be specified");
		err = -EINVAL;
		goto err_out;
	}
	kind = nla_data(tb[P4TC_EXT_KIND]);

	ops = p4tc_extern_ops_get(kind);
	if (!ops) { /*some idjot trying to flush unknown extern */
		NL_SET_ERR_MSG(extack, "Cannot flush unknown TC extern");
		goto err_out;
	}

	if (!tb[P4TC_EXT_INST_NAME]) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		err = -EINVAL;
		goto out_ops_put;
	}
	instname = nla_data(tb[P4TC_EXT_INST_NAME]);

	inst = __p4tc_ext_inst_find_bynames(net, pipeline, ops->kind, instname,
					    extack);
	if (IS_ERR(inst)) {
		err = PTR_ERR(inst);
		goto out_ops_put;
	}

	nlh = nlmsg_put(skb, portid, n->nlmsg_seq, RTM_P4TC_DEL,
			sizeof(*t), 0);
	if (!nlh) {
		NL_SET_ERR_MSG(extack, "Failed to create TC extern flush notification");
		goto out_ops_put;
	}
	t = nlmsg_data(nlh);
	t->obj = P4TC_OBJ_RUNTIME_EXTERN;
	t->pipeid = pipeline->common.p_id;

	nest = nla_nest_start_noflag(skb, P4TC_ROOT);
	if (!nest) {
		NL_SET_ERR_MSG(extack, "Failed to add new netlink message");
		goto out_ops_put;
	}

	err = __p4tc_ext_generic_walker(skb, &dcb, RTM_P4TC_DEL, inst, ops,
					extack);
	if (err <= 0) {
		nla_nest_cancel(skb, nest);
		goto out_ops_put;
	}

	nla_nest_end(skb, nest);

	nlh->nlmsg_len = skb_tail_pointer(skb) - b;
	nlh->nlmsg_flags |= NLM_F_ROOT;
	p4tc_extern_ops_put(ops);
	err = rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			     n->nlmsg_flags & NLM_F_ECHO);
	if (err < 0)
		NL_SET_ERR_MSG(extack, "Failed to send TC extern flush notification");

	return err;

out_ops_put:
	p4tc_extern_ops_put(ops);
err_out:
	kfree_skb(skb);
	return err;
}

static int p4tc_extern_delete(struct net *net, struct p4tc_extern *externs[])
{
	int i;

	for (i = 0; i < P4TC_MSGBATCH_SIZE && externs[i]; i++) {
		struct p4tc_extern *e = externs[i];
		const struct p4tc_extern_ops *ops = e->ops;
		u32 ext_key = e->p4tc_ext_key;
		/* Actions can be deleted concurrently so we must save their
		 * type and id to search again after reference is released.
		 */
		struct idr *elems_idr = e->elems_idr;

		externs[i] = NULL;
		if (p4tc_extern_put(e)) {
			/* last reference, extern was deleted concurrently */
			p4tc_extern_ops_put(ops);
		} else  {
			int ret;

			/* now do the delete */
			ret = p4tc_ext_idr_delete_key(elems_idr, ext_key);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

static int
p4tc_extern_del_notify(struct net *net, struct nlmsghdr *n,
		       struct p4tc_extern *externs[], u32 portid, u32 pipeid,
		       size_t attr_size, struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;
	int ret;

	skb = alloc_skb(attr_size <= NLMSG_GOODSIZE ? NLMSG_GOODSIZE : attr_size,
			GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tce_get_fill(skb, externs, portid, n->nlmsg_seq, 0, pipeid,
			 RTM_P4TC_DEL, 2, extack) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill netlink TC extern attributes");
		kfree_skb(skb);
		return -EINVAL;
	}

	/* now do the delete */
	ret = p4tc_extern_delete(net, externs);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Failed to delete TC extern");
		kfree_skb(skb);
		return ret;
	}

	ret = rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			     n->nlmsg_flags & NLM_F_ECHO);
	return ret;
}

static int
p4tc_extern_gd(struct net *net, struct p4tc_pipeline *pipeline,
	       struct nlattr *nla, struct nlmsghdr *n,
	       u32 portid, int cmd, struct netlink_ext_ack *extack)
{
	struct p4tc_extern *externs[P4TC_MSGBATCH_SIZE] = {};
	size_t attr_size = 0;
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_extern *ext;
	u32 pipeid;
	int i, ret;

	ret = nla_parse_nested_deprecated(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
					  extack);
	if (ret < 0)
		return ret;

	if (cmd == RTM_P4TC_DEL && n->nlmsg_flags & NLM_F_ROOT) {
		if (tb[1])
			return p4tc_extern_flush(net, pipeline, tb[1], n,
						 portid, extack);

		NL_SET_ERR_MSG(extack,
			       "Invalid netlink attributes while flushing TC extern");
		return -EINVAL;
	}

	for (i = 1; i <= P4TC_MSGBATCH_SIZE && tb[i]; i++) {
		ext = p4tc_extern_get_1(net, pipeline, tb[i], n, portid,
					extack);
		if (IS_ERR(ext)) {
			ret = PTR_ERR(ext);
			goto err;
		}
		attr_size += ext->attrs_size;
		externs[i - 1] = ext;
	}

	attr_size = p4tc_extern_full_attrs_size(attr_size);

	pipeid = pipeline->common.p_id;
	if (cmd == RTM_P4TC_GET) {
		ret = p4tc_extern_get_respond(net, portid, n, externs, pipeid,
					      cmd, attr_size, extack);
	} else { /* delete */
		ret = p4tc_extern_del_notify(net, n, externs, portid, pipeid,
					     attr_size, extack);
		if (ret)
			goto err;
		return 0;
	}
err:
	p4tc_extern_put_many(externs);
	return ret;
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
			 pipeid, RTM_P4TC_CREATE, 0, extack) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill netlink attributes while adding TC extern");
		kfree_skb(skb);
		return -EINVAL;
	}

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static int p4tc_extern_add(struct net *net, struct p4tc_pipeline *pipeline,
			   struct nlattr *nla, struct nlmsghdr *n, u32 portid,
			   u32 flags, struct netlink_ext_ack *extack)
{
	struct p4tc_extern *externs[P4TC_MSGBATCH_SIZE] = {};
	int init_res[P4TC_MSGBATCH_SIZE] = {};
	size_t attr_size = 0;
	int loop, ret, i;
	u32 pipeid;

	for (loop = 0; loop < 10; loop++) {
		ret = p4tc_extern_init(net, pipeline, nla, externs,
				       init_res, &attr_size, flags, extack);
		if (ret != -EAGAIN)
			break;
	}

	if (ret < 0)
		return ret;

	pipeid = pipeline->common.p_id;
	ret = p4tc_extern_add_notify(net, n, externs, portid, pipeid, attr_size,
				     extack);

	/* only put existing externs */
	for (i = 0; i < P4TC_MSGBATCH_SIZE; i++)
		if (init_res[i] == P4TC_EXT_P_CREATED)
			externs[i] = NULL;
	p4tc_extern_put_many(externs);

	return ret;
}

static int parse_dump_ext_attrs(struct nlattr *nla,
				struct nlattr **tb2)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];

	if (nla_parse_nested_deprecated(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
					NULL) < 0)
		return -EINVAL;

	if (!tb[1])
		return -EINVAL;
	if (nla_parse_nested_deprecated(tb2, P4TC_EXT_MAX, tb[1],
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
	unsigned char *b = skb_tail_pointer(skb);
	struct net *net = sock_net(skb->sk);
	struct nlattr *count_attr = NULL;
	struct nla_bitfield32 bf;
	u32 ext_count = 0;
	int ret = 0;
	struct nlattr *tb2[P4TC_EXT_MAX + 1];
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;
	struct p4tc_extern_ops *a_o;
	char *kind_str, *instname;
	struct nlmsghdr *nlh;
	struct nlattr *nest;
	struct p4tcmsg *t;

	pipeline = tcf_pipeline_find_byany(net, pname, 0, extack);
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

	a_o = p4tc_extern_ops_get(kind_str);
	if (!a_o)
		return 0;

	instname = nla_data(tb2[P4TC_EXT_INST_NAME]);

	inst = __p4tc_ext_inst_find_bynames(net, pipeline, a_o->kind, instname,
					    extack);
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
		goto out_ops_put;

	t = nlmsg_data(nlh);
	t->pipeid = pipeline->common.p_id;
	t->obj = P4TC_OBJ_RUNTIME_EXTERN;
	count_attr = nla_reserve(skb, P4TC_ROOT_COUNT, sizeof(u32));
	if (!count_attr)
		goto out_ops_put;

	nest = nla_nest_start_noflag(skb, P4TC_ROOT);
	if (!nest)
		goto out_ops_put;

	ret = __p4tc_ext_generic_walker(skb, cb, RTM_P4TC_GET, inst, a_o, NULL);
	if (ret < 0)
		goto out_ops_put;

	if (ret > 0) {
		nla_nest_end(skb, nest);
		ret = skb->len;
		ext_count = cb->args[1];
		memcpy(nla_data(count_attr), &ext_count, sizeof(u32));
		cb->args[1] = 0;
	} else {
		nlmsg_trim(skb, b);
	}

	nlh->nlmsg_len = skb_tail_pointer(skb) - b;
	if (NETLINK_CB(cb->skb).portid && ret)
		nlh->nlmsg_flags |= NLM_F_MULTI;
	p4tc_extern_ops_put(a_o);
	return skb->len;

out_ops_put:
	p4tc_extern_ops_put(a_o);
	nlmsg_trim(skb, b);
	return skb->len;
}

int p4tc_ctl_extern(struct sk_buff *skb, struct nlmsghdr *n, const char *pname,
		    struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	u32 flags = 0;
	int ret = 0;
	struct p4tc_pipeline *pipeline;

	if (n->nlmsg_type != RTM_P4TC_GET &&
	    !netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	pipeline = tcf_pipeline_find_byany(net, pname, 0, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Pipeline must be sealed for extern runtime ops");
		return -EINVAL;
	}

	/* n->nlmsg_flags & NLM_F_CREATE */
	switch (n->nlmsg_type) {
	case RTM_P4TC_CREATE:
		/* we are going to assume all other flags
		 * imply create only if it doesn't exist
		 * Note that CREATE | EXCL implies that
		 * but since we want avoid ambiguity (eg when flags
		 * is zero) then just set this
		 */
		if (n->nlmsg_flags & NLM_F_REPLACE)
			flags |= P4TC_EXT_FLAGS_REPLACE;
		ret = p4tc_extern_add(net, pipeline, nla, n, portid, flags,
				      extack);
		break;
	case RTM_P4TC_DEL:
		ret = p4tc_extern_gd(net, pipeline, nla, n, portid,
				     RTM_P4TC_DEL, extack);
		break;
	case RTM_P4TC_GET:
		ret = p4tc_extern_gd(net, pipeline, nla, n, portid,
				     RTM_P4TC_GET, extack);
		break;
	default:
		WARN_ON_ONCE("Unknown extern command");
	}

	return ret;
}
