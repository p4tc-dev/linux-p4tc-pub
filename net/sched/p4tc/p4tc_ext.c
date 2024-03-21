// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_ext.c	P4 TC EXTERN API
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/p4tc.h>
#include <net/p4tc_ext_api.h>
#include <net/netlink.h>
#include <uapi/linux/p4tc.h>

static void p4tc_extern_put_param(struct p4tc_extern_param *param)
{
	if (param->value) {
		if (param->ops && param->ops->free)
			param->ops->free(param);
		else
			kfree(param->value);
	}
	kfree(param);
}

static void p4tc_ext_put_params_idr(struct idr *params_idr)
{
	struct p4tc_extern_param *param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(params_idr, param, tmp, param_id)
		p4tc_extern_put_param(param);
}

static void p4tc_ext_put_many_params(struct p4tc_extern_param *params[],
				     int params_count)
{
	int i;

	for (i = 0; i < params_count; i++)
		p4tc_extern_put_param(params[i]);
}

static void p4tc_ext_replace_param_val(struct p4tc_extern_params *params,
				       struct p4tc_extern_param *nparam,
				       struct p4tc_extern_param *param)
{
	const u16 param_bytesz =
		BITS_TO_BYTES(param->tmpl_param->bitsz);

	memcpy(nparam->value, param->value, param_bytesz);

	p4tc_extern_put_param(param);
}

static int
p4tc_ext_params_array_id_cnt(struct p4tc_extern_param **params_arr,
			     u32 param_id, u32 num_params)
{
	int num_matches = 0;
	int i;

	for (i = 0; i < num_params; i++)
		if (param_id == params_arr[i]->tmpl_param->id)
			num_matches++;

	return num_matches;
}

static int p4tc_ext_check_params(struct p4tc_extern_params *params,
				 struct p4tc_extern_param *params_arr[],
				 struct netlink_ext_ack *extack)
{
	u32 num_params = params->num_params;
	int i;

	for (i = 0; i < num_params; i++) {
		u32 param_id = params_arr[i]->tmpl_param->id;
		int matches;

		matches = p4tc_ext_params_array_id_cnt(params_arr,
						       param_id,
						       num_params);
		if (matches > 1) {
			NL_SET_ERR_MSG_FMT(extack, "Param %s is duplicated",
					   params_arr[i]->tmpl_param->name);
			return -EINVAL;
		}
	}

	return 0;
}

static void p4tc_ext_replace_many_params(struct p4tc_extern_params *params,
					 struct p4tc_extern_param *params_arr[])
{
	struct idr *params_idr = &params->params_idr;
	int i;

	for (i = 0; i < params->num_params; i++) {
		struct p4tc_extern_param *param =
			p4tc_ext_param_find_byid(params_idr,
						 params_arr[i]->tmpl_param->id);

		p4tc_ext_replace_param_val(params, param, params_arr[i]);
	}
}

static int p4tc_ext_idr_release_dec_num_elems(struct p4tc_extern_common *common)
{
	struct p4tc_extern_inst *inst = common->inst;
	int ret;

	ret = __p4tc_ext_idr_release(common);
	if (ret == P4TC_EXT_P_DELETED)
		p4tc_ext_inst_dec_num_elems(inst);

	return ret;
}

static size_t p4tc_extern_shared_attrs_size(void)
{
	return  nla_total_size(0) /* extern number nested */
		+ nla_total_size(P4TC_EXTERN_NAMSIZ)  /* P4TC_EXT_KIND */
		+ nla_total_size(P4TC_EXTERN_INST_NAMSIZ) /* P4TC_EXT_INST_NAME */
		+ nla_total_size(sizeof(struct nla_bitfield32)); /* P4TC_EXT_FLAGS */
}

static const struct nla_policy
p4tc_extern_params_value_policy[P4TC_EXT_VALUE_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_VALUE_RAW] = { .type = NLA_BINARY },
};

static int p4tc_extern_elem_dump_param_noval(struct sk_buff *skb,
					     struct p4tc_extern_tmpl_param *parm)
{
	unsigned char *b = nlmsg_get_pos(skb);

	if (nla_put_string(skb, P4TC_EXT_PARAMS_NAME,
			   parm->name))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_ID, parm->id))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_TYPE, parm->type->typeid))
		goto nla_put_failure;

	if (parm->bitsz &&
	    nla_put_u32(skb, P4TC_EXT_PARAMS_BITSZ, parm->bitsz))
		goto nla_put_failure;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_FLAGS,
			parm->flags))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int p4tc_ext_param_value_dump(struct sk_buff *skb,
				     struct p4tc_extern_param *param)
{
	struct p4tc_extern_tmpl_param *tmpl_param = param->tmpl_param;
	struct p4tc_extern_param_ops *ops = param->ops;

	if (ops && ops->dump_value)
		return ops->dump_value(skb, ops, param);

	return generic_dump_ext_param_value(skb, tmpl_param->type,
					    param->value);
}

static int
p4tc_extern_elem_dump_params(struct sk_buff *skb, struct p4tc_extern_common *e,
			     bool lock_params)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_extern_param *parm;
	struct nlattr *nest_parms;
	int id;

	nest_parms = nla_nest_start(skb, P4TC_EXT_PARAMS);
	if (e->params) {
		int i = 1;

		idr_for_each_entry(&e->params->params_idr, parm, id) {
			struct nlattr *nest_count;

			nest_count = nla_nest_start(skb, i);
			if (!nest_count)
				goto nla_put_failure;

			if (p4tc_extern_elem_dump_param_noval(skb,
							      parm->tmpl_param) < 0)
				goto nla_put_failure;

			if (lock_params)
				spin_lock_bh(&e->params->params_lock);
			if (p4tc_ext_param_value_dump(skb, parm)) {
				if (lock_params)
					spin_unlock_bh(&e->params->params_lock);
				goto nla_put_failure;
			}
			if (lock_params)
				spin_unlock_bh(&e->params->params_lock);

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
p4tc_ext_elem_dump_1(struct sk_buff *skb, struct p4tc_extern_common *e,
		     bool lock_params)
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

	err = p4tc_extern_elem_dump_params(skb, e, lock_params);
	if (err < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}
EXPORT_SYMBOL(p4tc_ext_elem_dump_1);

struct p4tc_ext_dump_ctx {
	int s_i;
	int n_i;
	u32 ext_flags;
};

static int p4tc_ext_dump_walker(struct sk_buff *skb,
				struct p4tc_ext_dump_ctx *dump_ctx,
				struct p4tc_pipeline *pipeline,
				struct p4tc_extern_inst *inst,
				struct netlink_callback *cb)
{
	struct idr *idr = &inst->control_elems_idr;
	u32 ext_flags = dump_ctx->ext_flags;
	int err = 0, s_i = 0, n_i = 0;
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
		s_i = dump_ctx->s_i;

		idr_for_each_entry_ul(idr, p, tmp, id) {
			key++;
			if (key < s_i)
				continue;
			if (IS_ERR(p))
				continue;

			if (p4tc_ext_is_hidden(&p->common))
				continue;

			nest = nla_nest_start(skb, n_i);
			if (!nest) {
				key--;
				goto nla_put_failure;
			}

			err = p4tc_ext_elem_dump_1(skb, &p->common, true);
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
		dump_ctx->s_i = key + 1;

	if (n_i) {
		if (ext_flags & P4TC_EXT_FLAG_LARGE_DUMP_ON)
			dump_ctx->n_i = n_i;
	}
	return n_i;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	goto done;
}

static void __p4tc_ext_idr_purge(struct p4tc_extern_common *common)
{
	if (common->p4tc_ext_key != P4TC_EXT_ELEM_PRIV_IDX)
		atomic_dec(&common->inst->curr_num_elems);
	p4tc_extern_cleanup(common);
}

static void p4tc_ext_idr_purge(struct idr *elems_idr, struct p4tc_extern *p)
{
	idr_remove(elems_idr, p->common.p4tc_ext_key);
	__p4tc_ext_idr_purge(&p->common);
}

/* Called when pipeline is being purged */
void p4tc_ext_purge(struct idr *idr)
{
	struct p4tc_extern *p;
	unsigned long tmp, id;

	idr_for_each_entry_ul(idr, p, tmp, id) {
		if (IS_ERR(p))
			continue;
		p4tc_ext_idr_purge(idr, p);
	}
}

static int p4tc_ext_idr_create(struct p4tc_extern_inst *inst,
			       u32 key, struct p4tc_extern_common **common,
			       const struct p4tc_extern_ops *ops,
			       u32 flags)
{
	size_t ext_size = (ops && ops->elem_size) ?
		ops->elem_size : sizeof(struct p4tc_extern);
	struct p4tc_extern_common *p = kzalloc(ext_size, GFP_KERNEL_ACCOUNT);
	const bool is_priv_elem = key == P4TC_EXT_ELEM_PRIV_IDX;
	u32 max_num_elems = inst->max_num_elems;
	struct p4tc_pipeline *root_pipeline;
	struct p4tc_tmpl_extern *tmpl_ext;

	if (unlikely(!p))
		return -ENOMEM;

	if (!is_priv_elem &&
	    atomic_read(&inst->curr_num_elems) == max_num_elems) {
		kfree(p);
		return -E2BIG;
	}

	if (!is_priv_elem)
		p4tc_ext_inst_inc_num_elems(inst);

	refcount_set(&p->p4tc_ext_refcnt, 1);

	p->p4tc_ext_key = key;
	p->p4tc_ext_flags = flags;

	if (ops) {
		root_pipeline = p4tc_pipeline_find_byid(NULL,
							P4TC_KERNEL_PIPEID);
		tmpl_ext = p4tc_tmpl_ext_find_byid(root_pipeline, ops->id);
		if (!tmpl_ext) {
			kfree(p);
			return -EINVAL;
		}
	} else {
		tmpl_ext = inst->pipe_ext->tmpl_ext;
	}

	p->p4tc_ext_permissions = tmpl_ext->ext_permissions;
	p->inst = inst;
	p->ops = ops;
	*common = p;
	return 0;
}

static struct p4tc_ext_bpf_val_kern *
p4tc_ext_from_ext_bpf_res(struct p4tc_extern_common *common,
			  struct p4tc_ext_bpf_val *val_kern)
__must_hold(RCU)
{
	struct p4tc_extern_params *params = common->params;
	struct p4tc_ext_bpf_val_kern *new_bpf_val_kern;
	struct p4tc_extern_param *param;
	unsigned long param_id, tmp;
	u8 *params_cursor;

	new_bpf_val_kern = kzalloc(sizeof(*new_bpf_val_kern), GFP_ATOMIC);
	if (unlikely(!new_bpf_val_kern))
		return ERR_PTR(-ENOMEM);

	params_cursor = val_kern->out_params;
	idr_for_each_entry_ul(&params->params_idr, param, tmp, param_id) {
		struct p4tc_extern_tmpl_param *tmpl_param = param->tmpl_param;
		u16 param_bytesz = BITS_TO_BYTES(tmpl_param->bitsz);

		memcpy(param->value, params_cursor, param_bytesz);
		params_cursor += param_bytesz;
	}

	new_bpf_val_kern->val = *val_kern;
	new_bpf_val_kern->val.ext_id = common->inst->ext_id;
	new_bpf_val_kern->val.index = common->p4tc_ext_key;

	return new_bpf_val_kern;
}

int p4tc_datapath_extern_md_write(struct net *net,
				  struct p4tc_ext_bpf_params *params,
				  const u32 params__sz,
				  struct p4tc_ext_bpf_val *val,
				  const u32 val__sz)
{
	struct p4tc_ext_nlmsg_attrs nlmsg_attrs = {};
	struct p4tc_ext_bpf_val_kern *val_kern;
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_common *e;
	int err = 0;

	if (!params || !val)
		return -EINVAL;

	if (params__sz != P4TC_EXT_BPF_PARAMS_SZ ||
	    val__sz != P4TC_EXT_BPF_RES_SZ)
		return -EINVAL;

	if (params->index == P4TC_EXT_ELEM_PRIV_IDX)
		return -EPERM;

	e = __p4tc_ext_common_elem_get(net, &pipeline, params);
	if (IS_ERR(e))
		return PTR_ERR(e);

	if (e->inst->flags & P4TC_EXT_INST_FLAGS_HAS_CUST_PARAM) {
		err = -EPERM;
		goto put_pipe;
	}

	if (!p4tc_data_update_ok(e->p4tc_ext_permissions)) {
		err = -EPERM;
		goto put_pipe;
	}

	/* Can't write to hidden element */
	if (p4tc_ext_is_hidden(e)) {
		err = -EPERM;
		goto put_pipe;
	}

	nlmsg_attrs.pipeid = pipeline->common.p_id;
	nlmsg_attrs.cmd = RTM_P4TC_UPDATE;

	spin_lock_bh(&e->params->params_lock);
	val_kern = p4tc_ext_from_ext_bpf_res(e, val);
	if (IS_ERR(val_kern)) {
		spin_unlock_bh(&e->params->params_lock);
		goto put_pipe;
	}

	spin_lock_bh(&e->p4tc_ext_bpf_val_lock);
	val_kern = rcu_replace_pointer(e->val_kern, val_kern,
				       lockdep_is_held(&e->p4tc_ext_bpf_val_lock));
	spin_unlock_bh(&e->p4tc_ext_bpf_val_lock);

	p4tc_extern_send(pipeline, e, &nlmsg_attrs, 0, false, NULL);
	spin_unlock_bh(&e->params->params_lock);

	if (val_kern)
		kfree_rcu(val_kern, rcu);

	err = 0;

put_pipe:
	p4tc_ext_common_elem_put(pipeline, e);

	return err;
}

struct p4tc_ext_bpf_val *
p4tc_datapath_extern_md_read(struct net *net,
			     struct p4tc_ext_bpf_params *params,
			     const u32 params__sz)
{
	struct p4tc_ext_bpf_val_kern *val_kern = NULL;
	struct p4tc_ext_bpf_val *val = NULL;
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_common *e;

	if (!params)
		return NULL;

	if (params__sz != P4TC_EXT_BPF_PARAMS_SZ)
		return NULL;

	if (params->index == P4TC_EXT_ELEM_PRIV_IDX)
		return NULL;

	e = __p4tc_ext_common_elem_get(net, &pipeline, params);
	if (IS_ERR(e))
		return NULL;

	if (e->inst->flags & P4TC_EXT_INST_FLAGS_HAS_CUST_PARAM)
		goto refcount_dec;

	if (!p4tc_data_read_ok(e->p4tc_ext_permissions))
		goto refcount_dec;

	val_kern = rcu_dereference(e->val_kern);
	val = &val_kern->val;

refcount_dec:
	p4tc_ext_common_elem_put(pipeline, e);

	return val;
}

static const struct nla_policy p4tc_extern_policy[P4TC_EXT_MAX + 1] = {
	[P4TC_EXT_INST_NAME] = {
		.type = NLA_STRING,
		.len = P4TC_EXTERN_INST_NAMSIZ
	},
	[P4TC_EXT_KIND]		= { .type = NLA_STRING },
	[P4TC_EXT_PARAMS]	= { .type = NLA_NESTED },
	[P4TC_EXT_KEY]		= { .type = NLA_NESTED },
	[P4TC_EXT_FLAGS]	= { .type = NLA_BITFIELD32 },
};

static const struct nla_policy
p4tc_extern_params_policy[P4TC_EXT_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_NAME] = { .type = NLA_STRING, .len = EXTPARAMNAMSIZ },
	[P4TC_EXT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_EXT_PARAMS_TYPE] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_BITSZ] = { .type = NLA_U16 },
	[P4TC_EXT_PARAMS_FLAGS] = { .type = NLA_U8 },
};

static struct p4tc_extern_param *
__p4tc_ext_init_param(struct net *net, struct idr *control_params_idr,
		      struct nlattr **tb, size_t *attrs_size,
		      struct netlink_ext_ack *extack)
{
	struct p4tc_extern_tmpl_param *tmpl_param;
	struct p4tc_extern_param *nparam;
	u32 param_id = 0;
	int err = 0;
	u32 typeid;
	u16 bitsz;

	if (tb[P4TC_EXT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_EXT_PARAMS_ID]);
	*attrs_size += nla_total_size(sizeof(u32));

	tmpl_param = p4tc_ext_param_find_byanyattr(control_params_idr,
						   tb[P4TC_EXT_PARAMS_NAME],
						   param_id, extack);
	if (IS_ERR(tmpl_param))
		return (void *)tmpl_param;

	if (tmpl_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Key param %s also specified in P4TC_EXT_PARAMS",
				   tmpl_param->name);
		return ERR_PTR(-EINVAL);
	}

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_PARAMS_TYPE)) {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		return ERR_PTR(-EINVAL);
	}

	typeid = nla_get_u32(tb[P4TC_EXT_PARAMS_TYPE]);
	if (tmpl_param->type->typeid != typeid) {
		NL_SET_ERR_MSG(extack,
			       "Param type differs from template");
		return ERR_PTR(-EINVAL);
	}

	if (tb[P4TC_EXT_PARAMS_BITSZ]) {
		bitsz = nla_get_u16(tb[P4TC_EXT_PARAMS_BITSZ]);
		if (tmpl_param->bitsz != bitsz) {
			NL_SET_ERR_MSG(extack,
				       "Param bitsz differs from template");
			return ERR_PTR(-EINVAL);
		}
	} else {
		if (tmpl_param->bitsz != tmpl_param->type->bitsz) {
			NL_SET_ERR_MSG(extack,
				       "Param bitsz differs from template");
			return ERR_PTR(-EINVAL);
		}
	}

	*attrs_size += nla_total_size(sizeof(u32));

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL);
	if (!nparam)
		return ERR_PTR(-ENOMEM);
	nparam->tmpl_param = tmpl_param;

	err = p4tc_ext_param_value_parse_and_init(net, nparam, tb,
						  true, extack);
	if (err < 0)
		goto free;

	*attrs_size += nla_total_size(BITS_TO_BYTES(tmpl_param->bitsz));

	return nparam;

free:
	kfree(nparam);

	return ERR_PTR(err);
}

struct p4tc_extern_param *
p4tc_ext_init_param(struct net *net, struct idr *control_params_idr,
		    struct nlattr *nla, size_t *attrs_size,
		    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	int err;

	err = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (err < 0)
		return ERR_PTR(err);

	return __p4tc_ext_init_param(net, control_params_idr, tb,
				     attrs_size, extack);
}

static int p4tc_ext_get_key_param_value(struct nlattr *nla, u32 *key,
					struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_VALUE_PARAMS_MAX + 1];
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
	struct p4tc_extern_tmpl_param *index_tmpl_param;
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

	index_tmpl_param = p4tc_ext_param_find_byanyattr(params_idr,
							 tb[P4TC_EXT_PARAMS_NAME],
							 0, extack);
	if (IS_ERR(index_tmpl_param)) {
		NL_SET_ERR_MSG(extack, "Key param name not found");
		return -EINVAL;
	}

	if (!(index_tmpl_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)) {
		NL_SET_ERR_MSG_FMT(extack, "%s is not the key param name",
				   param_name);
		return -EINVAL;
	}

	err = p4tc_ext_get_key_param_value(tb[P4TC_EXT_PARAMS_VALUE], key,
					   extack);
	if (err < 0)
		return err;

	return index_tmpl_param->id;
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

static struct p4tc_extern_param **
__p4tc_ext_update_params(struct net *net,
			 struct idr *control_params_idr,
			 struct p4tc_extern_params *params,
			 struct nlattr *nla, size_t *attrs_size,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param **params_backup;
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int err;
	int i;

	err = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (err < 0)
		return ERR_PTR(err);

	params_backup = kcalloc(params->num_params, sizeof(**params_backup),
				GFP_KERNEL);
	if (!params_backup)
		return ERR_PTR(-ENOMEM);

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_param *param;

		if (i - 1 == params->num_params) {
			NL_SET_ERR_MSG_FMT(extack, "Num params passed > %u",
					   params->num_params);
			err = -EINVAL;
			goto params_del;
		}

		param = p4tc_ext_init_param(net, control_params_idr, tb[i],
					    attrs_size, extack);
		if (IS_ERR(param)) {
			err = PTR_ERR(param);
			goto params_del;
		}
		params_backup[i - 1] = param;
		*attrs_size = nla_total_size(0); /* params array element nested */
	}

	if (params->num_params > i - 1) {
		NL_SET_ERR_MSG_FMT(extack, "Num params passed %u < %u",
				   i - 1, params->num_params);
		err = -EINVAL;
		goto params_del;
	}

	return params_backup;

params_del:
	p4tc_ext_put_many_params(params_backup, i - 1);
	kfree(params_backup);
	return ERR_PTR(err);
}

static struct p4tc_extern_param **
p4tc_ext_update_params(struct net *net,
		       struct idr *control_params_idr,
		       struct p4tc_extern_params *params,
		       struct nlattr *nla, size_t *attrs_size,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param **params_backup;
	int err;

	params_backup = __p4tc_ext_update_params(net, control_params_idr,
						 params, nla, attrs_size,
						 extack);
	if (IS_ERR(params_backup))
		return params_backup;

	err = p4tc_ext_check_params(params, params_backup, extack);
	if (err < 0)
		return ERR_PTR(err);

	return params_backup;
}

static int p4tc_ext_extract_params(struct net *net,
				   struct idr *control_params_idr,
				   struct p4tc_extern_params *params,
				   struct nlattr *nla, size_t *attrs_size,
				   struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param **params_backup;
	int err;
	int i;

	params_backup = __p4tc_ext_update_params(net, control_params_idr,
						 params, nla, attrs_size,
						 extack);
	if (IS_ERR(params_backup))
		return PTR_ERR(params_backup);

	for (i = 0; i < params->num_params; i++) {
		struct p4tc_extern_param *nparam = params_backup[i];

		err = idr_alloc_u32(&params->params_idr, nparam,
				    &nparam->tmpl_param->id,
				    nparam->tmpl_param->id, GFP_KERNEL);
		if (err < 0)
			goto params_del;
	}
	kfree(params_backup);

	return 0;

params_del:
	idr_destroy(&params->params_idr);
	p4tc_ext_put_many_params(params_backup, params->num_params);
	kfree(params_backup);
	return err;
}

static struct p4tc_ext_bpf_val_kern *
__p4tc_ext_runt_create_bpf(gfp_t alloc_flags)
{
	struct p4tc_ext_bpf_val_kern *val_kern;

	val_kern = kzalloc(sizeof(*val_kern), alloc_flags);
	if (!val_kern)
		return ERR_PTR(-ENOMEM);

	return val_kern;
}

static struct p4tc_ext_bpf_val_kern *
p4tc_ext_runt_create_bpf(struct p4tc_extern_common *common,
			 gfp_t alloc_flags,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_ext_bpf_val_kern *val_kern;

	val_kern = __p4tc_ext_runt_create_bpf(alloc_flags);
	if (IS_ERR(val_kern))
		return val_kern;

	p4tc_ext_runt_copy_bpf(val_kern, &common->params->params_idr,
			       common->inst->ext_id, common->p4tc_ext_key);

	return val_kern;
}

static void p4tc_ext_param_copy_defval(struct p4tc_extern_inst *inst,
				       struct p4tc_extern_param *param,
				       const u16 param_bytesz)
{
	struct p4tc_extern_tmpl_param *ctrl_param;

	ctrl_param = p4tc_ext_tmpl_param_find_byid(&inst->params->params_idr,
						   param->tmpl_param->id);

	memcpy(param->value, ctrl_param->default_value, param_bytesz);
}

struct p4tc_extern_common *p4tc_ext_elem_next(struct p4tc_extern_inst *inst)
{
	struct p4tc_ext_bpf_val_kern *val_kern;
	struct p4tc_extern_params *params;
	struct p4tc_extern_param *param;
	struct p4tc_extern_common *e;
	unsigned long param_id, tmp;

	spin_lock_bh(&inst->available_list_lock);
	e = list_first_entry_or_null(&inst->unused_elems,
				     struct p4tc_extern_common, node);
	if (!e) {
		spin_unlock_bh(&inst->available_list_lock);
		return NULL;
	}
	list_del_init(&e->node);
	spin_unlock_bh(&inst->available_list_lock);

	val_kern = __p4tc_ext_runt_create_bpf(GFP_ATOMIC);
	if (IS_ERR(val_kern)) {
		__p4tc_ext_elem_put_list(inst, e);
		return NULL;
	}

	params = e->params;

	spin_lock_bh(&params->params_lock);
	idr_for_each_entry_ul(&params->params_idr, param, tmp,
			      param_id) {
		struct p4tc_extern_tmpl_param *tmpl_param = param->tmpl_param;
		const u16 param_bytesz = BITS_TO_BYTES(tmpl_param->bitsz);

		if (param->ops && param->ops->default_value)
			param->ops->default_value(param);
		else
			p4tc_ext_param_copy_defval(inst, param, param_bytesz);
	}

	p4tc_ext_runt_copy_bpf(val_kern, &params->params_idr,
			       e->inst->ext_id, e->p4tc_ext_key);
	spin_lock_bh(&e->p4tc_ext_bpf_val_lock);
	val_kern = rcu_replace_pointer(e->val_kern, val_kern,
				       lockdep_is_held(&e->p4tc_ext_bpf_val_lock));
	spin_unlock_bh(&e->p4tc_ext_bpf_val_lock);
	spin_unlock_bh(&params->params_lock);
	atomic_set(&e->hidden, 0);
	refcount_set(&e->p4tc_ext_refcnt, 1);

	if (val_kern)
		kfree_rcu(val_kern, rcu);

	return e;
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

/* Check if extern with specified key exists. If extern is found, increments
 * its reference, and return 1. Otherwise return -ENOENT.
 */
static inline int p4tc_ext_idr_check_alloc(struct p4tc_extern_inst *inst,
					   u32 key, struct p4tc_extern **e,
					   struct netlink_ext_ack *extack)
{
	struct idr *elems_idr = &inst->control_elems_idr;
	struct p4tc_extern *p;

	if (key == P4TC_EXT_ELEM_PRIV_IDX) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Elem of index %u cannot be updated",
				   P4TC_EXT_ELEM_PRIV_IDX);
		return -EPERM;
	}

	p = idr_find(elems_idr, key);
	if (p) {
		*e = p;
		return 1;
	}

	NL_SET_ERR_MSG_FMT(extack, "Unable to find element with key %u",
			   key);
	return -ENOENT;
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
	struct p4tc_extern_param **params_backup;
	struct p4tc_ext_bpf_val_kern *val_kern;
	struct p4tc_extern *e = NULL;
	size_t attrs_size = 0;
	int err = 0;

	if (!nla) {
		NL_SET_ERR_MSG(extack, "Must specify extern params");
		err =  -EINVAL;
		goto out;
	}

	if (p4tc_ext_has_rctrl(e_o)) {
		params = p4tc_extern_params_init(GFP_KERNEL_ACCOUNT);
		if (!params) {
			err = -ENOMEM;
			goto out;
		}
		/* Decrement key parameter which comes separately in netlink */
		params->num_params = inst->params->num_params - 1;

		err = p4tc_ext_extract_params(net, control_params_idr, params,
					      nla, &attrs_size, extack);
		if (err < 0) {
			p4tc_ext_params_free(params);
			goto out;
		}

		err = e_o->rctrl(RTM_P4TC_UPDATE, inst,
				 (struct p4tc_extern_common **)&e, params, key,
				 extack);
		p4tc_ext_params_free(params);
		if (err < 0)
			goto out;

		return e;
	}

	err = p4tc_ext_idr_check_alloc(inst, key, &e, extack);
	if (err < 0)
		goto out;

	if (!p4tc_ctrl_update_ok(e->common.p4tc_ext_permissions)) {
		NL_SET_ERR_MSG(extack, "Update permissions not set");
		err = -EPERM;
		goto out;
	}

	if (p4tc_ext_is_hidden(&e->common)) {
		NL_SET_ERR_MSG(extack,
			       "Unable to write to inaccessible extern elem");
		err = -EPERM;
		goto out;
	}

	val_kern = __p4tc_ext_runt_create_bpf(GFP_KERNEL_ACCOUNT);
	if (IS_ERR(val_kern)) {
		err = PTR_ERR(val_kern);
		goto out;
	}

	params_backup = p4tc_ext_update_params(net, control_params_idr,
					       e->common.params,
					       nla, &attrs_size, extack);
	if (IS_ERR(params_backup)) {
		err = PTR_ERR(params_backup);
		goto free_val_kern;
	}

	p4tc_ext_runt_array_copy_bpf(val_kern, params_backup, inst->ext_id,
				     e->common.p4tc_ext_key,
				     e->common.params->num_params);

	attrs_size += nla_total_size(0) + p4tc_extern_shared_attrs_size();
	e->attrs_size = attrs_size;

	spin_lock_bh(&e->common.params->params_lock);
	p4tc_ext_replace_many_params(e->common.params, params_backup);
	spin_lock_bh(&e->common.p4tc_ext_bpf_val_lock);
	val_kern = rcu_replace_pointer(e->common.val_kern, val_kern,
				       lockdep_is_held(&e->common.p4tc_ext_bpf_val_lock));
	spin_unlock_bh(&e->common.p4tc_ext_bpf_val_lock);
	spin_unlock_bh(&e->common.params->params_lock);

	kfree(params_backup);

	if (val_kern)
		kfree_rcu(val_kern, rcu);

	return e;

free_val_kern:
	kfree(val_kern);

out:
	return ERR_PTR(err);
}

static struct p4tc_extern_tmpl_param *find_key_param(struct idr *params_idr)
{
	struct p4tc_extern_tmpl_param *tmpl_param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, tmpl_param, tmp, id) {
		if (tmpl_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)
			return tmpl_param;
	}

	return NULL;
}

static struct p4tc_extern_param *
p4tc_ext_init_defval_param(struct p4tc_extern_inst *inst,
			   struct p4tc_extern_tmpl_param *tmpl_param,
			   struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(tmpl_param->type->container_bitsz);
	const u16 bytesz = BITS_TO_BYTES(tmpl_param->bitsz);
	struct p4tc_extern_param *nparam;
	int err;

	nparam = kzalloc(sizeof(*nparam), GFP_KERNEL_ACCOUNT);
	if (!nparam) {
		err = -ENOMEM;
		goto out;
	}
	nparam->tmpl_param = tmpl_param;

	if (p4tc_ext_has_init_param_value(inst->ops)) {
		err = inst->ops->init_param_value(inst, nparam,
						  tmpl_param->default_value,
						  extack);
		if (err < 0)
			goto free_param;
	} else {
		nparam->value = kzalloc(alloc_len, GFP_KERNEL_ACCOUNT);
		if (!nparam->value) {
			err = -ENOMEM;
			goto free_param;
		}

		if (tmpl_param->default_value)
			memcpy(nparam->value, tmpl_param->default_value,
			       bytesz);
	}

	return nparam;

free_param:
	kfree(nparam);
out:
	return ERR_PTR(err);
}

struct p4tc_extern_params *
p4tc_ext_params_copy(struct p4tc_extern_params *params_orig)
{
	struct p4tc_extern_tmpl_param *tmpl_param;
	struct p4tc_extern_tmpl_param *nparam = NULL;
	struct p4tc_extern_params *params_copy;
	unsigned long tmp, id;
	int err;

	params_copy = p4tc_extern_params_init(GFP_KERNEL_ACCOUNT);
	if (!params_copy) {
		err = -ENOMEM;
		goto err_out;
	}

	idr_for_each_entry_ul(&params_orig->params_idr, tmpl_param, tmp, id) {
		struct p4tc_type *param_type = tmpl_param->type;
		u32 alloc_len = BITS_TO_BYTES(param_type->container_bitsz);
		u16 param_bytesz = BITS_TO_BYTES(tmpl_param->bitsz);

		nparam = kzalloc(sizeof(*nparam), GFP_KERNEL_ACCOUNT);
		if (!nparam) {
			err = -ENOMEM;
			goto free_params;
		}

		if (tmpl_param->default_value) {
			nparam->default_value = kzalloc(alloc_len,
							GFP_KERNEL_ACCOUNT);
			if (!nparam->default_value) {
				err = -ENOMEM;
				goto free_param;
			}
			memcpy(nparam->default_value, tmpl_param->default_value,
			       param_bytesz);
		}

		if (param_type->ops && param_type->ops->create_bitops) {
			struct p4tc_type_mask_shift *mask_shift;
			const u32 bitsz = tmpl_param->bitsz ?:
				param_type->bitsz;

			mask_shift = param_type->ops->create_bitops(bitsz, 0,
								    bitsz - 1,
								    NULL);
			if (IS_ERR(mask_shift)) {
				err = PTR_ERR(mask_shift);
				goto free_param_value;
			}
			nparam->mask_shift = mask_shift;
		}

		err = idr_alloc_u32(&params_copy->params_idr, nparam,
				    &tmpl_param->id, tmpl_param->id,
				    GFP_KERNEL_ACCOUNT);
		if (err < 0)
			goto free_mask_shift;

		nparam->type = tmpl_param->type;
		nparam->ops = tmpl_param->ops;
		nparam->id = tmpl_param->id;
		nparam->index = tmpl_param->index;
		nparam->bitsz = tmpl_param->bitsz;
		nparam->flags = tmpl_param->flags;
		strscpy(nparam->name, tmpl_param->name, EXTPARAMNAMSIZ);

		params_copy->num_params++;
	}

	return params_copy;

free_mask_shift:
	if (nparam->mask_shift)
		p4t_release(nparam->mask_shift);

free_param_value:
	kfree(nparam->default_value);
free_param:
	kfree(nparam);
free_params:
	p4tc_ext_params_free(params_copy);
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
	struct p4tc_extern_tmpl_param *param;
	bool has_custom_param = false;
	unsigned long tmp, id;
	int err;

	params = p4tc_extern_params_init(GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	if (common->ops && common->ops->rctrl)
		has_custom_param = true;

	idr_for_each_entry_ul(control_params_idr, param, tmp, id) {
		struct p4tc_extern_param *nparam;

		if (param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)
			/* Skip key param */
			continue;

		nparam = p4tc_ext_init_defval_param(inst, param, extack);
		if (IS_ERR(nparam)) {
			err = PTR_ERR(nparam);
			goto free_params;
		}

		err = idr_alloc_u32(&params->params_idr, nparam,
				    &nparam->tmpl_param->id,
				    nparam->tmpl_param->id, GFP_KERNEL_ACCOUNT);
		if (err < 0) {
			kfree(nparam);
			goto free_params;
		}
		params->num_params++;
		if (nparam->ops &&
		    (nparam->ops->init_value || nparam->ops->dump_value))
			has_custom_param = true;
	}

	common->params = params;
	common->inst = inst;
	common->ops = inst->ops;
	refcount_set(&common->p4tc_ext_refcnt, 1);
	if (inst->tbl_bindable)
		list_add_tail(&common->node, &inst->unused_elems);

	if (has_custom_param)
		inst->flags |= BIT(P4TC_EXT_INST_FLAGS_HAS_CUST_PARAM);

	return 0;

free_params:
	p4tc_ext_params_free(params);
	return err;
}
EXPORT_SYMBOL_GPL(p4tc_ext_init_defval_params);

static int p4tc_ext_init_defval(struct p4tc_extern_common **common,
				struct p4tc_extern_inst *inst,
				u32 key, struct netlink_ext_ack *extack)
{
	const struct p4tc_extern_ops *e_o = inst->ops;
	struct p4tc_ext_bpf_val_kern *val_kern;
	int err;

	if (!inst->is_scalar) {
		struct p4tc_extern_tmpl_param *key_param;

		key_param = find_key_param(&inst->params->params_idr);
		if (!key_param) {
			NL_SET_ERR_MSG(extack, "Unable to find key param");
			return -ENOENT;
		}
	}

	err = p4tc_ext_idr_create(inst, key, common, e_o, 0);
	if (err < 0)
		return err;

	/* We already store it in the IDR, because we arrive here with the
	 * rtnl_lock, so this code is never accessed concurrently.
	 */
	err = idr_alloc_u32(&inst->control_elems_idr, *common, &key,
			    key, GFP_KERNEL_ACCOUNT);
	if (err < 0) {
		__p4tc_ext_idr_purge(*common);
		return err;
	}

	err = p4tc_ext_init_defval_params(inst, *common,
					  &inst->params->params_idr, extack);
	if (err < 0)
		goto release_idr;

	val_kern = p4tc_ext_runt_create_bpf(*common, GFP_KERNEL_ACCOUNT,
					    extack);
	if (IS_ERR(val_kern)) {
		err = PTR_ERR(val_kern);
		goto put_params;
	}

	if (e_o && e_o->init) {
		err = e_o->init(*common, extack);
		if (err < 0)
			goto free_val_kern;
	}

	spin_lock_init(&((*common)->p4tc_ext_bpf_val_lock));

	rcu_assign_pointer((*common)->val_kern, val_kern);

	return 0;

free_val_kern:
	kfree_rcu(val_kern, rcu);

put_params:
	p4tc_ext_put_params_idr(&((*common)->params->params_idr));

release_idr:
	p4tc_ext_idr_release_dec_num_elems(*common);

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
			p4tc_ext_idr_purge(&inst->control_elems_idr, e);
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

int p4tc_extern_inst_init_elems(struct p4tc_extern_inst *inst, u32 num_elems)
{
	int err = 0;
	int i;

	/* Special case where module wants to use element not accessible by
	 * users (index P4TC_EXT_ELEM_PRIV_IDX)
	 */
	if (!num_elems) {
		struct p4tc_extern_common *common = NULL;

		return p4tc_ext_init_defval(&common, inst,
					    P4TC_EXT_ELEM_PRIV_IDX,
					    NULL);
	}

	for (i = 0; i < num_elems; i++) {
		struct p4tc_extern_common *common = NULL;

		err = p4tc_ext_init_defval(&common, inst, i + 1, NULL);
		if (err)
			return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(p4tc_extern_inst_init_elems);

static int
__p4tc_extern_insts_init_elems(struct idr *insts_idr)
{
	struct p4tc_extern_inst *inst;
	unsigned long tmp, id;
	int err = 0;

	idr_for_each_entry_ul(insts_idr, inst, tmp, id) {
		u32 max_num_elems = inst->max_num_elems;

		err = p4tc_extern_inst_init_elems(inst, max_num_elems);
		if (err < 0)
			return err;
	}

	return 0;
}

/* Called before sealing the pipeline */
int p4tc_extern_insts_init_elems(struct idr *user_ext_idr)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	unsigned long tmp, id;
	int err;

	idr_for_each_entry_ul(user_ext_idr, pipe_ext, tmp, id) {
		/* We assume the module construct will create the initial elems
		 * by itself.
		 * We only initialise when sealing if we don't have construct.
		 */
		if (p4tc_ext_has_construct(pipe_ext->tmpl_ext->ops))
			continue;

		err = __p4tc_extern_insts_init_elems(&pipe_ext->e_inst_idr);
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
				       NULL, key, extack);
		if (err < 0)
			return ERR_PTR(err);

		return e;
	}

	return (struct p4tc_extern *)p4tc_ext_get_common(inst, key, extack);
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
p4tc_ctl_extern_1(struct p4tc_pipeline *pipeline,
		  struct nlattr *nla, struct nlmsghdr *n,
		  u32 portid, u32 flags, bool has_one_batched_entry,
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

	if (!has_one_batched_entry && p4tc_ext_has_rctrl(inst->ops)) {
		NL_SET_ERR_MSG(extack,
			       "Runtime message may only have one extern with rctrl op");
		return ERR_PTR(-EINVAL);
	}

	if (!has_one_batched_entry && n->nlmsg_type == RTM_P4TC_GET) {
		NL_SET_ERR_MSG(extack, "Batched get is not allowed");
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

static int __p4tc_ctl_extern_num_batched(struct nlattr *tb[])
{
	int i = 1;

	while (i < P4TC_MSGBATCH_SIZE + 1 && tb[i])
		i++;

	return i - 1;
}

static int __p4tc_ctl_extern(struct p4tc_pipeline *pipeline,
			     struct nlattr *nla, struct nlmsghdr *n,
			     u32 portid, u32 flags,
			     struct netlink_ext_ack *extack)
{
	struct p4tc_ext_nlmsg_attrs nlmsg_attrs = {};
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_extern *ext;
	size_t attr_size = 0;
	bool has_one_element;
	int num_batched;
	int i, ret;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
			       extack);
	if (ret < 0)
		return ret;

	if (!tb[1]) {
		NL_SET_ERR_MSG(extack,
			       "Must specify at least one batched element");
		return -EINVAL;
	}

	/* We only allow 1 batched element in case the extern has an rctrl
	 * callback.
	 */
	has_one_element = !tb[2];
	ext = p4tc_ctl_extern_1(pipeline, tb[1], n, portid,
				flags, has_one_element, extack);
	if (IS_ERR(ext)) {
		ret = PTR_ERR(ext);
		i = 1;
		goto err;
	}

	nlmsg_attrs.portid = portid;
	nlmsg_attrs.pipeid = pipeline->common.p_id;
	nlmsg_attrs.flags = n->nlmsg_flags;
	nlmsg_attrs.seq = n->nlmsg_seq;
	nlmsg_attrs.cmd = n->nlmsg_type;

	p4tc_extern_send(pipeline, &ext->common,
			 &nlmsg_attrs, attr_size, true, extack);

	if (p4tc_ext_has_rctrl(ext->common.ops))
		return 0;

	attr_size += ext->attrs_size;

	for (i = 2; i <= P4TC_MSGBATCH_SIZE && tb[i]; i++) {
		ext = p4tc_ctl_extern_1(pipeline, tb[i], n, portid,
					flags, false, extack);
		if (IS_ERR(ext)) {
			ret = PTR_ERR(ext);
			goto err;
		}

		attr_size += ext->attrs_size;
		/* Only add to externs array, extern modules that don't
		 * implement rctrl callback.
		 */
		p4tc_extern_send(pipeline, &ext->common, &nlmsg_attrs,
				 attr_size, true, extack);
	}

	return 0;

err:
	num_batched = __p4tc_ctl_extern_num_batched(tb);
	NL_SET_ERR_MSG_FMT(extack,
			   "%s\nProcessed %d/%d entries", extack->_msg, i,
			    num_batched);

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
	struct p4tc_ext_dump_ctx *dump_ctx =
		(struct p4tc_ext_dump_ctx *)cb->ctx;
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

	if (!p4tc_pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Pipeline must be sealed for extern runtime ops");
		return -EINVAL;
	}

	ret = parse_dump_ext_attrs(tb[P4TC_ROOT], tb2);
	if (ret < 0)
		return ret;

	kind_str = nla_data(tb2[P4TC_EXT_KIND]);
	if (NL_REQ_ATTR_CHECK(extack, NULL, tb2, P4TC_EXT_KIND)) {
		NL_SET_ERR_MSG(extack,
			       "TC extern kind name must be specified");
		return -EINVAL;
	}

	instname = nla_data(tb2[P4TC_EXT_INST_NAME]);
	if (NL_REQ_ATTR_CHECK(extack, NULL, tb2, P4TC_EXT_INST_NAME)) {
		NL_SET_ERR_MSG(extack,
			       "TC extern inst name must be specified");
		return -EINVAL;
	}

	inst = p4tc_ext_inst_find_bynames(pipeline->net, pipeline, kind_str,
					  instname, extack);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

	dump_ctx->ext_flags = 0;
	if (tb[P4TC_ROOT_FLAGS]) {
		bf = nla_get_bitfield32(tb[P4TC_ROOT_FLAGS]);
		dump_ctx->ext_flags = bf.value;
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

	if (nla_put_string(skb, P4TC_ROOT_PNAME, pipeline->common.name))
		goto err_out;

	nest = nla_nest_start(skb, P4TC_ROOT);
	if (!nest)
		goto err_out;

	ret = p4tc_ext_dump_walker(skb, dump_ctx, pipeline, inst,
				   cb);
	if (ret < 0)
		goto err_out;

	if (ret > 0) {
		nla_nest_end(skb, nest);
		ret = skb->len;
		ext_count = dump_ctx->n_i;
		memcpy(nla_data(count_attr), &ext_count, sizeof(u32));
		dump_ctx->n_i = 0;
	} else {
		nlmsg_trim(skb, b);
	}

	nlh->nlmsg_len = (unsigned char *)nlmsg_get_pos(skb) - b;
	if (NETLINK_CB(cb->skb).portid && ret)
		nlh->nlmsg_flags |= NLM_F_MULTI;
	return skb->len;

err_out:
	nlmsg_trim(skb, b);
	return ret;
}

int p4tc_ctl_extern(struct sk_buff *skb, struct nlmsghdr *n, struct nlattr **tb,
		    struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	struct p4tc_pipeline *pipeline;
	struct nlattr *root;
	char *pname = NULL;
	u32 flags = 0;

	if (n->nlmsg_type != RTM_P4TC_GET &&
	    !netlink_capable(skb, CAP_NET_ADMIN)) {
		NL_SET_ERR_MSG(extack, "Need CAP_NET_ADMIN to do CUD ops");
		return -EPERM;
	}

	if (tb[P4TC_ROOT_PNAME])
		pname = nla_data(tb[P4TC_ROOT_PNAME]);

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC extern attributes missing");
		return -EINVAL;
	}

	root = tb[P4TC_ROOT];

	pipeline = p4tc_pipeline_find_byany(net, pname, 0, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!p4tc_pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Pipeline must be sealed for extern runtime ops");
		return -EPERM;
	}

	return __p4tc_ctl_extern(pipeline, root, n, portid, flags, extack);
}
