// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_tmpl_extern.c	P4 TC EXTERN TEMPLATE
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/p4tc_ext_api.h>

static LIST_HEAD(ext_base);
static DEFINE_RWLOCK(ext_mod_lock);

static struct netlink_range_validation range_inst_elems = {
	.min = 0,
	.max = P4TC_MAX_NUM_EXT_INST_ELEMS,
};

static const struct nla_policy
tc_extern_inst_policy[P4TC_TMPL_EXT_INST_MAX + 1] = {
	[P4TC_TMPL_EXT_INST_EXT_NAME] = {
		.type = NLA_STRING,
		.len =  P4TC_EXTERN_NAMSIZ
	},
	[P4TC_TMPL_EXT_INST_NAME] = {
		.type = NLA_STRING,
		.len =  P4TC_EXTERN_INST_NAMSIZ
	},
	[P4TC_TMPL_EXT_INST_NUM_ELEMS] =
		NLA_POLICY_FULL_RANGE(NLA_U32, &range_inst_elems),
	[P4TC_TMPL_EXT_INST_CONTROL_PARAMS] = { .type = NLA_NESTED },
	[P4TC_TMPL_EXT_INST_TABLE_BINDABLE] = { . type = NLA_U8 },
	[P4TC_TMPL_EXT_INST_CONSTR_PARAMS] = { .type = NLA_NESTED },
};

static const struct netlink_range_validation permissions_range = {
	.min = 0,
	.max = P4TC_MAX_PERMISSION,
};

static const struct nla_policy tc_extern_policy[P4TC_TMPL_EXT_MAX + 1] = {
	[P4TC_TMPL_EXT_NAME] = {
		.type = NLA_STRING,
		.len =  P4TC_EXTERN_NAMSIZ
	},
	[P4TC_TMPL_EXT_NUM_INSTS] = NLA_POLICY_RANGE(NLA_U16, 1,
						     P4TC_MAX_NUM_EXT_INSTS),
	[P4TC_TMPL_EXT_HAS_EXEC_METHOD] = NLA_POLICY_RANGE(NLA_U8, 1, 1),
	[P4TC_TMPL_EXT_PERMISSIONS] =
		NLA_POLICY_FULL_RANGE(NLA_U16, &permissions_range),
};

static const struct nla_policy
p4tc_extern_params_policy[P4TC_EXT_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_NAME] = { .type = NLA_STRING, .len = EXTPARAMNAMSIZ },
	[P4TC_EXT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_EXT_PARAMS_TYPE] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_BITSZ] =
		NLA_POLICY_RANGE(NLA_U16, 1, P4TC_T_MAX_BITSZ),
	[P4TC_EXT_PARAMS_FLAGS] = { .type = NLA_U8 },
};

static void p4tc_extern_ops_put(const struct p4tc_extern_ops *ops)
{
	if (ops)
		module_put(ops->owner);
}

static bool
p4tc_extern_mod_callbacks_check(const struct p4tc_extern_ops *ext)
{
	if ((ext->construct || ext->deconstruct))
		return (ext->construct && ext->deconstruct);

	return true;
}

static struct p4tc_extern_ops *p4tc_extern_lookup_n(const char *kind)
{
	struct p4tc_extern_ops *a = NULL;

	read_lock(&ext_mod_lock);
	list_for_each_entry(a, &ext_base, head) {
		if (strncmp(kind, a->kind, P4TC_EXT_NAMSIZ) == 0) {
			read_unlock(&ext_mod_lock);
			return a;
		}
	}
	read_unlock(&ext_mod_lock);

	return NULL;
}

static struct p4tc_extern_ops *p4tc_extern_lookup_id(const u32 id)
{
	struct p4tc_extern_ops *a = NULL;

	read_lock(&ext_mod_lock);
	list_for_each_entry(a, &ext_base, head) {
		if (a->id == id) {
			read_unlock(&ext_mod_lock);
			return a;
		}
	}
	read_unlock(&ext_mod_lock);

	return NULL;
}

static int
p4tc_extern_mod_name(char *mod_name, const char *kind)
{
	int nbytes;

	nbytes = snprintf(mod_name, P4TC_EXTERN_NAMSIZ, "ext_%s", kind);
	/* Extern name was too long */
	if (nbytes == P4TC_EXTERN_NAMSIZ)
		return -E2BIG;

	return 0;
}

static struct p4tc_extern_ops *p4tc_extern_ops_load(const char *kind)
{
	char mod_name[P4TC_EXTERN_NAMSIZ] = {0};
	struct p4tc_extern_ops *ops = NULL;
	int err;

	if (!kind)
		return NULL;

	err = p4tc_extern_mod_name(mod_name, kind);
	if (err < 0)
		return NULL;

	ops = p4tc_extern_lookup_n(mod_name);
	if (ops && try_module_get(ops->owner))
		return ops;

	if (!ops) {
		rtnl_unlock();
		request_module("ext_%s", kind);
		rtnl_lock();

		ops = p4tc_extern_lookup_n(mod_name);
		if (ops) {
			if (try_module_get(ops->owner))
				return ops;

			return NULL;
		}
	}

	return ops;
}

static void p4tc_extern_tmpl_put_param(struct p4tc_extern_tmpl_param *param)
{
	if (param->mask_shift)
		p4t_release(param->mask_shift);

	if (param->default_value)
		kfree(param->default_value);

	kfree(param);
}

static void p4tc_extern_put_tmpl_param_idr(struct idr *params_idr,
					   struct p4tc_extern_tmpl_param *param)
{
	idr_remove(params_idr, param->id);
	p4tc_extern_tmpl_put_param(param);
}

static void
p4tc_user_pipeline_ext_put_ref(struct p4tc_user_pipeline_extern *pipe_ext)
{
	refcount_dec(&pipe_ext->ext_ref);
}

static void
p4tc_user_pipeline_ext_free(struct p4tc_user_pipeline_extern *pipe_ext,
			    struct idr *tmpl_exts_idr)
{
	idr_remove(tmpl_exts_idr, pipe_ext->ext_id);
	idr_destroy(&pipe_ext->e_inst_idr);
	refcount_dec(&pipe_ext->tmpl_ext->tmpl_ref);
	kfree(pipe_ext);
}

static void
p4tc_user_pipeline_ext_put(struct p4tc_pipeline *pipeline,
			   struct p4tc_user_pipeline_extern *pipe_ext,
			   bool release, struct idr *tmpl_exts_idr)
{
	if (refcount_dec_and_test(&pipe_ext->ext_ref) && release)
		p4tc_user_pipeline_ext_free(pipe_ext, tmpl_exts_idr);
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_byid(struct p4tc_pipeline *pipeline,
				 const u32 ext_id)
{
	struct p4tc_user_pipeline_extern *pipe_ext;

	pipe_ext = idr_find(&pipeline->user_ext_idr, ext_id);

	return pipe_ext;
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_get(struct p4tc_pipeline *pipeline, const u32 ext_id)
{
	struct p4tc_user_pipeline_extern *pipe_ext;

	pipe_ext = p4tc_user_pipeline_ext_find_byid(pipeline, ext_id);
	if (!pipe_ext)
		return ERR_PTR(-ENOENT);

	refcount_inc(&pipe_ext->ext_ref);

	return pipe_ext;
}

void p4tc_ext_tmpl_params_free(struct p4tc_extern_params *params)
{
	struct p4tc_extern_tmpl_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&params->params_idr, param, tmp, id)
		p4tc_extern_put_tmpl_param_idr(&params->params_idr, param);

	idr_destroy(&params->params_idr);
	kfree(params);
}
EXPORT_SYMBOL(p4tc_ext_tmpl_params_free);

static void ___p4tc_ext_inst_put(struct p4tc_extern_inst *inst, bool put_params)
{
	if (p4tc_ext_inst_has_construct(inst)) {
		inst->ops->deconstruct(inst);
	} else {
		if (inst->params && put_params)
			p4tc_ext_tmpl_params_free(inst->params);
		kfree(inst);
	}
}

static int __p4tc_ext_inst_put(struct p4tc_pipeline *pipeline,
			       struct p4tc_extern_inst *inst, bool teardown,
			       bool release, struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext = inst->pipe_ext;
	const u32 inst_id = inst->ext_inst_id;

	if (!teardown && !refcount_dec_if_one(&inst->inst_ref)) {
		NL_SET_ERR_MSG(extack,
			       "Can't delete referenced extern instance template");
		return -EBUSY;
	}

	___p4tc_ext_inst_put(inst, true);

	atomic_dec(&pipe_ext->curr_insts_num);
	idr_remove(&pipe_ext->e_inst_idr, inst_id);

	p4tc_user_pipeline_ext_put(pipeline, pipe_ext, release,
				   &pipeline->user_ext_idr);

	return 0;
}

static int _p4tc_tmpl_ext_put(struct p4tc_pipeline *pipeline,
			      struct p4tc_tmpl_extern *ext, bool teardown,
			      struct netlink_ext_ack *extack)
{
	if (!teardown && !refcount_dec_if_one(&ext->tmpl_ref)) {
		NL_SET_ERR_MSG(extack,
			       "Can't delete referenced extern template");
		return -EBUSY;
	}

	idr_remove(&pipeline->p_ext_idr, ext->ext_id);
	p4tc_extern_ops_put(ext->ops);

	kfree(ext);

	return 0;
}

static int p4tc_tmpl_ext_put(struct p4tc_pipeline *pipeline,
			     struct p4tc_template_common *tmpl,
			     struct netlink_ext_ack *extack)
{
	struct p4tc_tmpl_extern *ext;

	ext = to_extern(tmpl);

	return _p4tc_tmpl_ext_put(pipeline, ext, true, extack);
}

static const struct p4tc_template_ops p4tc_ext_inst_ops;

static const struct p4tc_template_ops p4tc_tmpl_ext_ops;

static int p4tc_ext_inst_put(struct p4tc_pipeline *pipeline,
			     struct p4tc_template_common *tmpl,
			     struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst *inst;

	inst = to_extern_inst(tmpl);

	return __p4tc_ext_inst_put(pipeline, inst, true, false, extack);
}

static struct p4tc_extern_inst *
p4tc_ext_inst_find_byname(struct p4tc_user_pipeline_extern *pipe_ext,
			  const char *instname)
{
	struct p4tc_extern_inst *ext_inst;
	unsigned long tmp, inst_id;

	idr_for_each_entry_ul(&pipe_ext->e_inst_idr, ext_inst, tmp, inst_id) {
		if (strncmp(ext_inst->common.name, instname,
			    P4TC_EXTERN_INST_NAMSIZ) == 0)
			return ext_inst;
	}

	return NULL;
}

static struct p4tc_extern_tmpl_param *
p4tc_ext_tmpl_param_find_byname(struct idr *params_idr, const char *param_name)
{
	struct p4tc_extern_tmpl_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		if (param == ERR_PTR(-EBUSY))
			continue;
		if (strncmp(param->name, param_name, EXTPARAMNAMSIZ) == 0)
			return param;
	}

	return NULL;
}

static struct p4tc_extern_inst *
p4tc_ext_inst_find_byid(struct p4tc_user_pipeline_extern *pipe_ext,
			const u32 inst_id)
{
	struct p4tc_extern_inst *ext_inst;

	ext_inst = idr_find(&pipe_ext->e_inst_idr, inst_id);

	return ext_inst;
}

static struct p4tc_extern_inst *
p4tc_ext_inst_find_byany(struct p4tc_user_pipeline_extern *pipe_ext,
			 const char *instname, u32 instid,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst *inst;
	int err;

	if (instid) {
		inst = p4tc_ext_inst_find_byid(pipe_ext, instid);
		if (!inst) {
			NL_SET_ERR_MSG(extack, "Unable to find instance by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (instname) {
			inst = p4tc_ext_inst_find_byname(pipe_ext, instname);
			if (!inst) {
				NL_SET_ERR_MSG_FMT(extack,
						   "Instance name not found %s\n",
						   instname);
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify instance name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return inst;

out:
	return ERR_PTR(err);
}

static struct p4tc_extern_inst *
p4tc_ext_inst_get(struct p4tc_user_pipeline_extern *pipe_ext,
		  const char *instname, const u32 ext_inst_id,
		  struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst *ext_inst;

	ext_inst = p4tc_ext_inst_find_byany(pipe_ext, instname, ext_inst_id,
					    extack);
	if (IS_ERR(ext_inst))
		return ext_inst;

	/* Extern instance template was deleted in parallel */
	if (!refcount_inc_not_zero(&ext_inst->inst_ref))
		return ERR_PTR(-EBUSY);

	return ext_inst;
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_name(struct p4tc_pipeline *pipeline, const char *extern_name)
{
	struct p4tc_tmpl_extern *ext;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_ext_idr, ext, tmp, id)
		if (ext->common.name[0] &&
		    strncmp(ext->common.name, extern_name,
			    P4TC_EXTERN_NAMSIZ) == 0)
			return ext;

	return NULL;
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_byid(struct p4tc_pipeline *pipeline, const u32 ext_id)
{
	return idr_find(&pipeline->p_ext_idr, ext_id);
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_byany(struct p4tc_pipeline *pipeline,
			 const char *extern_name, u32 ext_id,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_tmpl_extern *ext;
	int err;

	if (ext_id) {
		ext = p4tc_tmpl_ext_find_byid(pipeline, ext_id);
		if (!ext) {
			NL_SET_ERR_MSG(extack, "Unable to find ext by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (extern_name) {
			ext = p4tc_tmpl_ext_find_name(pipeline, extern_name);
			if (!ext) {
				NL_SET_ERR_MSG(extack,
					       "Extern name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify ext name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return ext;

out:
	return ERR_PTR(err);
}

static struct p4tc_extern_inst *
p4tc_ext_inst_find_byanyattr(struct p4tc_user_pipeline_extern *pipe_ext,
			     struct nlattr *name_attr, u32 instid,
			     struct netlink_ext_ack *extack)
{
	char *instname = NULL;

	if (name_attr)
		instname = nla_data(name_attr);

	return p4tc_ext_inst_find_byany(pipe_ext, instname, instid,
					extack);
}

static int dev_validate_val(struct net *net, void *value,
			    struct netlink_ext_ack *extack)
{
	u32 ifindex = *((u32 *)value);

	rcu_read_lock();
	if (!dev_get_by_index_rcu(net, ifindex)) {
		NL_SET_ERR_MSG(extack, "Invalid ifindex");
		rcu_read_unlock();
		return -EINVAL;
	}
	rcu_read_unlock();

	return 0;
}

static void *dev_default_val(void)
{
	u32 *ifindex = kzalloc(sizeof(*ifindex), GFP_KERNEL);

	if (!ifindex)
		return ERR_PTR(-ENOMEM);
	*ifindex = 1;

	return ifindex;
}

static struct p4tc_extern_tmpl_param_ops tmpl_params_ops[P4TC_T_MAX + 1] = {
	[P4TC_T_DEV] = {
		.validate_val = dev_validate_val,
		.default_val = dev_default_val,
	},
};

static struct p4tc_extern_tmpl_param *
p4tc_extern_create_param(struct idr *params_idr, struct nlattr **tb,
			 u32 param_id, struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift = NULL;
	struct p4tc_extern_tmpl_param *param;
	struct p4tc_type *type;
	u8 *flags = NULL;
	u16 bitsz = 0;
	char *name;
	u32 typeid;
	int ret;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_PARAMS_NAME)) {
		NL_SET_ERR_MSG(extack, "Must specify param name");
		ret = -EINVAL;
		goto out;
	}
	name = nla_data(tb[P4TC_EXT_PARAMS_NAME]);

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	if ((param_id && p4tc_ext_param_find_byid(params_idr, param_id)) ||
	    p4tc_ext_tmpl_param_find_byname(params_idr, name)) {
		NL_SET_ERR_MSG_FMT(extack, "Param already exists %s", name);
		ret = -EEXIST;
		goto free;
	}

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_PARAMS_TYPE)) {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}
	typeid = nla_get_u32(tb[P4TC_EXT_PARAMS_TYPE]);

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_EXT_PARAMS_BITSZ)) {
		NL_SET_ERR_MSG(extack, "Must specify param bitsz");
		ret = -EINVAL;
		goto free;
	}

	if (tb[P4TC_EXT_PARAMS_BITSZ])
		bitsz = nla_get_u16(tb[P4TC_EXT_PARAMS_BITSZ]);

	type = p4type_find_byid(typeid);
	if (!type) {
		NL_SET_ERR_MSG(extack, "Param type is invalid");
		ret = -EINVAL;
		goto free;
	}
	param->type = type;
	if (bitsz > param->type->bitsz) {
		NL_SET_ERR_MSG(extack, "Bit size is bigger than type");
		ret = -EINVAL;
		goto free;
	}
	if (type->ops->create_bitops) {
		mask_shift = type->ops->create_bitops(bitsz, 0, bitsz - 1,
						      extack);
		if (IS_ERR(mask_shift)) {
			ret = PTR_ERR(mask_shift);
			goto free;
		}
	}
	param->mask_shift = mask_shift;
	param->bitsz = bitsz ?: type->bitsz;

	if (tb[P4TC_EXT_PARAMS_FLAGS]) {
		flags = nla_data(tb[P4TC_EXT_PARAMS_FLAGS]);
		param->flags = *flags;
	}

	if (flags && *flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		switch (param->type->typeid) {
		case P4TC_T_U8:
		case P4TC_T_U16:
		case P4TC_T_U32:
			break;
		default: {
			NL_SET_ERR_MSG(extack,
				       "Key must be an unsigned integer");
			ret = -EINVAL;
			goto free_mask_shift;
		}
		}
	}

	if (param_id) {
		ret = idr_alloc_u32(params_idr, param, &param_id,
				    param_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free_mask_shift;
		}
		param->id = param_id;
	} else {
		param->id = 1;

		ret = idr_alloc_u32(params_idr, param, &param->id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free_mask_shift;
		}
	}

	param->ops = &tmpl_params_ops[typeid];
	strscpy(param->name, name, EXTPARAMNAMSIZ);

	return param;

free_mask_shift:
	if (param->mask_shift)
		p4t_release(param->mask_shift);

free:
	kfree(param);

out:
	return ERR_PTR(ret);
}

static const struct nla_policy
p4tc_extern_params_value_policy[P4TC_EXT_VALUE_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_VALUE_RAW] = { .type = NLA_BINARY },
};

static void *
generic_param_value_parse(struct p4tc_extern_tmpl_param *param,
			  struct net *net, struct nlattr *nla,
			  struct p4tc_extern_tmpl_param_ops *tmpl_param_ops,
			  bool value_required,
			  struct netlink_ext_ack *extack)
{
	struct nlattr *tb_value[P4TC_EXT_VALUE_PARAMS_MAX + 1];
	const u16 param_bytesz = BITS_TO_BYTES(param->bitsz);
	struct p4tc_type *type = param->type;
	void *value;
	int err;

	if (!nla) {
		if (value_required) {
			NL_SET_ERR_MSG(extack, "Must specify param value");
			return ERR_PTR(-EINVAL);
		} else {
			u32 alloc_len =
				BITS_TO_BYTES(type->container_bitsz);

			if (tmpl_param_ops && tmpl_param_ops->default_val) {
				return tmpl_param_ops->default_val();
			} else  {
				value = kzalloc(alloc_len, GFP_KERNEL);
				if (!value)
					return ERR_PTR(-ENOMEM);
			}


			return value;
		}
	}

	err = nla_parse_nested(tb_value, P4TC_EXT_VALUE_PARAMS_MAX,
			       nla, p4tc_extern_params_value_policy,
			       extack);
	if (err < 0)
		return ERR_PTR(err);

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb_value,
			      P4TC_EXT_PARAMS_VALUE_RAW)) {
		NL_SET_ERR_MSG(extack,
			       "Must specify param raw value");
		return ERR_PTR(-EINVAL);
	}
	value = nla_data(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]);

	if (type->ops->validate_p4t) {
		err = type->ops->validate_p4t(type, value, 0, param->bitsz - 1,
					      extack);
		if (err < 0)
			return ERR_PTR(err);
	}

	if (tmpl_param_ops && tmpl_param_ops->validate_val) {
		err = tmpl_param_ops->validate_val(net, value, extack);

		if (err < 0)
			return ERR_PTR(err);
	}

	if (nla_len(tb_value[P4TC_EXT_PARAMS_VALUE_RAW]) != param_bytesz)
		return ERR_PTR(-EINVAL);

	return value;
}

static int
p4tc_extern_tmpl_param_value_init(struct net *net,
				  struct p4tc_extern_tmpl_param *nparam,
				  struct nlattr **tb,
				  struct netlink_ext_ack *extack)
{
	const u32 alloc_len = BITS_TO_BYTES(nparam->type->container_bitsz);
	bool free_value = !tb[P4TC_EXT_PARAMS_VALUE];
	u16 param_bytesz = BITS_TO_BYTES(nparam->bitsz);
	void *value;

	value = generic_param_value_parse(nparam, net,
					  tb[P4TC_EXT_PARAMS_VALUE],
					  nparam->ops, false, extack);
	if (IS_ERR(value))
		return PTR_ERR(value);

	nparam->default_value = kzalloc(alloc_len, GFP_KERNEL);
	if (!nparam->default_value) {
		if (free_value)
			kfree(value);
		return -ENOMEM;
	}

	memcpy(nparam->default_value, value, param_bytesz);
	if (free_value)
		kfree(value);

	return 0;
}

static struct p4tc_extern_tmpl_param *
p4tc_extern_create_param_value(struct net *net, struct idr *params_idr,
			       struct nlattr **tb, u32 param_id,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_extern_tmpl_param *param;
	int err;

	param = p4tc_extern_create_param(params_idr, tb, param_id, extack);
	if (IS_ERR(param))
		return param;

	err = p4tc_extern_tmpl_param_value_init(net, param, tb, extack);
	if (err < 0)
		goto extern_put_param;

	return param;

extern_put_param:
	p4tc_extern_put_tmpl_param_idr(params_idr, param);
	return ERR_PTR(err);
}

static struct p4tc_extern_tmpl_param *
p4tc_extern_init_param_value(struct net *net, struct idr *params_idr,
			     struct nlattr *nla,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_EXT_PARAMS_MAX + 1];
	u32 param_id = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_EXT_PARAMS_MAX, nla,
			       p4tc_extern_params_policy, extack);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (tb[P4TC_EXT_PARAMS_ID])
		param_id = nla_get_u32(tb[P4TC_EXT_PARAMS_ID]);

	return p4tc_extern_create_param_value(net, params_idr, tb,
					      param_id, extack);

out:
	return ERR_PTR(ret);
}

static bool
p4tc_extern_params_check_flags(struct p4tc_extern_tmpl_param *param,
			       struct netlink_ext_ack *extack)
{
	if (param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY &&
	    param->flags & P4TC_EXT_PARAMS_FLAG_IS_DATASCALAR) {
		NL_SET_ERR_MSG(extack,
			       "Can't set key and data scalar flags at the same time");
		return false;
	}

	return true;
}

static struct p4tc_extern_params *
p4tc_extern_init_params_value(struct net *net,
			      struct p4tc_extern_params *params,
			      struct nlattr **tb,
			      bool *is_scalar, bool tbl_bindable,
			      bool needs_value_param,
			      struct netlink_ext_ack *extack)
{
	bool has_scalar_param = false;
	bool has_value_param = false;
	bool has_key_param = false;
	size_t tot_params_sz = 0;
	int ret;
	int i;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_tmpl_param *param;

		param = p4tc_extern_init_param_value(net, &params->params_idr,
						     tb[i], extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_del;
		}

		if (!p4tc_extern_params_check_flags(param, extack)) {
			ret = -EINVAL;
			goto params_del;
		}

		has_value_param = has_value_param ?
			has_value_param : !(param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY);
		if (has_key_param) {
			if (param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
				NL_SET_ERR_MSG(extack,
					       "There can't be 2 key params");
				ret = -EINVAL;
				goto params_del;
			}
		} else {
			has_key_param =
				param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY;
		}

		if (has_scalar_param) {
			if (!param->flags ||
			    (param->flags & P4TC_EXT_PARAMS_FLAG_IS_DATASCALAR)) {
				NL_SET_ERR_MSG(extack,
					       "All data parameters must be scalars");
				ret = -EINVAL;
				goto params_del;
			}
		} else {
			has_scalar_param =
				param->flags & P4TC_EXT_PARAMS_FLAG_IS_DATASCALAR;
		}
		if (tbl_bindable) {
			if (!p4tc_is_type_unsigned_he(param->type->typeid)) {
				NL_SET_ERR_MSG_FMT(extack,
						   "Extern with non host endian param(%s) is unbindable",
						   param->type->name);
				ret = -EINVAL;
				goto params_del;
			}
		}

		if (tot_params_sz > P4TC_EXT_MAX_PARAM_DATA_SIZE) {
			NL_SET_ERR_MSG(extack,
				       "Maximum parameter byte size reached");
			ret = -EINVAL;
			goto params_del;
		}
		tot_params_sz += BITS_TO_BYTES(param->bitsz);
		params->num_params++;
	}
	*is_scalar = has_scalar_param;

	if (needs_value_param && !has_value_param) {
		NL_SET_ERR_MSG(extack,
			       "Instance must have a value param");
		ret = -EINVAL;
		goto params_del;
	}

	return params;

params_del:
	p4tc_ext_tmpl_params_free(params);
	return ERR_PTR(ret);
}

static struct p4tc_extern_params *
p4tc_extern_create_params_value(struct net *net, struct nlattr *nla,
				bool *is_scalar, bool tbl_bindable,
				bool has_value_param,
				struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_extern_params *params;
	int ret;

	params = p4tc_extern_params_init();
	if (!params) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
				       extack);
		if (ret < 0) {
			ret = -EINVAL;
			goto params_del;
		}
	} else {
		return params;
	}

	return p4tc_extern_init_params_value(net, params, tb, is_scalar,
					     tbl_bindable, has_value_param,
					     extack);

params_del:
	p4tc_ext_tmpl_params_free(params);
err_out:
	return ERR_PTR(ret);
}

static struct p4tc_extern_params *
p4tc_extern_update_params_value(struct net *net, struct nlattr *nla,
				bool *is_scalar, bool tbl_bindable,
				bool needs_value_param,
				struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_extern_params *params;
	int ret;

	if (nla) {
		params = p4tc_extern_params_init();
		if (!params) {
			ret = -ENOMEM;
			goto err_out;
		}

		ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL,
				       extack);
		if (ret < 0) {
			ret = -EINVAL;
			goto params_del;
		}
	} else {
		return NULL;
	}

	return p4tc_extern_init_params_value(net, params, tb, is_scalar,
					     tbl_bindable, needs_value_param,
					     extack);

params_del:
	p4tc_ext_tmpl_params_free(params);
err_out:
	return ERR_PTR(ret);
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_byanyattr(struct p4tc_pipeline *pipeline,
			     struct nlattr *name_attr, u32 ext_id,
			     struct netlink_ext_ack *extack)
{
	char *extern_name = NULL;

	if (name_attr)
		extern_name = nla_data(name_attr);

	return p4tc_tmpl_ext_find_byany(pipeline, extern_name, ext_id,
				       extack);
}

int p4tc_register_extern(struct p4tc_extern_ops *ext)
{
	if (p4tc_extern_lookup_n(ext->kind) ||
	    p4tc_extern_lookup_id(ext->id))
		return -EEXIST;

	if (!p4tc_extern_mod_callbacks_check(ext))
		return -EINVAL;

	write_lock(&ext_mod_lock);
	list_add_tail(&ext->head, &ext_base);
	write_unlock(&ext_mod_lock);

	return 0;
}
EXPORT_SYMBOL(p4tc_register_extern);

int p4tc_unregister_extern(struct p4tc_extern_ops *ext)
{
	struct p4tc_extern_ops *a;
	int err = -ENOENT;

	write_lock(&ext_mod_lock);
	list_for_each_entry(a, &ext_base, head) {
		if (a == ext) {
			list_del(&ext->head);
			err = 0;
			break;
		}
	}
	write_unlock(&ext_mod_lock);
	return err;
}
EXPORT_SYMBOL(p4tc_unregister_extern);

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_byname(struct p4tc_pipeline *pipeline,
				   const char *extname)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	unsigned long tmp, ext_id;

	idr_for_each_entry_ul(&pipeline->user_ext_idr, pipe_ext, tmp, ext_id) {
		if (strncmp(pipe_ext->ext_name, extname,
			    P4TC_EXTERN_NAMSIZ) == 0)
			return pipe_ext;
	}

	return NULL;
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_byany(struct p4tc_pipeline *pipeline,
				  const char *extname, u32 ext_id,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	int err;

	if (ext_id) {
		pipe_ext = p4tc_user_pipeline_ext_find_byid(pipeline, ext_id);
		if (!pipe_ext) {
			NL_SET_ERR_MSG(extack, "Unable to find extern");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (extname) {
			pipe_ext = p4tc_user_pipeline_ext_find_byname(pipeline,
								      extname);
			if (!pipe_ext) {
				NL_SET_ERR_MSG(extack,
					       "Extern name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify extern name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return pipe_ext;

out:
	return ERR_PTR(err);
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_byanyattr(struct p4tc_pipeline *pipeline,
				      struct nlattr *name_attr, u32 ext_id,
				      struct netlink_ext_ack *extack)
{
	char *extname = NULL;

	if (name_attr)
		extname = nla_data(name_attr);

	return p4tc_user_pipeline_ext_find_byany(pipeline, extname, ext_id,
						 extack);
}

static bool
p4tc_user_pipeline_insts_exceeded(struct p4tc_user_pipeline_extern *pipe_ext)
{
	const u32 max_num_insts = pipe_ext->tmpl_ext->max_num_insts;

	return atomic_read(&pipe_ext->curr_insts_num) == max_num_insts;
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_or_create(struct p4tc_pipeline *pipeline,
				      struct p4tc_tmpl_extern *tmpl_ext,
				      struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	int err;

	pipe_ext = p4tc_user_pipeline_ext_get(pipeline, tmpl_ext->ext_id);
	if (pipe_ext != ERR_PTR(-ENOENT)) {
		if (p4tc_user_pipeline_insts_exceeded(pipe_ext)) {
			NL_SET_ERR_MSG(extack,
				       "Maximum number of instances exceeded");
			p4tc_user_pipeline_ext_put_ref(pipe_ext);
			return ERR_PTR(-ENOSPC);
		}

		return pipe_ext;
	}

	pipe_ext = kzalloc(sizeof(*pipe_ext), GFP_KERNEL);
	if (!pipe_ext)
		return ERR_PTR(-ENOMEM);

	pipe_ext->ext_id = tmpl_ext->ext_id;
	err = idr_alloc_u32(&pipeline->user_ext_idr, pipe_ext,
			    &pipe_ext->ext_id, pipe_ext->ext_id, GFP_KERNEL);
	if (err < 0)
		goto free_pipe_ext;

	strscpy(pipe_ext->ext_name, tmpl_ext->common.name, P4TC_EXTERN_NAMSIZ);
	idr_init(&pipe_ext->e_inst_idr);
	refcount_set(&pipe_ext->ext_ref, 2);
	atomic_set(&pipe_ext->curr_insts_num, 0);
	refcount_inc(&tmpl_ext->tmpl_ref);
	pipe_ext->tmpl_ext = tmpl_ext;
	pipe_ext->free = p4tc_user_pipeline_ext_free;

	return pipe_ext;

free_pipe_ext:
	kfree(pipe_ext);
	return ERR_PTR(err);
}

struct p4tc_user_pipeline_extern *
p4tc_pipe_ext_find_bynames(struct net *net, struct p4tc_pipeline *pipeline,
			   const char *extname, struct netlink_ext_ack *extack)
{
	return p4tc_user_pipeline_ext_find_byany(pipeline, extname, 0,
						 extack);
}

static struct p4tc_user_pipeline_extern *
p4tc_pipe_ext_get_byname(struct net *net, struct p4tc_pipeline *pipeline,
			 const char *extname, struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext;

	pipe_ext = p4tc_user_pipeline_ext_find_byany(pipeline, extname, 0,
						     extack);
	if (!IS_ERR(pipe_ext))
		refcount_inc(&pipe_ext->ext_ref);

	return pipe_ext;
}

struct p4tc_extern_inst *
p4tc_ext_inst_find_bynames(struct net *net, struct p4tc_pipeline *pipeline,
			   const char *extname, const char *instname,
			   struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_extern_inst *inst;

	pipe_ext = p4tc_pipe_ext_find_bynames(net, pipeline, extname, extack);
	if (IS_ERR(pipe_ext))
		return (void *)pipe_ext;

	inst = p4tc_ext_inst_find_byany(pipe_ext, instname, 0, extack);
	if (IS_ERR(inst))
		return inst;

	return inst;
}

static void
__p4tc_ext_inst_table_unbind(struct p4tc_user_pipeline_extern *pipe_ext,
			     struct p4tc_extern_inst *inst)
{
	p4tc_user_pipeline_ext_put_ref(pipe_ext);
	p4tc_ext_inst_put_ref(inst);
}

void
p4tc_ext_inst_table_unbind(struct p4tc_table *table,
			   struct p4tc_user_pipeline_extern *pipe_ext,
			   struct p4tc_extern_inst *inst)
{
	table->tbl_counter = NULL;
	__p4tc_ext_inst_table_unbind(pipe_ext, inst);
}

struct p4tc_extern_inst *
p4tc_ext_find_byids(struct p4tc_pipeline *pipeline,
		    const u32 ext_id, const u32 inst_id)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_extern_inst *inst;
	int err;

	pipe_ext = p4tc_user_pipeline_ext_find_byid(pipeline, ext_id);
	if (!pipe_ext) {
		err = -ENOENT;
		goto out;
	}

	inst = p4tc_ext_inst_find_byid(pipe_ext, inst_id);
	if (!inst) {
		err = -EBUSY;
		goto out;
	}

	return inst;

out:
	return ERR_PTR(err);
}

struct p4tc_extern_inst *
p4tc_ext_inst_alloc(const struct p4tc_extern_ops *ops, const u32 max_num_elems,
		    bool tbl_bindable, char *ext_name)
{
	struct p4tc_extern_inst *inst;
	const u32 inst_size = (ops && ops->size) ? ops->size : sizeof(*inst);

	inst = kzalloc(inst_size, GFP_KERNEL);
	if (!inst)
		return ERR_PTR(-ENOMEM);

	inst->ops = ops;
	inst->max_num_elems = max_num_elems;
	refcount_set(&inst->inst_ref, 1);
	inst->ext_name = ext_name;
	inst->tbl_bindable = tbl_bindable;

	inst->common.ops = (typeof(inst->common.ops))&p4tc_ext_inst_ops;

	return inst;
}
EXPORT_SYMBOL(p4tc_ext_inst_alloc);

#define SEPARATOR "/"

struct p4tc_extern_inst *
p4tc_ext_inst_table_bind(struct p4tc_pipeline *pipeline,
			 struct p4tc_user_pipeline_extern **pipe_ext,
			 const char *ext_inst_path,
			 struct netlink_ext_ack *extack)
{
	char *instname_clone, *extname, *instname;
	struct p4tc_extern_inst *inst;
	int err;

	instname = kstrdup(ext_inst_path, GFP_KERNEL);
	if (!instname)
		return ERR_PTR(-ENOMEM);
	instname_clone = instname;

	extname = strsep(&instname, SEPARATOR);

	*pipe_ext = p4tc_pipe_ext_get_byname(pipeline->net, pipeline, extname,
					     extack);
	if (IS_ERR(*pipe_ext)) {
		err = PTR_ERR(*pipe_ext);
		goto free_inst_path;
	}

	inst = p4tc_ext_inst_get(*pipe_ext, instname, 0, extack);
	if (IS_ERR(inst)) {
		p4tc_user_pipeline_ext_put_ref(*pipe_ext);
		err = PTR_ERR(inst);
		goto free_inst_path;
	}

	if (!inst->tbl_bindable) {
		__p4tc_ext_inst_table_unbind(*pipe_ext, inst);
		NL_SET_ERR_MSG_FMT(extack,
				   "Extern instance %s can't be bound to a table",
				   inst->common.name);
		err = -EPERM;
		goto free_inst_path;
	}

	kfree(instname_clone);

	return inst;

free_inst_path:
	kfree(instname_clone);
	return ERR_PTR(err);
}

static struct p4tc_extern_inst *
p4tc_ext_inst_update(struct net *net, struct nlmsghdr *n,
		     struct nlattr *nla, struct p4tc_pipeline *pipeline,
		     u32 *ids, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_params *new_params, *new_constr_params;
	struct p4tc_extern_params *params, *constr_params;
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1];
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_extern_inst *new_inst = NULL;
	struct p4tc_pipeline *root_pipeline;
	struct p4tc_extern_inst *old_inst;
	bool has_scalar_params = false;
	struct p4tc_tmpl_extern *ext;
	u32 ext_id = 0, inst_id = 0;
	bool tbl_bindable = false;
	bool needs_value_param;
	char *inst_name = NULL;
	u32 max_num_elems;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TMPL_EXT_INST_MAX, nla,
			       tc_extern_inst_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	ext_id = ids[P4TC_TMPL_EXT_IDX];

	root_pipeline = p4tc_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	ext = p4tc_tmpl_ext_find_byanyattr(root_pipeline,
					   tb[P4TC_TMPL_EXT_INST_EXT_NAME],
					   ext_id, extack);
	if (IS_ERR(ext))
		return (struct p4tc_extern_inst *)ext;

	inst_id = ids[P4TC_TMPL_EXT_INST_IDX];

	if (tb[P4TC_TMPL_EXT_INST_NAME])
		inst_name = nla_data(tb[P4TC_TMPL_EXT_INST_NAME]);

	pipe_ext = p4tc_user_pipeline_ext_find_byid(pipeline, ext->ext_id);
	if (!pipe_ext) {
		NL_SET_ERR_MSG(extack, "Unable to find pipeline extern by id");
		return ERR_PTR(-ENOENT);
	}

	old_inst = p4tc_ext_inst_find_byanyattr(pipe_ext,
						tb[P4TC_TMPL_EXT_INST_NAME],
						inst_id, extack);
	if (IS_ERR(old_inst)) {
		NL_SET_ERR_MSG(extack, "Unable to find extern instance by id");
		return ERR_PTR(-ENOENT);
	}

	if (tb[P4TC_TMPL_EXT_INST_NUM_ELEMS])
		max_num_elems = nla_get_u32(tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]);
	else
		max_num_elems = old_inst->max_num_elems;

	if (tb[P4TC_TMPL_EXT_INST_TABLE_BINDABLE])
		tbl_bindable = true;
	else
		tbl_bindable = old_inst->tbl_bindable;

	needs_value_param = !ext->ops;
	new_params = p4tc_extern_update_params_value(net,
						     tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS],
						     &has_scalar_params,
						     tbl_bindable,
						     needs_value_param, extack);
	if (IS_ERR(new_params))
		return (struct p4tc_extern_inst *)new_params;

	params = new_params ?: old_inst->params;

	if (p4tc_ext_inst_has_construct(old_inst)) {
		struct nlattr *nla_constr_params =
			tb[P4TC_TMPL_EXT_INST_CONSTR_PARAMS];

		new_constr_params = p4tc_extern_update_params_value(net,
								    nla_constr_params,
								    &has_scalar_params,
								    tbl_bindable,
								    false,
								    extack);
		if (IS_ERR(new_constr_params)) {
			if (new_params)
				p4tc_ext_tmpl_params_free(new_params);

			return (struct p4tc_extern_inst *)new_constr_params;
		}
		constr_params = new_constr_params ?: old_inst->constr_params;

		ret = old_inst->ops->construct(&new_inst, old_inst->ops, params,
					       constr_params, max_num_elems,
					       tbl_bindable, extack);
		if (new_params)
			p4tc_ext_tmpl_params_free(new_params);
		if (new_constr_params)
			p4tc_ext_tmpl_params_free(new_constr_params);
		if (ret < 0)
			return ERR_PTR(ret);
	} else {
		if (tb[P4TC_TMPL_EXT_INST_CONSTR_PARAMS]) {
			NL_SET_ERR_MSG(extack,
				       "Need construct mod op to pass constructor params");
			ret = -EINVAL;
			goto free_control_params;
		}

		new_inst = p4tc_ext_inst_alloc(ext->ops, max_num_elems,
					       tbl_bindable,
					       pipe_ext->ext_name);
		if (IS_ERR(new_inst)) {
			ret = PTR_ERR(new_inst);
			goto free_control_params;
		}
		new_inst->params = params;
	}

	new_inst->ext_inst_id = old_inst->ext_inst_id;
	new_inst->is_scalar = has_scalar_params;
	new_inst->ext_id = ext->ext_id;
	new_inst->pipe_ext = pipe_ext;

	strscpy(new_inst->common.name, inst_name, P4TC_EXTERN_INST_NAMSIZ);

	idr_replace(&pipe_ext->e_inst_idr, new_inst, old_inst->ext_inst_id);

	___p4tc_ext_inst_put(old_inst, !!new_params);

	return new_inst;

free_control_params:
	if (new_params)
		p4tc_ext_tmpl_params_free(new_params);

	return ERR_PTR(ret);
}

static struct p4tc_extern_inst *
p4tc_ext_inst_create(struct net *net, struct nlmsghdr *n,
		     struct nlattr *nla, struct p4tc_pipeline *pipeline,
		     u32 *ids, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_params *constr_params = NULL, *params;
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1];
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_pipeline *root_pipeline;
	bool has_scalar_params = false;
	struct p4tc_extern_inst *inst;
	struct p4tc_tmpl_extern *ext;
	u32 ext_id = 0, inst_id = 0;
	bool tbl_bindable = false;
	char *inst_name = NULL;
	bool needs_value_param;
	u32 max_num_elems;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TMPL_EXT_INST_MAX, nla,
			       tc_extern_inst_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	ext_id = ids[P4TC_TMPL_EXT_IDX];

	root_pipeline = p4tc_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	ext = p4tc_tmpl_ext_find_byanyattr(root_pipeline,
					   tb[P4TC_TMPL_EXT_INST_EXT_NAME],
					   ext_id, extack);
	if (IS_ERR(ext))
		return (struct p4tc_extern_inst *)ext;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_TMPL_EXT_INST_NAME)) {
		NL_SET_ERR_MSG(extack,
			       "Must specify extern instance name");
		return ERR_PTR(-EINVAL);
	}
	inst_name = nla_data(tb[P4TC_TMPL_EXT_INST_NAME]);

	inst_id = ids[P4TC_TMPL_EXT_INST_IDX];
	if (!inst_id) {
		NL_SET_ERR_MSG(extack, "Must specify extern instance id");
		return ERR_PTR(-EINVAL);
	}

	pipe_ext = p4tc_user_pipeline_ext_find_or_create(pipeline, ext, extack);
	if (IS_ERR(pipe_ext))
		return (struct p4tc_extern_inst *)pipe_ext;

	if (p4tc_ext_inst_find_byid(pipe_ext, inst_id) ||
	    p4tc_ext_inst_find_byname(pipe_ext, inst_name)) {
		NL_SET_ERR_MSG(extack,
			       "Extern instance with same name or ID already exists");
		ret = -EEXIST;
		goto put_pipe_ext;
	}

	if (tb[P4TC_TMPL_EXT_INST_NUM_ELEMS])
		max_num_elems = nla_get_u32(tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]);
	else
		max_num_elems = P4TC_DEFAULT_NUM_EXT_INST_ELEMS;

	if (tb[P4TC_TMPL_EXT_INST_TABLE_BINDABLE])
		tbl_bindable = true;

	if (tbl_bindable) {
		if (!ext->ops) {
			NL_SET_ERR_MSG(extack,
				       "Table bindable instance must have extern module");
			return ERR_PTR(-EINVAL);
		}
	}
	needs_value_param = !ext->ops;

	params = p4tc_extern_create_params_value(net,
						 tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS],
						 &has_scalar_params,
						 tbl_bindable,
						 needs_value_param, extack);
	if (IS_ERR(params))
		return (struct p4tc_extern_inst *)params;

	if (p4tc_ext_has_construct(ext->ops)) {
		struct nlattr *nla_constr_params =
			tb[P4TC_TMPL_EXT_INST_CONSTR_PARAMS];

		constr_params = p4tc_extern_create_params_value(net,
								nla_constr_params,
								&has_scalar_params,
								tbl_bindable,
								false,
								extack);
		if (IS_ERR(constr_params)) {
			ret = PTR_ERR(constr_params);
			goto free_control_params;
		}

		ret = ext->ops->construct(&inst, ext->ops, params,
					  constr_params, max_num_elems,
					  tbl_bindable, extack);
		p4tc_ext_tmpl_params_free(params);
		p4tc_ext_tmpl_params_free(constr_params);
		if (ret < 0)
			goto put_pipe_ext;
	} else {
		if (tb[P4TC_TMPL_EXT_INST_CONSTR_PARAMS]) {
			NL_SET_ERR_MSG(extack,
				       "Need construct mod op to pass constructor params");
			ret = -EINVAL;
			goto free_control_params;
		}

		inst = p4tc_ext_inst_alloc(ext->ops, max_num_elems,
					   tbl_bindable, pipe_ext->ext_name);
		if (IS_ERR(inst)) {
			ret = -ENOMEM;
			goto free_control_params;
		}

		inst->params = params;
	}

	inst->ext_id = ext->ext_id;
	inst->ext_inst_id = inst_id;
	inst->pipe_ext = pipe_ext;
	inst->ext_id = ext->ext_id;
	inst->is_scalar = has_scalar_params;

	strscpy(inst->common.name, inst_name, P4TC_EXTERN_INST_NAMSIZ);

	ret = idr_alloc_u32(&pipe_ext->e_inst_idr, inst, &inst_id,
			    inst_id, GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to allocate ID for extern instance");
		goto free_extern;
	}

	atomic_inc(&pipe_ext->curr_insts_num);

	return inst;

free_extern:
	if (p4tc_ext_inst_has_construct(inst))
		inst->ops->deconstruct(inst);
	else
		kfree(inst);

free_control_params:
	if (!p4tc_ext_has_construct(ext->ops) && params)
		p4tc_ext_tmpl_params_free(params);

put_pipe_ext:
	p4tc_user_pipeline_ext_put_ref(pipe_ext);

	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_ext_inst_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		 struct p4tc_path_nlattrs *nl_path_attrs,
		 struct netlink_ext_ack *extack)
{
	u32 *ids = nl_path_attrs->ids;
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;

	pipeline = p4tc_pipeline_find_byany_unsealed(net, nl_path_attrs->pname,
						     pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		inst = p4tc_ext_inst_create(net, n, nla, pipeline, ids,
					    extack);
		break;
	case RTM_UPDATEP4TEMPLATE:
		inst = p4tc_ext_inst_update(net, n, nla, pipeline, ids,
					    extack);
		break;
	default:
		/* Should never happen */
		NL_SET_ERR_MSG(extack,
			       "Only create and update are supported for extern inst");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (IS_ERR(inst))
		goto out;

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TMPL_EXT_IDX])
		ids[P4TC_TMPL_EXT_IDX] = inst->ext_id;

	if (!ids[P4TC_TMPL_EXT_INST_IDX])
		ids[P4TC_TMPL_EXT_INST_IDX] = inst->ext_inst_id;

out:
	return (struct p4tc_template_common *)inst;
}

static bool p4tc_extern_name_ok(const char *name)
{
	return !strchr(name, '%');
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_create(struct nlmsghdr *n, struct nlattr *nla,
		     struct p4tc_pipeline *pipeline, u32 *ids,
		     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_MAX + 1];
	struct p4tc_tmpl_extern *ext;
	char *extern_name = NULL;
	u32 ext_id = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TMPL_EXT_MAX, nla, tc_extern_policy,
			       extack);
	if (ret < 0)
		return ERR_PTR(ret);

	ext_id = ids[P4TC_TMPL_EXT_IDX];
	if (!ext_id) {
		NL_SET_ERR_MSG(extack, "Must specify extern id");
		return ERR_PTR(-EINVAL);
	}

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_TMPL_EXT_NAME)) {
		NL_SET_ERR_MSG(extack,
			       "Must specify extern name");
		return ERR_PTR(-EINVAL);
	}

	extern_name = nla_data(tb[P4TC_TMPL_EXT_NAME]);
	if (!p4tc_extern_name_ok(extern_name)) {
		NL_SET_ERR_MSG(extack, "Illegal extern name");
		return ERR_PTR(-EINVAL);
	}

	if (p4tc_tmpl_ext_find_byid(pipeline, ext_id) ||
	    p4tc_tmpl_ext_find_name(pipeline, extern_name)) {
		NL_SET_ERR_MSG(extack,
			       "Extern with same id or name was already inserted");
		return ERR_PTR(-EEXIST);
	}

	ext = kzalloc(sizeof(*ext), GFP_KERNEL);
	if (!ext) {
		NL_SET_ERR_MSG(extack, "Failed to allocate ext");
		return ERR_PTR(-ENOMEM);
	}

	if (tb[P4TC_TMPL_EXT_NUM_INSTS]) {
		u16 *num_insts = nla_data(tb[P4TC_TMPL_EXT_NUM_INSTS]);

		ext->max_num_insts = *num_insts;
	} else {
		ext->max_num_insts = P4TC_DEFAULT_NUM_EXT_INSTS;
	}

	if (tb[P4TC_TMPL_EXT_HAS_EXEC_METHOD])
		ext->has_exec_method =
			nla_get_u8(tb[P4TC_TMPL_EXT_HAS_EXEC_METHOD]);

	if (tb[P4TC_TMPL_EXT_PERMISSIONS]) {
		u16 ext_permissions;

		ext_permissions = nla_get_u16(tb[P4TC_TMPL_EXT_PERMISSIONS]);
		if (p4tc_ctrl_create_ok(ext_permissions) ||
		    p4tc_ctrl_delete_ok(ext_permissions) ||
		    p4tc_ctrl_exec_ok(ext_permissions)) {
			NL_SET_ERR_MSG(extack, "CDX ctrl perms are disallowed");
			ret = -EPERM;
			goto free_extern;
		}
		if (p4tc_data_create_ok(ext_permissions) ||
		    p4tc_data_delete_ok(ext_permissions)) {
			NL_SET_ERR_MSG(extack,
				       "CD datapath perms are disallowed");
			ret = -EPERM;
			goto free_extern;
		}
		ext->ext_permissions = ext_permissions;
	} else {
		ext->ext_permissions = P4TC_EXTERN_DEFAULT_PERMISSIONS;
	}

	/* Extern module is not mandatory */
	if (ext->has_exec_method) {
		struct p4tc_extern_ops *ops;

		ops = p4tc_extern_ops_load(extern_name);
		if (!ops) {
			ret = -ENOENT;
			goto free_extern;
		}
		ext->ops = ops;

		if (ops->id != ext_id) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Extern template ID (%u) differs from module's ID (%u)",
					   ext_id, ops->id);
			ret = -EINVAL;
			goto free_extern;
		}
	}

	ret = idr_alloc_u32(&pipeline->p_ext_idr, ext, &ext_id, ext_id,
			    GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate ID for extern");
		goto free_extern;
	}

	ext->ext_id = ext_id;

	strscpy(ext->common.name, extern_name, P4TC_EXTERN_NAMSIZ);

	refcount_set(&ext->tmpl_ref, 1);

	ext->common.p_id = pipeline->common.p_id;
	ext->common.ops = (struct p4tc_template_ops *)&p4tc_tmpl_ext_ops;

	return ext;

free_extern:
	p4tc_extern_ops_put(ext->ops);
	kfree(ext);

	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_tmpl_ext_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		 struct p4tc_path_nlattrs *nl_path_attrs,
		 struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline;
	u32 *ids = nl_path_attrs->ids;
	struct p4tc_tmpl_extern *ext;

	if (p4tc_tmpl_msg_is_update(n)) {
		NL_SET_ERR_MSG(extack, "Extern update not supported");
		return ERR_PTR(-EOPNOTSUPP);
	}

	pipeline = p4tc_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	ext = p4tc_tmpl_ext_create(n, nla, pipeline, ids, extack);
	if (IS_ERR(ext))
		goto out;

out:
	return (struct p4tc_template_common *)ext;
}

int
generic_dump_ext_param_value(struct sk_buff *skb, struct p4tc_type *type,
			     const void *value)
{
	const u32 bytesz = BITS_TO_BYTES(type->container_bitsz);
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nla_value;

	nla_value = nla_nest_start(skb, P4TC_EXT_PARAMS_VALUE);
	if (nla_put(skb, P4TC_EXT_PARAMS_VALUE_RAW, bytesz, value))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nla_value);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int ext_inst_param_fill_nlmsg(struct sk_buff *skb,
				     struct p4tc_extern_tmpl_param *param)
{
	unsigned char *b = nlmsg_get_pos(skb);

	if (nla_put_string(skb, P4TC_EXT_PARAMS_NAME, param->name))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_ID, param->id))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_EXT_PARAMS_TYPE, param->type->typeid))
		goto out_nlmsg_trim;

	if (param->default_value &&
	    generic_dump_ext_param_value(skb, param->type, param->default_value))
		goto out_nlmsg_trim;

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int ext_inst_params_fill_nlmsg(struct sk_buff *skb,
				      struct p4tc_extern_params *params)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_extern_tmpl_param *param;
	struct nlattr *nest_count;
	unsigned long id, tmp;
	int i = 1;

	if (!params)
		return skb->len;

	idr_for_each_entry_ul(&params->params_idr, param, tmp, id) {
		nest_count = nla_nest_start(skb, i);
		if (!nest_count)
			goto out_nlmsg_trim;

		if (ext_inst_param_fill_nlmsg(skb, param) < 0)
			goto out_nlmsg_trim;

		nla_nest_end(skb, nest_count);
		i++;
	}

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int
__p4tc_ext_inst_fill_nlmsg(struct sk_buff *skb, struct p4tc_extern_inst *inst,
			   struct netlink_ext_ack *extack)
{
	struct nlattr *nest, *parms, *constr_parms;
	const char *ext_name = inst->ext_name;
	unsigned char *b = nlmsg_get_pos(skb);
	/* Parser instance id + header field id */
	u32 ids[2];

	ids[0] = inst->ext_id;
	ids[1] = inst->ext_inst_id;

	if (nla_put(skb, P4TC_PATH, sizeof(ids), &ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (ext_name[0]) {
		if (nla_put_string(skb, P4TC_TMPL_EXT_INST_EXT_NAME,
				   ext_name))
			goto out_nlmsg_trim;
	}

	if (inst->common.name[0]) {
		if (nla_put_string(skb, P4TC_TMPL_EXT_INST_NAME,
				   inst->common.name))
			goto out_nlmsg_trim;
	}

	if (nla_put_u32(skb, P4TC_TMPL_EXT_INST_NUM_ELEMS,
			inst->max_num_elems))
		goto out_nlmsg_trim;

	parms = nla_nest_start(skb, P4TC_TMPL_EXT_INST_CONTROL_PARAMS);
	if (!parms)
		goto out_nlmsg_trim;

	if (ext_inst_params_fill_nlmsg(skb, inst->params) < 0)
		goto out_nlmsg_trim;

	nla_nest_end(skb, parms);

	constr_parms = nla_nest_start(skb, P4TC_TMPL_EXT_INST_CONSTR_PARAMS);
	if (!constr_parms)
		goto out_nlmsg_trim;

	if (ext_inst_params_fill_nlmsg(skb, inst->constr_params) < 0)
		goto out_nlmsg_trim;

	nla_nest_end(skb, constr_parms);

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int __p4tc_tmpl_ext_fill_nlmsg(struct sk_buff *skb,
				      struct p4tc_tmpl_extern *ext)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nest;
	/* Parser instance id + header field id */
	u32 id;

	id = ext->ext_id;

	if (nla_put(skb, P4TC_PATH, sizeof(id), &id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (ext->common.name[0]) {
		if (nla_put_string(skb, P4TC_TMPL_EXT_NAME, ext->common.name))
			goto out_nlmsg_trim;
	}

	if (nla_put_u16(skb, P4TC_TMPL_EXT_NUM_INSTS, ext->max_num_insts))
		goto out_nlmsg_trim;

	if (nla_put_u16(skb, P4TC_TMPL_EXT_PERMISSIONS, ext->ext_permissions))
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int p4tc_ext_inst_fill_nlmsg(struct net *net, struct sk_buff *skb,
				    struct p4tc_template_common *template,
				    struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst *inst = to_extern_inst(template);

	if (__p4tc_ext_inst_fill_nlmsg(skb, inst, extack) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for extern instance");
		return -EINVAL;
	}

	return 0;
}

static int p4tc_tmpl_ext_fill_nlmsg(struct net *net, struct sk_buff *skb,
				    struct p4tc_template_common *template,
				    struct netlink_ext_ack *extack)
{
	struct p4tc_tmpl_extern *ext = to_extern(template);

	if (__p4tc_tmpl_ext_fill_nlmsg(skb, ext) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for extern");
		return -EINVAL;
	}

	return 0;
}

static int p4tc_tmpl_ext_flush(struct sk_buff *skb,
			       struct p4tc_pipeline *pipeline,
			       struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_tmpl_extern *ext;
	unsigned long tmp, ext_id;
	int ret = 0;
	u32 path[1];
	int i = 0;

	path[0] = 0;

	if (idr_is_empty(&pipeline->p_ext_idr)) {
		NL_SET_ERR_MSG(extack, "There are no externs to flush");
		goto out_nlmsg_trim;
	}

	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	idr_for_each_entry_ul(&pipeline->p_ext_idr, ext, tmp, ext_id) {
		if (_p4tc_tmpl_ext_put(pipeline, ext, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	if (nla_put_u32(skb, P4TC_COUNT, i))
		goto out_nlmsg_trim;

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any externs");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG_FMT(extack,
					   "Flush only %u externs", i);
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return 0;
}

static int p4tc_ext_inst_flush(struct sk_buff *skb,
			       struct p4tc_pipeline *pipeline,
			       struct p4tc_user_pipeline_extern *pipe_ext,
			       struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_extern_inst *inst;
	unsigned long tmp, inst_id;
	int ret = 0;
	u32 path[2];
	int i = 0;

	if (idr_is_empty(&pipe_ext->e_inst_idr)) {
		NL_SET_ERR_MSG(extack, "There are no externs to flush");
		goto out_nlmsg_trim;
	}

	path[0] = pipe_ext->ext_id;
	path[1] = 0;

	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	idr_for_each_entry_ul(&pipe_ext->e_inst_idr, inst, tmp, inst_id) {
		if (__p4tc_ext_inst_put(pipeline, inst, false, false,
					extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	/* We don't release pipe_ext in the loop to avoid use-after-free whilst
	 * iterating through e_inst_idr. We free it here only if flush
	 * succeeded, that is, all instances were deleted and thus ext_ref == 1
	 */
	if (refcount_read(&pipe_ext->ext_ref) == 1)
		p4tc_user_pipeline_ext_free(pipe_ext, &pipeline->user_ext_idr);

	if (nla_put_u32(skb, P4TC_COUNT, i))
		goto out_nlmsg_trim;

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any externs instance");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG_FMT(extack,
					   "Flushed only %u extern instances",
					   i);
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return 0;
}

static int p4tc_ext_inst_gd(struct net *net, struct sk_buff *skb,
			    struct nlmsghdr *n, struct nlattr *nla,
			    struct p4tc_path_nlattrs *nl_path_attrs,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1] = {NULL};
	struct p4tc_user_pipeline_extern *pipe_ext;
	u32 *ids = nl_path_attrs->ids;
	u32 inst_id = ids[P4TC_TMPL_EXT_INST_IDX];
	unsigned char *b = nlmsg_get_pos(skb);
	u32 ext_id = ids[P4TC_TMPL_EXT_IDX];
	u32 pipe_id = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;
	int ret;

	if (n->nlmsg_type == RTM_GETP4TEMPLATE)
		pipeline = p4tc_pipeline_find_byany(net, nl_path_attrs->pname,
						    pipe_id, extack);
	else
		pipeline = p4tc_pipeline_find_byany_unsealed(net,
							     nl_path_attrs->pname,
							     pipe_id, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_TMPL_EXT_MAX, nla,
				       tc_extern_inst_policy, extack);
		if (ret < 0)
			return ret;
	}

	pipe_ext = p4tc_user_pipeline_ext_find_byanyattr(pipeline,
							 tb[P4TC_TMPL_EXT_INST_EXT_NAME],
							 ext_id, extack);
	if (IS_ERR(pipe_ext))
		return PTR_ERR(pipe_ext);

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TMPL_EXT_IDX])
		ids[P4TC_TMPL_EXT_IDX] = pipe_ext->ext_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && n->nlmsg_flags & NLM_F_ROOT)
		return p4tc_ext_inst_flush(skb, pipeline, pipe_ext, extack);

	inst = p4tc_ext_inst_find_byanyattr(pipe_ext,
					    tb[P4TC_TMPL_EXT_INST_NAME],
					    inst_id, extack);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

	ret = __p4tc_ext_inst_fill_nlmsg(skb, inst, extack);
	if (ret < 0)
		return -ENOMEM;

	if (!ids[P4TC_TMPL_EXT_INST_IDX])
		ids[P4TC_TMPL_EXT_INST_IDX] = inst->ext_inst_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = __p4tc_ext_inst_put(pipeline, inst, false, true, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4tc_tmpl_ext_gd(struct net *net, struct sk_buff *skb,
			    struct nlmsghdr *n, struct nlattr *nla,
			    struct p4tc_path_nlattrs *nl_path_attrs,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_MAX + 1] = {NULL};
	unsigned char *b = nlmsg_get_pos(skb);
	u32 *ids = nl_path_attrs->ids;
	u32 ext_id = ids[P4TC_TMPL_EXT_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_tmpl_extern *ext;
	int ret;

	pipeline = p4tc_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_TMPL_EXT_MAX, nla,
				       tc_extern_policy, extack);
		if (ret < 0)
			return ret;
	}

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && n->nlmsg_flags & NLM_F_ROOT)
		return p4tc_tmpl_ext_flush(skb, pipeline, extack);

	ext = p4tc_tmpl_ext_find_byanyattr(pipeline, tb[P4TC_TMPL_EXT_NAME],
					   ext_id, extack);
	if (IS_ERR(ext))
		return PTR_ERR(ext);

	ret = __p4tc_tmpl_ext_fill_nlmsg(skb, ext);
	if (ret < 0)
		return -ENOMEM;

	if (!ids[P4TC_TMPL_EXT_IDX])
		ids[P4TC_TMPL_EXT_IDX] = ext->ext_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _p4tc_tmpl_ext_put(pipeline, ext, false, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4tc_tmpl_ext_dump_1(struct sk_buff *skb,
				struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_tmpl_extern *ext = to_extern(common);
	unsigned char *b = nlmsg_get_pos(skb);
	u32 path[2];

	if (!param)
		goto out_nlmsg_trim;

	if (ext->common.name[0] &&
	    nla_put_string(skb, P4TC_TMPL_EXT_NAME, ext->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	path[0] = ext->ext_id;
	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int p4tc_tmpl_ext_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			      struct nlattr *nla, char **p_name, u32 *ids,
			      struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;

	pipeline = p4tc_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return p4tc_tmpl_generic_dump(skb, ctx, &pipeline->p_ext_idr,
				      P4TC_TMPL_EXT_IDX, extack);
}

static int p4tc_ext_inst_dump_1(struct sk_buff *skb,
				struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_extern_inst *inst = to_extern_inst(common);
	unsigned char *b = nlmsg_get_pos(skb);
	u32 path[2];

	if (!param)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_TMPL_EXT_INST_EXT_NAME, inst->ext_name))
		goto out_nlmsg_trim;

	if (inst->common.name[0] &&
	    nla_put_string(skb, P4TC_TMPL_EXT_INST_NAME, inst->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	path[0] = inst->ext_id;
	path[1] = inst->ext_inst_id;
	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int p4tc_ext_inst_dump(struct sk_buff *skb,
			      struct p4tc_dump_ctx *ctx,
			      struct nlattr *nla, char **p_name,
			      u32 *ids, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1] = {NULL};
	struct p4tc_user_pipeline_extern *pipe_ext;
	u32 ext_id = ids[P4TC_TMPL_EXT_IDX];
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;
	u32 pipeid = ids[P4TC_PID_IDX];
	int ret;

	pipeline = p4tc_pipeline_find_byany(net, *p_name,
					    pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_TMPL_EXT_INST_MAX, nla,
				       tc_extern_inst_policy, extack);
		if (ret < 0)
			return ret;
	}

	pipe_ext = p4tc_user_pipeline_ext_find_byanyattr(pipeline,
							 tb[P4TC_TMPL_EXT_INST_EXT_NAME],
							 ext_id, extack);
	if (IS_ERR(pipe_ext))
		return PTR_ERR(pipe_ext);

	return p4tc_tmpl_generic_dump(skb, ctx, &pipe_ext->e_inst_idr,
				      P4TC_TMPL_EXT_INST_IDX, extack);
}

static const struct p4tc_template_ops p4tc_ext_inst_ops = {
	.cu = p4tc_ext_inst_cu,
	.fill_nlmsg = p4tc_ext_inst_fill_nlmsg,
	.gd = p4tc_ext_inst_gd,
	.put = p4tc_ext_inst_put,
	.dump = p4tc_ext_inst_dump,
	.dump_1 = p4tc_ext_inst_dump_1,
	.obj_id = P4TC_OBJ_EXT_INST,
};

static const struct p4tc_template_ops p4tc_tmpl_ext_ops = {
	.cu = p4tc_tmpl_ext_cu,
	.fill_nlmsg = p4tc_tmpl_ext_fill_nlmsg,
	.gd = p4tc_tmpl_ext_gd,
	.put = p4tc_tmpl_ext_put,
	.dump = p4tc_tmpl_ext_dump,
	.dump_1 = p4tc_tmpl_ext_dump_1,
	.obj_id = P4TC_OBJ_EXT,
};

static int __init p4tc_ext_init(void)
{
	p4tc_tmpl_register_ops(&p4tc_tmpl_ext_ops);
	p4tc_tmpl_register_ops(&p4tc_ext_inst_ops);

	return 0;
}

subsys_initcall(p4tc_ext_init);
