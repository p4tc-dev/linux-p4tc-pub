// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_tmpl_extern.c	P4 TC EXTERN TEMPLATE
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
#include <linux/err.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/p4tc_types.h>
#include <net/sock.h>
#include <net/p4tc_ext_api.h>

static LIST_HEAD(ext_base);
static DEFINE_RWLOCK(ext_mod_lock);

static const struct nla_policy tc_extern_inst_policy[P4TC_TMPL_EXT_INST_MAX + 1] = {
	[P4TC_TMPL_EXT_INST_EXT_NAME] = {
		.type = NLA_STRING,
		.len =  EXTERNNAMSIZ
	},
	[P4TC_TMPL_EXT_INST_NAME] = {
		.type = NLA_STRING,
		.len =  EXTERNINSTNAMSIZ
	},
	[P4TC_TMPL_EXT_INST_NUM_ELEMS] = NLA_POLICY_RANGE(NLA_U32, 1,
							  P4TC_MAX_NUM_EXT_INST_ELEMS),
	[P4TC_TMPL_EXT_INST_METHODS] = { .type = NLA_NESTED },
	[P4TC_TMPL_EXT_INST_CONTROL_PARAMS] = { .type = NLA_NESTED }
};

static const struct nla_policy tc_extern_policy[P4TC_TMPL_EXT_MAX + 1] = {
	[P4TC_TMPL_EXT_NAME] = { .type = NLA_STRING, .len =  EXTERNNAMSIZ },
	[P4TC_TMPL_EXT_NUM_INSTS] = NLA_POLICY_RANGE(NLA_U16, 1,
						     P4TC_MAX_NUM_EXT_INSTS),
};

static const struct nla_policy tc_method_policy[P4TC_TMPL_EXT_INST_METHOD_MAX + 1] = {
	[P4TC_TMPL_EXT_INST_METHOD_NAME] = { .type = NLA_STRING, .len = METHODNAMSIZ },
	[P4TC_TMPL_EXT_INST_METHOD_ID] = { .type = NLA_U32 },
	[P4TC_TMPL_EXT_INST_METHOD_PARAMS] = { .type = NLA_NESTED },
};

static const struct nla_policy p4tc_extern_params_policy[P4TC_EXT_PARAMS_MAX + 1] = {
	[P4TC_EXT_PARAMS_NAME] = { .type = NLA_STRING, .len = EXTPARAMNAMSIZ },
	[P4TC_EXT_PARAMS_ID] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_VALUE] = { .type = NLA_NESTED },
	[P4TC_EXT_PARAMS_TYPE] = { .type = NLA_U32 },
	[P4TC_EXT_PARAMS_BITSZ] = { .type = NLA_U16 },
	[P4TC_EXT_PARAMS_FLAGS] = { .type = NLA_U8 },
};

static void p4tc_extern_put_param(struct p4tc_extern_param *param)
{
	if (param->mask_shift)
		p4t_release(param->mask_shift);
	if (param->value)
		p4tc_ext_param_value_free(param);
	kfree(param);
}

static void p4tc_extern_put_param_idr(struct idr *params_idr,
				      struct p4tc_extern_param *param)
{
	idr_remove(params_idr, param->id);
	p4tc_extern_put_param(param);
}

static void p4tc_extern_put_method(struct p4tc_extern_method *method)
{
	struct p4tc_extern_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&method->params_idr, param, tmp, id) {
		idr_remove(&method->params_idr, id);
		p4tc_extern_put_param(param);
	}
	idr_destroy(&method->params_idr);
	kfree(method);
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

static void
_p4tc_tmpl_ext_inst_common_put(struct p4tc_extern_inst_common *common)
{
	struct p4tc_extern_method *method;
	struct p4tc_extern_param *param;
	unsigned long tmp, id;

	p4tc_ext_purge(&common->control_elems_idr);

	idr_for_each_entry_ul(&common->methods_idr, method, tmp, id) {
		idr_remove(&common->methods_idr, id);
		p4tc_extern_put_method(method);
	}

	idr_for_each_entry_ul(&common->control_params_idr, param, tmp, id) {
		idr_remove(&common->control_params_idr, id);
		p4tc_extern_put_param(param);
	}

	kfree(common);
}

static int _p4tc_tmpl_ext_inst_put(struct p4tc_pipeline *pipeline,
				   struct p4tc_user_pipeline_extern *pipe_ext,
				   struct p4tc_extern_inst *inst,
				   bool unconditional_purge, bool release,
				   struct netlink_ext_ack *extack)
{
	if (!unconditional_purge && !refcount_dec_if_one(&inst->inst_ref)) {
		NL_SET_ERR_MSG(extack,
			       "Can't delete referenced extern instance template");
		return -EBUSY;
	}

	_p4tc_tmpl_ext_inst_common_put(inst->inst_common);

	idr_remove(&pipe_ext->e_inst_idr, inst->ext_inst_id);
	refcount_dec(&pipe_ext->curr_insts_num);

	p4tc_user_pipeline_ext_put(pipeline, pipe_ext, release,
				   &pipeline->user_ext_idr);

	kfree(inst);

	return 0;
}

static int _p4tc_tmpl_ext_put(struct p4tc_pipeline *pipeline,
			      struct p4tc_tmpl_extern *ext,
			      bool unconditional_purge,
			      struct netlink_ext_ack *extack)
{
	if (!unconditional_purge && !refcount_dec_if_one(&ext->tmpl_ref)) {
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

static int p4tc_tmpl_ext_inst_put(struct p4tc_pipeline *pipeline,
				  struct p4tc_template_common *tmpl,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst *inst;

	inst = to_extern_inst(tmpl);

	return _p4tc_tmpl_ext_inst_put(pipeline, inst->pipe_ext, inst,
				       true, false, extack);
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_name(struct p4tc_pipeline *pipeline, const char *extern_name)
{
	struct p4tc_tmpl_extern *ext;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_ext_idr, ext, tmp, id)
		if (ext->common.name[0] &&
		    strncmp(ext->common.name, extern_name,
			    EXTERNNAMSIZ) == 0)
			return ext;

	return NULL;
}

static struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_byid(struct p4tc_pipeline *pipeline, const u32 ext_id)
{
	return idr_find(&pipeline->p_ext_idr, ext_id);
}

struct p4tc_tmpl_extern *
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
p4tc_ext_inst_find_byid(struct p4tc_user_pipeline_extern *pipe_ext,
			const u32 inst_id)
{
	struct p4tc_extern_inst *ext_inst;

	ext_inst = idr_find(&pipe_ext->e_inst_idr, inst_id);

	return ext_inst;
}

static struct p4tc_extern_inst *
p4tc_ext_inst_find_byname(struct p4tc_user_pipeline_extern *pipe_ext,
			  const char *instname)
{
	struct p4tc_extern_inst *ext_inst;
	unsigned long tmp, inst_id;

	idr_for_each_entry_ul(&pipe_ext->e_inst_idr, ext_inst, tmp, inst_id) {
		if (strncmp(ext_inst->common.name, instname, EXTERNINSTNAMSIZ) == 0)
			return ext_inst;
	}

	return NULL;
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

static void p4tc_extern_put_many_params(struct idr *params_idr,
					struct p4tc_extern_param *params[],
					bool remove_from_idr,
					int params_count)
{
	int i;

	for (i = 0; i < params_count; i++) {
		if (remove_from_idr)
			idr_remove(params_idr, params[i]->id);
		p4tc_extern_put_param(params[i]);
	}
}

static void p4tc_extern_put_many_methods(struct idr *methods_idr,
					 struct p4tc_extern_method *methods[],
					 bool remove_from_idr,
					 int methods_count)
{
	int i;

	for (i = 0; i < methods_count; i++) {
		if (remove_from_idr)
			idr_remove(methods_idr, methods[i]->method_id);
		p4tc_extern_put_method(methods[i]);
	}
}

static struct p4tc_extern_param *
p4tc_extern_param_find_byname(struct idr *params_idr, const char *param_name)
{
	struct p4tc_extern_param *param;
	unsigned long tmp, id;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		if (param == ERR_PTR(-EBUSY))
			continue;
		if (strncmp(param->name, param_name, EXTPARAMNAMSIZ) == 0)
			return param;
	}

	return NULL;
}

struct p4tc_extern_param *
p4tc_extern_param_find_byid(struct idr *params_idr, const u32 param_id)
{
	return idr_find(params_idr, param_id);
}
EXPORT_SYMBOL(p4tc_extern_param_find_byid);

static struct p4tc_extern_param *
p4tc_extern_param_find_byany(struct idr *params_idr, const char *param_name,
			     const u32 param_id, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param;
	int err;

	if (param_id) {
		param = p4tc_extern_param_find_byid(params_idr, param_id);
		if (!param) {
			NL_SET_ERR_MSG(extack, "Unable to find param by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (param_name) {
			param = p4tc_extern_param_find_byname(params_idr,
							      param_name);
			if (!param) {
				NL_SET_ERR_MSG(extack, "Param name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack, "Must specify param name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return param;

out:
	return ERR_PTR(err);
}

struct p4tc_extern_param *
p4tc_extern_param_find_byanyattr(struct idr *params_idr,
				 struct nlattr *name_attr,
				 const u32 param_id,
				 struct netlink_ext_ack *extack)
{
	char *param_name = NULL;

	if (name_attr)
		param_name = nla_data(name_attr);

	return p4tc_extern_param_find_byany(params_idr, param_name, param_id,
					    extack);
}

static void p4tc_extern_params_replace_many(struct idr *params_idr,
					    struct p4tc_extern_param *params[],
					    int params_count)
{
	int i;

	for (i = 0; i < params_count; i++) {
		struct p4tc_extern_param *param;

		param = idr_replace(params_idr, params[i], params[i]->id);
		if (param != ERR_PTR(-EBUSY))
			p4tc_extern_put_param(param);
	}
}

static struct p4tc_extern_param *
p4tc_extern_create_param(struct idr *params_idr, struct nlattr **tb,
			 u32 param_id, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param;
	u8 *flags = NULL;
	char *name;
	int ret;

	if (tb[P4TC_EXT_PARAMS_NAME]) {
		name = nla_data(tb[P4TC_EXT_PARAMS_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param name");
		ret = -EINVAL;
		goto out;
	}

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	if ((param_id && p4tc_extern_param_find_byid(params_idr, param_id)) ||
	    p4tc_extern_param_find_byname(params_idr, name)) {
		NL_SET_ERR_MSG_FMT(extack, "Param already exists %s", name);
		ret = -EEXIST;
		goto free;
	}

	if ((tb[P4TC_EXT_PARAMS_TYPE] && !tb[P4TC_EXT_PARAMS_BITSZ]) ||
	    (!tb[P4TC_EXT_PARAMS_TYPE] && tb[P4TC_EXT_PARAMS_BITSZ])) {
		NL_SET_ERR_MSG(extack, "Must specify type with bit size");
		ret = -EINVAL;
		goto free;
	}

	if (tb[P4TC_EXT_PARAMS_TYPE]) {
		struct p4tc_type_mask_shift *mask_shift = NULL;
		struct p4tc_type *type;
		u32 typeid;
		u16 bitsz;

		typeid = nla_get_u32(tb[P4TC_EXT_PARAMS_TYPE]);
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
			mask_shift = type->ops->create_bitops(bitsz, 0,
							      bitsz - 1,
							      extack);
			if (IS_ERR(mask_shift)) {
				ret = PTR_ERR(mask_shift);
				goto free;
			}
		}
		param->mask_shift = mask_shift;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}

	if (tb[P4TC_EXT_PARAMS_FLAGS]) {
		flags = nla_data(tb[P4TC_EXT_PARAMS_FLAGS]);
		param->flags = *flags;
	}

	if (flags && *flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		switch (param->type->typeid) {
		case P4T_U8:
		case P4T_U16:
		case P4T_U32:
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
		ret = idr_alloc_u32(params_idr, ERR_PTR(-EBUSY), &param_id,
				    param_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free_mask_shift;
		}
		param->id = param_id;
	} else {
		param->id = 1;

		ret = idr_alloc_u32(params_idr, ERR_PTR(-EBUSY), &param->id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate param id");
			goto free_mask_shift;
		}
	}

	strscpy(param->name, name, EXTPARAMNAMSIZ);

	return param;

free_mask_shift:
	p4t_release(param->mask_shift);

free:
	kfree(param);

out:
	return ERR_PTR(ret);
}

static struct p4tc_extern_param *
p4tc_extern_create_param_value(struct net *net, struct idr *params_idr,
			       struct nlattr **tb, u32 param_id,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param;
	int err;

	param = p4tc_extern_create_param(params_idr, tb, param_id, extack);
	if (IS_ERR(param))
		return param;

	err = p4tc_ext_param_value_init(net, param, tb, param->type->typeid,
					false, extack);
	if (err < 0) {
		p4tc_extern_put_param_idr(params_idr, param);
		return ERR_PTR(err);
	}

	return param;
}

static struct p4tc_extern_param *
p4tc_extern_update_param(struct idr *params_idr, struct nlattr **tb,
			 const u32 param_id, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param_old, *param;
	int ret;

	param_old = p4tc_extern_param_find_byanyattr(params_idr,
						     tb[P4TC_EXT_PARAMS_NAME],
						     param_id, extack);
	if (IS_ERR(param_old))
		return param_old;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto out;
	}

	strscpy(param->name, param_old->name, EXTPARAMNAMSIZ);
	param->id = param_old->id;

	if (tb[P4TC_EXT_PARAMS_TYPE]) {
		u32 typeid;

		typeid = nla_get_u32(tb[P4TC_EXT_PARAMS_TYPE]);
		param->type = p4type_find_byid(typeid);
		if (!param->type) {
			NL_SET_ERR_MSG(extack, "Param type is invalid");
			ret = -EINVAL;
			goto free;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify param type");
		ret = -EINVAL;
		goto free;
	}

	if (param_old->flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
		switch (param->type->typeid) {
		case P4T_U8:
		case P4T_U16:
		case P4T_U32:
			break;
		default: {
			NL_SET_ERR_MSG(extack,
				       "Key must be an unsigned integer");
			ret = -EINVAL;
			goto free;
		}
		}
	}

	return param;

free:
	kfree(param);
out:
	return ERR_PTR(ret);
}

static struct p4tc_extern_param *
p4tc_extern_update_param_value(struct net *net, struct idr *params_idr,
			       struct nlattr **tb, u32 param_id,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param;
	int err;

	param = p4tc_extern_update_param(params_idr, tb, param_id, extack);
	if (IS_ERR(param))
		return param;

	err = p4tc_ext_param_value_init(net, param, tb, param->type->typeid,
					false, extack);
	if (err < 0) {
		p4tc_extern_put_param(param);
		return ERR_PTR(err);
	}

	return param;
}

static struct p4tc_extern_param *
p4tc_extern_init_param(struct net *net, struct idr *params_idr,
		       struct nlattr *nla, bool update,
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

	if (update) {
		return p4tc_extern_update_param(params_idr, tb, param_id,
						extack);
	} else {
		return p4tc_extern_create_param(params_idr, tb, param_id,
						extack);
	}

out:
	return ERR_PTR(ret);
}

static struct p4tc_extern_param *
p4tc_extern_init_param_value(struct net *net, struct idr *params_idr,
			     struct nlattr *nla, bool update,
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

	if (update)
		return p4tc_extern_update_param_value(net, params_idr, tb,
						      param_id, extack);
	else
		return p4tc_extern_create_param_value(net, params_idr, tb,
						      param_id, extack);

out:
	return ERR_PTR(ret);
}

static int p4tc_extern_init_params(struct net *net, struct idr *params_idr,
				   struct nlattr *nla,
				   struct p4tc_extern_param *params[],
				   bool update,
				   struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return -EINVAL;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_param *param;

		param = p4tc_extern_init_param(net, params_idr, tb[i], update,
					       extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_del;
		}
		params[i - 1] = param;
	}

	return i - 1;

params_del:
	p4tc_extern_put_many_params(params_idr, params, !update, i - 1);
	return ret;
}

static int p4tc_extern_init_params_value(struct net *net,
					 struct p4tc_extern_inst *inst,
					 struct nlattr *nla,
					 struct p4tc_extern_param *params[],
					 bool update,
					 struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &inst->inst_common->control_params_idr;
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	bool has_scalar_param = false;
	bool has_key_param = false;
	int num_params_added = 0;
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return -EINVAL;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_param *param;

		param = p4tc_extern_init_param_value(net, params_idr, tb[i],
						     update, extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_del;
		}

		params[num_params_added] = param;
		num_params_added++;

		if (has_key_param) {
			if (param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY) {
				NL_SET_ERR_MSG(extack,
					       "There can't be 2 key params");
				ret = -EINVAL;
				goto params_del;
			}
		} else {
			has_key_param = param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY;
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
			has_scalar_param = param->flags & P4TC_EXT_PARAMS_FLAG_IS_DATASCALAR;
		}
	}
	inst->is_scalar = has_scalar_param;

	return num_params_added;

params_del:
	p4tc_extern_put_many_params(params_idr, params, !update,
				    num_params_added);
	return ret;
}

static void
p4tc_extern_methods_replace_many(struct idr *methods_idr,
				 struct p4tc_extern_method *methods[],
				 int methods_count)
{
	int i;

	for (i = 0; i < methods_count; i++) {
		struct p4tc_extern_method *method = methods[i];

		method = idr_replace(methods_idr, method, method->method_id);
		if (method != ERR_PTR(-EBUSY))
			p4tc_extern_put_method(method);
	}
}

static struct p4tc_extern_method *
method_find_byid(struct idr *methods_idr, const u32 method_id)
{
	return idr_find(methods_idr, method_id);
}

static struct p4tc_extern_method *
method_find_byname(struct idr *methods_idr, const char *method_name)
{
	struct p4tc_extern_method *method;
	unsigned long tmp, id;

	idr_for_each_entry_ul(methods_idr, method, tmp, id) {
		if (method == ERR_PTR(-EBUSY))
			continue;
		if (strncmp(method->method_name, method_name,
			    METHODNAMSIZ) == 0)
			return method;
	}

	return NULL;
}

static struct p4tc_extern_method *
method_find_byany(struct idr *methods_idr, const char *method_name,
		  const u32 method_id, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_method *method;
	int err;

	if (method_id) {
		method = method_find_byid(methods_idr, method_id);
		if (!method) {
			NL_SET_ERR_MSG(extack, "Unable to find method by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (method_name) {
			method = method_find_byname(methods_idr, method_name);
			if (!method) {
				NL_SET_ERR_MSG(extack,
					       "Method name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify method name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return method;

out:
	return ERR_PTR(err);
}

static struct p4tc_extern_method *
p4tc_extern_create_method(struct net *net, struct idr *methods_idr,
			  struct nlattr **tb, u32 method_id,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *params[P4TC_MSGBATCH_SIZE] = { NULL };
	struct p4tc_extern_method *method;
	int num_params;
	char *name;
	int ret;

	if (tb[P4TC_TMPL_EXT_INST_METHOD_NAME]) {
		name = nla_data(tb[P4TC_TMPL_EXT_INST_METHOD_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify method name");
		ret = -EINVAL;
		goto out;
	}

	method = kzalloc(sizeof(*method), GFP_KERNEL);
	if (!method) {
		ret = -ENOMEM;
		goto out;
	}

	if (method_find_byid(methods_idr, method_id) ||
	    (method_find_byname(methods_idr, name))) {
		NL_SET_ERR_MSG(extack, "Method already exists");
		ret = -EEXIST;
		goto free_method;
	}

	idr_init(&method->params_idr);
	if (method_id) {
		ret = idr_alloc_u32(methods_idr, ERR_PTR(-EBUSY), &method_id,
				    method_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate method id");
			goto free_method;
		}
		method->method_id = method_id;
	} else {
		method->method_id = 1;

		ret = idr_alloc_u32(methods_idr, ERR_PTR(-EBUSY),
				    &method->method_id, UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate method id");
			goto free_method;
		}
	}

	if (tb[P4TC_TMPL_EXT_INST_METHOD_PARAMS]) {
		num_params = p4tc_extern_init_params(net, &method->params_idr,
						     tb[P4TC_TMPL_EXT_INST_METHOD_PARAMS],
						     params, false, extack);
		if (num_params < 0) {
			ret = num_params;
			goto idr_rm;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify method name");
		ret = -EINVAL;
		goto free_method;
	}

	strscpy(method->method_name, name, METHODNAMSIZ);
	p4tc_extern_params_replace_many(&method->params_idr, params,
					num_params);

	return method;

idr_rm:
	idr_remove(methods_idr, method->method_id);

free_method:
	kfree(method);

out:
	return ERR_PTR(ret);
}

static struct p4tc_extern_method *
p4tc_extern_update_method(struct net *net, struct idr *methods_idr,
			  struct nlattr **tb, u32 method_id,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *params[P4TC_MSGBATCH_SIZE] = { NULL };
	struct p4tc_extern_method *method_old, *method;
	char *method_name;
	int num_params;
	int ret;

	if (tb[P4TC_TMPL_EXT_INST_METHOD_NAME]) {
		method_name = nla_data(tb[P4TC_TMPL_EXT_INST_METHOD_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify method name");
		ret = -EINVAL;
		goto out;
	}

	method_old = method_find_byany(methods_idr, method_name, method_id,
				       extack);
	if (IS_ERR(method_old))
		return method_old;

	method = kzalloc(sizeof(*method), GFP_KERNEL);
	if (!method) {
		ret = -ENOMEM;
		goto out;
	}
	strscpy(method->method_name, method_old->method_name, METHODNAMSIZ);
	method->method_id = method_old->method_id;

	idr_init(&method->params_idr);
	if (tb[P4TC_TMPL_EXT_INST_METHOD_PARAMS]) {
		num_params = p4tc_extern_init_params(net, &method->params_idr,
						     tb[P4TC_TMPL_EXT_INST_METHOD_PARAMS],
						     params, false, extack);
		if (num_params < 0) {
			ret = num_params;
			goto free_method;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify method name");
		ret = -EINVAL;
		goto free_method;
	}

	p4tc_extern_params_replace_many(&method->params_idr, params,
					num_params);

	return method;

free_method:
	kfree(method);

out:
	return ERR_PTR(ret);
}

static struct p4tc_extern_method *
p4tc_extern_init_method(struct net *net, struct idr *methods_idr,
			struct nlattr *nla, bool update,
			struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_INST_METHOD_MAX + 1];
	u32 method_id = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TMPL_EXT_INST_METHOD_MAX, nla,
			       tc_method_policy, extack);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (tb[P4TC_TMPL_EXT_INST_METHOD_ID])
		method_id = nla_get_u32(tb[P4TC_TMPL_EXT_INST_METHOD_ID]);

	if (update)
		return p4tc_extern_update_method(net, methods_idr, tb,
						 method_id, extack);

	return p4tc_extern_create_method(net, methods_idr, tb,
					 method_id, extack);

out:
	return ERR_PTR(ret);
}

static int p4tc_extern_init_methods(struct net *net,
				    struct idr *methods_idr,
				    struct p4tc_extern_method **methods,
				    struct nlattr *nla, bool update,
				    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return -EINVAL;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		struct p4tc_extern_method *method;

		method = p4tc_extern_init_method(net, methods_idr, tb[i],
						 update, extack);
		if (IS_ERR(method)) {
			ret = PTR_ERR(method);
			goto methods_del;
		}
		methods[i - 1] = method;
	}

	return i - 1;

methods_del:
	p4tc_extern_put_many_methods(methods_idr, methods, !update, i - 1);
	return ret;
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

static struct p4tc_extern_ops *p4tc_extern_lookup_n(char *kind)
{
	struct p4tc_extern_ops *a = NULL;

	read_lock(&ext_mod_lock);
	list_for_each_entry(a, &ext_base, head) {
		if (strcmp(kind, a->kind) == 0) {
			read_unlock(&ext_mod_lock);
			return a;
		}
	}
	read_unlock(&ext_mod_lock);

	return NULL;
}

/* lookup by name */
struct p4tc_extern_ops *p4tc_extern_ops_get(char *kind)
{
	char prepended_kind[EXTERNNAMSIZ] = {0};
	struct p4tc_extern_ops *a = NULL;
	int num_bytes_written;

	if (!kind)
		return NULL;

	num_bytes_written = snprintf(prepended_kind, EXTERNNAMSIZ, "ext_%s",
				     kind);
	/* Extern name was too long */
	if (num_bytes_written == EXTERNNAMSIZ)
		return NULL;

	a = p4tc_extern_lookup_n(prepended_kind);
	if (a) {
		if (try_module_get(a->owner))
			return a;
	}

	return a;
}

void p4tc_extern_ops_put(const struct p4tc_extern_ops *ops)
{
	if (ops)
		module_put(ops->owner);
}

int p4tc_register_extern(struct p4tc_extern_ops *ext)
{
	if (p4tc_extern_lookup_n(ext->kind))
		return -EEXIST;

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
p4tc_user_pipeline_ext_find_byid(struct p4tc_pipeline *pipeline,
				 const u32 ext_id)
{
	struct p4tc_user_pipeline_extern *pipe_ext;

	pipe_ext = idr_find(&pipeline->user_ext_idr, ext_id);

	return pipe_ext;
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_byname(struct p4tc_pipeline *pipeline,
				   const char *extname)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	unsigned long tmp, ext_id;

	idr_for_each_entry_ul(&pipeline->user_ext_idr, pipe_ext, tmp, ext_id) {
		if (strncmp(pipe_ext->ext_name, extname, EXTERNNAMSIZ) == 0)
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

static inline bool
p4tc_user_pipeline_insts_exceeded(struct p4tc_user_pipeline_extern *pipe_ext)
{
	const u32 max_num_insts = pipe_ext->tmpl_ext->max_num_insts;

	if (refcount_read(&pipe_ext->curr_insts_num) - 1 == max_num_insts)
		return true;

	return false;
}

static struct p4tc_user_pipeline_extern *
p4tc_user_pipeline_ext_find_or_create(struct p4tc_pipeline *pipeline,
				      struct p4tc_tmpl_extern *tmpl_ext,
				      bool *allocated_pipe_ext,
				      struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	int err;

	pipe_ext = p4tc_user_pipeline_ext_find_byid(pipeline, tmpl_ext->ext_id);
	if (pipe_ext) {
		bool exceeded_max_insts;

		exceeded_max_insts = p4tc_user_pipeline_insts_exceeded(pipe_ext);
		if (exceeded_max_insts) {
			NL_SET_ERR_MSG(extack,
				       "Maximum number of instances exceeded");
			return ERR_PTR(-EINVAL);
		}

		refcount_inc(&pipe_ext->ext_ref);
		refcount_inc(&pipe_ext->curr_insts_num);
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

	strscpy(pipe_ext->ext_name, tmpl_ext->common.name, EXTERNNAMSIZ);
	idr_init(&pipe_ext->e_inst_idr);
	refcount_set(&pipe_ext->ext_ref, 1);
	refcount_set(&pipe_ext->curr_insts_num, 1);
	refcount_inc(&tmpl_ext->tmpl_ref);
	pipe_ext->tmpl_ext = tmpl_ext;
	pipe_ext->free = p4tc_user_pipeline_ext_free;

	*allocated_pipe_ext = true;

	return pipe_ext;

free_pipe_ext:
	kfree(pipe_ext);
	return ERR_PTR(err);
}

struct p4tc_extern_inst *
p4tc_ext_inst_find_bynames(struct net *net, struct p4tc_pipeline *pipeline,
			   const char *extname, const char *instname,
			   struct netlink_ext_ack *extack)
{
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_extern_inst *inst;

	pipe_ext = p4tc_user_pipeline_ext_find_byany(pipeline, extname, 0,
						     extack);
	if (IS_ERR(pipe_ext))
		return (void *)pipe_ext;

	inst = p4tc_ext_inst_find_byany(pipe_ext, instname, 0, extack);
	if (IS_ERR(inst))
		return inst;

	return inst;
}

struct p4tc_extern_inst *
p4tc_ext_inst_get_byids(struct net *net, struct p4tc_pipeline **pipeline,
			const u32 pipe_id,
			struct p4tc_user_pipeline_extern **pipe_ext,
			const u32 ext_id, const u32 inst_id)
{
	struct p4tc_extern_inst *inst;
	int err;

	*pipeline = tcf_pipeline_find_byid(net, pipe_id);
	if (!*pipeline)
		return ERR_PTR(-ENOENT);

	/* Pipeline was deleted in parallel */
	if (!refcount_inc_not_zero(&((*pipeline)->p_ctrl_ref)))
		return ERR_PTR(-EBUSY);

	*pipe_ext = p4tc_user_pipeline_ext_find_byid(*pipeline, ext_id);
	if (!*pipe_ext) {
		err = -ENOENT;
		goto refcount_dec_pipeline;
	}

	/* Pipeline extern template was deleted in parallel */
	if (!refcount_inc_not_zero(&((*pipe_ext)->ext_ref))) {
		err = -EBUSY;
		goto refcount_dec_pipeline;
	}

	inst = p4tc_ext_inst_find_byid(*pipe_ext, inst_id);
	if (!inst) {
		err = -EBUSY;
		goto refcount_dec_pipe_tmpl_ext;
	}

	/* Extern instance was deleted in parallel */
	if (!refcount_inc_not_zero(&inst->inst_ref)) {
		err = -EBUSY;
		goto refcount_dec_pipe_tmpl_ext;
	}

	return inst;

refcount_dec_pipe_tmpl_ext:
	refcount_dec(&((*pipe_ext)->ext_ref));

refcount_dec_pipeline:
	refcount_dec(&((*pipeline)->p_ctrl_ref));

	return ERR_PTR(err);
}

static struct p4tc_extern_inst *
p4tc_tmpl_ext_inst_update(struct net *net, struct nlmsghdr *n,
			  struct nlattr *nla, struct p4tc_pipeline *pipeline,
			  u32 *ids, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *control_params[P4TC_MSGBATCH_SIZE] = { NULL };
	struct p4tc_extern_method *methods[P4TC_MAX_EXTERN_METHODS] = { NULL };
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1];
	struct p4tc_extern_inst_common *inst_common;
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_pipeline *root_pipeline;
	int num_params = 0, num_methods = 0;
	struct p4tc_extern_inst *inst;
	struct p4tc_tmpl_extern *ext;
	u32 ext_id = 0, inst_id = 0;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TMPL_EXT_INST_MAX, nla,
			       tc_extern_inst_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	ext_id = ids[P4TC_TMPL_EXT_IDX];

	root_pipeline = tcf_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	ext = p4tc_tmpl_ext_find_byanyattr(root_pipeline,
					   tb[P4TC_TMPL_EXT_INST_EXT_NAME],
					   ext_id, extack);
	if (IS_ERR(ext))
		return (struct p4tc_extern_inst *)ext;

	inst_id = ids[P4TC_TMPL_EXT_INST_IDX];

	pipe_ext = p4tc_user_pipeline_ext_find_byid(pipeline, ext->ext_id);
	if (!pipe_ext) {
		NL_SET_ERR_MSG(extack, "Unable to find pipeline extern by id");
		return ERR_PTR(-ENOENT);
	}
	inst = p4tc_ext_inst_find_byanyattr(pipe_ext,
					    tb[P4TC_TMPL_EXT_INST_NAME],
					    inst_id, extack);
	if (IS_ERR(inst))
		return ERR_PTR(-ENOMEM);

	if (tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]) {
		u32 *num_elems;

		num_elems = nla_data(tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]);
		inst->max_num_elems = *num_elems;
	}

	inst_common = inst->inst_common;
	if (tb[P4TC_TMPL_EXT_INST_METHODS]) {
		num_methods = p4tc_extern_init_methods(net, &inst_common->methods_idr,
						       methods,
						       tb[P4TC_TMPL_EXT_INST_METHODS],
						       true, extack);
		if (num_methods < 0)
			return ERR_PTR(num_methods);
		inst_common->num_methods = num_methods;
	}

	if (tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS]) {
		num_params = p4tc_extern_init_params_value(net, inst,
							   tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS],
							   control_params, true,
							   extack);
		if (num_params < 0) {
			ret = num_params;
			goto free_methods;
		}
		inst_common->num_control_params = num_params;
	}

	p4tc_extern_methods_replace_many(&inst_common->methods_idr, methods,
					 num_methods);
	p4tc_extern_params_replace_many(&inst_common->control_params_idr,
					control_params, num_params);

	return inst;

free_methods:
	p4tc_extern_put_many_methods(&inst_common->methods_idr, methods, false,
				     num_methods);

	return ERR_PTR(ret);
}

static struct p4tc_extern_inst *
p4tc_tmpl_ext_inst_create(struct net *net, struct nlmsghdr *n,
			  struct nlattr *nla, struct p4tc_pipeline *pipeline,
			  u32 *ids, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *control_params[P4TC_MSGBATCH_SIZE] = { NULL };
	struct p4tc_extern_method *methods[P4TC_MAX_EXTERN_METHODS] = { NULL };
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1];
	struct p4tc_extern_inst_common *inst_common;
	struct p4tc_user_pipeline_extern *pipe_ext;
	struct p4tc_pipeline *root_pipeline;
	int num_params = 0, num_methods = 0;
	bool allocated_pipe_ext = false;
	struct p4tc_extern_inst *inst;
	struct p4tc_tmpl_extern *ext;
	u32 ext_id = 0, inst_id = 0;
	char *inst_name = NULL;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TMPL_EXT_INST_MAX, nla,
			       tc_extern_inst_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	ext_id = ids[P4TC_TMPL_EXT_IDX];

	root_pipeline = tcf_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	ext = p4tc_tmpl_ext_find_byanyattr(root_pipeline,
					   tb[P4TC_TMPL_EXT_INST_EXT_NAME],
					   ext_id, extack);
	if (IS_ERR(ext))
		return (struct p4tc_extern_inst *)ext;

	if (tb[P4TC_TMPL_EXT_INST_NAME]) {
		inst_name = nla_data(tb[P4TC_TMPL_EXT_INST_NAME]);
	} else {
		NL_SET_ERR_MSG(extack,
			       "Must specify extern name");
		return ERR_PTR(-EEXIST);
	}

	inst_id = ids[P4TC_TMPL_EXT_INST_IDX];
	if (!inst_id) {
		NL_SET_ERR_MSG(extack, "Must specify extern instance id");
		return ERR_PTR(-EINVAL);
	}

	pipe_ext = p4tc_user_pipeline_ext_find_or_create(pipeline, ext,
							 &allocated_pipe_ext,
							 extack);
	if (IS_ERR(pipe_ext))
		return (struct p4tc_extern_inst *)pipe_ext;

	if (p4tc_ext_inst_find_byname(pipe_ext, inst_name) ||
	    p4tc_ext_inst_find_byid(pipe_ext, inst_id)) {
		NL_SET_ERR_MSG(extack,
			       "Extern instance with same name or ID already exists");
		ret = -EEXIST;
		goto dec_pipe_ext_ref;
	}

	inst = kzalloc(sizeof(*inst), GFP_KERNEL);
	if (!inst) {
		NL_SET_ERR_MSG(extack, "Failed to allocate ext inst");
		ret = -ENOMEM;
		goto dec_pipe_ext_ref;
	}

	inst_common = kzalloc(sizeof(*inst_common), GFP_KERNEL);
	if (!inst_common) {
		ret = -ENOMEM;
		goto free_extern;
	}

	if (tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]) {
		u32 *num_elems;

		num_elems = nla_data(tb[P4TC_TMPL_EXT_INST_NUM_ELEMS]);
		inst->max_num_elems = *num_elems;
	} else {
		inst->max_num_elems = P4TC_DEFAULT_NUM_EXT_INST_ELEMS;
	}
	refcount_set(&inst->curr_num_elems, 1);

	idr_init(&inst_common->methods_idr);
	if (tb[P4TC_TMPL_EXT_INST_METHODS]) {
		num_methods = p4tc_extern_init_methods(net, &inst_common->methods_idr,
						       methods,
						       tb[P4TC_TMPL_EXT_INST_METHODS],
						       false, extack);
		if (num_methods < 0) {
			idr_destroy(&inst_common->methods_idr);
			ret = num_methods;
			goto free_extern_common;
		}
		inst_common->num_methods = num_methods;
	}

	idr_init(&inst_common->control_params_idr);
	idr_init(&inst_common->control_elems_idr);
	inst->inst_common = inst_common;
	if (tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS]) {
		num_params = p4tc_extern_init_params_value(net, inst,
							   tb[P4TC_TMPL_EXT_INST_CONTROL_PARAMS],
							   control_params, false,
							   extack);
		if (num_params < 0) {
			ret = num_params;
			idr_destroy(&inst_common->control_params_idr);
			goto free_methods;
		}
		inst_common->num_control_params = num_params;
	}

	inst->ext_inst_id = inst_id;
	ret = idr_alloc_u32(&pipe_ext->e_inst_idr, inst, &inst->ext_inst_id,
			    inst->ext_inst_id, GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to allocate ID for extern instance");
		goto free_control_params;
	}

	if (allocated_pipe_ext)
		refcount_inc(&pipe_ext->curr_insts_num);

	inst->ext_id = ext->ext_id;
	inst->ext_inst_id = inst_id;
	inst->ops = ext->ops;

	strscpy(inst->common.name, inst_name, EXTERNINSTNAMSIZ);

	inst->common.p_id = pipeline->common.p_id;
	inst->common.ops = (struct p4tc_template_ops *)&p4tc_tmpl_ext_inst_ops;
	inst->pipe_ext = pipe_ext;
	refcount_set(&inst->inst_ref, 1);

	p4tc_extern_methods_replace_many(&inst_common->methods_idr, methods,
					 num_methods);
	p4tc_extern_params_replace_many(&inst_common->control_params_idr,
					control_params, num_params);

	return inst;

free_control_params:
	p4tc_extern_put_many_params(&inst_common->control_params_idr,
				    control_params, true, num_params);
	idr_destroy(&inst_common->control_elems_idr);

free_methods:
	p4tc_extern_put_many_methods(&inst_common->methods_idr, methods, true,
				     num_methods);
	idr_destroy(&inst_common->methods_idr);

free_extern_common:
	kfree(inst_common);

free_extern:
	kfree(inst);

dec_pipe_ext_ref:
	if (!allocated_pipe_ext)
		refcount_dec(&pipe_ext->ext_ref);

	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_tmpl_ext_inst_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		      struct p4tc_nl_pname *nl_pname, u32 *ids,
		      struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;

	pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data,
						    pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		inst = p4tc_tmpl_ext_inst_create(net, n, nla, pipeline, ids,
						 extack);
		break;
	case RTM_UPDATEP4TEMPLATE:
		inst = p4tc_tmpl_ext_inst_update(net, n, nla, pipeline, ids,
						 extack);
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (IS_ERR(inst))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TMPL_EXT_IDX])
		ids[P4TC_TMPL_EXT_IDX] = inst->ext_id;

	if (!ids[P4TC_TMPL_EXT_INST_IDX])
		ids[P4TC_TMPL_EXT_INST_IDX] = inst->ext_inst_id;

out:
	return (struct p4tc_template_common *)inst;
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

	if (tb[P4TC_TMPL_EXT_NAME]) {
		extern_name = nla_data(tb[P4TC_TMPL_EXT_NAME]);
	} else {
		NL_SET_ERR_MSG(extack,
			       "Must specify extern name");
		return ERR_PTR(-EEXIST);
	}

	if ((p4tc_tmpl_ext_find_name(pipeline, extern_name)) ||
	    p4tc_tmpl_ext_find_byid(pipeline, ext_id)) {
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

	ret = idr_alloc_u32(&pipeline->p_ext_idr, ext, &ext_id,
			    ext_id, GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate ID for extern");
		goto free_extern;
	}

	ext->ext_id = ext_id;

	strscpy(ext->common.name, extern_name, EXTERNNAMSIZ);

	refcount_set(&ext->tmpl_ref, 1);

	ext->common.p_id = pipeline->common.p_id;
	ext->common.ops = (struct p4tc_template_ops *)&p4tc_tmpl_ext_ops;

	/* Extern module is not mandatory */
	ext->ops = p4tc_extern_ops_get(extern_name);

	return ext;

free_extern:
	kfree(ext);
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_tmpl_ext_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		 struct p4tc_nl_pname *nl_pname, u32 *ids,
		 struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline;
	struct p4tc_tmpl_extern *ext;

	if (p4tc_tmpl_msg_is_update(n)) {
		NL_SET_ERR_MSG(extack, "Extern update not supported");
		return ERR_PTR(-EOPNOTSUPP);
	}

	pipeline = tcf_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ext = p4tc_tmpl_ext_create(n, nla, pipeline, ids, extack);
	if (IS_ERR(ext))
		goto out;

out:
	return (struct p4tc_template_common *)ext;
}

static int ext_inst_param_fill_nlmsg(struct sk_buff *skb,
				     struct idr *params_idr)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_extern_param *param;
	struct nlattr *nest_count;
	unsigned long id, tmp;
	int i = 1;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		nest_count = nla_nest_start(skb, i);
		if (!nest_count)
			goto out_nlmsg_trim;

		if (nla_put_string(skb, P4TC_EXT_PARAMS_NAME, param->name))
			goto out_nlmsg_trim;

		if (nla_put_u32(skb, P4TC_EXT_PARAMS_ID, param->id))
			goto out_nlmsg_trim;

		if (nla_put_u32(skb, P4TC_EXT_PARAMS_TYPE, param->type->typeid))
			goto out_nlmsg_trim;

		if (param->value && p4tc_ext_param_value_dump(skb, param))
			goto out_nlmsg_trim;

		nla_nest_end(skb, nest_count);
		i++;
	}

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int ext_method_fill_nlmsg(struct sk_buff *skb,
				 struct p4tc_extern_method *method)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *parms;

	if (nla_put_string(skb, P4TC_TMPL_EXT_INST_METHOD_NAME,
			   method->method_name))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_TMPL_EXT_INST_METHOD_ID, method->method_id))
		goto out_nlmsg_trim;

	parms = nla_nest_start(skb, P4TC_TMPL_EXT_INST_METHOD_PARAMS);
	if (!parms)
		goto out_nlmsg_trim;

	if (ext_inst_param_fill_nlmsg(skb, &method->params_idr) < 0)
		goto out_nlmsg_trim;

	nla_nest_end(skb, parms);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int _p4tc_tmpl_ext_inst_fill_nlmsg(struct sk_buff *skb,
					  struct p4tc_extern_inst *inst)
{
	struct p4tc_extern_inst_common *common = inst->inst_common;
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nest, *methods, *parms;
	struct p4tc_user_pipeline_extern *ext;
	struct p4tc_extern_method *method;
	unsigned long method_id, tmp;
	/* Parser instance id + header field id */
	u32 ids[2];
	int i = 1;

	ids[0] = inst->ext_id;
	ids[1] = inst->ext_inst_id;

	if (nla_put(skb, P4TC_PATH, sizeof(ids), &ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	ext = inst->pipe_ext;
	if (ext->ext_name[0]) {
		if (nla_put_string(skb, P4TC_TMPL_EXT_INST_EXT_NAME,
				   ext->ext_name))
			goto out_nlmsg_trim;
	}

	if (inst->common.name[0]) {
		if (nla_put_string(skb, P4TC_TMPL_EXT_INST_NAME,
				   inst->common.name))
			goto out_nlmsg_trim;
	}

	if (nla_put_u32(skb, P4TC_TMPL_EXT_INST_NUM_ELEMS, inst->max_num_elems))
		goto out_nlmsg_trim;

	methods = nla_nest_start(skb, P4TC_TMPL_EXT_INST_METHODS);
	if (!methods)
		goto out_nlmsg_trim;

	idr_for_each_entry_ul(&common->methods_idr, method, tmp, method_id) {
		struct nlattr *nest_count = nla_nest_start(skb, i);

		if (ext_method_fill_nlmsg(skb, method) <= 0)
			goto out_nlmsg_trim;

		nla_nest_end(skb, nest_count);
		i++;
	}
	nla_nest_end(skb, methods);

	parms = nla_nest_start(skb, P4TC_TMPL_EXT_INST_CONTROL_PARAMS);
	if (!parms)
		goto out_nlmsg_trim;

	if (ext_inst_param_fill_nlmsg(skb, &common->control_params_idr) < 0)
		goto out_nlmsg_trim;

	nla_nest_end(skb, parms);
	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int _p4tc_tmpl_ext_fill_nlmsg(struct sk_buff *skb,
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

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int p4tc_tmpl_ext_inst_fill_nlmsg(struct net *net, struct sk_buff *skb,
					 struct p4tc_template_common *template,
					 struct netlink_ext_ack *extack)
{
	struct p4tc_extern_inst *inst = to_extern_inst(template);

	if (_p4tc_tmpl_ext_inst_fill_nlmsg(skb, inst) <= 0) {
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

	if (_p4tc_tmpl_ext_fill_nlmsg(skb, ext) <= 0) {
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

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any externs");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush all externs");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return 0;
}

static int p4tc_tmpl_ext_inst_flush(struct sk_buff *skb,
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

	path[0] = pipe_ext->ext_id;
	path[1] = 0;

	if (idr_is_empty(&pipe_ext->e_inst_idr)) {
		NL_SET_ERR_MSG(extack, "There are no externs to flush");
		goto out_nlmsg_trim;
	}

	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	idr_for_each_entry_ul(&pipe_ext->e_inst_idr, inst, tmp, inst_id) {
		if (_p4tc_tmpl_ext_inst_put(pipeline, pipe_ext, inst, false,
					    false, extack) < 0) {
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

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any externs instance");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush all extern instances");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return 0;
}

static int p4tc_tmpl_ext_inst_gd(struct net *net, struct sk_buff *skb,
				 struct nlmsghdr *n, struct nlattr *nla,
				 struct p4tc_nl_pname *nl_pname, u32 *ids,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_INST_MAX + 1] = {NULL};
	struct p4tc_user_pipeline_extern *pipe_ext;
	u32 inst_id = ids[P4TC_TMPL_EXT_INST_IDX];
	unsigned char *b = nlmsg_get_pos(skb);
	u32 ext_id = ids[P4TC_TMPL_EXT_IDX];
	u32 pipe_id = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_extern_inst *inst;
	int ret;

	if (n->nlmsg_type == RTM_GETP4TEMPLATE)
		pipeline = tcf_pipeline_find_byany(net, nl_pname->data,
						   pipe_id, extack);
	else
		pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data,
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

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TMPL_EXT_IDX])
		ids[P4TC_TMPL_EXT_IDX] = pipe_ext->ext_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && n->nlmsg_flags & NLM_F_ROOT)
		return p4tc_tmpl_ext_inst_flush(skb, pipeline, pipe_ext,
						extack);

	inst = p4tc_ext_inst_find_byanyattr(pipe_ext,
					    tb[P4TC_TMPL_EXT_INST_NAME],
					    inst_id, extack);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

	ret = _p4tc_tmpl_ext_inst_fill_nlmsg(skb, inst);
	if (ret < 0)
		return -ENOMEM;

	if (!ids[P4TC_TMPL_EXT_INST_IDX])
		ids[P4TC_TMPL_EXT_INST_IDX] = inst->ext_inst_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _p4tc_tmpl_ext_inst_put(pipeline, pipe_ext, inst, false,
					      true, extack);
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
			    struct p4tc_nl_pname *nl_pname, u32 *ids,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TMPL_EXT_MAX + 1] = {NULL};
	unsigned char *b = nlmsg_get_pos(skb);
	u32 ext_id = ids[P4TC_TMPL_EXT_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_tmpl_extern *ext;
	int ret;

	pipeline = tcf_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_TMPL_EXT_MAX, nla,
				       tc_extern_policy, extack);
		if (ret < 0)
			return ret;
	}

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && n->nlmsg_flags & NLM_F_ROOT)
		return p4tc_tmpl_ext_flush(skb, pipeline, extack);

	ext = p4tc_tmpl_ext_find_byanyattr(pipeline, tb[P4TC_TMPL_EXT_NAME],
					   ext_id, extack);
	if (IS_ERR(ext))
		return PTR_ERR(ext);

	ret = _p4tc_tmpl_ext_fill_nlmsg(skb, ext);
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

	pipeline = tcf_pipeline_find_byid(net, P4TC_KERNEL_PIPEID);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipeline->p_ext_idr,
					P4TC_TMPL_EXT_IDX, extack);
}

static int p4tc_tmpl_ext_inst_dump_1(struct sk_buff *skb,
				     struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_extern_inst *inst = to_extern_inst(common);
	unsigned char *b = nlmsg_get_pos(skb);
	u32 path[2];

	if (!param)
		goto out_nlmsg_trim;

	if (inst->common.name[0] &&
	    nla_put_string(skb, P4TC_TMPL_EXT_NAME, inst->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	path[0] = inst->pipe_ext->ext_id;
	path[1] = inst->ext_inst_id;
	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int p4tc_tmpl_ext_inst_dump(struct sk_buff *skb,
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

	pipeline = tcf_pipeline_find_byany_unsealed(net, *p_name,
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

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipe_ext->e_inst_idr,
					P4TC_TMPL_EXT_INST_IDX, extack);
}

const struct p4tc_template_ops p4tc_tmpl_ext_inst_ops = {
	.cu = p4tc_tmpl_ext_inst_cu,
	.fill_nlmsg = p4tc_tmpl_ext_inst_fill_nlmsg,
	.gd = p4tc_tmpl_ext_inst_gd,
	.put = p4tc_tmpl_ext_inst_put,
	.dump = p4tc_tmpl_ext_inst_dump,
	.dump_1 = p4tc_tmpl_ext_inst_dump_1,
};

const struct p4tc_template_ops p4tc_tmpl_ext_ops = {
	.cu = p4tc_tmpl_ext_cu,
	.fill_nlmsg = p4tc_tmpl_ext_fill_nlmsg,
	.gd = p4tc_tmpl_ext_gd,
	.put = p4tc_tmpl_ext_put,
	.dump = p4tc_tmpl_ext_dump,
	.dump_1 = p4tc_tmpl_ext_dump_1,
};
