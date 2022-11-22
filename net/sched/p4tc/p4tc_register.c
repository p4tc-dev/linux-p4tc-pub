// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_register.c	P4 TC REGISTER
 *
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
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
#include <net/netlink.h>
#include <net/flow_offload.h>

static const struct nla_policy p4tc_register_policy[P4TC_REGISTER_MAX + 1] = {
	[P4TC_REGISTER_NAME] = { .type = NLA_STRING, .len  = REGISTERNAMSIZ },
	[P4TC_REGISTER_INFO] = {
		.type = NLA_BINARY,
		.len = sizeof(struct p4tc_u_register),
	},
	[P4TC_REGISTER_VALUE] = { .type = NLA_BINARY },
};

struct p4tc_register *tcf_register_find_byid(struct p4tc_pipeline *pipeline,
					     const u32 reg_id)
{
	return idr_find(&pipeline->p_reg_idr, reg_id);
}

static struct p4tc_register *
tcf_register_find_byname(const char *regname, struct p4tc_pipeline *pipeline)
{
	struct p4tc_register *reg;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_reg_idr, reg, tmp, id)
		if (strncmp(reg->common.name, regname, REGISTERNAMSIZ) == 0)
			return reg;

	return NULL;
}

struct p4tc_register *tcf_register_find_byany(struct p4tc_pipeline *pipeline,
					      const char *regname,
					      const u32 reg_id,
					      struct netlink_ext_ack *extack)
{
	struct p4tc_register *reg;
	int err;

	if (reg_id) {
		reg = tcf_register_find_byid(pipeline, reg_id);
		if (!reg) {
			NL_SET_ERR_MSG(extack, "Unable to find register by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (regname) {
			reg = tcf_register_find_byname(regname, pipeline);
			if (!reg) {
				NL_SET_ERR_MSG(extack,
					       "Register name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify register name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return reg;
out:
	return ERR_PTR(err);
}

struct p4tc_register *tcf_register_get(struct p4tc_pipeline *pipeline,
				       const char *regname, const u32 reg_id,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_register *reg;

	reg = tcf_register_find_byany(pipeline, regname, reg_id, extack);
	if (IS_ERR(reg))
		return reg;

	WARN_ON(!refcount_inc_not_zero(&reg->reg_ref));

	return reg;
}

void tcf_register_put_ref(struct p4tc_register *reg)
{
	WARN_ON(!refcount_dec_not_one(&reg->reg_ref));
}

static struct p4tc_register *
tcf_register_find_byanyattr(struct p4tc_pipeline *pipeline,
			    struct nlattr *name_attr, const u32 reg_id,
			    struct netlink_ext_ack *extack)
{
	char *regname = NULL;

	if (name_attr)
		regname = nla_data(name_attr);

	return tcf_register_find_byany(pipeline, regname, reg_id, extack);
}

static int _tcf_register_fill_nlmsg(struct sk_buff *skb,
				    struct p4tc_register *reg,
				    struct p4tc_u_register *parm_arg)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_u_register parm = { 0 };
	size_t value_bytesz;
	struct nlattr *nest;
	void *value;

	if (nla_put_u32(skb, P4TC_PATH, reg->reg_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_REGISTER_NAME, reg->common.name))
		goto out_nlmsg_trim;

	parm.datatype = reg->reg_type->typeid;
	parm.flags |= P4TC_REGISTER_FLAGS_DATATYPE;
	if (parm_arg) {
		parm.index = parm_arg->index;
		parm.flags |= P4TC_REGISTER_FLAGS_INDEX;
	} else {
		parm.startbit = reg->reg_startbit;
		parm.flags |= P4TC_REGISTER_FLAGS_STARTBIT;
		parm.endbit = reg->reg_endbit;
		parm.flags |= P4TC_REGISTER_FLAGS_ENDBIT;
		parm.num_elems = reg->reg_num_elems;
		parm.flags |= P4TC_REGISTER_FLAGS_NUMELEMS;
	}

	if (nla_put(skb, P4TC_REGISTER_INFO, sizeof(parm), &parm))
		goto out_nlmsg_trim;

	value_bytesz = BITS_TO_BYTES(reg->reg_type->container_bitsz);
	spin_lock_bh(&reg->reg_value_lock);
	if (parm.flags & P4TC_REGISTER_FLAGS_INDEX) {
		value = reg->reg_value + parm.index * value_bytesz;
	} else {
		value = reg->reg_value;
		value_bytesz *= reg->reg_num_elems;
	}

	if (nla_put(skb, P4TC_REGISTER_VALUE, value_bytesz, value)) {
		spin_unlock_bh(&reg->reg_value_lock);
		goto out_nlmsg_trim;
	}
	spin_unlock_bh(&reg->reg_value_lock);

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_register_fill_nlmsg(struct net *net, struct sk_buff *skb,
				   struct p4tc_template_common *template,
				   struct netlink_ext_ack *extack)
{
	struct p4tc_register *reg = to_register(template);

	if (_tcf_register_fill_nlmsg(skb, reg, NULL) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for register");
		return -EINVAL;
	}

	return 0;
}

static int _tcf_register_put(struct p4tc_pipeline *pipeline,
			     struct p4tc_register *reg,
			     bool unconditional_purge,
			     struct netlink_ext_ack *extack)
{
	void *value;

	if (!refcount_dec_if_one(&reg->reg_ref) && !unconditional_purge)
		return -EBUSY;

	idr_remove(&pipeline->p_reg_idr, reg->reg_id);

	spin_lock_bh(&reg->reg_value_lock);
	value = reg->reg_value;
	reg->reg_value = NULL;
	spin_unlock_bh(&reg->reg_value_lock);
	kfree(value);

	if (reg->reg_mask_shift) {
		kfree(reg->reg_mask_shift->mask);
		kfree(reg->reg_mask_shift);
	}
	kfree(reg);

	return 0;
}

static int tcf_register_put(struct net *net, struct p4tc_template_common *tmpl,
			    bool unconditional_purge,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		tcf_pipeline_find_byid(net, tmpl->p_id);
	struct p4tc_register *reg = to_register(tmpl);
	int ret;

	ret = _tcf_register_put(pipeline, reg, unconditional_purge, extack);
	if (ret < 0)
		NL_SET_ERR_MSG(extack, "Unable to delete referenced register");

	return ret;
}

static struct p4tc_register *tcf_register_create(struct net *net,
						 struct nlmsghdr *n,
						 struct nlattr *nla, u32 reg_id,
						 struct p4tc_pipeline *pipeline,
						 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_REGISTER_MAX + 1];
	struct p4tc_u_register *parm;
	struct p4tc_type *datatype;
	struct p4tc_register *reg;
	int ret;

	ret = nla_parse_nested(tb, P4TC_REGISTER_MAX, nla, p4tc_register_policy,
			       extack);

	if (ret < 0)
		return ERR_PTR(ret);

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (!reg)
		return ERR_PTR(-ENOMEM);

	if (!tb[P4TC_REGISTER_NAME]) {
		NL_SET_ERR_MSG(extack, "Must specify register name");
		ret = -EINVAL;
		goto free_reg;
	}

	if (tcf_register_find_byname(nla_data(tb[P4TC_REGISTER_NAME]), pipeline) ||
	    tcf_register_find_byid(pipeline, reg_id)) {
		NL_SET_ERR_MSG(extack, "Register already exists");
		ret = -EEXIST;
		goto free_reg;
	}

	reg->common.p_id = pipeline->common.p_id;
	strscpy(reg->common.name, nla_data(tb[P4TC_REGISTER_NAME]),
		REGISTERNAMSIZ);

	if (tb[P4TC_REGISTER_INFO]) {
		parm = nla_data(tb[P4TC_REGISTER_INFO]);
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Missing register info");
		goto free_reg;
	}

	if (tb[P4TC_REGISTER_VALUE]) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Value can't be passed in create");
		goto free_reg;
	}

	if (parm->flags & P4TC_REGISTER_FLAGS_INDEX) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Index can't be passed in create");
		goto free_reg;
	}

	if (parm->flags & P4TC_REGISTER_FLAGS_NUMELEMS) {
		if (!parm->num_elems) {
			ret = -EINVAL;
			NL_SET_ERR_MSG(extack, "Num elems can't be zero");
			goto free_reg;
		}

		if (parm->num_elems > P4TC_MAX_REGISTER_ELEMS) {
			NL_SET_ERR_MSG(extack,
				       "Number of elements exceededs P4 register maximum");
			ret = -EINVAL;
			goto free_reg;
		}
	} else {
		NL_SET_ERR_MSG(extack, "Must specify num elems");
		ret = -EINVAL;
		goto free_reg;
	}

	if (!(parm->flags & P4TC_REGISTER_FLAGS_STARTBIT) ||
	    !(parm->flags & P4TC_REGISTER_FLAGS_ENDBIT)) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Must specify start and endbit");
		goto free_reg;
	}

	if (parm->startbit > parm->endbit) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "startbit > endbit");
		goto free_reg;
	}

	if (parm->flags & P4TC_REGISTER_FLAGS_DATATYPE) {
		datatype = p4type_find_byid(parm->datatype);
		if (!datatype) {
			NL_SET_ERR_MSG(extack,
				       "Invalid data type for P4 register");
			ret = -EINVAL;
			goto free_reg;
		}
		reg->reg_type = datatype;
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Must specify datatype");
		goto free_reg;
	}

	if (parm->endbit > datatype->bitsz) {
		NL_SET_ERR_MSG(extack,
			       "Endbit doesn't fix in container datatype");
		ret = -EINVAL;
		goto free_reg;
	}
	reg->reg_startbit = parm->startbit;
	reg->reg_endbit = parm->endbit;

	reg->reg_num_elems = parm->num_elems;

	spin_lock_init(&reg->reg_value_lock);

	reg->reg_value = kcalloc(reg->reg_num_elems,
				 BITS_TO_BYTES(datatype->container_bitsz),
				 GFP_KERNEL);
	if (!reg->reg_value) {
		ret = -ENOMEM;
		goto free_reg;
	}

	if (reg_id) {
		reg->reg_id = reg_id;
		ret = idr_alloc_u32(&pipeline->p_reg_idr, reg, &reg->reg_id,
				    reg->reg_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to allocate register id");
			goto free_reg_value;
		}
	} else {
		reg->reg_id = 1;
		ret = idr_alloc_u32(&pipeline->p_reg_idr, reg, &reg->reg_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to allocate register id");
			goto free_reg_value;
		}
	}

	if (datatype->ops->create_bitops) {
		size_t bitsz = reg->reg_endbit - reg->reg_startbit + 1;
		struct p4tc_type_mask_shift *mask_shift;

		mask_shift = datatype->ops->create_bitops(bitsz,
							  reg->reg_startbit,
							  reg->reg_endbit,
							  extack);
		if (IS_ERR(mask_shift)) {
			ret = PTR_ERR(mask_shift);
			goto idr_rm;
		}
		reg->reg_mask_shift = mask_shift;
	}

	refcount_set(&reg->reg_ref, 1);

	reg->common.ops = (struct p4tc_template_ops *)&p4tc_register_ops;

	return reg;

idr_rm:
	idr_remove(&pipeline->p_reg_idr, reg->reg_id);

free_reg_value:
	kfree(reg->reg_value);

free_reg:
	kfree(reg);
	return ERR_PTR(ret);
}

static struct p4tc_register *tcf_register_update(struct net *net,
						 struct nlmsghdr *n,
						 struct nlattr *nla, u32 reg_id,
						 struct p4tc_pipeline *pipeline,
						 struct netlink_ext_ack *extack)
{
	void *user_value = NULL;
	struct nlattr *tb[P4TC_REGISTER_MAX + 1];
	struct p4tc_u_register *parm;
	struct p4tc_type *datatype;
	struct p4tc_register *reg;
	int ret;

	ret = nla_parse_nested(tb, P4TC_REGISTER_MAX, nla, p4tc_register_policy,
			       extack);

	if (ret < 0)
		return ERR_PTR(ret);

	reg = tcf_register_find_byanyattr(pipeline, tb[P4TC_REGISTER_NAME],
					  reg_id, extack);
	if (IS_ERR(reg))
		return reg;

	if (tb[P4TC_REGISTER_INFO]) {
		parm = nla_data(tb[P4TC_REGISTER_INFO]);
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Missing register info");
		goto err;
	}

	datatype = reg->reg_type;

	if (parm->flags & P4TC_REGISTER_FLAGS_NUMELEMS) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Can't update register num elems");
		goto err;
	}

	if (!(parm->flags & P4TC_REGISTER_FLAGS_STARTBIT) ||
	    !(parm->flags & P4TC_REGISTER_FLAGS_ENDBIT)) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Must specify start and endbit");
		goto err;
	}

	if (parm->startbit != reg->reg_startbit ||
	    parm->endbit != reg->reg_endbit) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack,
			       "Start and endbit don't match with register values");
		goto err;
	}

	if (!(parm->flags & P4TC_REGISTER_FLAGS_INDEX)) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Must specify index");
		goto err;
	}

	if (tb[P4TC_REGISTER_VALUE]) {
		if (nla_len(tb[P4TC_REGISTER_VALUE]) !=
		    BITS_TO_BYTES(datatype->container_bitsz)) {
			ret = -EINVAL;
			NL_SET_ERR_MSG(extack,
				       "Value size differs from register type's container size");
			goto err;
		}
		user_value = nla_data(tb[P4TC_REGISTER_VALUE]);
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Missing register value");
		goto err;
	}

	if (parm->index >= reg->reg_num_elems) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Register index out of bounds");
		goto err;
	}

	if (user_value) {
		u64 read_user_value[2] = { 0 };
		size_t type_bytesz;
		void *value;

		type_bytesz = BITS_TO_BYTES(datatype->container_bitsz);

		datatype->ops->host_read(datatype, reg->reg_mask_shift,
					 user_value, read_user_value);

		spin_lock_bh(&reg->reg_value_lock);
		value = reg->reg_value + parm->index * type_bytesz;
		datatype->ops->host_write(datatype, reg->reg_mask_shift,
					  read_user_value, value);
		spin_unlock_bh(&reg->reg_value_lock);
	}

	return reg;

err:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_register_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		struct p4tc_nl_pname *nl_pname, u32 *ids,
		struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], reg_id = ids[P4TC_REGID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_register *reg;

	pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data, pipeid,
						    extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		reg = tcf_register_update(net, n, nla, reg_id, pipeline,
					  extack);
	else
		reg = tcf_register_create(net, n, nla, reg_id, pipeline,
					  extack);

	if (IS_ERR(reg))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = reg->common.p_id;

out:
	return (struct p4tc_template_common *)reg;
}

static int tcf_register_flush(struct sk_buff *skb,
			      struct p4tc_pipeline *pipeline,
			      struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_register *reg;
	unsigned long tmp, reg_id;
	int ret = 0;
	int i = 0;

	if (nla_put_u32(skb, P4TC_PATH, 0))
		goto out_nlmsg_trim;

	if (idr_is_empty(&pipeline->p_reg_idr)) {
		NL_SET_ERR_MSG(extack, "There are no registers to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&pipeline->p_reg_idr, reg, tmp, reg_id) {
		if (_tcf_register_put(pipeline, reg, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack, "Unable to flush any register");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack, "Unable to flush all registers");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_register_gd(struct net *net, struct sk_buff *skb,
			   struct nlmsghdr *n, struct nlattr *nla,
			   struct p4tc_nl_pname *nl_pname, u32 *ids,
			   struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], reg_id = ids[P4TC_REGID_IDX];
	struct nlattr *tb[P4TC_REGISTER_MAX + 1] = {};
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_u_register *parm_arg = NULL;
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_register *reg;
	struct nlattr *attr_info;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data,
							    pipeid, extack);
	else
		pipeline = tcf_pipeline_find_byany(net, nl_pname->data, pipeid,
						   extack);

	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_REGISTER_MAX, nla,
				       p4tc_register_policy, extack);

		if (ret < 0)
			return ret;
	}

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_register_flush(skb, pipeline, extack);

	reg = tcf_register_find_byanyattr(pipeline, tb[P4TC_REGISTER_NAME],
					  reg_id, extack);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	attr_info = tb[P4TC_REGISTER_INFO];
	if (attr_info) {
		if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
			NL_SET_ERR_MSG(extack,
				       "Can't pass info attribute in delete");
			return -EINVAL;
		}
		parm_arg = nla_data(attr_info);
		if (!(parm_arg->flags & P4TC_REGISTER_FLAGS_INDEX) ||
		    (parm_arg->flags & ~P4TC_REGISTER_FLAGS_INDEX)) {
			NL_SET_ERR_MSG(extack,
				       "Must specify param index and only param index");
			return -EINVAL;
		}
		if (parm_arg->index >= reg->reg_num_elems) {
			NL_SET_ERR_MSG(extack, "Register index out of bounds");
			return -EINVAL;
		}
	}
	if (_tcf_register_fill_nlmsg(skb, reg, parm_arg) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for register");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _tcf_register_put(pipeline, reg, false, extack);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete referenced register");
			goto out_nlmsg_trim;
		}
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_register_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			     struct nlattr *nla, char **p_name, u32 *ids,
			     struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = tcf_pipeline_find_byany(net, *p_name,
						   ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipeline->p_reg_idr,
					P4TC_REGID_IDX, extack);
}

static int tcf_register_dump_1(struct sk_buff *skb,
			       struct p4tc_template_common *common)
{
	struct nlattr *nest = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_register *reg = to_register(common);

	if (!nest)
		return -ENOMEM;

	if (nla_put_string(skb, P4TC_REGISTER_NAME, reg->common.name)) {
		nla_nest_cancel(skb, nest);
		return -ENOMEM;
	}

	nla_nest_end(skb, nest);

	return 0;
}

const struct p4tc_template_ops p4tc_register_ops = {
	.cu = tcf_register_cu,
	.fill_nlmsg = tcf_register_fill_nlmsg,
	.gd = tcf_register_gd,
	.put = tcf_register_put,
	.dump = tcf_register_dump,
	.dump_1 = tcf_register_dump_1,
};
