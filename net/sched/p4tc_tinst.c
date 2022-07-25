// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_tinst.c	P4 TC TABLE INSTANCE
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

static const struct nla_policy p4tc_tinst_policy[P4TC_TINST_MAX + 1] = {
	[P4TC_TINST_CLASS] = { .type = P4T_STRING, .len = TCLASSNAMSIZ},
	[P4TC_TINST_NAME] = { .type = P4T_STRING, .len = TINSTNAMSIZ },
	[P4TC_TINST_MAX_ENTRIES] = P4T_POLICY_RANGE(P4T_U32, 1, P4TC_MAX_TIENTRIES),
};

static int _tcf_tinst_fill_nlmsg(struct sk_buff *skb,
				 struct p4tc_table_instance *tinst,
				 const char *tc_name)
{
	unsigned char *b = skb_tail_pointer(skb);
	int ret = -1;
	struct nlattr *nest;
	u32 ids[P4TC_PATH_MAX - 1];

	ids[P4TC_TBCID_IDX - 1] = tinst->tbc_id;
	ids[P4TC_TIID_IDX - 1] = tinst->ti_id;

	if (nla_put(skb, P4TC_PATH, sizeof(u32) * (P4TC_PATH_MAX - 1), ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start_noflag(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;
	if (nla_put_string(skb, P4TC_TINST_CLASS, tc_name))
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_TINST_NAME, tinst->common.name))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_TINST_MAX_ENTRIES, tinst->ti_max_entries))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_tinst_fill_nlmsg(struct net *net, struct sk_buff *skb,
				struct p4tc_template_common *tmpl,
				struct netlink_ext_ack *extack)
{
	struct p4tc_table_instance *tinst = to_tinst(tmpl);
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;

	pipeline = idr_find(&pipeline_idr, tinst->common.p_id);
	tclass = idr_find(&pipeline->p_tbc_idr, tinst->tbc_id);

	if (_tcf_tinst_fill_nlmsg(skb, tinst, tclass->common.name) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table instance");
		return -EINVAL;
	}

	return 0;
}

static inline struct p4tc_table_instance *
tinst_find_name(struct nlattr *name_attr, struct p4tc_table_class *tclass)
{
	const char *ti_name = nla_data(name_attr);
	struct p4tc_table_instance *tinst;
	unsigned long tmp, ti_id;

	idr_for_each_entry_ul(&tclass->tbc_ti_idr, tinst, tmp, ti_id)
		if (strncmp(tinst->common.name, ti_name, TINSTNAMSIZ) == 0)
			return tinst;

	return NULL;
}

static struct p4tc_table_instance *
tinst_find(struct nlattr *name_attr,
	   const u32 ti_id,
	   struct p4tc_pipeline *pipeline,
	   struct p4tc_table_class *tclass,
	   struct netlink_ext_ack *extack)
{
	struct p4tc_table_instance *tinst;
	int err;

	if (ti_id) {
		tinst = idr_find(&tclass->tbc_ti_idr, ti_id);
		if (!tinst) {
			NL_SET_ERR_MSG(extack, "Table instance id not found");
			err = -ENOENT;
			goto out;
		}
	} else {
		if (name_attr) {
			tinst = tinst_find_name(name_attr, tclass);
			if (!tinst) {
				NL_SET_ERR_MSG(extack,
					       "Table instance name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify table instance name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return tinst;

out:
	return ERR_PTR(err);
}

int p4tc_tinst_init(struct p4tc_table_instance *tinst,
		    struct p4tc_pipeline *pipeline,
		    const char *ti_name,
		    struct p4tc_table_class *tclass,
		    u32 max_entries)
{
	if (tclass->tbc_curr_used_entries + max_entries > tclass->tbc_max_entries)
		return -EINVAL;

	tinst->ti_max_entries = max_entries;
	tclass->tbc_curr_used_entries += max_entries;

	tinst->common.p_id = pipeline->common.p_id;
	tinst->tbc_id = tclass->tbc_id;

	strscpy(tinst->common.name, ti_name, TINSTNAMSIZ);

	refcount_set(&tinst->ti_ref, 1);

	tinst->common.ops = (struct p4tc_template_ops *)&p4tc_tinst_ops;

	tclass->tbc_curr_count++;

	return 0;
}

static struct p4tc_table_instance *
tcf_tinst_create(struct nlattr **tb, u32 *ids,
		 struct p4tc_pipeline *pipeline,
		 struct p4tc_table_class *tclass,
		 struct netlink_ext_ack *extack)
{
	u32 ti_id = ids[P4TC_TIID_IDX];
	u32 max_entries = P4TC_DEFAULT_TIENTRIES;
	struct p4tc_table_instance *tinst;
	int ret;

	if (tclass->tbc_curr_count == tclass->tbc_count) {
		NL_SET_ERR_MSG(extack,
			       "Max number of table instances was exceeded");
		ret = -EINVAL;
		goto out;
	}

	if (!tb[P4TC_TINST_NAME]) {
		NL_SET_ERR_MSG(extack, "Must specify table instance name");
		ret = -EINVAL;
		goto out;
	}

	if (tinst_find_name(tb[P4TC_TINST_NAME], tclass) ||
	    idr_find(&tclass->tbc_ti_idr, ti_id)) {
		NL_SET_ERR_MSG(extack, "Table instance already exists");
		ret = -EEXIST;
		goto out;
	}

	tinst = kmalloc(sizeof(*tinst), GFP_KERNEL);
	if (!tinst) {
		NL_SET_ERR_MSG(extack, "Unable to create table instance");
		ret = -ENOMEM;
		goto out;
	}

	if (ti_id) {
		ret = idr_alloc_u32(&tclass->tbc_ti_idr, tinst, &ti_id, ti_id,
				    GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to allocate table instance id");
			goto free;
		}

		tinst->ti_id = ti_id;
	} else {
		tinst->ti_id = 1;
		ret = idr_alloc_u32(&tclass->tbc_ti_idr, tinst, &tinst->ti_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate table instance id");
			goto free;
		}
	}

	if (tb[P4TC_TINST_MAX_ENTRIES])
		max_entries = *((u32 *)nla_data(tb[P4TC_TINST_MAX_ENTRIES]));

	ret = p4tc_tinst_init(tinst, pipeline, nla_data(tb[P4TC_TINST_NAME]),
			      tclass, max_entries);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack,
			       "Creating this instance will exceed max entries for table class");
		goto idr_rm;
	}

	if (!ids[P4TC_TBCID_IDX])
		ids[P4TC_TBCID_IDX] = tclass->tbc_id;

	return tinst;

idr_rm:
	idr_remove(&tclass->tbc_ti_idr, tinst->ti_id);

free:
	kfree(tinst);

out:
	return ERR_PTR(ret);
}

static struct p4tc_table_instance *
tcf_tinst_update(struct nlattr **tb, u32 *ids,
		 struct p4tc_pipeline *pipeline,
		 struct p4tc_table_class *tclass,
		 struct netlink_ext_ack *extack)
{
	u32 ti_id = ids[P4TC_TIID_IDX];
	struct p4tc_table_instance *tinst;

	tinst = tinst_find(tb[P4TC_TINST_NAME], ti_id, pipeline, tclass, extack);
	if (IS_ERR(tinst))
		return tinst;

	if (tb[P4TC_TINST_MAX_ENTRIES]) {
		const u32 *max_entries = nla_data(tb[P4TC_TINST_MAX_ENTRIES]);
		u32 curr_max_entires = tclass->tbc_curr_used_entries;

		curr_max_entires += *max_entries - tinst->ti_max_entries;

		if (curr_max_entires > tclass->tbc_max_entries) {
			NL_SET_ERR_MSG(extack,
				       "Updating this instance will exceed max entries for table class");
			return ERR_PTR(-EINVAL);
		}

		tclass->tbc_curr_used_entries = curr_max_entires;
		tinst->ti_max_entries = *max_entries;
	}

	if (!ids[P4TC_TBCID_IDX])
		ids[P4TC_TBCID_IDX] = tclass->tbc_id;

	return tinst;
}

static struct p4tc_template_common *
tcf_tinst_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	     char **p_name, u32 *ids, struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], tbc_id = ids[P4TC_TBCID_IDX];
	struct nlattr *tb[P4TC_TINST_MAX + 1];
	struct p4tc_table_instance *tinst;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;
	int ret;

	pipeline = pipeline_find_unsealed(*p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ret = nla_parse_nested_deprecated(tb, P4TC_TINST_MAX, nla,
					  p4tc_tinst_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	tclass = tclass_find(pipeline, tb[P4TC_TINST_CLASS], tbc_id, extack);
	if (IS_ERR(tclass))
		return (void *)tclass;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		tinst = tcf_tinst_update(tb, ids, pipeline, tclass, extack);
	else
		tinst = tcf_tinst_create(tb, ids, pipeline, tclass, extack);
	if (IS_ERR(tinst))
		goto out;

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TIID_IDX])
		ids[P4TC_TIID_IDX] = tinst->ti_id;

out:
	return (struct p4tc_template_common *)tinst;
}

static int _tcf_tinst_put(struct p4tc_table_class *tclass,
			  struct p4tc_table_instance *tinst)
{
	if (!refcount_dec_if_one(&tinst->ti_ref))
		return -EBUSY;

	idr_remove(&tclass->tbc_ti_idr, tinst->ti_id);

	tclass->tbc_curr_count--;
	tclass->tbc_curr_used_entries -= tinst->ti_max_entries;

	kfree(tinst);

	return 0;
}

static int tcf_tinst_flush(struct sk_buff *skb,
			   struct p4tc_pipeline *pipeline,
			   struct nlattr **tb,
			   struct p4tc_table_class *tclass,
			   struct netlink_ext_ack *extack)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_table_instance *tinst;
	u32 path[P4TC_PATH_MAX - 1];
	unsigned long tmp, ti_id;
	int ret = 0;
	int i = 0;

	path[P4TC_TBCID_IDX - 1] = tclass->tbc_id;
	path[P4TC_TIID_IDX - 1] = 0;

	if (nla_put(skb, P4TC_PATH, sizeof(u32) * (P4TC_PATH_MAX - 1), path))
		goto out_nlmsg_trim;

	if (idr_is_empty(&tclass->tbc_ti_idr)) {
		NL_SET_ERR_MSG(extack, "There are no table instances to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&tclass->tbc_ti_idr, tinst, tmp, ti_id) {
		if (_tcf_tinst_put(tclass, tinst) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any table instance");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush all table instances");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return 0;
}

static int tcf_tinst_gd(struct net *net, struct sk_buff *skb,
			struct nlmsghdr *n, struct nlattr *nla,
			char **p_name, u32 *ids,
			struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], tbc_id = ids[P4TC_MID_IDX];
	struct nlattr *tb[P4TC_TINST_MAX + 1] = {};
	unsigned char *b = skb_tail_pointer(skb);
	u32 ti_id = ids[P4TC_TIID_IDX];
	int ret = 0;
	struct p4tc_table_instance *tinst;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		pipeline = pipeline_find_unsealed(*p_name, pipeid, extack);
	} else {
		pipeline = pipeline_find(*p_name, pipeid, extack);
	}
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested_deprecated(tb, P4TC_TINST_MAX, nla,
						  p4tc_tinst_policy, extack);

		if (ret < 0)
			return ret;
	}

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	tclass = tclass_find(pipeline, tb[P4TC_TINST_CLASS], tbc_id, extack);
	if (IS_ERR(tclass))
		return PTR_ERR(tclass);

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_tinst_flush(skb, pipeline, tb, tclass, extack);

	tinst = tinst_find(tb[P4TC_TINST_NAME], ti_id, pipeline, tclass, extack);
	if (IS_ERR(tinst))
		return PTR_ERR(tinst);

	if (_tcf_tinst_fill_nlmsg(skb, tinst, tclass->common.name) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table instance");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _tcf_tinst_put(tclass, tinst);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete referenced table instance");
			goto out_nlmsg_trim;
		}
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_tinst_put(struct net *net, struct p4tc_template_common *tmpl,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_table_instance *tinst = to_tinst(tmpl);
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;

	pipeline = idr_find(&pipeline_idr, tinst->common.p_id);
	tclass = idr_find(&pipeline->p_tbc_idr, tinst->tbc_id);

	return _tcf_tinst_put(tclass, tinst);
}

static int tcf_tinst_dump(struct sk_buff *skb,
			  struct p4tc_dump_ctx *ctx,
			  struct nlattr *nla,
			  char **p_name, u32 *ids,
			  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TINST_MAX + 1] = {};
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;
	int ret;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = pipeline_find(*p_name, ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = idr_find(&pipeline_idr, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ctx->ids[P4TC_TBCID_IDX]) {
		if (nla) {
			ret = nla_parse_nested_deprecated(tb, P4TC_TINST_MAX, nla,
							  p4tc_tinst_policy, extack);

			if (ret < 0)
				return ret;
		}
		tclass = tclass_find(pipeline, tb[P4TC_TINST_CLASS],
				     ids[P4TC_TBCID_IDX], extack);
		if (IS_ERR(tclass))
			return PTR_ERR(tclass);
		ctx->ids[P4TC_TBCID_IDX] = tclass->tbc_id;
	} else {
		tclass = idr_find(&pipeline->p_tbc_idr, ctx->ids[P4TC_TBCID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return tcf_p4_tmpl_generic_dump(skb, ctx, &tclass->tbc_ti_idr,
					P4TC_TIID_IDX, extack);
}

static int tcf_tinst_dump_1(struct sk_buff *skb,
			    struct p4tc_template_common *common)
{
	struct p4tc_table_instance *tinst = to_tinst(common);
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	unsigned char *b = skb_tail_pointer(skb);
	u32 path[P4TC_PATH_MAX - 1];

	if (!param)
		goto out_nlmsg_trim;
	if (nla_put_string(skb, P4TC_TINST_NAME, tinst->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	path[P4TC_TBCID_IDX - 1] = tinst->tbc_id;
	path[P4TC_TIID_IDX - 1] = tinst->ti_id;

	if (nla_put(skb, P4TC_PATH, sizeof(u32) * (P4TC_PATH_MAX - 1), path))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

const struct p4tc_template_ops p4tc_tinst_ops = {
	.cu = tcf_tinst_cu,
	.gd = tcf_tinst_gd,
	.put = tcf_tinst_put,
	.fill_nlmsg = tcf_tinst_fill_nlmsg,
	.dump = tcf_tinst_dump,
	.dump_1 = tcf_tinst_dump_1,
};
