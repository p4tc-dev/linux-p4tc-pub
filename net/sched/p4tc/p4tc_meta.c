// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_meta.c	P4 TC API METADATA
 *
 * Copyright (c) 2022-2023, Mojatatu Networks
 * Copyright (c) 2022-2023, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <asm/byteorder.h>
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
#include <net/p4tc_types.h>

#define START_META_OFFSET 0

static const struct nla_policy p4tc_meta_policy[P4TC_META_MAX + 1] = {
	[P4TC_META_NAME] = { .type = NLA_STRING, .len = METANAMSIZ },
	[P4TC_META_SIZE] = { .type = NLA_BINARY,
			     .len = sizeof(struct p4tc_meta_size_params) },
};

static int _tcf_meta_put(struct p4tc_pipeline *pipeline,
			 struct p4tc_metadata *meta, bool unconditional_purge,
			 struct netlink_ext_ack *extack)
{
	if (!unconditional_purge && !refcount_dec_if_one(&meta->m_ref))
		return -EBUSY;

	pipeline->p_meta_offset -= BITS_TO_U32(meta->m_sz) * sizeof(u32);
	idr_remove(&pipeline->p_meta_idr, meta->m_id);

	kfree_rcu(meta, rcu);

	return 0;
}

static int tcf_meta_put(struct net *net, struct p4tc_template_common *template,
			bool unconditional_purge,
			struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		tcf_pipeline_find_byid(net, template->p_id);
	struct p4tc_metadata *meta = to_meta(template);
	int ret;

	ret = _tcf_meta_put(pipeline, meta, unconditional_purge, extack);
	if (ret < 0)
		NL_SET_ERR_MSG(extack, "Unable to delete referenced metadatum");

	return ret;
}

struct p4tc_metadata *tcf_meta_find_byid(struct p4tc_pipeline *pipeline,
					 u32 m_id)
{
	return idr_find(&pipeline->p_meta_idr, m_id);
}

static struct p4tc_metadata *
tcf_meta_find_byname(const char *m_name, struct p4tc_pipeline *pipeline)
{
	struct p4tc_metadata *meta;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_meta_idr, meta, tmp, id)
		if (strncmp(meta->common.name, m_name, METANAMSIZ) == 0)
			return meta;

	return NULL;
}

static inline struct p4tc_metadata *
tcf_meta_find_byname_attr(struct nlattr *name_attr,
			  struct p4tc_pipeline *pipeline)
{
	return tcf_meta_find_byname(nla_data(name_attr), pipeline);
}

static struct p4tc_metadata *tcf_meta_find_byany(struct p4tc_pipeline *pipeline,
						 const char *mname,
						 const u32 m_id,
						 struct netlink_ext_ack *extack)
{
	struct p4tc_metadata *meta;
	int err;

	if (m_id) {
		meta = tcf_meta_find_byid(pipeline, m_id);
		if (!meta) {
			NL_SET_ERR_MSG(extack,
				       "Unable to find metadatum by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (mname) {
			meta = tcf_meta_find_byname(mname, pipeline);
			if (!meta) {
				NL_SET_ERR_MSG(extack,
					       "Metadatum name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify metadatum name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return meta;
out:
	return ERR_PTR(err);
}

struct p4tc_metadata *tcf_meta_get(struct p4tc_pipeline *pipeline,
				   const char *mname, const u32 m_id,
				   struct netlink_ext_ack *extack)
{
	struct p4tc_metadata *meta;

	meta = tcf_meta_find_byany(pipeline, mname, m_id, extack);
	if (IS_ERR(meta))
		return meta;

	/* Should never be zero */
	WARN_ON(!refcount_inc_not_zero(&meta->m_ref));
	return meta;
}

void tcf_meta_put_ref(struct p4tc_metadata *meta)
{
	WARN_ON(!refcount_dec_not_one(&meta->m_ref));
}

static struct p4tc_metadata *
tcf_meta_find_byanyattr(struct p4tc_pipeline *pipeline,
			struct nlattr *name_attr, const u32 m_id,
			struct netlink_ext_ack *extack)
{
	char *mname = NULL;

	if (name_attr)
		mname = nla_data(name_attr);

	return tcf_meta_find_byany(pipeline, mname, m_id, extack);
}

static int p4tc_check_meta_size(struct p4tc_meta_size_params *sz_params,
				struct p4tc_type *type,
				struct netlink_ext_ack *extack)
{
	int new_bitsz;

	if (sz_params->startbit > P4T_MAX_BITSZ ||
	    sz_params->startbit > type->bitsz) {
		NL_SET_ERR_MSG(extack, "Startbit value too big");
		return -EINVAL;
	}

	if (sz_params->endbit > P4T_MAX_BITSZ ||
	    sz_params->endbit > type->bitsz) {
		NL_SET_ERR_MSG(extack, "Endbit value too big");
		return -EINVAL;
	}

	if (sz_params->endbit < sz_params->startbit) {
		NL_SET_ERR_MSG(extack, "Endbit value smaller than startbit");
		return -EINVAL;
	}

	new_bitsz = (sz_params->endbit - sz_params->startbit + 1);
	if (new_bitsz == 0) {
		NL_SET_ERR_MSG(extack, "Bit size can't be zero");
		return -EINVAL;
	}

	if (new_bitsz > P4T_MAX_BITSZ || new_bitsz > type->bitsz) {
		NL_SET_ERR_MSG(extack, "Bit size too big");
		return -EINVAL;
	}

	return new_bitsz;
}

void tcf_meta_fill_user_offsets(struct p4tc_pipeline *pipeline)
{
	u32 meta_off = START_META_OFFSET;
	struct p4tc_metadata *meta;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_meta_idr, meta, tmp, id) {
		/* Offsets are multiples of 4 for alignment purposes */
		meta->m_skb_off = meta_off;
		meta_off += BITS_TO_U32(meta->m_sz) * sizeof(u32);
	}
}

static struct p4tc_metadata *
__tcf_meta_create(struct p4tc_pipeline *pipeline, u32 m_id, const char *m_name,
		  struct p4tc_meta_size_params *sz_params, gfp_t alloc_flag,
		  bool read_only, struct netlink_ext_ack *extack)
{
	u32 p_meta_offset = 0;
	bool kmeta;
	struct p4tc_metadata *meta;
	struct p4tc_type *datatype;
	u32 sz_bytes;
	int sz_bits;
	int ret;

	kmeta = pipeline->common.p_id == P4TC_KERNEL_PIPEID;

	meta = kzalloc(sizeof(*meta), alloc_flag);
	if (!meta) {
		if (kmeta)
			pr_err("Unable to allocate kernel metadatum");
		else
			NL_SET_ERR_MSG(extack,
				       "Unable to allocate user metadatum");
		ret = -ENOMEM;
		goto out;
	}

	meta->common.p_id = pipeline->common.p_id;

	datatype = p4type_find_byid(sz_params->datatype);
	if (!datatype) {
		if (kmeta)
			pr_err("Invalid data type for kernel metadataum %u\n",
			       sz_params->datatype);
		else
			NL_SET_ERR_MSG(extack,
				       "Invalid data type for user metdatum");
		ret = -EINVAL;
		goto free;
	}

	sz_bits = p4tc_check_meta_size(sz_params, datatype, extack);
	if (sz_bits < 0) {
		ret = sz_bits;
		goto free;
	}

	sz_bytes = BITS_TO_U32(datatype->bitsz) * sizeof(u32);
	if (!kmeta) {
		p_meta_offset = pipeline->p_meta_offset + sz_bytes;
		if (p_meta_offset > BITS_TO_BYTES(P4TC_MAXMETA_OFFSET)) {
			NL_SET_ERR_MSG(extack, "Metadata max offset exceeded");
			ret = -EINVAL;
			goto free;
		}
	}

	meta->m_datatype = datatype->typeid;
	meta->m_startbit = sz_params->startbit;
	meta->m_endbit = sz_params->endbit;
	meta->m_sz = sz_bits;
	meta->m_read_only = read_only;

	if (m_id) {
		ret = idr_alloc_u32(&pipeline->p_meta_idr, meta, &m_id, m_id,
				    alloc_flag);
		if (ret < 0) {
			if (kmeta)
				pr_err("Unable to alloc kernel metadatum id %u\n",
				       m_id);
			else
				NL_SET_ERR_MSG(extack,
					       "Unable to alloc user metadatum id");
			goto free;
		}

		meta->m_id = m_id;
	} else {
		meta->m_id = 1;

		ret = idr_alloc_u32(&pipeline->p_meta_idr, meta, &meta->m_id,
				    UINT_MAX, alloc_flag);
		if (ret < 0) {
			if (kmeta)
				pr_err("Unable to alloc kernel metadatum id %u\n",
				       meta->m_id);
			else
				NL_SET_ERR_MSG(extack,
					       "Unable to alloc metadatum id");
			goto free;
		}
	}

	if (!kmeta)
		pipeline->p_meta_offset = p_meta_offset;

	strscpy(meta->common.name, m_name, METANAMSIZ);
	meta->common.ops = (struct p4tc_template_ops *)&p4tc_meta_ops;

	refcount_set(&meta->m_ref, 1);

	return meta;

free:
	kfree(meta);
out:
	return ERR_PTR(ret);
}

struct p4tc_metadata *tcf_meta_create(struct nlmsghdr *n, struct nlattr *nla,
				      u32 m_id, struct p4tc_pipeline *pipeline,
				      struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct p4tc_meta_size_params *sz_params;
	struct nlattr *tb[P4TC_META_MAX + 1];
	char *m_name;

	ret = nla_parse_nested(tb, P4TC_META_MAX, nla, p4tc_meta_policy,
			       extack);
	if (ret < 0)
		goto out;

	if (tcf_meta_find_byname_attr(tb[P4TC_META_NAME], pipeline) ||
	    tcf_meta_find_byid(pipeline, m_id)) {
		NL_SET_ERR_MSG(extack, "Metadatum already exists");
		ret = -EEXIST;
		goto out;
	}

	if (tb[P4TC_META_NAME]) {
		m_name = nla_data(tb[P4TC_META_NAME]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify metadatum name");
		ret = -ENOENT;
		goto out;
	}

	if (tb[P4TC_META_SIZE]) {
		sz_params = nla_data(tb[P4TC_META_SIZE]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify metadatum size params");
		ret = -ENOENT;
		goto out;
	}

	return __tcf_meta_create(pipeline, m_id, m_name, sz_params, GFP_KERNEL,
				 false, extack);

out:
	return ERR_PTR(ret);
}

static struct p4tc_metadata *tcf_meta_update(struct nlmsghdr *n,
					     struct nlattr *nla, u32 m_id,
					     struct p4tc_pipeline *pipeline,
					     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_META_MAX + 1];
	struct p4tc_metadata *meta;
	int ret;

	ret = nla_parse_nested(tb, P4TC_META_MAX, nla, p4tc_meta_policy,
			       extack);

	if (ret < 0)
		goto out;

	meta = tcf_meta_find_byanyattr(pipeline, tb[P4TC_META_NAME], m_id,
				       extack);
	if (IS_ERR(meta))
		return meta;

	if (tb[P4TC_META_SIZE]) {
		struct p4tc_type *new_datatype, *curr_datatype;
		struct p4tc_meta_size_params *sz_params;
		u32 new_bytesz, curr_bytesz;
		int new_bitsz;
		u32 p_meta_offset;
		int diff;

		sz_params = nla_data(tb[P4TC_META_SIZE]);
		new_datatype = p4type_find_byid(sz_params->datatype);
		if (!new_datatype) {
			NL_SET_ERR_MSG(extack, "Invalid data type");
			ret = -EINVAL;
			goto out;
		}

		new_bitsz =
			p4tc_check_meta_size(sz_params, new_datatype, extack);
		if (new_bitsz < 0) {
			ret = new_bitsz;
			goto out;
		}

		new_bytesz = BITS_TO_U32(new_datatype->bitsz) * sizeof(u32);

		curr_datatype = p4type_find_byid(meta->m_datatype);
		curr_bytesz = BITS_TO_U32(curr_datatype->bitsz) * sizeof(u32);

		diff = new_bytesz - curr_bytesz;
		p_meta_offset = pipeline->p_meta_offset + diff;
		if (p_meta_offset > BITS_TO_BYTES(P4TC_MAXMETA_OFFSET)) {
			NL_SET_ERR_MSG(extack, "Metadata max offset exceeded");
			ret = -EINVAL;
			goto out;
		}

		pipeline->p_meta_offset = p_meta_offset;

		meta->m_datatype = new_datatype->typeid;
		meta->m_startbit = sz_params->startbit;
		meta->m_endbit = sz_params->endbit;
		meta->m_sz = new_bitsz;
	}

	return meta;

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_meta_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	    struct p4tc_nl_pname *nl_pname, u32 *ids,
	    struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], m_id = ids[P4TC_MID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;

	pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data, pipeid,
						    extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		meta = tcf_meta_update(n, nla, m_id, pipeline, extack);
	else
		meta = tcf_meta_create(n, nla, m_id, pipeline, extack);

	if (IS_ERR(meta))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)meta;
}

static int _tcf_meta_fill_nlmsg(struct sk_buff *skb,
				const struct p4tc_metadata *meta)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_meta_size_params sz_params;
	struct nlattr *nest;

	if (nla_put_u32(skb, P4TC_PATH, meta->m_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	sz_params.datatype = meta->m_datatype;
	sz_params.startbit = meta->m_startbit;
	sz_params.endbit = meta->m_endbit;

	if (nla_put_string(skb, P4TC_META_NAME, meta->common.name))
		goto out_nlmsg_trim;
	if (nla_put(skb, P4TC_META_SIZE, sizeof(sz_params), &sz_params))
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_meta_fill_nlmsg(struct net *net, struct sk_buff *skb,
			       struct p4tc_template_common *template,
			       struct netlink_ext_ack *extack)
{
	const struct p4tc_metadata *meta = to_meta(template);

	if (_tcf_meta_fill_nlmsg(skb, meta) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for metadatum");
		return -EINVAL;
	}

	return 0;
}

static int tcf_meta_flush(struct sk_buff *skb, struct p4tc_pipeline *pipeline,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_metadata *meta;
	unsigned long tmp, m_id;
	unsigned char *b = nlmsg_get_pos(skb);
	int ret = 0;
	int i = 0;

	if (nla_put_u32(skb, P4TC_PATH, 0))
		goto out_nlmsg_trim;

	if (idr_is_empty(&pipeline->p_meta_idr)) {
		NL_SET_ERR_MSG(extack, "There is not metadata to flush");
		ret = 0;
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&pipeline->p_meta_idr, meta, tmp, m_id) {
		if (_tcf_meta_put(pipeline, meta, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack, "Unable to flush any metadata");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack, "Unable to flush all metadata");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_meta_gd(struct net *net, struct sk_buff *skb, struct nlmsghdr *n,
		       struct nlattr *nla, struct p4tc_nl_pname *nl_pname,
		       u32 *ids, struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], m_id = ids[P4TC_MID_IDX];
	struct nlattr *tb[P4TC_META_MAX + 1] = {};
	unsigned char *b = nlmsg_get_pos(skb);
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data,
							    pipeid, extack);
	else
		pipeline = tcf_pipeline_find_byany(net, nl_pname->data, pipeid,
						   extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_META_MAX, nla, p4tc_meta_policy,
				       extack);

		if (ret < 0)
			return ret;
	}

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_meta_flush(skb, pipeline, extack);

	meta = tcf_meta_find_byanyattr(pipeline, tb[P4TC_META_NAME], m_id,
				       extack);
	if (IS_ERR(meta))
		return PTR_ERR(meta);

	if (_tcf_meta_fill_nlmsg(skb, meta) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for metadatum");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _tcf_meta_put(pipeline, meta, false, extack);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete referenced metadatum");
			goto out_nlmsg_trim;
		}
	}

	return ret;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_meta_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			 struct nlattr *nla, char **p_name, u32 *ids,
			 struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	const u32 pipeid = ids[P4TC_PID_IDX];
	struct net *net = sock_net(skb->sk);
	unsigned long m_id = 0;
	int i = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;
	unsigned long tmp;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline =
			tcf_pipeline_find_byany(net, *p_name, pipeid, extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	m_id = ctx->ids[P4TC_MID_IDX];

	idr_for_each_entry_continue_ul(&pipeline->p_meta_idr, meta, tmp, m_id) {
		struct nlattr *count, *param;

		if (i == P4TC_MSGBATCH_SIZE)
			break;

		count = nla_nest_start(skb, i + 1);
		if (!count)
			goto out_nlmsg_trim;

		param = nla_nest_start(skb, P4TC_PARAMS);
		if (!param)
			goto out_nlmsg_trim;
		if (nla_put_string(skb, P4TC_META_NAME, meta->common.name))
			goto out_nlmsg_trim;

		nla_nest_end(skb, param);
		nla_nest_end(skb, count);

		i++;
	}

	if (i == 0) {
		if (!ctx->ids[P4TC_MID_IDX])
			NL_SET_ERR_MSG(extack, "There is no metadata to dump");
		return 0;
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	ctx->ids[P4TC_MID_IDX] = m_id;

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int __p4tc_register_kmeta(struct p4tc_pipeline *pipeline, u32 m_id,
				 const char *m_name, u8 startbit, u8 endbit,
				 bool read_only, u32 datatype)
{
	struct p4tc_meta_size_params sz_params = {
		.startbit = startbit,
		.endbit = endbit,
		.datatype = datatype,
	};
	struct p4tc_metadata *meta;

	meta = __tcf_meta_create(pipeline, m_id, m_name, &sz_params, GFP_ATOMIC,
				 read_only, NULL);
	if (IS_ERR(meta)) {
		pr_err("Failed to register metadata %s %ld\n", m_name,
		       PTR_ERR(meta));
		return PTR_ERR(meta);
	}

	pr_debug("Registered kernel metadata %s with id %u\n", m_name, m_id);

	return 0;
}

#define p4tc_register_kmeta(...)                            \
	do {                                                \
		if (__p4tc_register_kmeta(__VA_ARGS__) < 0) \
			return;                             \
	} while (0)

void tcf_meta_init(struct p4tc_pipeline *root_pipe)
{
	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PKTLEN, "pktlen", 0, 31,
			    false, P4T_U32);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_DATALEN, "datalen", 0,
			    31, false, P4T_U32);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_SKBMARK, "skbmark", 0,
			    31, false, P4T_U32);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_TCINDEX, "tcindex", 0,
			    15, false, P4T_U16);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_SKBHASH, "skbhash", 0,
			    31, false, P4T_U32);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_SKBPRIO, "skbprio", 0,
			    31, false, P4T_U32);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_IFINDEX, "ifindex", 0,
			    31, false, P4T_S32);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_SKBIIF, "iif", 0, 31,
			    true, P4T_DEV);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PROTOCOL, "skbproto", 0,
			    15, false, P4T_BE16);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PTYPEOFF, "ptypeoff", 0,
			    7, false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_CLONEOFF, "cloneoff", 0,
			    7, false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PTCLNOFF, "ptclnoff", 0,
			    15, false, P4T_U16);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_QMAP, "skbqmap", 0, 15,
			    false, P4T_U16);

#if defined(__LITTLE_ENDIAN_BITFIELD)
	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PKTYPE, "skbptype", 0,
			    2, false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_IDF, "skbidf", 3, 3,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_IPSUM, "skbipsum", 5, 6,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_OOOK, "skboook", 7, 7,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_FCLONE, "fclone", 2, 3,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PEEKED, "skbpeek", 4, 4,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_DIRECTION, "direction",
			    7, 7, false, P4T_U8);
#elif defined(__BIG_ENDIAN_BITFIELD)
	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PKTYPE, "skbptype", 5,
			    7, false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_IDF, "skbidf", 4, 4,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_IPSUM, "skbipsum", 1, 2,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_OOOK, "skboook", 0, 0,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_FCLONE, "fclone", 4, 5,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_PEEKED, "skbpeek", 3, 3,
			    false, P4T_U8);

	p4tc_register_kmeta(root_pipe, P4TC_KERNEL_META_DIRECTION, "direction",
			    0, 0, false, P4T_U8);
#else
#error "Please fix <asm/byteorder.h>"
#endif
}

const struct p4tc_template_ops p4tc_meta_ops = {
	.cu = tcf_meta_cu,
	.fill_nlmsg = tcf_meta_fill_nlmsg,
	.gd = tcf_meta_gd,
	.put = tcf_meta_put,
	.dump = tcf_meta_dump,
};
