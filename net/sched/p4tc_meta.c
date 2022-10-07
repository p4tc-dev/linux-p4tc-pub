// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_meta.c	P4 TC API METADATA
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
#include <net/p4_types.h>

#define START_META_OFFSET 0

static const struct nla_policy p4tc_meta_policy[P4TC_META_MAX + 1] = {
	[P4TC_META_NAME] = { .type = NLA_STRING, .len = METANAMSIZ },
	[P4TC_META_SIZE] = { .len = sizeof(struct p4tc_meta_size_params) },
};

static int _tcf_meta_put(struct p4tc_pipeline *pipeline,
			 struct p4tc_metadata *meta,
			 struct netlink_ext_ack *extack)
{
	if (!refcount_dec_if_one(&meta->m_ref))
		return -EBUSY;

	pipeline->p_meta_offset -= BITS_TO_U32(meta->m_sz) * sizeof(u32);
	idr_remove(&pipeline->p_meta_idr, meta->m_id);

	kfree_rcu(meta, rcu);

	return 0;
}

static int tcf_meta_put(struct net *net, struct p4tc_template_common *template,
			struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = tcf_pipeline_find_byid(template->p_id);
	struct p4tc_metadata *meta = to_meta(template);
	int ret;

	ret = _tcf_meta_put(pipeline, meta, extack);
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
tcf_meta_find_byname_attr(struct nlattr *name_attr, struct p4tc_pipeline *pipeline)
{
	return tcf_meta_find_byname(nla_data(name_attr), pipeline);
}

struct p4tc_metadata *
tcf_meta_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
	      const u32 m_id, struct netlink_ext_ack *extack)
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
		if (name_attr) {
			meta = tcf_meta_find_byname_attr(name_attr, pipeline);
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

static int verify_meta_size(struct p4tc_meta_size_params *sz_params,
			    struct p4_type *type, struct netlink_ext_ack *extack)
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
	if (!new_bitsz) {
		NL_SET_ERR_MSG(extack, "Bit size can't be zero");
		return -EINVAL;
	}

	if (new_bitsz > P4T_MAX_BITSZ || new_bitsz > type->bitsz) {
		NL_SET_ERR_MSG(extack, "Bit size too big");
		return -EINVAL;
	}

	return new_bitsz;
}

void tcf_meta_set_offsets(struct p4tc_pipeline *pipeline)
{
	u32 meta_off = START_META_OFFSET;
	struct p4tc_metadata *meta;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_meta_idr, meta, tmp, id) {
		/* Offsets are multiples of 4 for alignment purposes */
		meta->m_skb_off = meta_off;
		meta_off += BITS_TO_U32(meta->m_sz) << 2;
	}
}

static struct p4tc_metadata *
__tcf_meta_create(struct p4tc_pipeline *pipeline, u32 m_id,
		  const char *m_name, struct p4tc_meta_size_params *sz_params,
		  gfp_t alloc_flag, struct netlink_ext_ack *extack)
{
	u32 p_meta_offset = 0;
	bool called_for_kernel_meta;
	struct p4tc_metadata *meta;
	struct p4_type *datatype;
	u32 sz_bytes;
	int sz_bits;
	int ret;

	called_for_kernel_meta = pipeline->common.p_id == P4TC_KERNEL_PIPEID;

	meta = kzalloc(sizeof(*meta), alloc_flag);
	if (!meta) {
		if (called_for_kernel_meta)
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
		if (called_for_kernel_meta)
			pr_err("Invalid data type for kernel metadataum %u\n",
			       sz_params->datatype);
		else
			NL_SET_ERR_MSG(extack,
				       "Invalid data type for user metdatum");
		ret = -EINVAL;
		goto free;
	}

	sz_bits = verify_meta_size(sz_params, datatype, extack);
	if (sz_bits < 0) {
		ret = sz_bits;
		goto free;
	}

	sz_bytes = BITS_TO_U32(datatype->bitsz) << 2;
	if (!called_for_kernel_meta) {
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

	if (m_id) {
		ret = idr_alloc_u32(&pipeline->p_meta_idr, meta, &m_id,
				    m_id, alloc_flag);
		if (ret < 0) {
			if (called_for_kernel_meta)
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
			if (called_for_kernel_meta)
				pr_err("Unable to alloc kernel metadatum id %u\n",
				       meta->m_id);
			else
				NL_SET_ERR_MSG(extack, "Unable to alloc metadatum id");
			goto free;
		}
	}
	if (!called_for_kernel_meta)
		pipeline->p_meta_offset = p_meta_offset;

	meta->common.ops = (struct p4tc_template_ops *)&p4tc_meta_ops;
	strscpy(meta->common.name, m_name, METANAMSIZ);

	refcount_set(&meta->m_ref, 1);

	return meta;

free:
	kfree(meta);
out:
	return ERR_PTR(ret);
}

struct p4tc_metadata *
tcf_meta_create(struct nlmsghdr *n, struct nlattr *nla, u32 m_id,
		struct p4tc_pipeline *pipeline, struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct p4tc_meta_size_params *sz_params;
	struct nlattr *tb[P4TC_META_MAX + 1];
	char *m_name;

	ret = nla_parse_nested_deprecated(tb, P4TC_META_MAX, nla,
					  p4tc_meta_policy, extack);
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
				 extack);

out:
	return ERR_PTR(ret);
}

static struct p4tc_metadata *
tcf_meta_update(struct nlmsghdr *n, struct nlattr *nla, u32 m_id,
		struct p4tc_pipeline *pipeline, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_META_MAX + 1];
	struct p4tc_metadata *meta;
	int ret;

	ret = nla_parse_nested_deprecated(tb, P4TC_META_MAX, nla,
					  p4tc_meta_policy, extack);

	if (ret < 0)
		goto out;

	meta = tcf_meta_find_byany(pipeline, tb[P4TC_META_NAME], m_id, extack);
	if (IS_ERR(meta))
		return meta;

	if (tb[P4TC_META_SIZE]) {
		struct p4_type *new_datatype, *curr_datatype;
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

		new_bitsz = verify_meta_size(sz_params, new_datatype, extack);
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
	    char **p_name, u32 *ids, struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], m_id = ids[P4TC_MID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;

	pipeline = tcf_pipeline_find_byany_unsealed(*p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		meta = tcf_meta_update(n, nla, m_id, pipeline, extack);
	else
		meta = tcf_meta_create(n, nla, m_id, pipeline, extack);

	if (IS_ERR(meta))
		goto out;

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)meta;
}

static int _tcf_meta_fill_nlmsg(struct sk_buff *skb,
				const struct p4tc_metadata *meta)
{
	unsigned char *b = skb_tail_pointer(skb);
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

static int tcf_meta_flush(struct sk_buff *skb,
			  struct p4tc_pipeline *pipeline,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_metadata *meta;
	unsigned long tmp, m_id;
	unsigned char *b = skb_tail_pointer(skb);
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
		if (_tcf_meta_put(pipeline, meta, extack) < 0) {
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
		       struct nlattr *nla,  char **p_name, u32 *ids,
		       struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], m_id = ids[P4TC_MID_IDX];
	struct nlattr *tb[P4TC_META_MAX + 1] = {};
	unsigned char *b = skb_tail_pointer(skb);
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)
		pipeline = tcf_pipeline_find_byany_unsealed(*p_name, pipeid, extack);
	else
		pipeline = tcf_pipeline_find_byany(*p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested_deprecated(tb, P4TC_META_MAX, nla,
						  p4tc_meta_policy, extack);

		if (ret < 0)
			return ret;
	}

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_meta_flush(skb, pipeline, extack);

	meta = tcf_meta_find_byany(pipeline, tb[P4TC_META_NAME], m_id, extack);
	if (IS_ERR(meta))
		return PTR_ERR(meta);

	if (_tcf_meta_fill_nlmsg(skb, meta) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for metadatum");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE)  {
		ret = _tcf_meta_put(pipeline, meta, extack);
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

static int tcf_meta_dump(struct sk_buff *skb,
			 struct p4tc_dump_ctx *ctx,
			 struct nlattr *nla,
			 char **p_name, u32 *ids,
			 struct netlink_ext_ack *extack)
{
	unsigned char *b = skb_tail_pointer(skb);
	const u32 pipeid = ids[P4TC_PID_IDX];
	unsigned long m_id = 0;
	int i = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_metadata *meta;
	unsigned long tmp;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = tcf_pipeline_find_byany(*p_name, pipeid, extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(ctx->ids[P4TC_PID_IDX]);
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
		if (nla_put_string(skb, P4TC_META_NAME,
				   meta->common.name)) {
			goto out_nlmsg_trim;
		}

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

static int register_kernel_meta(struct p4tc_pipeline *pipeline, u32 m_id,
				const char *m_name, u8 startbit, u8 endbit,
				u32 datatype)
{
	struct p4tc_meta_size_params sz_params;
	struct p4tc_metadata *meta;

	sz_params.startbit = startbit;
	sz_params.endbit = endbit;
	sz_params.datatype = datatype;

	meta = __tcf_meta_create(pipeline, m_id, m_name, &sz_params, GFP_ATOMIC,
				 NULL);
	if (IS_ERR(meta)) {
		pr_err("Error in metadata create %ld\n", PTR_ERR(meta));
		return PTR_ERR(meta);
	}
	pr_info("Registered kernel metadata %s with id %u\n", m_name, m_id);

	return 0;
}

#define REGISTER_KERNEL_META(pipeline, m_id, m_name, startbit, endbit, datatype) \
	do { \
		if (register_kernel_meta(pipeline, m_id, m_name, startbit, endbit, datatype)) { \
			pr_err("Failed to register kernel metadatum %s\n", m_name); \
			return; \
		} \
	} while (0)

static void tcf_meta_init(void)
{
	struct p4tc_pipeline *pipeline;

	pipeline = tcf_pipeline_find_byid(0);
	if (!pipeline) {
		pr_err("Kernel pipeline was not registered\n");
		return;
	}

	REGISTER_KERNEL_META(pipeline, METACT_LMETA_PKTLEN, "pktlen", 0, 31,
			     P4T_U32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_DATALEN, "datalen", 0, 31,
			     P4T_U32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_SKBMARK, "skbmark", 0, 31,
			     P4T_U32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_TCINDEX, "tcindex", 0, 15,
			     P4T_U16);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_SKBHASH, "skbhash", 0, 31,
			     P4T_U32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_SKBPRIO, "skbprio", 0, 31,
			     P4T_U32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_IFINDEX, "ifindex", 0, 31,
			     P4T_S32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_SKBIIF, "skbiif", 0, 31,
			     P4T_S32);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_PROTOCOL, "protocol", 0, 15,
			     P4T_BE16);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_PKTYPE, "pktype", 0, 2,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_IDF, "idf", 3, 3,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_IPSUM, "ipsum", 5, 6,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_OOOK, "oook", 7, 7,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_FCLONE, "fclone", 2, 3,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_PEEKED, "peeked", 4, 4,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_QMAP, "qmap", 0, 15,
			     P4T_U16);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_PTYPEOFF, "ptypeoff", 0, 7,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_CLONEOFF, "cloneoff", 0, 7,
			     P4T_U8);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_PTCLNOFF, "ptclnoff", 0, 15,
			     P4T_U16);
	REGISTER_KERNEL_META(pipeline, METACT_LMETA_DIRECTION, "direction", 7, 7,
			     P4T_U8);
}

const struct p4tc_template_ops p4tc_meta_ops = {
	.init = tcf_meta_init,
	.cu = tcf_meta_cu,
	.fill_nlmsg = tcf_meta_fill_nlmsg,
	.gd = tcf_meta_gd,
	.put = tcf_meta_put,
	.dump = tcf_meta_dump,
};
