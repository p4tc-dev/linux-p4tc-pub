// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_hdrfield.c	P4 TC HEADER FIELD
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

static const struct nla_policy tc_hdrfield_policy[P4TC_HDRFIELD_MAX + 1] = {
	[P4TC_HDRFIELD_DATA] =
		NLA_POLICY_EXACT_LEN(sizeof(struct p4tc_hdrfield_type)),
	[P4TC_HDRFIELD_NAME] = { .type = NLA_STRING, .len = HDRFIELDNAMSIZ },
	[P4TC_HDRFIELD_PARSER_NAME] = { .type = NLA_STRING,
					.len = PARSERNAMSIZ },
};

static int __p4tc_hdrfield_put(struct p4tc_pipeline *pipeline,
			       struct p4tc_hdrfield *hdrfield, bool teardown,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;

	if (!teardown && !p4tc_hdrfield_put_ref(hdrfield)) {
		NL_SET_ERR_MSG(extack,
			       "Unable to delete referenced header field");
		return -EBUSY;
	}

	parser = pipeline->parser;
	idr_remove(&parser->hdrfield_idr, hdrfield->hdrfield_id);
	tcf_parser_put(parser);

	kfree(hdrfield);

	return 0;
}

static int p4tc_hdrfield_put(struct p4tc_pipeline *pipeline,
			     struct p4tc_template_common *tmpl,
			     struct netlink_ext_ack *extack)
{
	struct p4tc_hdrfield *hdrfield;

	hdrfield = to_hdrfield(tmpl);

	return __p4tc_hdrfield_put(pipeline, hdrfield, true, extack);
}

static struct p4tc_hdrfield *hdrfield_find_name(struct p4tc_parser *parser,
						const char *hdrfield_name)
{
	struct p4tc_hdrfield *hdrfield;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&parser->hdrfield_idr, hdrfield, tmp, id)
		if (strncmp(hdrfield->common.name, hdrfield_name,
			    HDRFIELDNAMSIZ) == 0)
			return hdrfield;

	return NULL;
}

struct p4tc_hdrfield *p4tc_hdrfield_find_byid(struct p4tc_parser *parser,
					      const u32 hdrfield_id)
{
	return idr_find(&parser->hdrfield_idr, hdrfield_id);
}

struct p4tc_hdrfield *p4tc_hdrfield_find_byany(struct p4tc_parser *parser,
					       const char *hdrfield_name,
					       u32 hdrfield_id,
					       struct netlink_ext_ack *extack)
{
	struct p4tc_hdrfield *hdrfield;
	int err;

	if (hdrfield_id) {
		hdrfield = p4tc_hdrfield_find_byid(parser, hdrfield_id);
		if (!hdrfield) {
			NL_SET_ERR_MSG(extack, "Unable to find hdrfield by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (hdrfield_name) {
			hdrfield = hdrfield_find_name(parser, hdrfield_name);
			if (!hdrfield) {
				NL_SET_ERR_MSG(extack,
					       "Header field name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify hdrfield name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return hdrfield;

out:
	return ERR_PTR(err);
}

struct p4tc_hdrfield *p4tc_hdrfield_find_get(struct p4tc_parser *parser,
					     const char *hdrfield_name,
					     u32 hdrfield_id,
					     struct netlink_ext_ack *extack)
{
	struct p4tc_hdrfield *hdrfield;

	hdrfield = p4tc_hdrfield_find_byany(parser, hdrfield_name, hdrfield_id,
					    extack);
	if (IS_ERR(hdrfield))
		return hdrfield;

	if (!refcount_inc_not_zero(&hdrfield->hdrfield_ref)) {
		NL_SET_ERR_MSG(extack, "Header field is stale");
		return ERR_PTR(-EINVAL);
	}

	return hdrfield;
}

static struct p4tc_hdrfield *
p4tc_hdrfield_find_byanyattr(struct p4tc_parser *parser,
			     struct nlattr *name_attr, u32 hdrfield_id,
			     struct netlink_ext_ack *extack)
{
	char *hdrfield_name = NULL;

	if (name_attr)
		hdrfield_name = nla_data(name_attr);

	return p4tc_hdrfield_find_byany(parser, hdrfield_name, hdrfield_id,
					extack);
}

static struct p4tc_hdrfield *p4tc_hdrfield_create(struct nlmsghdr *n,
						  struct nlattr *nla,
						  struct p4tc_pipeline *pipeline,
						  u32 *ids,
						  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_HDRFIELD_MAX + 1];
	u32 parser_id = ids[P4TC_PARSEID_IDX];
	struct p4tc_hdrfield_type *hdr_arg;
	const char *parser_name = NULL;
	struct p4tc_hdrfield *hdrfield;
	struct p4tc_parser *parser;
	char *hdrfield_name = NULL;
	u32 hdrfield_id = 0;
	char *s;
	int ret;

	ret = nla_parse_nested(tb, P4TC_HDRFIELD_MAX, nla, tc_hdrfield_policy,
			       extack);
	if (ret < 0)
		return ERR_PTR(ret);

	hdrfield_id = ids[P4TC_HDRFIELDID_IDX];
	if (!hdrfield_id) {
		NL_SET_ERR_MSG(extack, "Must specify header field id");
		return ERR_PTR(-EINVAL);
	}

	if (NL_REQ_ATTR_CHECK(extack, nla, tb, P4TC_HDRFIELD_DATA)) {
		NL_SET_ERR_MSG(extack, "Must supply header field data");
		return ERR_PTR(-EINVAL);
	}

	hdr_arg = nla_data(tb[P4TC_HDRFIELD_DATA]);

	if (tb[P4TC_HDRFIELD_PARSER_NAME])
		parser_name = nla_data(tb[P4TC_HDRFIELD_PARSER_NAME]);

	rcu_read_lock();
	parser = tcf_parser_find_get(pipeline, parser_name, parser_id, NULL);
	rcu_read_unlock();
	if (IS_ERR(parser)) {
		if (!parser_name) {
			NL_SET_ERR_MSG(extack, "Must supply parser name");
			return ERR_PTR(-EINVAL);
		}

		/* If the parser instance wasn't created, let's create it here */
		parser = tcf_parser_create(pipeline, parser_name, parser_id,
					   extack);

		if (IS_ERR(parser))
			return (void *)parser;
	}

	if (tb[P4TC_HDRFIELD_NAME])
		hdrfield_name = nla_data(tb[P4TC_HDRFIELD_NAME]);

	if (IS_ERR(p4tc_hdrfield_find_byany(parser, hdrfield_name, hdrfield_id,
					    extack))) {
		NL_SET_ERR_MSG(extack, "Header field exists");
		ret = -EEXIST;
		goto put_parser;
	}

	if (hdr_arg->startbit > hdr_arg->endbit) {
		NL_SET_ERR_MSG(extack, "Header field startbit > endbit");
		ret = -EINVAL;
		goto put_parser;
	}

	hdrfield = kzalloc(sizeof(*hdrfield), GFP_KERNEL);
	if (!hdrfield) {
		NL_SET_ERR_MSG(extack, "Failed to allocate hdrfield");
		ret = -ENOMEM;
		goto put_parser;
	}

	hdrfield->hdrfield_id = hdrfield_id;

	s = strnchr(hdrfield_name, HDRFIELDNAMSIZ, '/');
	if (s++ && strncmp(s, "isValid", HDRFIELDNAMSIZ) == 0) {
		if (hdr_arg->datatype != P4T_U8 || hdr_arg->startbit != 0 ||
		    hdr_arg->endbit != 0) {
			NL_SET_ERR_MSG(extack,
				       "isValid data type must be bit1");
			ret = -EINVAL;
			goto free_hdr;
		}
		hdrfield->datatype = hdr_arg->datatype;
		hdrfield->flags = P4TC_HDRFIELD_IS_VALIDITY_BIT;
	} else {
		if (!p4type_find_byid(hdr_arg->datatype)) {
			NL_SET_ERR_MSG(extack, "Invalid hdrfield data type");
			ret = -EINVAL;
			goto free_hdr;
		}
		hdrfield->datatype = hdr_arg->datatype;
	}

	hdrfield->startbit = hdr_arg->startbit;
	hdrfield->endbit = hdr_arg->endbit;

	ret = idr_alloc_u32(&parser->hdrfield_idr, hdrfield, &hdrfield_id,
			    hdrfield_id, GFP_KERNEL);
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate ID for hdrfield");
		goto free_hdr;
	}

	hdrfield->common.p_id = pipeline->common.p_id;
	hdrfield->common.ops = (struct p4tc_template_ops *)&p4tc_hdrfield_ops;
	hdrfield->parser = parser;
	refcount_set(&hdrfield->hdrfield_ref, 1);

	if (hdrfield_name)
		strscpy(hdrfield->common.name, hdrfield_name, HDRFIELDNAMSIZ);

	return hdrfield;

free_hdr:
	kfree(hdrfield);

put_parser:
	tcf_parser_put(parser);
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_hdrfield_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		 struct p4tc_nl_pname *nl_pname, u32 *ids,
		 struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_hdrfield *hdrfield;
	struct p4tc_pipeline *pipeline;

	if (p4tc_tmpl_msg_is_update(n)) {
		NL_SET_ERR_MSG(extack, "Header field update not supported");
		return ERR_PTR(-EOPNOTSUPP);
	}

	pipeline = p4tc_pipeline_find_byany_unsealed(net, nl_pname->data, pipeid,
						     extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	hdrfield = p4tc_hdrfield_create(n, nla, pipeline, ids, extack);
	if (IS_ERR(hdrfield))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)hdrfield;
}

static int _p4tc_hdrfield_fill_nlmsg(struct sk_buff *skb,
				     struct p4tc_hdrfield *hdrfield)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_hdrfield_type hdr_arg = {0};
	struct nlattr *nest;
	/* Parser instance id + header field id */
	u32 ids[2];

	ids[0] = hdrfield->parser->parser_id;
	ids[1] = hdrfield->hdrfield_id;

	if (nla_put(skb, P4TC_PATH, sizeof(ids), ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	hdr_arg.datatype = hdrfield->datatype;
	hdr_arg.startbit = hdrfield->startbit;
	hdr_arg.endbit = hdrfield->endbit;

	if (hdrfield->common.name[0]) {
		if (nla_put_string(skb, P4TC_HDRFIELD_NAME,
				   hdrfield->common.name))
			goto out_nlmsg_trim;
	}

	if (nla_put(skb, P4TC_HDRFIELD_DATA, sizeof(hdr_arg), &hdr_arg))
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int p4tc_hdrfield_fill_nlmsg(struct net *net, struct sk_buff *skb,
				    struct p4tc_template_common *template,
				    struct netlink_ext_ack *extack)
{
	struct p4tc_hdrfield *hdrfield = to_hdrfield(template);

	if (_p4tc_hdrfield_fill_nlmsg(skb, hdrfield) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for pipeline");
		return -EINVAL;
	}

	return 0;
}

static int p4tc_hdrfield_flush(struct sk_buff *skb,
			       struct p4tc_pipeline *pipeline,
			       struct p4tc_parser *parser,
			       struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_hdrfield *hdrfield;
	unsigned long tmp, hdrfield_id;
	int ret = 0;
	u32 path[2];
	int i = 0;

	path[0] = parser->parser_id;
	path[1] = 0;

	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	if (idr_is_empty(&parser->hdrfield_idr)) {
		NL_SET_ERR_MSG(extack, "There are no header fields to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&parser->hdrfield_idr, hdrfield, tmp,
			      hdrfield_id) {
		if (__p4tc_hdrfield_put(pipeline, hdrfield, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any header fields");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG_FMT(extack,
					   "Flush only %u header fields", i);
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return 0;
}

static int p4tc_hdrfield_gd(struct net *net, struct sk_buff *skb,
			    struct nlmsghdr *n, struct nlattr *nla,
			    struct p4tc_nl_pname *nl_pname, u32 *ids,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_HDRFIELD_MAX + 1] = {NULL};
	u32 parser_inst_id = ids[P4TC_PARSEID_IDX];
	u32 hdrfield_id = ids[P4TC_HDRFIELDID_IDX];
	unsigned char *b = nlmsg_get_pos(skb);
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_hdrfield *hdrfield;
	struct p4tc_pipeline *pipeline;
	struct p4tc_parser *parser;
	char *parser_name;
	int ret;

	pipeline = p4tc_pipeline_find_byany(net, nl_pname->data, pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_HDRFIELD_MAX, nla,
				       tc_hdrfield_policy, extack);
		if (ret < 0)
			return ret;
	}

	parser_name = tb[P4TC_HDRFIELD_PARSER_NAME] ?
		nla_data(tb[P4TC_HDRFIELD_PARSER_NAME]) : NULL;

	parser = tcf_parser_find_byany(pipeline, parser_name, parser_inst_id,
				       extack);
	if (IS_ERR(parser))
		return PTR_ERR(parser);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && n->nlmsg_flags & NLM_F_ROOT)
		return p4tc_hdrfield_flush(skb, pipeline, parser, extack);

	hdrfield = p4tc_hdrfield_find_byanyattr(parser, tb[P4TC_HDRFIELD_NAME],
						hdrfield_id, extack);
	if (IS_ERR(hdrfield))
		return PTR_ERR(hdrfield);

	ret = _p4tc_hdrfield_fill_nlmsg(skb, hdrfield);
	if (ret < 0)
		return -ENOMEM;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = __p4tc_hdrfield_put(pipeline, hdrfield, false, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4tc_hdrfield_dump_1(struct sk_buff *skb,
				struct p4tc_template_common *common)
{
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_hdrfield *hdrfield = to_hdrfield(common);
	unsigned char *b = nlmsg_get_pos(skb);
	u32 path[2];

	if (!param)
		goto out_nlmsg_trim;

	if (hdrfield->common.name[0] &&
	    nla_put_string(skb, P4TC_HDRFIELD_NAME, hdrfield->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	path[0] = hdrfield->parser->parser_id;
	path[1] = hdrfield->hdrfield_id;
	if (nla_put(skb, P4TC_PATH, sizeof(path), path))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int p4tc_hdrfield_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			      struct nlattr *nla, char **p_name, u32 *ids,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_HDRFIELD_MAX + 1] = { NULL };
	const u32 pipeid = ids[P4TC_PID_IDX];
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;
	struct p4tc_parser *parser;
	int ret;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline =
			p4tc_pipeline_find_byany(net, *p_name, pipeid, extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = p4tc_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ctx->ids[P4TC_PARSEID_IDX]) {
		if (nla) {
			ret = nla_parse_nested(tb, P4TC_HDRFIELD_MAX, nla,
					       tc_hdrfield_policy, extack);
			if (ret < 0)
				return ret;
		}

		parser = tcf_parser_find_byany(pipeline,
					       nla_data(tb[P4TC_HDRFIELD_PARSER_NAME]),
					       ids[P4TC_PARSEID_IDX], extack);
		if (IS_ERR(parser))
			return PTR_ERR(parser);

		ctx->ids[P4TC_PARSEID_IDX] = parser->parser_id;
	} else {
		parser = pipeline->parser;
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return p4tc_tmpl_generic_dump(skb, ctx, &parser->hdrfield_idr,
				      P4TC_HDRFIELDID_IDX, extack);
}

const struct p4tc_template_ops p4tc_hdrfield_ops = {
	.init = NULL,
	.cu = p4tc_hdrfield_cu,
	.fill_nlmsg = p4tc_hdrfield_fill_nlmsg,
	.gd = p4tc_hdrfield_gd,
	.put = p4tc_hdrfield_put,
	.dump = p4tc_hdrfield_dump,
	.dump_1 = p4tc_hdrfield_dump_1,
};
