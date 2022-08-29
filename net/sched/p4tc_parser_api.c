// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_parser_api.c	P4 TC PARSER API
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
#include <linux/err.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>

static struct p4tc_parser *
parser_find_name(struct p4tc_pipeline *pipeline, const char *parser_name)
{
	struct p4tc_parser *parser;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_parser_idr, parser, tmp, id)
		if (strncmp(parser->parser_name, parser_name, PARSERNAMSIZ) == 0)
			return parser;

	return NULL;
}

#define parser_find_id(pipeline, parser_inst_id) \
	(idr_find(&(pipeline)->p_parser_idr, parser_inst_id))

struct p4tc_parser *
tcf_parser_find(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
		u32 parser_inst_id, struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;
	int err;

	if (parser_inst_id) {
		parser = parser_find_id(pipeline, parser_inst_id);
		if (!parser) {
			NL_SET_ERR_MSG(extack,
				       "Unable to find parser by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (name_attr) {
			const char *parser_name = nla_data(name_attr);

			parser = parser_find_name(pipeline, parser_name);
			if (!parser) {
				NL_SET_ERR_MSG(extack,
					       "Parser name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify parser name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return parser;

out:
	return ERR_PTR(err);
}

struct p4tc_parser *
tcf_parser_create(struct p4tc_pipeline *pipeline, const char *parser_name,
		  u32 parser_inst_id, struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;
	int ret;

	if ((parser_name && parser_find_name(pipeline, parser_name)) ||
	    parser_find_id(pipeline, parser_inst_id)) {
		NL_SET_ERR_MSG(extack, "Parser already exists");
		return ERR_PTR(-EEXIST);
	}

	parser = kzalloc(sizeof(*parser), GFP_KERNEL);
	if (!parser)
		return ERR_PTR(-ENOMEM);

	if (parser_inst_id) {
		parser->parser_inst_id = parser_inst_id;

		ret = idr_alloc_u32(&pipeline->p_parser_idr, parser,
				    &parser_inst_id, parser_inst_id,
				    GFP_KERNEL);
	} else {
		parser->parser_inst_id = 1;
		ret = idr_alloc_u32(&pipeline->p_parser_idr, parser,
				    &parser->parser_inst_id, UINT_MAX,
				    GFP_KERNEL);
	}
	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate parser id");
		goto free_parser;
	}

	refcount_set(&parser->parser_ref, 1);

	strscpy(parser->parser_name, parser_name, PARSERNAMSIZ);

	return parser;

free_parser:
	kfree(parser);
	return ERR_PTR(ret);
}

int tcf_parser_del(struct p4tc_pipeline *pipeline, const char *parser_name,
		   u32 parser_inst_id, struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;

	if (parser_inst_id)
		parser = parser_find_id(pipeline, parser_inst_id);
	else
		parser = parser_find_name(pipeline, parser_name);
	if (!parser) {
		NL_SET_ERR_MSG(extack, "Unable to find parser");
		return -ENOENT;
	}

	if (!refcount_dec_if_one(&parser->parser_ref)) {
		NL_SET_ERR_MSG(extack, "Unable to delete referenced parser");
		return -EBUSY;
	}

	idr_remove(&pipeline->p_parser_idr, parser_inst_id);

	kfree(parser);

	return 0;
}
