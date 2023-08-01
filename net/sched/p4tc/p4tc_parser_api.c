// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_parser_api.c	P4 TC PARSER API
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
#include <linux/err.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>

static struct p4tc_parser *
p4tc_parser_find_byname(struct p4tc_pipeline *pipeline, const char *parser_name)
{
	if (unlikely(!pipeline->parser))
		return NULL;

	if (!strncmp(pipeline->parser->parser_name, parser_name, PARSERNAMSIZ))
		return pipeline->parser;

	return NULL;
}

static struct p4tc_parser *
p4tc_parser_find_byid(struct p4tc_pipeline *pipeline, const u32 parser_id)
{
	if (unlikely(!pipeline->parser))
		return NULL;

	if (parser_id == pipeline->parser->parser_id)
		return pipeline->parser;

	return NULL;
}

struct p4tc_parser *tcf_parser_find_byany(struct p4tc_pipeline *pipeline,
					  const char *parser_name,
					  u32 parser_id,
					  struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;
	int err;

	if (parser_id) {
		parser = p4tc_parser_find_byid(pipeline, parser_id);
		if (!parser) {
			NL_SET_ERR_MSG(extack, "Unable to find parser by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (parser_name) {
			parser = p4tc_parser_find_byname(pipeline, parser_name);
			if (!parser) {
				NL_SET_ERR_MSG(extack, "Parser name not found");
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

struct p4tc_parser *tcf_parser_find_get(struct p4tc_pipeline *pipeline,
					const char *parser_name, u32 parser_id,
					struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;

	parser =
		tcf_parser_find_byany(pipeline, parser_name, parser_id, extack);
	if (IS_ERR(parser))
		return parser;

	if (!refcount_inc_not_zero(&parser->parser_ref)) {
		NL_SET_ERR_MSG(extack, "Parser is stale");
		return ERR_PTR(-EINVAL);
	}

	return parser;
}

struct p4tc_parser *tcf_parser_create(struct p4tc_pipeline *pipeline,
				      const char *parser_name, u32 parser_id,
				      struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;

	if (pipeline->parser) {
		NL_SET_ERR_MSG(extack,
			       "Can only have one parser instance per pipeline");
		return ERR_PTR(-EEXIST);
	}

	parser = kzalloc(sizeof(*parser), GFP_KERNEL);
	if (!parser)
		return ERR_PTR(-ENOMEM);

	parser->parser_id = parser_id ?: 1;

	strscpy(parser->parser_name, parser_name, PARSERNAMSIZ);

	refcount_set(&parser->parser_ref, 1);

	idr_init(&parser->hdrfield_idr);

	pipeline->parser = parser;

	return parser;
}

int tcf_parser_del(struct net *net, struct p4tc_pipeline *pipeline,
		   struct p4tc_parser *parser, struct netlink_ext_ack *extack)
{
	unsigned long hdr_field_id, tmp;
	struct p4tc_hdrfield *hdrfield;

	idr_for_each_entry_ul(&parser->hdrfield_idr, hdrfield, tmp,
			      hdr_field_id)
		hdrfield->common.ops->put(pipeline, &hdrfield->common, extack);

	idr_destroy(&parser->hdrfield_idr);

	pipeline->parser = NULL;

	kfree(parser);

	return 0;
}
