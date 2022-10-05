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
#include <net/kparser/kparser.h>
#include <net/netlink.h>

static struct p4tc_parser *
parser_find_name(struct p4tc_pipeline *pipeline, const char *parser_name)
{

	if (unlikely(!pipeline->parser))
		return NULL;

	if (!strncmp(pipeline->parser->parser_name, parser_name, PARSERNAMSIZ))
		return pipeline->parser;

	return NULL;
}

struct p4tc_parser *
tcf_parser_find_byid(struct p4tc_pipeline *pipeline, const u32 parser_inst_id)
{
	if (unlikely(!pipeline->parser))
		return NULL;

	if (parser_inst_id == pipeline->parser->parser_inst_id)
		return pipeline->parser;

	return NULL;
}

static struct p4tc_parser *
__parser_find(struct p4tc_pipeline *pipeline, const char *parser_name,
	      u32 parser_inst_id, struct netlink_ext_ack *extack)
{
	struct p4tc_parser *parser;
	int err;

	if (parser_inst_id) {
		parser = tcf_parser_find_byid(pipeline, parser_inst_id);
		if (!parser) {
			if (extack)
				NL_SET_ERR_MSG(extack,
					       "Unable to find parser by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (parser_name) {
			parser = parser_find_name(pipeline, parser_name);
			if (!parser) {
				if (extack)
					NL_SET_ERR_MSG(extack,
						       "Parser name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			if (extack)
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
tcf_parser_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
		      u32 parser_inst_id, struct netlink_ext_ack *extack)
{
	const char *parser_name = NULL;

	if (name_attr)
		parser_name = nla_data(name_attr);

	return __parser_find(pipeline, parser_name, parser_inst_id, extack);
}

int tcf_skb_parse(struct sk_buff *skb, struct p4tc_skb_ext *p4tc_skb_ext,
		  struct p4tc_parser *parser)
{
	void *hdr = skb_mac_header(skb);

#ifdef CONFIG_KPARSER
	return __kparser_parse(parser->kparser, hdr, skb->len,
			       p4tc_skb_ext->p4tc_ext->hdrs, HEADER_MAX_LEN);
#endif
	return 0;
}

struct p4tc_parser *
tcf_parser_create(struct p4tc_pipeline *pipeline, const char *parser_name,
		  u32 parser_inst_id, struct netlink_ext_ack *extack)
{
#ifdef CONFIG_KPARSER
	struct kparser_hkey kparser_key;
#endif
	struct p4tc_parser *parser;
	int ret;

	if (pipeline->parser) {
		NL_SET_ERR_MSG(extack,
			       "Can only have one parser instance per pipeline");
		return ERR_PTR(-EEXIST);
	}

	parser = kzalloc(sizeof(*parser), GFP_KERNEL);
	if (!parser)
		return ERR_PTR(-ENOMEM);

	if (parser_inst_id)
		parser->parser_inst_id = parser_inst_id;
	else
		/* Assign to one if no ID was supplied */
		parser->parser_inst_id = 1;

#ifdef CONFIG_KPARSER
	kparser_key.id = parser->parser_inst_id;
	strscpy(kparser_key.name, parser_name, KPARSER_MAX_NAME);
	parser->kparser = kparser_get_parser(&kparser_key);
	if (!parser->kparser) {
		ret = -ENOENT;
		NL_SET_ERR_MSG(extack, "Unable to get kparser instance");
		goto free_parser;
	}
#endif

	refcount_set(&parser->parser_ref, 1);

	idr_init(&parser->hdr_fields_idr);

	strscpy(parser->parser_name, parser_name, PARSERNAMSIZ);

	pipeline->parser = parser;

	return parser;

free_parser:
	kfree(parser);
	return ERR_PTR(ret);
}

/* Dummy function which just returns true
 * Once we have the proper parser code, this function will work properly
 */
bool tcf_parser_check_hdrfields(struct p4tc_parser *parser,
				struct p4tc_header_field *hdrfield)
{
	return true;
}

int tcf_parser_del(struct p4tc_pipeline *pipeline,
		   struct p4tc_parser *parser, struct netlink_ext_ack *extack)
{
	if (!refcount_dec_if_one(&parser->parser_ref)) {
		NL_SET_ERR_MSG(extack, "Unable to delete referenced parser");
		return -EBUSY;
	}

#ifdef CONFIG_KPARSER
	kparser_put_parser(parser->kparser);
#endif

	idr_destroy(&parser->hdr_fields_idr);

	pipeline->parser = NULL;

	kfree(parser);

	return 0;
}

bool tcf_parser_is_callable(struct p4tc_parser *parser)
{
	if (!parser)
		return false;

#ifdef CONFIG_KPARSER
	if (!parser->kparser)
		return false;
#endif

	return true;
}
