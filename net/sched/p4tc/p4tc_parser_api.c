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
#include <net/kparser.h>
#include <net/netlink.h>

static struct p4tc_parser *parser_find_name(struct p4tc_pipeline *pipeline,
					    const char *parser_name)
{
	if (unlikely(!pipeline->parser))
		return NULL;

	if (!strncmp(pipeline->parser->parser_name, parser_name, PARSERNAMSIZ))
		return pipeline->parser;

	return NULL;
}

struct p4tc_parser *tcf_parser_find_byid(struct p4tc_pipeline *pipeline,
					 const u32 parser_inst_id)
{
	if (unlikely(!pipeline->parser))
		return NULL;

	if (parser_inst_id == pipeline->parser->parser_inst_id)
		return pipeline->parser;

	return NULL;
}

static struct p4tc_parser *__parser_find(struct p4tc_pipeline *pipeline,
					 const char *parser_name,
					 u32 parser_inst_id,
					 struct netlink_ext_ack *extack)
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

struct p4tc_parser *tcf_parser_find_byany(struct p4tc_pipeline *pipeline,
					  const char *parser_name,
					  u32 parser_inst_id,
					  struct netlink_ext_ack *extack)
{
	return __parser_find(pipeline, parser_name, parser_inst_id, extack);
}

#ifdef CONFIG_KPARSER
int tcf_skb_parse(struct sk_buff *skb, struct p4tc_skb_ext *p4tc_skb_ext,
		  struct p4tc_parser *parser)
{
	void *hdr = skb_mac_header(skb);
	size_t pktlen = skb_mac_header_len(skb) + skb->len;

	return __kparser_parse(parser->kparser, hdr, pktlen,
			       p4tc_skb_ext->p4tc_ext->hdrs, HEADER_MAX_LEN);
}

static int __tcf_parser_fill(struct p4tc_parser *parser,
			     struct netlink_ext_ack *extack)
{
	struct kparser_hkey kparser_key = { 0 };

	kparser_key.id = parser->parser_inst_id;
	strscpy(kparser_key.name, parser->parser_name, KPARSER_MAX_NAME);

	parser->kparser = kparser_get_parser(&kparser_key, false);
	if (!parser->kparser) {
		NL_SET_ERR_MSG(extack, "Unable to get kparser instance");
		return -ENOENT;
	}

	return 0;
}

void __tcf_parser_put(struct p4tc_parser *parser)
{
	kparser_put_parser(parser->kparser, false);
}

bool tcf_parser_is_callable(struct p4tc_parser *parser)
{
	return parser && parser->kparser;
}
#else
int tcf_skb_parse(struct sk_buff *skb, struct p4tc_skb_ext *p4tc_skb_ext,
		  struct p4tc_parser *parser)
{
	return 0;
}

static int __tcf_parser_fill(struct p4tc_parser *parser,
			     struct netlink_ext_ack *extack)
{
	return 0;
}

void __tcf_parser_put(struct p4tc_parser *parser)
{
}

bool tcf_parser_is_callable(struct p4tc_parser *parser)
{
	return !!parser;
}
#endif

struct p4tc_parser *
tcf_parser_create(struct p4tc_pipeline *pipeline, const char *parser_name,
		  u32 parser_inst_id, struct netlink_ext_ack *extack)
{
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
		/* Assign to KPARSER_KMOD_ID_MAX + 1 if no ID was supplied */
		parser->parser_inst_id = KPARSER_KMOD_ID_MAX + 1;

	strscpy(parser->parser_name, parser_name, PARSERNAMSIZ);

	ret = __tcf_parser_fill(parser, extack);
	if (ret < 0)
		goto err;

	refcount_set(&parser->parser_ref, 1);

	idr_init(&parser->hdr_fields_idr);

	pipeline->parser = parser;

	return parser;

err:
	kfree(parser);
	return ERR_PTR(ret);
}

/* Dummy function which just returns true
 * Once we have the proper parser code, this function will work properly
 */
bool tcf_parser_check_hdrfields(struct p4tc_parser *parser,
				struct p4tc_hdrfield *hdrfield)
{
	return true;
}

int tcf_parser_del(struct net *net, struct p4tc_pipeline *pipeline,
		   struct p4tc_parser *parser, struct netlink_ext_ack *extack)
{
	struct p4tc_hdrfield *hdrfield;
	unsigned long hdr_field_id, tmp;

	__tcf_parser_put(parser);

	idr_for_each_entry_ul(&parser->hdr_fields_idr, hdrfield, tmp, hdr_field_id)
		hdrfield->common.ops->put(net, &hdrfield->common, true, extack);

	idr_destroy(&parser->hdr_fields_idr);

	pipeline->parser = NULL;

	kfree(parser);

	return 0;
}
