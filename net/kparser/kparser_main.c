// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kParser KMOD main module source file with netlink handlers
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kparser.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <net/act_api.h>
#include <net/genetlink.h>
#include <net/kparser.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>

#include "kparser.h"

static int kparser_cli_cmd_handler(struct sk_buff *skb, struct genl_info *info);

/* define netlink msg policies */
#define NS_DEFINE_POLICY_ATTR_ENTRY(ID, STRUC_NAME, RSP_STRUC_NAME)	\
	[KPARSER_ATTR_CREATE_##ID] = {					\
		.type = NLA_BINARY,					\
		.validation_type = NLA_VALIDATE_MIN,			\
		.min = sizeof(struct STRUC_NAME)			\
	},								\
	[KPARSER_ATTR_UPDATE_##ID] = {					\
		.type = NLA_BINARY,					\
		.len = sizeof(struct STRUC_NAME),			\
		.validation_type = NLA_VALIDATE_MIN,			\
		.min = sizeof(struct STRUC_NAME)			\
	},								\
	[KPARSER_ATTR_READ_##ID] = {					\
		.type = NLA_BINARY,					\
		.len = sizeof(struct STRUC_NAME),			\
		.validation_type = NLA_VALIDATE_MIN,			\
		.min = sizeof(struct STRUC_NAME)			\
	},								\
	[KPARSER_ATTR_DELETE_##ID] = {					\
		.type = NLA_BINARY,					\
		.len = sizeof(struct STRUC_NAME),			\
		.validation_type = NLA_VALIDATE_MIN,			\
		.min = sizeof(struct STRUC_NAME)			\
	},								\
	[KPARSER_ATTR_RSP_##ID] = {					\
		.type = NLA_BINARY,					\
		.len = sizeof(struct RSP_STRUC_NAME),			\
		.validation_type = NLA_VALIDATE_MIN,			\
		.min = sizeof(struct RSP_STRUC_NAME)			\
	}

static const struct nla_policy kparser_nl_policy[KPARSER_ATTR_MAX] = {
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_CONDEXPRS,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_CONDEXPRS_TABLE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_CONDEXPRS_TABLES,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_COUNTER,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_COUNTER_TABLE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_METADATA,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_METALIST,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_NODE_PARSE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_PROTO_TABLE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_TLV_NODE_PARSE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_TLV_PROTO_TABLE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_FLAG_FIELD,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_FLAG_FIELD_TABLE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_FLAG_FIELD_NODE_PARSE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_PARSER,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
	NS_DEFINE_POLICY_ATTR_ENTRY(KPARSER_NS_OP_PARSER_LOCK_UNLOCK,
				    kparser_conf_cmd,
			kparser_cmd_rsp_hdr),
};

/* define netlink operations and family */
static const struct genl_ops kparser_nl_ops[] = {
	{
	  .cmd = KPARSER_CMD_CONFIGURE,
	  .doit = kparser_cli_cmd_handler,
	  .flags = GENL_ADMIN_PERM,
	},
};

struct genl_family kparser_nl_family __ro_after_init = {
	.hdrsize	= 0,
	.name		= KPARSER_GENL_NAME,
	.version	= KPARSER_GENL_VERSION,
	.maxattr	= KPARSER_ATTR_MAX - 1,
	.policy		= kparser_nl_policy,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.ops		= kparser_nl_ops,
	.n_ops		= ARRAY_SIZE(kparser_nl_ops),
	.resv_start_op	= KPARSER_CMD_CONFIGURE + 1,
};

/* send response to netlink msg requests */
static int kparser_send_cmd_rsp(int cmd, int attrtype,
				const struct kparser_cmd_rsp_hdr *rsp,
				size_t rsp_len, struct genl_info *info, int err)
{
	struct sk_buff *msg;
	size_t msgsz = NLMSG_DEFAULT_SIZE;
	void *hdr;
	int ret;

	if (rsp_len > msgsz)
		msgsz = rsp_len;

	msg = nlmsg_new(msgsz, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &kparser_nl_family, 0, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	if (rsp->op_ret_code != 0) {
		struct nlmsghdr *nlh = hdr - GENL_HDRLEN - NLMSG_HDRLEN;
		struct nlmsgerr *e;

		nlh->nlmsg_type = NLMSG_ERROR;
		nlh->nlmsg_len += nlmsg_msg_size(sizeof(*e));
		nlh->nlmsg_flags |= NLM_F_ACK_TLVS;
		e = (struct nlmsgerr *)NLMSG_DATA(nlh);
		memset(&e->msg, 0, sizeof(e->msg));
		e->error = rsp->op_ret_code;
		nlmsg_free(msg);
		return e->error;
	}

	if (nla_put(msg, attrtype, (int)rsp_len, rsp)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	ret = genlmsg_reply(msg, info);

	/* pr_debug("genlmsg_reply() ret:%d\n", ret); */

	return ret;
}

typedef int kparser_ops(const void *, size_t, struct kparser_cmd_rsp_hdr **,
			size_t *, void *extack, int *err);

/* define netlink msg processors */
#define KPARSER_NS_DEFINE_OP_HANDLERS(NS_ID)				\
	[KPARSER_ATTR_CREATE_##NS_ID] = kparser_config_handler_add,	\
	[KPARSER_ATTR_UPDATE_##NS_ID] = kparser_config_handler_update,	\
	[KPARSER_ATTR_READ_##NS_ID] = kparser_config_handler_read,	\
	[KPARSER_ATTR_DELETE_##NS_ID] = kparser_config_handler_delete,	\
	[KPARSER_ATTR_RSP_##NS_ID] = NULL

static kparser_ops *kparser_ns_op_handler[KPARSER_ATTR_MAX] = {
	NULL,
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_CONDEXPRS),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_CONDEXPRS_TABLE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_CONDEXPRS_TABLES),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_COUNTER),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_COUNTER_TABLE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_METADATA),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_METALIST),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_NODE_PARSE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_PROTO_TABLE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_TLV_NODE_PARSE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_TLV_PROTO_TABLE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_FLAG_FIELD),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_FLAG_FIELD_TABLE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_FLAG_FIELD_NODE_PARSE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_FLAG_FIELD_PROTO_TABLE),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_PARSER),
	KPARSER_NS_DEFINE_OP_HANDLERS(KPARSER_NS_OP_PARSER_LOCK_UNLOCK),
};

/* netlink msg request handler */
static int kparser_cli_cmd_handler(struct sk_buff *skb, struct genl_info *info)
{
	struct kparser_cmd_rsp_hdr *rsp = NULL;
	size_t rsp_len = 0;
	int ret_attr_id;
	int attr_idx;
	int rc, err;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	for (attr_idx = KPARSER_ATTR_UNSPEC + 1; attr_idx < KPARSER_ATTR_MAX; attr_idx++) {
		if (!info->attrs[attr_idx] || !kparser_ns_op_handler[attr_idx])
			continue;

		ret_attr_id = kparser_ns_op_handler[attr_idx](nla_data(info->attrs[attr_idx]),
							      nla_len(info->attrs[attr_idx]),
							      &rsp, &rsp_len,
							      info->extack, &err);

		if (ret_attr_id <= KPARSER_ATTR_UNSPEC || ret_attr_id >= KPARSER_ATTR_MAX) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "attr %d handler failed", attr_idx);
			rc = EIO;
			goto out;
		}

		rc = kparser_send_cmd_rsp(KPARSER_CMD_CONFIGURE, ret_attr_id,
					  rsp, rsp_len, info, err);
		if (rc) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "kparser_send_cmd_rsp() failed,attr:%d, rc:%d\n",
						 attr_idx, rc);
			// rc = EIO;
			goto out;
		}

		kfree(rsp);
		rsp = NULL;
		rsp_len = 0;
	}

out:
	if (rsp)
		kfree(rsp);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");

	return rc;
}

/* kParser KMOD's init handler */
static int __init init_kparser(void)
{
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	rc = genl_register_family(&kparser_nl_family);
	if (rc) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "genl_register_family failed\n");
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
		return rc;
	}

	rc = kparser_init();
	if (rc) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "kparser_init() err:%d\n", rc);
		goto out;
	}
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");

	return rc;

out:
	rc = genl_unregister_family(&kparser_nl_family);
	if (rc != 0)
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "kparser_deinit() err:%d\n", rc);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "ERR OUT: ");

	return rc;
}

/* kParser KMOD's exit handler */
static void __exit exit_kparser(void)
{
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	rc = genl_unregister_family(&kparser_nl_family);
	if (rc != 0)
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "genl_unregister_family() err:%d\n",
					 rc);

	rc = kparser_deinit();
	if (rc != 0)
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "kparser_deinit() err:%d\n", rc);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
}

module_init(init_kparser);
module_exit(exit_kparser);
MODULE_AUTHOR("Pratyush Khan <pratyush@sipanda.io>");
MODULE_AUTHOR("SiPanda Inc");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Configurable Parameterized Parser in Kernel (KPARSER)");
