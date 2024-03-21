// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_filter.c P4 TC FILTER
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
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
#include <linux/err.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/sock.h>

enum {
	P4TC_FILTER_OPND_ENTRY_KIND_UNSPEC,
	P4TC_FILTER_OPND_ENTRY_KIND_KEY,
	P4TC_FILTER_OPND_ENTRY_KIND_ACT,
	P4TC_FILTER_OPND_ENTRY_KIND_ACT_PARAM,
	P4TC_FILTER_OPND_ENTRY_KIND_PRIO,
	P4TC_FILTER_OPND_ENTRY_KIND_MSECS,
};

struct p4tc_filter_opnd_entry {
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;
	u32 opnd_entry_kind;
	union {
		struct {
			u8 val[BITS_TO_BYTES(P4TC_MAX_KEYSZ)];
			u8 mask[BITS_TO_BYTES(P4TC_MAX_KEYSZ)];
		} entry_key;
		struct {
			struct p4tc_act *val;
			struct p4tc_act_param *param;
		} act;
		u32 prio;
		u32 msecs_since;
	};
};

struct p4tc_filter_opnd_cmd {
	u32 cmd;
};

struct p4tc_filter_opnd {
	u32 opnd_kind;
	union {
		struct p4tc_filter_opnd_entry opnd_entry;
		struct p4tc_filter_opnd_cmd opnd_cmd;
	};
};

struct p4tc_filter_oper;
struct p4tc_filter_node {
	enum p4tc_filter_ntype ntype;
	union {
		struct p4tc_filter_opnd *opnd;
		struct p4tc_filter_oper *operation;
	};
};

struct p4tc_filter_oper {
	struct p4tc_filter_node *node1;
	struct p4tc_filter_node *node2;
	u16 op_kind;
	u16 op_value;
};

struct p4tc_filter_sock {
	struct rhash_head ht_node;
	struct rcu_head rcu;
	struct p4tc_filter *p4tc_filter;
	struct sock *sk;
	possible_net_t pnet;
	u32 portid;
	u32 obj_id;
};

struct p4tc_filter_sock_cmp_arg
{
	possible_net_t pnet;
	u32 portid;
};

static const struct rhashtable_params p4tc_filter_sock_table_params = {
	.head_offset = offsetof(struct p4tc_filter_sock, ht_node),
	.key_len = sizeof(struct sock *),
	.key_offset = offsetof(struct p4tc_filter_sock, sk),
	.automatic_shrinking = true,
};

static struct rhashtable p4tc_filter_sock_table;
static DEFINE_SPINLOCK(p4tc_filter_sock_table_lock);

static void p4tc_filter_sock_destroy(struct p4tc_filter_sock *filter_sock)
{
	spin_lock(&p4tc_filter_sock_table_lock);
	rhashtable_remove_fast(&p4tc_filter_sock_table, &filter_sock->ht_node,
			       p4tc_filter_sock_table_params);
	spin_unlock(&p4tc_filter_sock_table_lock);
	__sock_put(filter_sock->sk);
	p4tc_filter_destroy(filter_sock->p4tc_filter);
	kfree_rcu(filter_sock, rcu);
}

static struct p4tc_filter_sock *
p4tc_filter_sock_table_lookup_by_sock(struct sock *sk)
{

	return rhashtable_lookup(&p4tc_filter_sock_table, &sk,
				 p4tc_filter_sock_table_params);
}

static int p4tc_filter_sock_insert(struct p4tc_filter_sock *filter_sock)
{
	int ret;

	spin_lock(&p4tc_filter_sock_table_lock);
	ret = rhashtable_insert_fast(&p4tc_filter_sock_table,
				     &filter_sock->ht_node,
				     p4tc_filter_sock_table_params);
	spin_unlock(&p4tc_filter_sock_table_lock);
	return ret;
}

static int p4tc_filter_netlink_notify(struct notifier_block *nb,
				      unsigned long state,
				      void *_notify)
{
	struct p4tc_filter_sock *filter_sock = NULL;
	struct netlink_notify *notify = _notify;
	struct rhashtable_iter iter;

	if (state != NETLINK_URELEASE || notify->protocol != NETLINK_ROUTE)
		return NOTIFY_DONE;

	rhashtable_walk_enter(&p4tc_filter_sock_table, &iter);
	do {
		rhashtable_walk_start(&iter);

		while ((filter_sock = rhashtable_walk_next(&iter)) &&
		       !IS_ERR(filter_sock)) {
			if (read_pnet(&filter_sock->pnet) == notify->net &&
			    filter_sock->portid == notify->portid) {
				rhashtable_walk_stop(&iter);
				goto walk_exit;
			}
		}

		rhashtable_walk_stop(&iter);
	} while (filter_sock == ERR_PTR(-EAGAIN));
walk_exit:
	rhashtable_walk_exit(&iter);
	if (!filter_sock || IS_ERR(filter_sock))
		return NOTIFY_DONE;

	p4tc_filter_sock_destroy(filter_sock);

	return NOTIFY_OK;
}

static struct notifier_block p4tc_filter_notifier = {
	.notifier_call = p4tc_filter_netlink_notify,
};

void p4tc_filter_sock_table_init(void)
{
	/* Since parameters are hardcoded, rhashtable_init will never fail */
	rhashtable_init(&p4tc_filter_sock_table,
			&p4tc_filter_sock_table_params);
	/* Since no other user is registering this notifier,
	 * netlink_register_notifier will never fail
	 */
	netlink_register_notifier(&p4tc_filter_notifier);
}

static const struct nla_policy
p4tc_entry_filter_act_policy[P4TC_FILTER_OPND_ENTRY_ACT_MAX + 1] = {
	[P4TC_FILTER_OPND_ENTRY_ACT_NAME] = {
		.type = NLA_STRING,
		.len = ACTNAMSIZ
	},
	[P4TC_FILTER_OPND_ENTRY_ACT_ID] = { .type = NLA_U32 },
	[P4TC_FILTER_OPND_ENTRY_ACT_PARAMS] = { .type = NLA_NESTED },
};

static const struct nla_policy
p4tc_filter_opnd_entry_policy[P4TC_FILTER_OPND_ENTRY_MAX + 1] = {
	[P4TC_FILTER_OPND_ENTRY_KEY_BLOB] =
		NLA_POLICY_MAX(NLA_BINARY, BITS_TO_BYTES(P4TC_MAX_KEYSZ)),
	[P4TC_FILTER_OPND_ENTRY_MASK_BLOB] =
		NLA_POLICY_MAX(NLA_BINARY, BITS_TO_BYTES(P4TC_MAX_KEYSZ)),
	[P4TC_FILTER_OPND_ENTRY_ACT] = { .type = NLA_NESTED },
	[P4TC_FILTER_OPND_ENTRY_PRIO] = { .type = NLA_U32 },
	[P4TC_FILTER_OPND_ENTRY_TIME_DELTA] = { .type = NLA_U32 },
};

static struct netlink_range_validation range_filter_op_cmd = {
	.min = RTM_P4TC_CREATE,
	.max = RTM_P4TC_UPDATE,
};

static const struct nla_policy
p4tc_filter_opnd_policy[P4TC_FILTER_OPND_MAX + 1] = {
	[P4TC_FILTER_OPND_ENTRY] = { .type = NLA_NESTED },
	[P4TC_FILTER_OPND_CMD] =
		NLA_POLICY_FULL_RANGE(NLA_U32, &range_filter_op_cmd),
};

static const struct nla_policy
p4tc_entry_filter_op_node_policy[P4TC_FILTER_OP_NODE_MAX + 1] = {
	[P4TC_FILTER_OP_NODE_PARENT] = { .type = NLA_NESTED },
	[P4TC_FILTER_OP_NODE_LEAF] = { .type = NLA_NESTED },
};

static struct netlink_range_validation range_filter_op_kind = {
	.min = P4TC_FILTER_OP_KIND_REL,
	.max = P4TC_FILTER_OP_KIND_MAX,
};

static const struct nla_policy
p4tc_entry_filter_op_policy[P4TC_FILTER_OP_MAX + 1] = {
	[P4TC_FILTER_OP_KIND] =
		NLA_POLICY_FULL_RANGE(NLA_U16, &range_filter_op_kind),
	[P4TC_FILTER_OP_VALUE] = { .type = NLA_U16 },
	[P4TC_FILTER_OP_NODE1] = { .type = NLA_NESTED },
	[P4TC_FILTER_OP_NODE2] = { .type = NLA_NESTED },
};

static const struct nla_policy
p4tc_entry_filter_policy[P4TC_FILTER_OP_MAX + 1] = {
	[P4TC_FILTER_OP] = { .type = NLA_NESTED },
};

static bool p4tc_filter_msg_valid(struct nlattr **tb,
				  struct netlink_ext_ack *extack)
{
	bool is_empty = true;
	int i;

	if ((tb[P4TC_FILTER_OPND_ENTRY_KEY_BLOB] &&
	     !tb[P4TC_FILTER_OPND_ENTRY_MASK_BLOB]) ||
	    (tb[P4TC_FILTER_OPND_ENTRY_MASK_BLOB] &&
	     !tb[P4TC_FILTER_OPND_ENTRY_KEY_BLOB])) {
		NL_SET_ERR_MSG(extack, "Must specify key with mask");
		return false;
	}

	for (i = P4TC_FILTER_OPND_ENTRY_MASK_BLOB;
	     i < P4TC_FILTER_OPND_ENTRY_MAX + 1; i++) {
		if (tb[i]) {
			if (!is_empty) {
				NL_SET_ERR_MSG(extack,
					       "May only specify one filter key attribute");
				return false;
			}
			is_empty = false;
		}
	}

	if (is_empty) {
		NL_SET_ERR_MSG(extack, "Filter opnd message is empty");
		return false;
	}

	return true;
}

static bool p4tc_filter_op_value_valid(const u16 filter_op_kind,
				       const u16 filter_op_value,
				       struct netlink_ext_ack *extack)
{
	switch (filter_op_kind) {
	case P4TC_FILTER_OP_KIND_REL:
		if (filter_op_value < P4TC_FILTER_OP_KIND_REL_EQ ||
		    filter_op_value > P4TC_FILTER_OP_KIND_REL_MAX) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Invalid filter relational op %u\n",
					   filter_op_value);
			return false;
		}
		break;
	case P4TC_FILTER_OP_KIND_LOGICAL:
		if (filter_op_value < P4TC_FILTER_OP_KIND_LOGICAL_AND ||
		    filter_op_value > P4TC_FILTER_OP_KIND_LOGICAL_MAX) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Invalid filter logical op %u\n",
					   filter_op_value);
			return false;
		}
		break;
	default:
		/* Will never happen */
		return false;
	}

	return true;
}

static bool p4tc_filter_op_requires_node2(const u16 filter_op_kind,
					  const u16 filter_op_value)
{
	switch (filter_op_kind) {
	case P4TC_FILTER_OP_KIND_LOGICAL:
		switch (filter_op_value) {
		case P4TC_FILTER_OP_KIND_LOGICAL_AND:
		case P4TC_FILTER_OP_KIND_LOGICAL_OR:
		case P4TC_FILTER_OP_KIND_LOGICAL_XOR:
			return true;
		default:
			return false;
		}
	case P4TC_FILTER_OP_KIND_REL:
		return false;
	default:
		return false;
	}
}

static void
p4tc_filter_opnd_entry_destroy(struct p4tc_filter_opnd_entry *opnd_entry)
{
	switch (opnd_entry->opnd_entry_kind) {
	case P4TC_FILTER_OPND_ENTRY_KIND_ACT:
		p4tc_action_put_ref(opnd_entry->act.val);
		break;
	case P4TC_FILTER_OPND_ENTRY_KIND_ACT_PARAM:
		p4a_runt_parm_destroy(opnd_entry->act.param);
		break;
	default:
		break;
	}

	p4tc_table_put_ref(opnd_entry->table);
	p4tc_pipeline_put_ref(opnd_entry->pipeline);
}

static void p4tc_filter_opnd_destroy(struct p4tc_filter_opnd *opnd)
{
	switch (opnd->opnd_kind) {
	case P4TC_FILTER_OPND_KIND_ENTRY:
		p4tc_filter_opnd_entry_destroy(&opnd->opnd_entry);
		break;
	case P4TC_FILTER_OPND_KIND_CMD:
		break;
	default:
		break;
	}
	kfree(opnd);
}

static void
p4tc_filter_oper_destroy(struct p4tc_filter_oper *operation);

static void p4tc_filter_node_destroy(struct p4tc_filter_node *node)
{
	if (!node)
		return;

	if (node->ntype == P4TC_FILTER_OP_NODE_LEAF)
		p4tc_filter_opnd_destroy(node->opnd);
	else
		p4tc_filter_oper_destroy(node->operation);
	kfree(node);
}

static void p4tc_filter_oper_destroy(struct p4tc_filter_oper *operation)
{
	p4tc_filter_node_destroy(operation->node1);
	p4tc_filter_node_destroy(operation->node2);
	kfree(operation);
}

void p4tc_filter_destroy(struct p4tc_filter *filter)
{
	if (filter && filter->operation)
		p4tc_filter_oper_destroy(filter->operation);
	kfree(filter);
}

static void
p4tc_filter_opnd_entry_prio_build(struct p4tc_filter_opnd_entry *opnd_entry,
				  struct nlattr *nla)
{
	opnd_entry->opnd_entry_kind = P4TC_FILTER_OPND_ENTRY_KIND_PRIO;
	opnd_entry->prio = nla_get_u32(nla);
}

static void
p4tc_filter_opnd_entry_ms_since_build(struct p4tc_filter_opnd_entry *opnd_entry,
				      struct nlattr *nla)
{
	opnd_entry->opnd_entry_kind = P4TC_FILTER_OPND_ENTRY_KIND_MSECS;
	opnd_entry->msecs_since = nla_get_u32(nla);
}

static int
p4tc_filter_opnd_entry_act_build(struct p4tc_filter_context *ctx,
				 struct nlattr *nla,
				 struct p4tc_filter_opnd_entry *opnd_entry,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_FILTER_OPND_ENTRY_MAX + 1];
	struct p4tc_pipeline *pipeline = ctx->pipeline;
	struct p4tc_table *table = ctx->table;
	struct p4tc_act_param *param = NULL;
	struct p4tc_act *act;
	char *act_name;
	u32 act_id;
	int ret;

	if (!nla)
		return 0;

	ret = nla_parse_nested(tb, P4TC_FILTER_OPND_ENTRY_ACT_MAX, nla,
			       p4tc_entry_filter_act_policy, extack);
	if (ret < 0)
		return ret;

	act_id = tb[P4TC_FILTER_OPND_ENTRY_ACT_ID] ?
		nla_get_u32(tb[P4TC_FILTER_OPND_ENTRY_ACT_ID]) : 0;

	act_name = tb[P4TC_FILTER_OPND_ENTRY_ACT_NAME] ?
		nla_data(tb[P4TC_FILTER_OPND_ENTRY_ACT_NAME]) : NULL;

	act = p4a_tmpl_get(pipeline, act_name, act_id, extack);
	if (IS_ERR(act))
		return PTR_ERR(act);

	if (p4tc_table_check_act(table, pipeline->common.p_id, act_id,
				 false)) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Action %s does not belong to tbl %s",
				   act->common.name, table->common.name);
		ret = -EINVAL;
		goto act_put;
	}

	if (tb[P4TC_FILTER_OPND_ENTRY_ACT_PARAMS]) {
		struct nlattr *act_params_attr;

		act_params_attr = tb[P4TC_FILTER_OPND_ENTRY_ACT_PARAMS];
		param = p4a_runt_parm_init(pipeline->net, act, act_params_attr,
					   extack);
		if (IS_ERR(param)) {
			ret = PTR_ERR(param);
			goto params_destroy;
		}

		opnd_entry->act.param = param;
		opnd_entry->opnd_entry_kind =
			P4TC_FILTER_OPND_ENTRY_KIND_ACT_PARAM;
	} else {
		opnd_entry->opnd_entry_kind = P4TC_FILTER_OPND_ENTRY_KIND_ACT;
	}

	opnd_entry->act.val = act;

	return 0;

params_destroy:
	p4a_runt_parm_destroy(param);
act_put:
	p4tc_action_put_ref(act);

	return ret;
}

static int
p4tc_filter_opnd_entry_key_build(struct nlattr **tb,
				 struct p4tc_table *table,
				 struct p4tc_filter_opnd_entry *opnd_entry,
				 struct netlink_ext_ack *extack)
{
	u32 maskblob_len;
	u32 keysz;

	keysz = nla_len(tb[P4TC_FILTER_OPND_ENTRY_KEY_BLOB]);
	nla_memcpy(opnd_entry->entry_key.val,
		   tb[P4TC_FILTER_OPND_ENTRY_KEY_BLOB], keysz);

	if (BITS_TO_BYTES(table->tbl_keysz) != keysz)
		return -EINVAL;

	maskblob_len =
		nla_len(tb[P4TC_FILTER_OPND_ENTRY_MASK_BLOB]);
	if (keysz != maskblob_len) {
		NL_SET_ERR_MSG(extack,
			       "Key and mask blob must have the same length");
		return -EINVAL;
	}

	nla_memcpy(opnd_entry->entry_key.mask,
		   tb[P4TC_FILTER_OPND_ENTRY_MASK_BLOB], keysz);
	p4tc_tbl_entry_mask_key(opnd_entry->entry_key.val,
				opnd_entry->entry_key.val,
				opnd_entry->entry_key.mask, keysz);

	opnd_entry->opnd_entry_kind = P4TC_FILTER_OPND_ENTRY_KIND_KEY;

	return 0;
}

static int
p4tc_filter_opnd_entry_build(struct p4tc_filter_context *ctx,
			     struct p4tc_filter_opnd_entry *opnd_entry,
			     struct nlattr *nla,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_FILTER_OPND_ENTRY_MAX + 1];
	int ret;

	if (ctx->obj_id != P4TC_FILTER_OBJ_RUNTIME_TABLE) {
		NL_SET_ERR_MSG(extack,
			       "Tbl entry operand specified without tbl entry ctx");
		return -EINVAL;
	}

	ret = nla_parse_nested(tb, P4TC_FILTER_OPND_ENTRY_MAX, nla,
			       p4tc_filter_opnd_entry_policy, extack);
	if (ret < 0)
		return ret;

	if (!p4tc_filter_msg_valid(tb, extack))
		return -EINVAL;

	if (tb[P4TC_FILTER_OPND_ENTRY_PRIO]) {
		struct nlattr *prio_attr;

		prio_attr = tb[P4TC_FILTER_OPND_ENTRY_PRIO];
		p4tc_filter_opnd_entry_prio_build(opnd_entry, prio_attr);
	} else if (tb[P4TC_FILTER_OPND_ENTRY_TIME_DELTA]) {
		struct nlattr *msecs_attr =
			tb[P4TC_FILTER_OPND_ENTRY_TIME_DELTA];

		p4tc_filter_opnd_entry_ms_since_build(opnd_entry,
						      msecs_attr);
	} else if (tb[P4TC_FILTER_OPND_ENTRY_ACT]) {
		struct nlattr *entry_act_attr;

		entry_act_attr = tb[P4TC_FILTER_OPND_ENTRY_ACT];
		ret = p4tc_filter_opnd_entry_act_build(ctx,
						       entry_act_attr,
						       opnd_entry, extack);
		if (ret < 0)
			return ret;
	} else if (tb[P4TC_FILTER_OPND_ENTRY_KEY_BLOB]) {
		ret = p4tc_filter_opnd_entry_key_build(tb, ctx->table,
						       opnd_entry, extack);
		if (ret < 0)
			return ret;
	} else {
		return -EINVAL;
	}

	p4tc_pipeline_get(ctx->pipeline);
	opnd_entry->pipeline = ctx->pipeline;
	p4tc_table_get(ctx->table);
	opnd_entry->table = ctx->table;

	return 0;
}

static int
p4tc_filter_opnd_cmd_build(struct p4tc_filter_opnd *opnd, struct nlattr *nla,
			   struct netlink_ext_ack *extack)
{
	u32 cmd = nla_get_u32(nla);

	if (cmd == RTM_P4TC_GET) {
		NL_SET_ERR_MSG(extack,
			       "Get command is not allowed");
		return -EINVAL;
	}

	opnd->opnd_cmd.cmd = cmd;

	return 0;
}

static struct p4tc_filter_opnd *
p4tc_filter_opnd_build(struct p4tc_filter_context *ctx, struct nlattr *nla,
		       struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_FILTER_OPND_MAX + 1];
	struct p4tc_filter_opnd *filter_opnd;
	int ret;

	ret = nla_parse_nested(tb, P4TC_FILTER_OPND_MAX, nla,
			       p4tc_filter_opnd_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	filter_opnd = kzalloc(sizeof(*filter_opnd), GFP_KERNEL);
	if (!filter_opnd)
		return ERR_PTR(-ENOMEM);

	if (tb[P4TC_FILTER_OPND_ENTRY]) {
		ret = p4tc_filter_opnd_entry_build(ctx,
						   &filter_opnd->opnd_entry,
						   tb[P4TC_FILTER_OPND_ENTRY],
						   extack);
		if (ret < 0)
			goto free_filter_opnd;

		filter_opnd->opnd_kind = P4TC_FILTER_OPND_KIND_ENTRY;
	} else if (tb[P4TC_FILTER_OPND_CMD]) {
		ret = p4tc_filter_opnd_cmd_build(filter_opnd,
						 tb[P4TC_FILTER_OPND_CMD],
						 extack);
		if (ret < 0)
			goto free_filter_opnd;
		filter_opnd->opnd_kind = P4TC_FILTER_OPND_KIND_CMD;
	} else {
		NL_SET_ERR_MSG(extack, "Unsupported operand kind");
		ret = -ENOTSUPP;
		goto free_filter_opnd;
	}

	return filter_opnd;

free_filter_opnd:
	kfree(filter_opnd);
	return ERR_PTR(ret);
}

static bool
p4tc_filter_oper_rel_opnd_entry_is_comp(struct p4tc_filter_opnd_entry *opnd1,
					struct netlink_ext_ack *extack)
{
	switch (opnd1->opnd_entry_kind) {
	case P4TC_FILTER_OPND_ENTRY_KIND_KEY:
		NL_SET_ERR_MSG(extack,
			       "Compare with key operand isn't allowed");
		return false;
	case P4TC_FILTER_OPND_ENTRY_KIND_ACT:
		NL_SET_ERR_MSG(extack,
			       "Compare with act operand is forbidden");
		return false;
	case P4TC_FILTER_OPND_ENTRY_KIND_ACT_PARAM: {
		struct p4tc_act_param *param;

		param = opnd1->act.param;
		if (!p4tc_is_type_numeric(param->type->typeid)) {
			NL_SET_ERR_MSG(extack,
				       "May only compare numeric act parameters");
			return false;
		}
		return true;
	}
	default:
		return true;
	}
}

static bool p4tc_filter_oper_rel_opnd_is_comp(struct p4tc_filter_opnd *opnd1,
					      struct netlink_ext_ack *extack)
{
	switch (opnd1->opnd_kind) {
	case P4TC_FILTER_OPND_KIND_ENTRY: {
		struct p4tc_filter_opnd_entry *opnd_entry = &opnd1->opnd_entry;

		return p4tc_filter_oper_rel_opnd_entry_is_comp(opnd_entry,
							       extack);
	}
	case P4TC_FILTER_OPND_KIND_CMD:
		NL_SET_ERR_MSG(extack, "Unable to compare command");
		return false;
	default:
		/* Will never happen */
		return false;
	}
}

static bool p4tc_filter_oper_rel_is_valid(struct p4tc_filter_oper *filter_oper,
					  struct netlink_ext_ack *extack)
{
	struct p4tc_filter_node *filter_node1 = filter_oper->node1;
	struct p4tc_filter_opnd *opnd = filter_node1->opnd;

	switch (filter_oper->op_value) {
	case P4TC_FILTER_OP_KIND_REL_EQ:
	case P4TC_FILTER_OP_KIND_REL_NEQ:
		return true;
	case P4TC_FILTER_OP_KIND_REL_LT:
	case P4TC_FILTER_OP_KIND_REL_GT:
	case P4TC_FILTER_OP_KIND_REL_LE:
	case P4TC_FILTER_OP_KIND_REL_GE:
		return p4tc_filter_oper_rel_opnd_is_comp(opnd, extack);
	default:
		/* Will never happen */
		return false;
	}
}

static bool p4tc_filter_oper_is_valid(struct p4tc_filter_oper *filter_oper,
				      struct netlink_ext_ack *extack)
{
	switch (filter_oper->op_kind) {
	case P4TC_FILTER_OP_KIND_LOGICAL:
		return true;
	case P4TC_FILTER_OP_KIND_REL:
		return p4tc_filter_oper_rel_is_valid(filter_oper, extack);
	default:
		/* Will never happen */
		return false;
	}
}

static struct p4tc_filter_oper *
p4tc_filter_oper_build(struct p4tc_filter_context *ctx, struct nlattr *nla,
		       u32 depth, struct netlink_ext_ack *extack);

static struct p4tc_filter_node *
p4tc_filter_node_build(struct p4tc_filter_context *ctx,  struct nlattr *nla,
		       u32 depth, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_FILTER_OP_NODE_MAX + 1];
	struct p4tc_filter_oper *operation;
	struct p4tc_filter_node *node;
	int ret;

	ret = nla_parse_nested(tb, P4TC_FILTER_OP_NODE_MAX, nla,
			       p4tc_entry_filter_op_node_policy, extack);
	if (ret < 0)
		return ERR_PTR(-EINVAL);

	if ((!tb[P4TC_FILTER_OP_NODE_PARENT] &&
	     !tb[P4TC_FILTER_OP_NODE_LEAF]) ||
	    (tb[P4TC_FILTER_OP_NODE_PARENT] && tb[P4TC_FILTER_OP_NODE_LEAF])) {
		NL_SET_ERR_MSG(extack,
			       "Must specify either P4TC_FILTER_OP_NODE_PARENT or P4TC_FILTER_OP_NODE_LEAF");
		return ERR_PTR(-EINVAL);
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	if (tb[P4TC_FILTER_OP_NODE_LEAF]) {
		struct p4tc_filter_opnd *opnd;

		opnd = p4tc_filter_opnd_build(ctx,
					      tb[P4TC_FILTER_OP_NODE_LEAF],
					      extack);
		if (IS_ERR(opnd)) {
			ret = PTR_ERR(opnd);
			goto free_node;
		}
		node->ntype = P4TC_FILTER_OP_NODE_LEAF;
		node->opnd = opnd;

		return node;
	}

	if (depth == P4TC_FILTER_DEPTH_LIMIT) {
		NL_SET_ERR_MSG_FMT(extack, "Recursion limit (%d) exceeded",
				   P4TC_FILTER_DEPTH_LIMIT);
		ret = -EINVAL;
		goto free_node;
	}

	operation = p4tc_filter_oper_build(ctx,
					   tb[P4TC_FILTER_OP_NODE_PARENT],
					   depth + 1, extack);
	if (IS_ERR(operation)) {
		ret = PTR_ERR(operation);
		goto free_node;
	}
	node->ntype = P4TC_FILTER_OP_NODE_PARENT;
	node->operation = operation;

	return node;

free_node:
	kfree(node);
	return ERR_PTR(ret);
}

static struct p4tc_filter_oper *
p4tc_filter_oper_build(struct p4tc_filter_context *ctx, struct nlattr *nla,
		       u32 depth, struct netlink_ext_ack *extack)
{
	struct p4tc_filter_node *filter_node2 = NULL;
	struct nlattr *tb[P4TC_FILTER_OP_MAX + 1];
	struct p4tc_filter_node *filter_node1;
	struct p4tc_filter_oper *filter_oper;
	u16 filter_op_value;
	u16 filter_op_kind;
	int ret;

	if (!nla)
		return ERR_PTR(-EINVAL);

	ret = nla_parse_nested(tb, P4TC_FILTER_OP_MAX, nla,
			       p4tc_entry_filter_op_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	if (!tb[P4TC_FILTER_OP_KIND] || !tb[P4TC_FILTER_OP_VALUE]) {
		NL_SET_ERR_MSG(extack, "Must specify filter op kind and value");
		return ERR_PTR(-EINVAL);
	}

	filter_op_kind = nla_get_u16(tb[P4TC_FILTER_OP_KIND]);
	filter_op_value = nla_get_u16(tb[P4TC_FILTER_OP_VALUE]);

	/* filter_op_kind is checked by netlink policy */
	if (!p4tc_filter_op_value_valid(filter_op_kind, filter_op_value,
					extack))
		return ERR_PTR(-EINVAL);

	if (!tb[P4TC_FILTER_OP_NODE1]) {
		NL_SET_ERR_MSG_FMT(extack, "Must specify filter node1");
		return ERR_PTR(-EINVAL);
	}

	if (p4tc_filter_op_requires_node2(filter_op_kind, filter_op_value)) {
		if (!tb[P4TC_FILTER_OP_NODE2]) {
			NL_SET_ERR_MSG(extack,
				       "Must specify filter node2");
			return ERR_PTR(-EINVAL);
		}
	}

	filter_oper = kzalloc(sizeof(*filter_oper), GFP_KERNEL);
	if (!filter_oper)
		return ERR_PTR(-ENOMEM);

	filter_node1 = p4tc_filter_node_build(ctx,
					      tb[P4TC_FILTER_OP_NODE1],
					      depth, extack);
	if (IS_ERR(filter_node1)) {
		ret = PTR_ERR(filter_node1);
		goto free_operation;
	}

	if (tb[P4TC_FILTER_OP_NODE2]) {
		filter_node2 = p4tc_filter_node_build(ctx,
						      tb[P4TC_FILTER_OP_NODE2],
						      depth, extack);
		if (IS_ERR(filter_node2)) {
			ret = PTR_ERR(filter_node2);
			goto free_node1;
		}
	}

	filter_oper->op_kind = filter_op_kind;
	filter_oper->op_value = filter_op_value;
	filter_oper->node1 = filter_node1;
	filter_oper->node2 = filter_node2;

	if (!p4tc_filter_oper_is_valid(filter_oper, extack)) {
		ret = -EINVAL;
		goto free_node2;
	}

	return filter_oper;

free_node2:
	p4tc_filter_node_destroy(filter_node2);

free_node1:
	p4tc_filter_node_destroy(filter_node1);

free_operation:
	kfree(filter_oper);

	return ERR_PTR(ret);
}

static bool p4tc_filter_obj_id_supported(u32 obj_id,
					 struct netlink_ext_ack *extack)
{
	switch (obj_id) {
	case P4TC_FILTER_OBJ_RUNTIME_TABLE:
		return true;
	default:
		NL_SET_ERR_MSG_FMT(extack, "Unsupported runtime object ID %u\n",
				   obj_id);
		return false;
	}
}

static struct p4tc_filter *
__p4tc_filter_build(struct p4tc_filter_context *ctx,
		    struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct p4tc_filter_oper *filter_oper = NULL;
	struct p4tc_filter *filter;

	if (!p4tc_filter_obj_id_supported(ctx->obj_id, extack))
		return ERR_PTR(-EOPNOTSUPP);

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return ERR_PTR(-ENOMEM);

	if (nla) {
		filter_oper = p4tc_filter_oper_build(ctx, nla, 0, extack);
		if (IS_ERR(filter_oper)) {
			kfree(filter);
			return (struct p4tc_filter *)filter_oper;
		}
	}

	filter->operation = filter_oper;
	filter->obj_id = ctx->obj_id;

	switch (ctx->obj_id) {
	case P4TC_FILTER_OBJ_RUNTIME_TABLE: {
		struct p4tc_table *table = ctx->table;

		filter->tbl_id = table ? table->tbl_id : 0;
		break;
	}
	default:
		break;
	}

	return filter;
}

struct p4tc_filter *
p4tc_filter_build(struct p4tc_filter_context *ctx,
		  struct nlattr *nla, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_FILTER_MAX + 1];
	int ret;

	if (!nla)
		return NULL;

	ret = nla_parse_nested(tb, P4TC_FILTER_MAX, nla,
			       p4tc_entry_filter_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	return __p4tc_filter_build(ctx, tb[P4TC_FILTER_OP], extack);
}

static int p4tc_filter_sock_build(struct sk_buff *skb,
				  struct p4tc_filter_context *ctx,
				  struct nlattr *nla,
				  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_FILTER_MAX + 1] = {0};
	struct p4tc_filter_sock *filter_sock;
	struct sock *sk = NETLINK_CB(skb).sk;
	struct p4tc_filter *filter = NULL;
	int ret;

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_FILTER_MAX, nla,
				       p4tc_entry_filter_policy, extack);
		if (ret < 0)
			return ret;
	}

	filter = __p4tc_filter_build(ctx, tb[P4TC_FILTER_OP], extack);
	if (IS_ERR(filter))
		return PTR_ERR(filter);

	filter_sock = kzalloc(sizeof(*filter_sock), GFP_KERNEL);
	if (!filter_sock) {
		ret = -ENOMEM;
		goto destroy_filter;
	}

	lock_sock(sk);
	sock_hold(sk);
	filter_sock->obj_id = ctx->obj_id;
	write_pnet(&filter_sock->pnet, sock_net(sk));
	filter_sock->portid = NETLINK_CB(skb).portid;
	filter_sock->sk = sk;
	filter_sock->p4tc_filter = filter;
	ret = p4tc_filter_sock_insert(filter_sock);
	release_sock(sk);

	if (ret < 0)
		goto free_filter_sock;

	return 0;

free_filter_sock:
	kfree(filter_sock);

destroy_filter:
	p4tc_filter_destroy(filter);
	__sock_put(sk);
	return ret;
}

int p4tc_filter_subscribe(struct sk_buff *skb,
			  struct p4tc_filter_context *ctx,
			  struct nlattr *nla,
			  struct netlink_ext_ack *extack)
{
	return p4tc_filter_sock_build(skb, ctx, nla, extack);
}

static int
p4tc_filter_act_param(struct p4tc_act_param *entry_act_param,
		      struct p4tc_act_param *filter_act_param)
{
	return p4t_cmp(NULL, entry_act_param->type, entry_act_param->value,
		       NULL, filter_act_param->type, filter_act_param->value);
}

static bool p4tc_filter_cmp_op(u16 op_value, int cmp)
{
	switch (op_value) {
	case P4TC_FILTER_OP_KIND_REL_EQ:
		return !cmp;
	case P4TC_FILTER_OP_KIND_REL_NEQ:
		return !!cmp;
	case P4TC_FILTER_OP_KIND_REL_LT:
		return cmp < 0;
	case P4TC_FILTER_OP_KIND_REL_GT:
		return cmp > 0;
	case P4TC_FILTER_OP_KIND_REL_LE:
		return cmp <= 0;
	case P4TC_FILTER_OP_KIND_REL_GE:
		return cmp >= 0;
	default:
		return false;
	}
}

static bool
p4tc_filter_act_params(struct p4tc_filter_oper *filter_oper,
		       struct tcf_p4act_params *entry_act_params,
		       struct p4tc_act_param *filter_act_param)
{
	struct idr *entry_act_params_idr = &entry_act_params->params_idr;
	struct p4tc_act_param *entry_act_param;
	int cmp;

	entry_act_param = p4a_parm_find_byid(entry_act_params_idr,
					     filter_act_param->id);
	if (!entry_act_param)
		return false;

	cmp = p4tc_filter_act_param(entry_act_param,
				    filter_act_param);
	return p4tc_filter_cmp_op(filter_oper->op_value, cmp);
}

static bool
p4tc_filter_exec_act(struct p4tc_filter_oper *filter_oper,
		     struct p4tc_table_entry_value *value,
		     struct p4tc_filter_opnd_entry *filter_opnd)
{
	struct tcf_p4act *p4act;

	if (!filter_opnd)
		return true;

	if (!value->acts[0])
		return false;

	p4act = to_p4act(value->acts[0]);
	if (filter_opnd->act.val->a_id != p4act->act_id)
		return false;

	if (filter_opnd->opnd_entry_kind == P4TC_FILTER_OPND_ENTRY_KIND_ACT_PARAM) {
		struct tcf_p4act_params *params;

		params = rcu_dereference(p4act->params);
		return p4tc_filter_act_params(filter_oper, params,
					      filter_opnd->act.param);
	}

	return true;
}

static bool
p4tc_filter_exec_opnd_entry(struct p4tc_filter_oper *filter_oper,
			    struct p4tc_table_entry *entry,
			    struct p4tc_filter_opnd_entry *opnd_entry)
{
	switch (opnd_entry->opnd_entry_kind) {
	case P4TC_FILTER_OPND_ENTRY_KIND_KEY: {
		u8 key[BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = {0};
		u32 keysz;
		int cmp;

		keysz = BITS_TO_BYTES(entry->key.keysz);
		p4tc_tbl_entry_mask_key(key, entry->key.fa_key,
					opnd_entry->entry_key.mask, keysz);

		cmp = memcmp(key, opnd_entry->entry_key.val, keysz);
		return p4tc_filter_cmp_op(filter_oper->op_value, cmp);
	}
	case P4TC_FILTER_OPND_ENTRY_KIND_ACT:
	case P4TC_FILTER_OPND_ENTRY_KIND_ACT_PARAM:
		return p4tc_filter_exec_act(filter_oper,
					     p4tc_table_entry_value(entry),
					     opnd_entry);
	case P4TC_FILTER_OPND_ENTRY_KIND_PRIO: {
		struct p4tc_table_entry_value *value;

		value = p4tc_table_entry_value(entry);
		switch (filter_oper->op_value) {
		case P4TC_FILTER_OP_KIND_REL_EQ:
			return value->prio == opnd_entry->prio;
		case P4TC_FILTER_OP_KIND_REL_NEQ:
			return value->prio != opnd_entry->prio;
		case P4TC_FILTER_OP_KIND_REL_LT:
			return value->prio < opnd_entry->prio;
		case P4TC_FILTER_OP_KIND_REL_GT:
			return value->prio > opnd_entry->prio;
		case P4TC_FILTER_OP_KIND_REL_LE:
			return value->prio <= opnd_entry->prio;
		case P4TC_FILTER_OP_KIND_REL_GE:
			return value->prio >= opnd_entry->prio;
		default:
			return false;
		}
	}
	case P4TC_FILTER_OPND_ENTRY_KIND_MSECS: {
		struct p4tc_table_entry_value *value;
		unsigned long jiffy_since;
		unsigned long last_used;

		jiffy_since = jiffies -
			msecs_to_jiffies(opnd_entry->msecs_since);

		value = p4tc_table_entry_value(entry);
		last_used = rcu_dereference(value->tm)->lastused;

		switch (filter_oper->op_value) {
		case P4TC_FILTER_OP_KIND_REL_EQ:
			return jiffy_since == last_used;
		case P4TC_FILTER_OP_KIND_REL_NEQ:
			return jiffy_since != last_used;
		case P4TC_FILTER_OP_KIND_REL_LT:
			return time_before(jiffy_since, last_used);
		case P4TC_FILTER_OP_KIND_REL_GT:
			return time_after(jiffy_since, last_used);
		case P4TC_FILTER_OP_KIND_REL_LE:
			return time_before_eq(jiffy_since, last_used);
		case P4TC_FILTER_OP_KIND_REL_GE:
			return time_after_eq(jiffy_since, last_used);
		default:
			/* Will never happen */
			return false;
		}
	}
	default:
		return false;
	}
}

static bool
p4tc_filter_exec_opnd_cmd(struct p4tc_filter_oper *filter_oper,
			  u32 cmd, struct p4tc_filter_opnd_cmd *opnd_cmd)
{
	switch (filter_oper->op_value) {
	case P4TC_FILTER_OP_KIND_REL_EQ:
		return cmd == opnd_cmd->cmd;
	case P4TC_FILTER_OP_KIND_REL_NEQ:
		return cmd != opnd_cmd->cmd;
	/* Will never happen */
	default:
		return false;
	}
}

static bool
p4tc_filter_exec_opnd(struct p4tc_filter_oper *filter_oper,
		      struct p4tc_filter_data *filter_data,
		      struct p4tc_filter_opnd *filter_opnd)
{
	switch (filter_opnd->opnd_kind) {
	case P4TC_FILTER_OPND_KIND_ENTRY: {
		struct p4tc_table_entry *entry = filter_data->table.entry;

		return p4tc_filter_exec_opnd_entry(filter_oper, entry,
						   &filter_opnd->opnd_entry);
	}
	case P4TC_FILTER_OPND_KIND_CMD:
		return p4tc_filter_exec_opnd_cmd(filter_oper, filter_data->cmd,
						 &filter_opnd->opnd_cmd);
	default:
		return false;
	}
}

static bool p4tc_filter_exec_oper(struct p4tc_filter_oper *filter_oper,
				  struct p4tc_filter_data *filter_data);

static bool p4tc_filter_exec_node(struct p4tc_filter_oper *filter_oper,
				  struct p4tc_filter_data *filter_data,
				  struct p4tc_filter_node *node)
{
	if (node->ntype == P4TC_FILTER_OP_NODE_PARENT)
		return p4tc_filter_exec_oper(node->operation, filter_data);

	return p4tc_filter_exec_opnd(filter_oper, filter_data, node->opnd);
}

static bool
p4tc_filter_exec_oper_logical(struct p4tc_filter_oper *filter_oper,
			      struct p4tc_filter_data *filter_data)
{
	bool ret;

	ret = p4tc_filter_exec_node(filter_oper, filter_data, filter_oper->node1);

	switch (filter_oper->op_value) {
	case P4TC_FILTER_OP_KIND_LOGICAL_AND:
		return ret && p4tc_filter_exec_node(filter_oper, filter_data,
						    filter_oper->node2);
	case P4TC_FILTER_OP_KIND_LOGICAL_OR:
		return ret || p4tc_filter_exec_node(filter_oper, filter_data,
						    filter_oper->node2);
	case P4TC_FILTER_OP_KIND_LOGICAL_NOT:
		return !ret;
	case P4TC_FILTER_OP_KIND_LOGICAL_XOR:
		return ret != p4tc_filter_exec_node(filter_oper, filter_data,
						    filter_oper->node2);
	default:
		/* Never happens */
		return false;
	}
}

static bool
p4tc_filter_exec_oper_rel(struct p4tc_filter_oper *filter_oper,
			  struct p4tc_filter_data *filter_data)
{
	return p4tc_filter_exec_node(filter_oper, filter_data,
				     filter_oper->node1);
}

static bool
p4tc_filter_exec_oper(struct p4tc_filter_oper *filter_oper,
		      struct p4tc_filter_data *filter_data)
{
	switch (filter_oper->op_kind) {
	case P4TC_FILTER_OP_KIND_REL:
		return p4tc_filter_exec_oper_rel(filter_oper, filter_data);
	case P4TC_FILTER_OP_KIND_LOGICAL:
		return p4tc_filter_exec_oper_logical(filter_oper, filter_data);
	default:
		return false;
	}
}

bool p4tc_filter_exec(struct p4tc_filter *filter,
		      struct p4tc_filter_data *filter_data)
{
	if (!filter)
		return true;

	if (filter->operation)
		return p4tc_filter_exec_oper(filter->operation, filter_data);

	return true;
}

int p4tc_filter_broadcast_cb(struct sock *dsk, struct sk_buff *skb,
			     void *data)
{
	struct p4tc_filter_data *filter_data = data;
	struct p4tc_filter_sock *filter_sock;
	int ret;

	filter_sock = p4tc_filter_sock_table_lookup_by_sock(dsk);
	if (!filter_sock)
		return 0;

	if (filter_data->obj_id != filter_sock->obj_id)
		return 1;

	switch (filter_data->obj_id) {
	case P4TC_FILTER_OBJ_RUNTIME_TABLE: {
		struct p4tc_filter *filter = filter_sock->p4tc_filter;
		if (filter->tbl_id != filter_data->table.id)
			return 1;

		return !p4tc_filter_exec(filter, filter_data);
	}
	default:
		ret = 0;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(p4tc_filter_broadcast_cb);
