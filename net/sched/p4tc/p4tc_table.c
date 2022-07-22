// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_table.c	P4 TC TABLE
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

#define P4TC_P_UNSPEC 0
#define P4TC_P_CREATED 1

static int tcf_key_try_set_state_ready(struct p4tc_table_key *key,
				       struct netlink_ext_ack *extack)
{
	if (!key->key_acts) {
		NL_SET_ERR_MSG(extack,
			       "Table key must have actions before sealing pipelline");
		return -EINVAL;
	}

	return 0;
}

static int __tcf_table_try_set_state_ready(struct p4tc_table *table,
					   struct netlink_ext_ack *extack)
{
	if (!table->tbl_postacts) {
		NL_SET_ERR_MSG(extack,
			       "All tables must have postactions before sealing pipelline");
		return -EINVAL;
	}

	if (!table->tbl_key) {
		NL_SET_ERR_MSG(extack,
			       "Table must have key before sealing pipeline");
		return -EINVAL;
	}

	return tcf_key_try_set_state_ready(table->tbl_key, extack);
}

int tcf_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;
	unsigned long tmp, id;
	int ret;

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, id) {
		ret = __tcf_table_try_set_state_ready(table, extack);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static const struct nla_policy p4tc_table_policy[P4TC_TABLE_MAX + 1] = {
	[P4TC_TABLE_NAME] = { .type = NLA_STRING, .len = TABLENAMSIZ },
	[P4TC_TABLE_INFO] = { .type = NLA_BINARY,
			      .len = sizeof(struct p4tc_table_parm) },
	[P4TC_TABLE_PREACTIONS] = { .type = NLA_NESTED },
	[P4TC_TABLE_KEY] = { .type = NLA_NESTED },
	[P4TC_TABLE_POSTACTIONS] = { .type = NLA_NESTED },
	[P4TC_TABLE_DEFAULT_HIT] = { .type = NLA_NESTED },
	[P4TC_TABLE_DEFAULT_MISS] = { .type = NLA_NESTED },
	[P4TC_TABLE_ACTS_LIST] = { .type = NLA_NESTED },
	[P4TC_TABLE_OPT_ENTRY] = { .type = NLA_NESTED },
};

static const struct nla_policy p4tc_table_key_policy[P4TC_MAXPARSE_KEYS + 1] = {
	[P4TC_KEY_ACT] = { .type = NLA_NESTED },
};

static int tcf_table_key_fill_nlmsg(struct sk_buff *skb,
				    struct p4tc_table_key *key)
{
	int ret = 0;
	struct nlattr *nest_action;

	if (key->key_acts) {
		nest_action = nla_nest_start(skb, P4TC_KEY_ACT);
		ret = tcf_action_dump(skb, key->key_acts, 0, 0, false);
		if (ret < 0)
			return ret;
		nla_nest_end(skb, nest_action);
	}

	return ret;
}

static int _tcf_table_fill_nlmsg(struct sk_buff *skb, struct p4tc_table *table)
{
	unsigned char *b = nlmsg_get_pos(skb);
	int i = 1;
	struct p4tc_table_perm *tbl_perm;
	struct p4tc_table_act *table_act;
	struct nlattr *nested_tbl_acts;
	struct nlattr *default_missact;
	struct nlattr *default_hitact;
	struct nlattr *nested_count;
	struct p4tc_table_parm parm;
	struct nlattr *nest_key;
	struct nlattr *nest;
	struct nlattr *preacts;
	struct nlattr *postacts;
	int err;

	if (nla_put_u32(skb, P4TC_PATH, table->tbl_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_TABLE_NAME, table->common.name))
		goto out_nlmsg_trim;

	parm.tbl_keysz = table->tbl_keysz;
	parm.tbl_max_entries = table->tbl_max_entries;
	parm.tbl_max_masks = table->tbl_max_masks;
	parm.tbl_num_entries = refcount_read(&table->tbl_entries_ref) - 1;

	tbl_perm = rcu_dereference_rtnl(table->tbl_permissions);
	parm.tbl_permissions = tbl_perm->permissions;

	if (table->tbl_key) {
		nest_key = nla_nest_start(skb, P4TC_TABLE_KEY);
		err = tcf_table_key_fill_nlmsg(skb, table->tbl_key);
		if (err < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, nest_key);
	}

	if (table->tbl_preacts) {
		preacts = nla_nest_start(skb, P4TC_TABLE_PREACTIONS);
		if (tcf_action_dump(skb, table->tbl_preacts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, preacts);
	}

	if (table->tbl_postacts) {
		postacts = nla_nest_start(skb, P4TC_TABLE_POSTACTIONS);
		if (tcf_action_dump(skb, table->tbl_postacts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, postacts);
	}

	if (table->tbl_default_hitact) {
		struct p4tc_table_defact *hitact;

		default_hitact = nla_nest_start(skb, P4TC_TABLE_DEFAULT_HIT);
		rcu_read_lock();
		hitact = rcu_dereference_rtnl(table->tbl_default_hitact);
		if (hitact->default_acts) {
			struct nlattr *nest;

			nest = nla_nest_start(skb, P4TC_TABLE_DEFAULT_ACTION);
			if (tcf_action_dump(skb, hitact->default_acts, 0, 0,
					    false) < 0) {
				rcu_read_unlock();
				goto out_nlmsg_trim;
			}
			nla_nest_end(skb, nest);
		}
		if (nla_put_u16(skb, P4TC_TABLE_DEFAULT_PERMISSIONS,
				hitact->permissions) < 0) {
			rcu_read_unlock();
			goto out_nlmsg_trim;
		}
		rcu_read_unlock();
		nla_nest_end(skb, default_hitact);
	}

	if (table->tbl_default_missact) {
		struct p4tc_table_defact *missact;

		default_missact = nla_nest_start(skb, P4TC_TABLE_DEFAULT_MISS);
		rcu_read_lock();
		missact = rcu_dereference_rtnl(table->tbl_default_missact);
		if (missact->default_acts) {
			struct nlattr *nest;

			nest = nla_nest_start(skb, P4TC_TABLE_DEFAULT_ACTION);
			if (tcf_action_dump(skb, missact->default_acts, 0, 0,
					    false) < 0) {
				rcu_read_unlock();
				goto out_nlmsg_trim;
			}
			nla_nest_end(skb, nest);
		}
		if (nla_put_u16(skb, P4TC_TABLE_DEFAULT_PERMISSIONS,
				missact->permissions) < 0) {
			rcu_read_unlock();
			goto out_nlmsg_trim;
		}
		rcu_read_unlock();
		nla_nest_end(skb, default_missact);
	}

	nested_tbl_acts = nla_nest_start(skb, P4TC_TABLE_ACTS_LIST);
	list_for_each_entry(table_act, &table->tbl_acts_list, node) {
		nested_count = nla_nest_start(skb, i);
		if (nla_put_string(skb, P4TC_TABLE_ACT_NAME,
				   table_act->ops->kind) < 0)
			goto out_nlmsg_trim;
		if (nla_put_u32(skb, P4TC_TABLE_ACT_FLAGS,
				table_act->flags) < 0)
			goto out_nlmsg_trim;

		nla_nest_end(skb, nested_count);
		i++;
	}
	nla_nest_end(skb, nested_tbl_acts);

	if (table->tbl_const_entry) {
		struct nlattr *const_nest;

		const_nest = nla_nest_start(skb, P4TC_TABLE_OPT_ENTRY);
		p4tca_table_get_entry_fill(skb, table, table->tbl_const_entry,
					   table->tbl_id);
		nla_nest_end(skb, const_nest);
	}
	kfree(table->tbl_const_entry);
	table->tbl_const_entry = NULL;

	if (nla_put(skb, P4TC_TABLE_INFO, sizeof(parm), &parm))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_table_fill_nlmsg(struct net *net, struct sk_buff *skb,
				struct p4tc_template_common *template,
				struct netlink_ext_ack *extack)
{
	struct p4tc_table *table = to_table(template);

	if (_tcf_table_fill_nlmsg(skb, table) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table");
		return -EINVAL;
	}

	return 0;
}

static inline void tcf_table_key_put(struct p4tc_table_key *key)
{
	p4tc_action_destroy(key->key_acts);
	kfree(key);
}

static inline void p4tc_table_defact_destroy(struct p4tc_table_defact *defact)
{
	if (defact) {
		p4tc_action_destroy(defact->default_acts);
		kfree(defact);
	}
}

void tcf_table_acts_list_destroy(struct list_head *acts_list)
{
	struct p4tc_table_act *table_act, *tmp;

	list_for_each_entry_safe(table_act, tmp, acts_list, node) {
		struct p4tc_act *act;

		act = container_of(table_act->ops, typeof(*act), ops);
		list_del(&table_act->node);
		kfree(table_act);
		WARN_ON(!refcount_dec_not_one(&act->a_ref));
	}
}

static inline int _tcf_table_put(struct net *net, struct nlattr **tb,
				 struct p4tc_pipeline *pipeline,
				 struct p4tc_table *table,
				 bool unconditional_purge,
				 struct netlink_ext_ack *extack)
{
	bool default_act_del = false;
	struct p4tc_table_perm *perm;

	if (tb)
		default_act_del = tb[P4TC_TABLE_DEFAULT_HIT] ||
				  tb[P4TC_TABLE_DEFAULT_MISS];

	if (!default_act_del) {
		if (!unconditional_purge &&
		    !refcount_dec_if_one(&table->tbl_ctrl_ref)) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete referenced table");
			return -EBUSY;
		}

		if (!unconditional_purge &&
		    !refcount_dec_if_one(&table->tbl_ref)) {
			refcount_set(&table->tbl_ctrl_ref, 1);
			NL_SET_ERR_MSG(extack,
				       "Unable to delete referenced table");
			return -EBUSY;
		}
	}

	if (tb && tb[P4TC_TABLE_DEFAULT_HIT]) {
		struct p4tc_table_defact *hitact;

		rcu_read_lock();
		hitact = rcu_dereference(table->tbl_default_hitact);
		if (hitact && !p4tc_ctrl_delete_ok(hitact->permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Permission denied: Unable to delete default hitact");
			rcu_read_unlock();
			return -EPERM;
		}
		rcu_read_unlock();
	}

	if (tb && tb[P4TC_TABLE_DEFAULT_MISS]) {
		struct p4tc_table_defact *missact;

		rcu_read_lock();
		missact = rcu_dereference(table->tbl_default_missact);
		if (missact && !p4tc_ctrl_delete_ok(missact->permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Permission denied: Unable to delete default missact");
			rcu_read_unlock();
			return -EPERM;
		}
		rcu_read_unlock();
	}

	if (!default_act_del || tb[P4TC_TABLE_DEFAULT_HIT]) {
		struct p4tc_table_defact *hitact;

		hitact = rtnl_dereference(table->tbl_default_hitact);
		if (hitact) {
			rcu_replace_pointer_rtnl(table->tbl_default_hitact,
						 NULL);
			synchronize_rcu();
			p4tc_table_defact_destroy(hitact);
		}
	}

	if (!default_act_del || tb[P4TC_TABLE_DEFAULT_MISS]) {
		struct p4tc_table_defact *missact;

		missact = rtnl_dereference(table->tbl_default_missact);
		if (missact) {
			rcu_replace_pointer_rtnl(table->tbl_default_missact,
						 NULL);
			synchronize_rcu();
			p4tc_table_defact_destroy(missact);
		}
	}

	if (default_act_del)
		return 0;

	if (table->tbl_key)
		tcf_table_key_put(table->tbl_key);

	p4tc_action_destroy(table->tbl_preacts);
	p4tc_action_destroy(table->tbl_postacts);

	tcf_table_acts_list_destroy(&table->tbl_acts_list);

	rhltable_free_and_destroy(&table->tbl_entries,
				  tcf_table_entry_destroy_hash, table);

	idr_destroy(&table->tbl_masks_idr);
	idr_destroy(&table->tbl_prio_idr);

	perm = rcu_replace_pointer_rtnl(table->tbl_permissions, NULL);
	kfree_rcu(perm, rcu);

	idr_remove(&pipeline->p_tbl_idr, table->tbl_id);
	pipeline->curr_tables -= 1;

	kfree(table);

	return 0;
}

static int tcf_table_put(struct net *net, struct p4tc_template_common *tmpl,
			 bool unconditional_purge,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		tcf_pipeline_find_byid(net, tmpl->p_id);
	struct p4tc_table *table = to_table(tmpl);

	return _tcf_table_put(net, NULL, pipeline, table, unconditional_purge,
			      extack);
}

static inline struct p4tc_table_key *
tcf_table_key_add(struct net *net, struct p4tc_table *table, struct nlattr *nla,
		  struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *tb[P4TC_TKEY_MAX + 1];
	struct p4tc_table_key *key;

	ret = nla_parse_nested(tb, P4TC_TKEY_MAX, nla, p4tc_table_key_policy,
			       extack);
	if (ret < 0)
		goto out;

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		NL_SET_ERR_MSG(extack, "Failed to allocate table key");
		ret = -ENOMEM;
		goto out;
	}

	if (tb[P4TC_KEY_ACT]) {
		key->key_acts = kcalloc(TCA_ACT_MAX_PRIO,
					sizeof(struct tc_action *), GFP_KERNEL);
		if (!key->key_acts) {
			ret = -ENOMEM;
			goto free_key;
		}

		ret = p4tc_action_init(net, tb[P4TC_KEY_ACT], key->key_acts,
				       table->common.p_id, 0, extack);
		if (ret < 0) {
			kfree(key->key_acts);
			goto free_key;
		}
		key->key_num_acts = ret;
	}

	return key;

free_key:
	kfree(key);

out:
	return ERR_PTR(ret);
}

struct p4tc_table *tcf_table_find_byid(struct p4tc_pipeline *pipeline,
				       const u32 tbl_id)
{
	return idr_find(&pipeline->p_tbl_idr, tbl_id);
}

static struct p4tc_table *table_find_byname(const char *tblname,
					    struct p4tc_pipeline *pipeline)
{
	struct p4tc_table *table;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, id)
		if (strncmp(table->common.name, tblname, TABLENAMSIZ) == 0)
			return table;

	return NULL;
}

#define SEPARATOR '/'
struct p4tc_table *tcf_table_find_byany(struct p4tc_pipeline *pipeline,
					const char *tblname, const u32 tbl_id,
					struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;
	int err;

	if (tbl_id) {
		table = tcf_table_find_byid(pipeline, tbl_id);
		if (!table) {
			NL_SET_ERR_MSG(extack, "Unable to find table by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (tblname) {
			table = table_find_byname(tblname, pipeline);
			if (!table) {
				NL_SET_ERR_MSG(extack, "Table name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack, "Must specify table name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return table;
out:
	return ERR_PTR(err);
}

struct p4tc_table *tcf_table_get(struct p4tc_pipeline *pipeline,
				 const char *tblname, const u32 tbl_id,
				 struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;

	table = tcf_table_find_byany(pipeline, tblname, tbl_id, extack);
	if (IS_ERR(table))
		return table;

	/* Should never be zero */
	WARN_ON(!refcount_inc_not_zero(&table->tbl_ref));
	return table;
}

void tcf_table_put_ref(struct p4tc_table *table)
{
	/* Should never be zero */
	WARN_ON(!refcount_dec_not_one(&table->tbl_ref));
}

static int tcf_table_init_default_act(struct net *net, struct nlattr **tb,
				      struct p4tc_table_defact **default_act,
				      u32 pipeid, __u16 curr_permissions,
				      struct netlink_ext_ack *extack)
{
	int ret;

	*default_act = kzalloc(sizeof(**default_act), GFP_KERNEL);
	if (!(*default_act))
		return -ENOMEM;

	if (tb[P4TC_TABLE_DEFAULT_PERMISSIONS]) {
		__u16 *permissions;

		permissions = nla_data(tb[P4TC_TABLE_DEFAULT_PERMISSIONS]);
		if (*permissions > P4TC_MAX_PERMISSION) {
			NL_SET_ERR_MSG(extack,
				       "Permission may only have 10 bits turned on");
			ret = -EINVAL;
			goto default_act_free;
		}
		if (!p4tc_data_exec_ok(*permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Default action must have data path execute permissions");
			ret = -EINVAL;
			goto default_act_free;
		}
		(*default_act)->permissions = *permissions;
	} else {
		(*default_act)->permissions = curr_permissions;
	}

	if (tb[P4TC_TABLE_DEFAULT_ACTION]) {
		struct tc_action **default_acts;

		if (!p4tc_ctrl_update_ok(curr_permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Permission denied: Unable to update default hit action");
			ret = -EPERM;
			goto default_act_free;
		}

		default_acts = kcalloc(TCA_ACT_MAX_PRIO,
				       sizeof(struct tc_action *), GFP_KERNEL);
		if (!default_acts) {
			ret = -ENOMEM;
			goto default_act_free;
		}

		ret = p4tc_action_init(net, tb[P4TC_TABLE_DEFAULT_ACTION],
				       default_acts, pipeid, 0, extack);
		if (ret < 0) {
			kfree(default_acts);
			goto default_act_free;
		} else if (ret > 1) {
			NL_SET_ERR_MSG(extack, "Can only have one hit action");
			tcf_action_destroy(default_acts, TCA_ACT_UNBIND);
			kfree(default_acts);
			ret = -EINVAL;
			goto default_act_free;
		}
		(*default_act)->default_acts = default_acts;
	}

	return 0;

default_act_free:
	kfree(*default_act);

	return ret;
}

static int tcf_table_check_defacts(struct tc_action *defact,
				   struct list_head *acts_list)
{
	struct p4tc_table_act *table_act;

	list_for_each_entry(table_act, acts_list, node) {
		if (table_act->ops->id == defact->ops->id &&
		    !(table_act->flags & BIT(P4TC_TABLE_ACTS_TABLE_ONLY)))
			return true;
	}

	return false;
}

static int
tcf_table_init_default_acts(struct net *net, struct nlattr **tb,
			    struct p4tc_table *table,
			    struct p4tc_table_defact **default_hitact,
			    struct p4tc_table_defact **default_missact,
			    struct list_head *acts_list,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb_default[P4TC_TABLE_DEFAULT_MAX + 1];
	__u16 permissions = P4TC_CONTROL_PERMISSIONS | P4TC_DATA_PERMISSIONS;
	int ret;

	*default_missact = NULL;
	*default_hitact = NULL;

	if (tb[P4TC_TABLE_DEFAULT_HIT]) {
		struct p4tc_table_defact *defact;

		rcu_read_lock();
		defact = rcu_dereference(table->tbl_default_hitact);
		if (defact)
			permissions = defact->permissions;
		rcu_read_unlock();

		ret = nla_parse_nested(tb_default, P4TC_TABLE_DEFAULT_MAX,
				       tb[P4TC_TABLE_DEFAULT_HIT], NULL,
				       extack);
		if (ret < 0)
			return ret;

		if (!tb_default[P4TC_TABLE_DEFAULT_ACTION] &&
		    !tb_default[P4TC_TABLE_DEFAULT_PERMISSIONS])
			return 0;

		ret = tcf_table_init_default_act(net, tb_default,
						 default_hitact,
						 table->common.p_id, permissions,
						 extack);
		if (ret < 0)
			return ret;
		if (!tcf_table_check_defacts((*default_hitact)->default_acts[0],
					     acts_list)) {
			ret = -EPERM;
			NL_SET_ERR_MSG(extack,
				       "Action is not allowed as default hit action");
			goto default_hitacts_free;
		}
	}

	if (tb[P4TC_TABLE_DEFAULT_MISS]) {
		struct p4tc_table_defact *defact;

		rcu_read_lock();
		defact = rcu_dereference(table->tbl_default_missact);
		if (defact)
			permissions = defact->permissions;
		rcu_read_unlock();

		ret = nla_parse_nested(tb_default, P4TC_TABLE_DEFAULT_MAX,
				       tb[P4TC_TABLE_DEFAULT_MISS], NULL,
				       extack);
		if (ret < 0)
			goto default_hitacts_free;

		if (!tb_default[P4TC_TABLE_DEFAULT_ACTION] &&
		    !tb_default[P4TC_TABLE_DEFAULT_PERMISSIONS])
			return 0;

		ret = tcf_table_init_default_act(net, tb_default,
						 default_missact,
						 table->common.p_id, permissions,
						 extack);
		if (ret < 0)
			goto default_hitacts_free;
		if (!tcf_table_check_defacts((*default_missact)->default_acts[0],
					     acts_list)) {
			ret = -EPERM;
			NL_SET_ERR_MSG(extack,
				       "Action is not allowed as default miss action");
			goto default_missact_free;
		}
	}

	return 0;

default_missact_free:
	p4tc_table_defact_destroy(*default_missact);

default_hitacts_free:
	p4tc_table_defact_destroy(*default_hitact);

	return ret;
}

static const struct nla_policy p4tc_acts_list_policy[P4TC_TABLE_MAX + 1] = {
	[P4TC_TABLE_ACT_FLAGS] =
		NLA_POLICY_RANGE(NLA_U8, 0, BIT(P4TC_TABLE_ACTS_FLAGS_MAX)),
	[P4TC_TABLE_ACT_NAME] = { .type = NLA_STRING, .len = ACTNAMSIZ },
};

static struct p4tc_table_act *tcf_table_act_init(struct nlattr *nla,
						 struct p4tc_pipeline *pipeline,
						 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TABLE_ACT_MAX + 1];
	struct p4tc_table_act *table_act;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TABLE_ACT_MAX, nla,
			       p4tc_acts_list_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	table_act = kzalloc(sizeof(*table_act), GFP_KERNEL);
	if (!table_act)
		return ERR_PTR(-ENOMEM);

	if (tb[P4TC_TABLE_ACT_NAME]) {
		const char *actname = nla_data(tb[P4TC_TABLE_ACT_NAME]);
		char *act_name_clone, *act_name, *p_name;
		struct p4tc_act *act;

		act_name_clone = act_name = kstrdup(actname, GFP_KERNEL);
		if (!act_name) {
			ret = -ENOMEM;
			goto free_table_act;
		}

		p_name = strsep(&act_name, "/");
		act = tcf_action_find_byname(act_name, pipeline);
		if (!act) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Unable to find action %s/%s",
					   p_name, act_name);
			ret = -ENOENT;
			kfree(act_name_clone);
			goto free_table_act;
		}

		kfree(act_name_clone);

		table_act->ops = &act->ops;
		WARN_ON(!refcount_inc_not_zero(&act->a_ref));
	} else {
		NL_SET_ERR_MSG(extack,
			       "Must specify allowed table action name");
		ret = -EINVAL;
		goto free_table_act;
	}

	if (tb[P4TC_TABLE_ACT_FLAGS]) {
		u8 *flags = nla_data(tb[P4TC_TABLE_ACT_FLAGS]);

		table_act->flags = *flags;
	}

	return table_act;

free_table_act:
	kfree(table_act);
	return ERR_PTR(ret);
}

static int tcf_table_acts_list_init(struct nlattr *nla,
				    struct p4tc_pipeline *pipeline,
				    struct list_head *acts_list,
				    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_table_act *table_act;
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return ret;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && tb[i]; i++) {
		table_act = tcf_table_act_init(tb[i], pipeline, extack);
		if (IS_ERR(table_act)) {
			ret = PTR_ERR(table_act);
			goto free_acts_list_list;
		}
		list_add_tail(&table_act->node, acts_list);
	}

	return 0;

free_acts_list_list:
	tcf_table_acts_list_destroy(acts_list);

	return ret;
}

static struct p4tc_table *
tcf_table_find_byanyattr(struct p4tc_pipeline *pipeline,
			 struct nlattr *name_attr, const u32 tbl_id,
			 struct netlink_ext_ack *extack)
{
	char *tblname = NULL;

	if (name_attr)
		tblname = nla_data(name_attr);

	return tcf_table_find_byany(pipeline, tblname, tbl_id, extack);
}

static struct p4tc_table *tcf_table_create(struct net *net, struct nlattr **tb,
					   u32 tbl_id,
					   struct p4tc_pipeline *pipeline,
					   struct netlink_ext_ack *extack)
{
	struct p4tc_table_key *key = NULL;
	struct p4tc_table_parm *parm;
	struct p4tc_table *table;
	char *tblname;
	int ret;

	if (pipeline->curr_tables == pipeline->num_tables) {
		NL_SET_ERR_MSG(extack,
			       "Table range exceeded max allowed value");
		ret = -EINVAL;
		goto out;
	}

	if (!tb[P4TC_TABLE_NAME]) {
		NL_SET_ERR_MSG(extack, "Must specify table name");
		ret = -EINVAL;
		goto out;
	}

	tblname =
		strnchr(nla_data(tb[P4TC_TABLE_NAME]), TABLENAMSIZ, SEPARATOR);
	if (!tblname) {
		NL_SET_ERR_MSG(extack, "Table name must contain control block");
		ret = -EINVAL;
		goto out;
	}

	tblname += 1;
	if (tblname[0] == '\0') {
		NL_SET_ERR_MSG(extack, "Control block name is too big");
		ret = -EINVAL;
		goto out;
	}

	table = tcf_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
					 NULL);
	if (!IS_ERR(table)) {
		NL_SET_ERR_MSG(extack, "Table already exists");
		ret = -EEXIST;
		goto out;
	}

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table) {
		NL_SET_ERR_MSG(extack, "Unable to create table");
		ret = -ENOMEM;
		goto out;
	}

	table->common.p_id = pipeline->common.p_id;
	strscpy(table->common.name, nla_data(tb[P4TC_TABLE_NAME]), TABLENAMSIZ);

	if (tb[P4TC_TABLE_INFO]) {
		parm = nla_data(tb[P4TC_TABLE_INFO]);
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Missing table info");
		goto free;
	}

	if (parm->tbl_flags & P4TC_TABLE_FLAGS_KEYSZ) {
		if (!parm->tbl_keysz) {
			NL_SET_ERR_MSG(extack, "Table keysz cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbl_keysz > P4TC_MAX_KEYSZ) {
			NL_SET_ERR_MSG(extack,
				       "Table keysz exceeds maximum keysz");
			ret = -EINVAL;
			goto free;
		}
		table->tbl_keysz = parm->tbl_keysz;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify table key size");
		ret = -EINVAL;
		goto free;
	}

	if (parm->tbl_flags & P4TC_TABLE_FLAGS_MAX_ENTRIES) {
		if (!parm->tbl_max_entries) {
			NL_SET_ERR_MSG(extack,
				       "Table max_entries cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbl_max_entries > P4TC_MAX_TENTRIES) {
			NL_SET_ERR_MSG(extack,
				       "Table max_entries exceeds maximum value");
			ret = -EINVAL;
			goto free;
		}
		table->tbl_max_entries = parm->tbl_max_entries;
	} else {
		table->tbl_max_entries = P4TC_DEFAULT_TENTRIES;
	}

	if (parm->tbl_flags & P4TC_TABLE_FLAGS_MAX_MASKS) {
		if (!parm->tbl_max_masks) {
			NL_SET_ERR_MSG(extack,
				       "Table max_masks cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbl_max_masks > P4TC_MAX_TMASKS) {
			NL_SET_ERR_MSG(extack,
				       "Table max_masks exceeds maximum value");
			ret = -EINVAL;
			goto free;
		}
		table->tbl_max_masks = parm->tbl_max_masks;
	} else {
		table->tbl_max_masks = P4TC_DEFAULT_TMASKS;
	}

	if (parm->tbl_flags & P4TC_TABLE_FLAGS_PERMISSIONS) {
		if (parm->tbl_permissions > P4TC_MAX_PERMISSION) {
			NL_SET_ERR_MSG(extack,
				       "Permission may only have 10 bits turned on");
			ret = -EINVAL;
			goto free;
		}
		if (!p4tc_data_exec_ok(parm->tbl_permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Table must have execute permissions");
			ret = -EINVAL;
			goto free;
		}
		if (!p4tc_data_read_ok(parm->tbl_permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Data path read permissions must be set");
			ret = -EINVAL;
			goto free;
		}
		table->tbl_permissions =
			kzalloc(sizeof(*table->tbl_permissions), GFP_KERNEL);
		if (!table->tbl_permissions) {
			ret = -ENOMEM;
			goto free;
		}
		table->tbl_permissions->permissions = parm->tbl_permissions;
	} else {
		table->tbl_permissions =
			kzalloc(sizeof(*table->tbl_permissions), GFP_KERNEL);
		if (!table->tbl_permissions) {
			ret = -ENOMEM;
			goto free;
		}
		table->tbl_permissions->permissions = P4TC_TABLE_PERMISSIONS;
	}

	refcount_set(&table->tbl_ref, 1);
	refcount_set(&table->tbl_ctrl_ref, 1);

	if (tbl_id) {
		table->tbl_id = tbl_id;
		ret = idr_alloc_u32(&pipeline->p_tbl_idr, table, &table->tbl_id,
				    table->tbl_id, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate table id");
			goto free_permissions;
		}
	} else {
		table->tbl_id = 1;
		ret = idr_alloc_u32(&pipeline->p_tbl_idr, table, &table->tbl_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate table id");
			goto free_permissions;
		}
	}

	INIT_LIST_HEAD(&table->tbl_acts_list);
	if (tb[P4TC_TABLE_ACTS_LIST]) {
		ret = tcf_table_acts_list_init(tb[P4TC_TABLE_ACTS_LIST],
					       pipeline, &table->tbl_acts_list,
					       extack);
		if (ret < 0)
			goto idr_rm;
	}

	if (tb[P4TC_TABLE_PREACTIONS]) {
		table->tbl_preacts = kcalloc(TCA_ACT_MAX_PRIO,
					     sizeof(struct tc_action *),
					     GFP_KERNEL);
		if (!table->tbl_preacts) {
			ret = -ENOMEM;
			goto table_acts_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_TABLE_PREACTIONS],
				       table->tbl_preacts, table->common.p_id,
				       0, extack);
		if (ret < 0) {
			kfree(table->tbl_preacts);
			goto table_acts_destroy;
		}
		table->tbl_num_preacts = ret;
	} else {
		table->tbl_preacts = NULL;
	}

	if (tb[P4TC_TABLE_POSTACTIONS]) {
		table->tbl_postacts = kcalloc(TCA_ACT_MAX_PRIO,
					      sizeof(struct tc_action *),
					      GFP_KERNEL);
		if (!table->tbl_postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_TABLE_POSTACTIONS],
				       table->tbl_postacts, table->common.p_id,
				       0, extack);
		if (ret < 0) {
			kfree(table->tbl_postacts);
			goto preactions_destroy;
		}
		table->tbl_num_postacts = ret;
	} else {
		table->tbl_postacts = NULL;
		table->tbl_num_postacts = 0;
	}

	if (tb[P4TC_TABLE_KEY]) {
		key = tcf_table_key_add(net, table, tb[P4TC_TABLE_KEY], extack);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto postacts_destroy;
		}
	}

	ret = tcf_table_init_default_acts(net, tb, table,
					  &table->tbl_default_hitact,
					  &table->tbl_default_missact,
					  &table->tbl_acts_list, extack);
	if (ret < 0)
		goto key_put;

	table->tbl_curr_used_entries = 0;
	table->tbl_curr_count = 0;

	refcount_set(&table->tbl_entries_ref, 1);

	idr_init(&table->tbl_masks_idr);
	idr_init(&table->tbl_prio_idr);
	spin_lock_init(&table->tbl_masks_idr_lock);
	spin_lock_init(&table->tbl_prio_idr_lock);

	if (rhltable_init(&table->tbl_entries, &entry_hlt_params) < 0) {
		ret = -EINVAL;
		goto defaultacts_destroy;
	}

	table->tbl_key = key;

	pipeline->curr_tables += 1;

	table->common.ops = (struct p4tc_template_ops *)&p4tc_table_ops;

	return table;

defaultacts_destroy:
	p4tc_table_defact_destroy(table->tbl_default_missact);
	p4tc_table_defact_destroy(table->tbl_default_hitact);

key_put:
	if (key)
		tcf_table_key_put(key);

postacts_destroy:
	p4tc_action_destroy(table->tbl_postacts);

preactions_destroy:
	p4tc_action_destroy(table->tbl_preacts);

idr_rm:
	idr_remove(&pipeline->p_tbl_idr, table->tbl_id);

free_permissions:
	kfree(table->tbl_permissions);

table_acts_destroy:
	tcf_table_acts_list_destroy(&table->tbl_acts_list);

free:
	kfree(table);

out:
	return ERR_PTR(ret);
}

static struct p4tc_table *tcf_table_update(struct net *net, struct nlattr **tb,
					   u32 tbl_id,
					   struct p4tc_pipeline *pipeline,
					   u32 flags,
					   struct netlink_ext_ack *extack)
{
	struct p4tc_table_key *key = NULL;
	int num_postacts = 0, num_preacts = 0;
	struct p4tc_table_defact *default_hitact = NULL;
	struct p4tc_table_defact *default_missact = NULL;
	struct list_head *tbl_acts_list = NULL;
	struct p4tc_table_perm *perm = NULL;
	struct p4tc_table_parm *parm = NULL;
	struct tc_action **postacts = NULL;
	struct tc_action **preacts = NULL;
	int ret = 0;
	struct p4tc_table *table;

	table = tcf_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
					 extack);
	if (IS_ERR(table))
		return table;

	if (tb[P4TC_TABLE_ACTS_LIST]) {
		tbl_acts_list = kzalloc(sizeof(*tbl_acts_list), GFP_KERNEL);
		if (!tbl_acts_list) {
			ret = -ENOMEM;
			goto out;
		}
		INIT_LIST_HEAD(tbl_acts_list);
		ret = tcf_table_acts_list_init(tb[P4TC_TABLE_ACTS_LIST],
					       pipeline, tbl_acts_list, extack);
		if (ret < 0)
			goto table_acts_destroy;
	}

	if (tb[P4TC_TABLE_PREACTIONS]) {
		preacts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				  GFP_KERNEL);
		if (!preacts) {
			ret = -ENOMEM;
			goto table_acts_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_TABLE_PREACTIONS], preacts,
				       table->common.p_id, 0, extack);
		if (ret < 0) {
			kfree(preacts);
			goto table_acts_destroy;
		}
		num_preacts = ret;
	}

	if (tb[P4TC_TABLE_POSTACTIONS]) {
		postacts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				   GFP_KERNEL);
		if (!postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_TABLE_POSTACTIONS],
				       postacts, table->common.p_id, 0, extack);
		if (ret < 0) {
			kfree(postacts);
			goto preactions_destroy;
		}
		num_postacts = ret;
	}

	if (tbl_acts_list)
		ret = tcf_table_init_default_acts(net, tb, table,
						  &default_hitact,
						  &default_missact,
						  tbl_acts_list, extack);
	else
		ret = tcf_table_init_default_acts(net, tb, table,
						  &default_hitact,
						  &default_missact,
						  &table->tbl_acts_list,
						  extack);
	if (ret < 0)
		goto postactions_destroy;

	if (tb[P4TC_TABLE_KEY]) {
		key = tcf_table_key_add(net, table, tb[P4TC_TABLE_KEY], extack);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto defaultacts_destroy;
		}
	}

	if (tb[P4TC_TABLE_INFO]) {
		parm = nla_data(tb[P4TC_TABLE_INFO]);
		if (parm->tbl_flags & P4TC_TABLE_FLAGS_KEYSZ) {
			if (!parm->tbl_keysz) {
				NL_SET_ERR_MSG(extack,
					       "Table keysz cannot be zero");
				ret = -EINVAL;
				goto key_destroy;
			}
			if (parm->tbl_keysz > P4TC_MAX_KEYSZ) {
				NL_SET_ERR_MSG(extack,
					       "Table keysz exceeds maximum keysz");
				ret = -EINVAL;
				goto key_destroy;
			}
			table->tbl_keysz = parm->tbl_keysz;
		}

		if (parm->tbl_flags & P4TC_TABLE_FLAGS_MAX_ENTRIES) {
			if (!parm->tbl_max_entries) {
				NL_SET_ERR_MSG(extack,
					       "Table max_entries cannot be zero");
				ret = -EINVAL;
				goto key_destroy;
			}
			if (parm->tbl_max_entries > P4TC_MAX_TENTRIES) {
				NL_SET_ERR_MSG(extack,
					       "Table max_entries exceeds maximum value");
				ret = -EINVAL;
				goto key_destroy;
			}
			table->tbl_max_entries = parm->tbl_max_entries;
		}

		if (parm->tbl_flags & P4TC_TABLE_FLAGS_MAX_MASKS) {
			if (!parm->tbl_max_masks) {
				NL_SET_ERR_MSG(extack,
					       "Table max_masks cannot be zero");
				ret = -EINVAL;
				goto key_destroy;
			}
			if (parm->tbl_max_masks > P4TC_MAX_TMASKS) {
				NL_SET_ERR_MSG(extack,
					       "Table max_masks exceeds maximum value");
				ret = -EINVAL;
				goto key_destroy;
			}
			table->tbl_max_masks = parm->tbl_max_masks;
		}
		if (parm->tbl_flags & P4TC_TABLE_FLAGS_PERMISSIONS) {
			if (parm->tbl_permissions > P4TC_MAX_PERMISSION) {
				NL_SET_ERR_MSG(extack,
					       "Permission may only have 10 bits turned on");
				ret = -EINVAL;
				goto key_destroy;
			}
			if (!p4tc_data_exec_ok(parm->tbl_permissions)) {
				NL_SET_ERR_MSG(extack,
					       "Table must have execute permissions");
				ret = -EINVAL;
				goto key_destroy;
			}
			if (!p4tc_data_read_ok(parm->tbl_permissions)) {
				NL_SET_ERR_MSG(extack,
					       "Data path read permissions must be set");
				ret = -EINVAL;
				goto key_destroy;
			}

			perm = kzalloc(sizeof(*perm), GFP_KERNEL);
			if (!perm) {
				ret = -ENOMEM;
				goto key_destroy;
			}
			perm->permissions = parm->tbl_permissions;
		}
	}

	if (tb[P4TC_TABLE_OPT_ENTRY]) {
		struct p4tc_table_entry *entry;

		entry = kzalloc(GFP_KERNEL, sizeof(*entry));
		if (!entry) {
			ret = -ENOMEM;
			goto free_perm;
		}

		/* Workaround to make this work */
		ret = tcf_table_const_entry_cu(net, tb[P4TC_TABLE_OPT_ENTRY],
					       entry, pipeline, table, extack);
		if (ret < 0) {
			kfree(entry);
			goto free_perm;
		}
		table->tbl_const_entry = entry;
	}

	if (preacts) {
		p4tc_action_destroy(table->tbl_preacts);
		table->tbl_preacts = preacts;
		table->tbl_num_preacts = num_preacts;
	}

	if (postacts) {
		p4tc_action_destroy(table->tbl_postacts);
		table->tbl_postacts = postacts;
		table->tbl_num_postacts = num_postacts;
	}

	if (default_hitact) {
		struct p4tc_table_defact *hitact;

		hitact = rcu_replace_pointer_rtnl(table->tbl_default_hitact,
						  default_hitact);
		if (hitact) {
			synchronize_rcu();
			p4tc_table_defact_destroy(hitact);
		}
	}

	if (default_missact) {
		struct p4tc_table_defact *missact;

		missact = rcu_replace_pointer_rtnl(table->tbl_default_missact,
						   default_missact);
		if (missact) {
			synchronize_rcu();
			p4tc_table_defact_destroy(missact);
		}
	}

	if (key) {
		if (table->tbl_key)
			tcf_table_key_put(table->tbl_key);
		table->tbl_key = key;
	}

	if (perm) {
		perm = rcu_replace_pointer_rtnl(table->tbl_permissions, perm);
		kfree_rcu(perm, rcu);
	}

	return table;

free_perm:
	kfree(perm);

key_destroy:
	if (key)
		tcf_table_key_put(key);

defaultacts_destroy:
	p4tc_table_defact_destroy(default_missact);
	p4tc_table_defact_destroy(default_hitact);

postactions_destroy:
	p4tc_action_destroy(postacts);

preactions_destroy:
	p4tc_action_destroy(preacts);

table_acts_destroy:
	if (tbl_acts_list) {
		tcf_table_acts_list_destroy(tbl_acts_list);
		kfree(tbl_acts_list);
	}

out:
	return ERR_PTR(ret);
}

static bool tcf_table_check_runtime_update(struct nlmsghdr *n,
					   struct nlattr **tb)
{
	int i;

	if (n->nlmsg_type == RTM_CREATEP4TEMPLATE &&
	    !(n->nlmsg_flags & NLM_F_REPLACE))
		return false;

	if (tb[P4TC_TABLE_INFO]) {
		struct p4tc_table_parm *info;

		info = nla_data(tb[P4TC_TABLE_INFO]);
		if ((info->tbl_flags & ~P4TC_TABLE_FLAGS_PERMISSIONS) ||
		    !(info->tbl_flags & P4TC_TABLE_FLAGS_PERMISSIONS))
			return false;
	}

	for (i = P4TC_TABLE_PREACTIONS; i < P4TC_TABLE_MAX; i++) {
		if (i != P4TC_TABLE_DEFAULT_HIT &&
		    i != P4TC_TABLE_DEFAULT_MISS && tb[i])
			return false;
	}

	return true;
}

static struct p4tc_template_common *
tcf_table_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	     struct p4tc_nl_pname *nl_pname, u32 *ids,
	     struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], tbl_id = ids[P4TC_TBLID_IDX];
	struct nlattr *tb[P4TC_TABLE_MAX + 1];
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;
	int ret;

	pipeline = tcf_pipeline_find_byany(net, nl_pname->data, pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ret = nla_parse_nested(tb, P4TC_TABLE_MAX, nla, p4tc_table_policy,
			       extack);
	if (ret < 0)
		return ERR_PTR(ret);

	if (pipeline_sealed(pipeline) &&
	    !tcf_table_check_runtime_update(n, tb)) {
		NL_SET_ERR_MSG(extack,
			       "Only default action updates are allowed in sealed pipeline");
		return ERR_PTR(-EINVAL);
	}

	if (n->nlmsg_flags & NLM_F_REPLACE)
		table = tcf_table_update(net, tb, tbl_id, pipeline,
					 n->nlmsg_flags, extack);
	else
		table = tcf_table_create(net, tb, tbl_id, pipeline, extack);

	if (IS_ERR(table))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TBLID_IDX])
		ids[P4TC_TBLID_IDX] = table->tbl_id;

out:
	return (struct p4tc_template_common *)table;
}

static int tcf_table_flush(struct net *net, struct sk_buff *skb,
			   struct p4tc_pipeline *pipeline,
			   struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_table *table;
	unsigned long tmp, tbl_id;
	int ret = 0;
	int i = 0;

	if (nla_put_u32(skb, P4TC_PATH, 0))
		goto out_nlmsg_trim;

	if (idr_is_empty(&pipeline->p_tbl_idr)) {
		NL_SET_ERR_MSG(extack, "There are not tables to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, tbl_id) {
		if (_tcf_table_put(net, NULL, pipeline, table, false, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack, "Unable to flush any table");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack, "Unable to flush all tables");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_table_gd(struct net *net, struct sk_buff *skb,
			struct nlmsghdr *n, struct nlattr *nla,
			struct p4tc_nl_pname *nl_pname, u32 *ids,
			struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], tbl_id = ids[P4TC_MID_IDX];
	struct nlattr *tb[P4TC_TABLE_MAX + 1] = {};
	unsigned char *b = nlmsg_get_pos(skb);
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_TABLE_MAX, nla,
				       p4tc_table_policy, extack);

		if (ret < 0)
			return ret;
	}

	if (n->nlmsg_type == RTM_GETP4TEMPLATE ||
	    tcf_table_check_runtime_update(n, tb))
		pipeline = tcf_pipeline_find_byany(net, nl_pname->data, pipeid,
						   extack);
	else
		pipeline = tcf_pipeline_find_byany_unsealed(net, nl_pname->data,
							    pipeid, extack);

	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_table_flush(net, skb, pipeline, extack);

	table = tcf_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
					 extack);
	if (IS_ERR(table))
		return PTR_ERR(table);

	if (_tcf_table_fill_nlmsg(skb, table) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _tcf_table_put(net, tb, pipeline, table, false, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_table_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			  struct nlattr *nla, char **p_name, u32 *ids,
			  struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = tcf_pipeline_find_byany(net, *p_name,
						   ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipeline->p_tbl_idr,
					P4TC_TBLID_IDX, extack);
}

static int tcf_table_dump_1(struct sk_buff *skb,
			    struct p4tc_template_common *common)
{
	struct p4tc_table *table = to_table(common);
	struct nlattr *nest = nla_nest_start(skb, P4TC_PARAMS);

	if (!nest)
		return -ENOMEM;

	if (nla_put_string(skb, P4TC_TABLE_NAME, table->common.name)) {
		nla_nest_cancel(skb, nest);
		return -ENOMEM;
	}

	nla_nest_end(skb, nest);

	return 0;
}

const struct p4tc_template_ops p4tc_table_ops = {
	.init = NULL,
	.cu = tcf_table_cu,
	.fill_nlmsg = tcf_table_fill_nlmsg,
	.gd = tcf_table_gd,
	.put = tcf_table_put,
	.dump = tcf_table_dump,
	.dump_1 = tcf_table_dump_1,
};
