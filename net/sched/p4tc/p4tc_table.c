// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_table.c	P4 TC TABLE
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
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/bitmap.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/flow_offload.h>

#define P4TC_P_UNSPEC 0
#define P4TC_P_CREATED 1

static int __tcf_table_try_set_state_ready(struct p4tc_table *table,
					   struct netlink_ext_ack *extack)
{
	table->tbl_masks_array = kcalloc(table->tbl_max_masks,
					 sizeof(*table->tbl_masks_array),
					 GFP_KERNEL);
	if (!table->tbl_masks_array)
		return -ENOMEM;

	table->tbl_free_masks_bitmap =
		bitmap_alloc(P4TC_MAX_TMASKS, GFP_KERNEL);
	if (!table->tbl_free_masks_bitmap) {
		kfree(table->tbl_masks_array);
		return -ENOMEM;
	}

	bitmap_fill(table->tbl_free_masks_bitmap, P4TC_MAX_TMASKS);

	return 0;
}

static void free_table_cache_array(struct p4tc_table **set_tables,
				   int num_tables)
{
	int i;

	for (i = 0; i < num_tables; i++) {
		struct p4tc_table *table = set_tables[i];

		kfree(table->tbl_masks_array);
		bitmap_free(table->tbl_free_masks_bitmap);
	}
}

int tcf_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_table **set_tables;
	struct p4tc_table *table;
	unsigned long tmp, id;
	int i = 0;
	int ret;

	set_tables = kcalloc(pipeline->num_tables, sizeof(*set_tables),
			     GFP_KERNEL);
	if (!set_tables)
		return -ENOMEM;

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, id) {
		ret = __tcf_table_try_set_state_ready(table, extack);
		if (ret < 0)
			goto free_set_tables;
		set_tables[i] = table;
		i++;
	}
	kfree(set_tables);

	return 0;

free_set_tables:
	free_table_cache_array(set_tables, i);
	kfree(set_tables);
	return ret;
}

static const struct nla_policy p4tc_table_policy[P4TC_TABLE_MAX + 1] = {
	[P4TC_TABLE_NAME] = { .type = NLA_STRING, .len = TABLENAMSIZ },
	[P4TC_TABLE_INFO] = { .type = NLA_BINARY,
			      .len = sizeof(struct p4tc_table_parm) },
	[P4TC_TABLE_DEFAULT_HIT] = { .type = NLA_NESTED },
	[P4TC_TABLE_DEFAULT_MISS] = { .type = NLA_NESTED },
	[P4TC_TABLE_ACTS_LIST] = { .type = NLA_NESTED },
	[P4TC_TABLE_CONST_ENTRY] = { .type = NLA_NESTED },
};

static int _tcf_table_fill_nlmsg(struct sk_buff *skb, struct p4tc_table *table)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_table_parm parm = {0};
	struct p4tc_table_perm *tbl_perm;
	struct p4tc_table_act *table_act;
	struct nlattr *nested_tbl_acts;
	struct nlattr *default_missact;
	struct nlattr *default_hitact;
	struct nlattr *nested_count;
	struct nlattr *nest;
	int i = 1;

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

		const_nest = nla_nest_start(skb, P4TC_TABLE_CONST_ENTRY);
		p4tc_tbl_entry_fill(skb, table, table->tbl_const_entry,
				    table->tbl_id);
		nla_nest_end(skb, const_nest);
	}
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

static inline void p4tc_table_defact_destroy(struct p4tc_table_defact *defact)
{
	if (defact) {
		p4tc_action_destroy(defact->default_acts);
		kfree(defact->defact_bpf);
		kfree(defact);
	}
}

static void tcf_table_acts_list_destroy(struct list_head *acts_list)
{
	struct p4tc_table_act *table_act, *tmp;

	list_for_each_entry_safe(table_act, tmp, acts_list, node) {
		struct p4tc_act *act;

		act = container_of(table_act->ops, typeof(*act), ops);
		list_del(&table_act->node);
		kfree(table_act);
		tcf_action_put(act);
	}
}

static void __tcf_table_put_mask_array(struct p4tc_table *table)
{
	kfree(table->tbl_masks_array);
	bitmap_free(table->tbl_free_masks_bitmap);
}

void tcf_table_put_mask_array(struct p4tc_pipeline *pipeline)
{
	struct p4tc_table *table;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, id) {
		__tcf_table_put_mask_array(table);
	}
}

static inline int _tcf_table_put(struct net *net, struct nlattr **tb,
				 struct p4tc_pipeline *pipeline,
				 struct p4tc_table *table,
				 struct netlink_ext_ack *extack)
{
	bool default_act_del = false;
	struct p4tc_table_perm *perm;

	if (tb)
		default_act_del = tb[P4TC_TABLE_DEFAULT_HIT] ||
				  tb[P4TC_TABLE_DEFAULT_MISS];

	if (!default_act_del) {
		if (!refcount_dec_if_one(&table->tbl_ctrl_ref)) {
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

	tcf_table_acts_list_destroy(&table->tbl_acts_list);

	rhltable_free_and_destroy(&table->tbl_entries,
				  tcf_table_entry_destroy_hash, table);
	p4tc_tbl_cache_remove(net, table);

	idr_destroy(&table->tbl_masks_idr);
	ida_destroy(&table->tbl_prio_idr);

	perm = rcu_replace_pointer_rtnl(table->tbl_permissions, NULL);
	kfree_rcu(perm, rcu);

	idr_remove(&pipeline->p_tbl_idr, table->tbl_id);
	pipeline->curr_tables -= 1;

	__tcf_table_put_mask_array(table);

	kfree(table);

	return 0;
}

static int tcf_table_put(struct p4tc_pipeline *pipeline,
			 struct p4tc_template_common *tmpl,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_table *table = to_table(tmpl);

	return _tcf_table_put(pipeline->net, NULL, pipeline, table, extack);
}

struct p4tc_table *tcf_table_find_byid(struct p4tc_pipeline *pipeline,
				       const u32 tbl_id)
{
	return idr_find(&pipeline->p_tbl_idr, tbl_id);
}

static struct p4tc_table *tcf_table_find_byname(const char *tblname,
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
			table = tcf_table_find_byname(tblname, pipeline);
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

static int tcf_table_get(struct p4tc_table *table)
{
	return refcount_inc_not_zero(&table->tbl_ctrl_ref);
}

struct p4tc_table *tcf_table_find_get(struct p4tc_pipeline *pipeline,
				      const char *tblname, const u32 tbl_id,
				      struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;

	table = tcf_table_find_byany(pipeline, tblname, tbl_id, extack);
	if (IS_ERR(table))
		return table;

	if (!tcf_table_get(table)) {
		NL_SET_ERR_MSG(extack, "Table is marked for deletion");
		return ERR_PTR(-EBUSY);
	}

	return table;
}

void tcf_table_put_ref(struct p4tc_table *table)
{
	/* Should never be zero */
	WARN_ON(!refcount_dec_not_one(&table->tbl_ctrl_ref));
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
		struct p4tc_table_entry_act_bpf *act_bpf;
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
		act_bpf = tcf_table_entry_create_act_bpf(default_acts[0],
							 extack);
		if (IS_ERR(act_bpf)) {
			tcf_action_destroy(default_acts, TCA_ACT_UNBIND);
			kfree(default_acts);
			ret = -EINVAL;
			goto default_act_free;
		}
		(*default_act)->defact_bpf = act_bpf;
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

static struct nla_policy p4tc_table_default_policy[P4TC_TABLE_DEFAULT_MAX + 1] = {
	[P4TC_TABLE_DEFAULT_ACTION] = { .type = NLA_NESTED },
	[P4TC_TABLE_DEFAULT_PERMISSIONS] =
		NLA_POLICY_MAX(NLA_U16, P4TC_MAX_PERMISSION),
};

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
				       tb[P4TC_TABLE_DEFAULT_HIT],
				       p4tc_table_default_policy, extack);
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
				       tb[P4TC_TABLE_DEFAULT_MISS],
				       p4tc_table_default_policy, extack);
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
	if (unlikely(!table_act))
		return ERR_PTR(-ENOMEM);

	if (tb[P4TC_TABLE_ACT_NAME]) {
		const char *actname = nla_data(tb[P4TC_TABLE_ACT_NAME]);
		char *act_name_clone, *act_name, *p_name;
		struct p4tc_act *act;

		act_name_clone = act_name = kstrdup(actname, GFP_KERNEL);
		if (unlikely(!act_name)) {
			ret = -ENOMEM;
			goto free_table_act;
		}

		p_name = strsep(&act_name, "/");
		act = tcf_action_find_get(pipeline, act_name, 0, extack);
		kfree(act_name_clone);
		if (IS_ERR(act)) {
			ret = PTR_ERR(act);
			goto free_table_act;
		}

		table_act->ops = &act->ops;
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
	struct rhashtable_params table_hlt_params = entry_hlt_params;
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

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_TABLE_NAME)) {
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

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_TABLE_INFO)) {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Missing table info");
		goto free;
	}
	parm = nla_data(tb[P4TC_TABLE_INFO]);

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

	if (parm->tbl_flags & P4TC_TABLE_FLAGS_TYPE) {
		if (parm->tbl_type > P4TC_TABLE_TYPE_MAX) {
			NL_SET_ERR_MSG(extack, "Table type can only be exact or LPM");
			ret = -EINVAL;
			goto free_permissions;
		}
		table->tbl_type = parm->tbl_type;
	} else {
		table->tbl_type = P4TC_TABLE_TYPE_EXACT;
	}

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

	ret = tcf_table_init_default_acts(net, tb, table,
					  &table->tbl_default_hitact,
					  &table->tbl_default_missact,
					  &table->tbl_acts_list, extack);
	if (ret < 0)
		goto idr_rm;

	idr_init(&table->tbl_masks_idr);
	ida_init(&table->tbl_prio_idr);
	spin_lock_init(&table->tbl_masks_idr_lock);

	table_hlt_params.max_size = table->tbl_max_entries;
	if (table->tbl_max_entries > U16_MAX)
		table_hlt_params.nelem_hint = U16_MAX / 4 * 3;
	else
		table_hlt_params.nelem_hint = table->tbl_max_entries / 4 * 3;

	if (rhltable_init(&table->tbl_entries, &table_hlt_params) < 0) {
		ret = -EINVAL;
		goto defaultacts_destroy;
	}

	ret = p4tc_tbl_cache_insert(net, pipeline->common.p_id, table);
	if (ret < 0)
		goto entries_hashtable_destroy;

	pipeline->curr_tables += 1;

	table->common.ops = (struct p4tc_template_ops *)&p4tc_table_ops;
	refcount_set(&table->tbl_entries_ref, 1);

	return table;

entries_hashtable_destroy:
	rhltable_destroy(&table->tbl_entries);

defaultacts_destroy:
	p4tc_table_defact_destroy(table->tbl_default_missact);
	p4tc_table_defact_destroy(table->tbl_default_hitact);

idr_rm:
	idr_remove(&pipeline->p_tbl_idr, table->tbl_id);

free_permissions:
	kfree(table->tbl_permissions);

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
	struct p4tc_table_defact *default_missact = NULL;
	struct p4tc_table_defact *default_hitact = NULL;
	struct list_head *tbl_acts_list = NULL;
	struct p4tc_table_perm *perm = NULL;
	struct p4tc_table_parm *parm = NULL;
	struct p4tc_table *table;
	int ret = 0;

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
		goto table_acts_destroy;

	if (tb[P4TC_TABLE_INFO]) {
		parm = nla_data(tb[P4TC_TABLE_INFO]);
		if (parm->tbl_flags & P4TC_TABLE_FLAGS_KEYSZ) {
			if (!parm->tbl_keysz) {
				NL_SET_ERR_MSG(extack,
					       "Table keysz cannot be zero");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			if (parm->tbl_keysz > P4TC_MAX_KEYSZ) {
				NL_SET_ERR_MSG(extack,
					       "Table keysz exceeds maximum keysz");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			table->tbl_keysz = parm->tbl_keysz;
		}

		if (parm->tbl_flags & P4TC_TABLE_FLAGS_MAX_ENTRIES) {
			if (!parm->tbl_max_entries) {
				NL_SET_ERR_MSG(extack,
					       "Table max_entries cannot be zero");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			if (parm->tbl_max_entries > P4TC_MAX_TENTRIES) {
				NL_SET_ERR_MSG(extack,
					       "Table max_entries exceeds maximum value");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			table->tbl_max_entries = parm->tbl_max_entries;
		}

		if (parm->tbl_flags & P4TC_TABLE_FLAGS_MAX_MASKS) {
			if (!parm->tbl_max_masks) {
				NL_SET_ERR_MSG(extack,
					       "Table max_masks cannot be zero");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			if (parm->tbl_max_masks > P4TC_MAX_TMASKS) {
				NL_SET_ERR_MSG(extack,
					       "Table max_masks exceeds maximum value");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			table->tbl_max_masks = parm->tbl_max_masks;
		}
		if (parm->tbl_flags & P4TC_TABLE_FLAGS_PERMISSIONS) {
			if (parm->tbl_permissions > P4TC_MAX_PERMISSION) {
				NL_SET_ERR_MSG(extack,
					       "Permission may only have 10 bits turned on");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			if (!p4tc_data_exec_ok(parm->tbl_permissions)) {
				NL_SET_ERR_MSG(extack,
					       "Table must have execute permissions");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}
			if (!p4tc_data_read_ok(parm->tbl_permissions)) {
				NL_SET_ERR_MSG(extack,
					       "Data path read permissions must be set");
				ret = -EINVAL;
				goto defaultacts_destroy;
			}

			perm = kzalloc(sizeof(*perm), GFP_KERNEL);
			if (!perm) {
				ret = -ENOMEM;
				goto defaultacts_destroy;
			}
			perm->permissions = parm->tbl_permissions;
		}

		if (parm->tbl_flags & P4TC_TABLE_FLAGS_TYPE) {
			if (parm->tbl_type > P4TC_TABLE_TYPE_MAX) {
				NL_SET_ERR_MSG(extack, "Table type can only be exact or LPM");
				ret = -EINVAL;
				goto free_perm;
			}
			table->tbl_type = parm->tbl_type;
		}
	}

	if (tb[P4TC_TABLE_CONST_ENTRY]) {
		struct p4tc_table_entry *entry;

		/* Workaround to make this work */
		entry = tcf_table_const_entry_cu(net,
						 tb[P4TC_TABLE_CONST_ENTRY],
						 pipeline, table, extack);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry);
			goto free_perm;
		}

		table->tbl_const_entry = entry;
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

	if (perm) {
		perm = rcu_replace_pointer_rtnl(table->tbl_permissions, perm);
		kfree_rcu(perm, rcu);
	}

	return table;

free_perm:
	kfree(perm);

defaultacts_destroy:
	p4tc_table_defact_destroy(default_missact);
	p4tc_table_defact_destroy(default_hitact);

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

	for (i = P4TC_TABLE_DEFAULT_MISS + 1; i < P4TC_TABLE_MAX; i++) {
		if (tb[i])
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
	unsigned long tmp, tbl_id;
	struct p4tc_table *table;
	int ret = 0;
	int i = 0;

	if (nla_put_u32(skb, P4TC_PATH, 0))
		goto out_nlmsg_trim;

	if (idr_is_empty(&pipeline->p_tbl_idr)) {
		NL_SET_ERR_MSG(extack, "There are no tables to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, tbl_id) {
		if (_tcf_table_put(net, NULL, pipeline, table, extack) < 0) {
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
	u32 pipeid = ids[P4TC_PID_IDX], tbl_id = ids[P4TC_TBLID_IDX];
	struct nlattr *tb[P4TC_TABLE_MAX + 1] = {};
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;
	int ret = 0;

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
		ret = _tcf_table_put(net, tb, pipeline, table, extack);
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
	struct nlattr *nest = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_table *table = to_table(common);

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
