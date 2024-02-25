// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_table.c	P4 TC TABLE
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

static int __p4tc_table_try_set_state_ready(struct net *net,
					    struct p4tc_table *table,
					    struct netlink_ext_ack *extack)
{
	struct p4tc_table_entry_mask __rcu **masks_array;
	unsigned long *tbl_free_masks_bitmap;

	masks_array = kcalloc(table->tbl_max_masks,
			      sizeof(*table->tbl_masks_array),
			      GFP_KERNEL);
	if (!masks_array)
		return -ENOMEM;

	tbl_free_masks_bitmap =
		bitmap_alloc(P4TC_MAX_TMASKS, GFP_KERNEL);
	if (!tbl_free_masks_bitmap) {
		kfree(masks_array);
		return -ENOMEM;
	}

	bitmap_fill(tbl_free_masks_bitmap, P4TC_MAX_TMASKS);

	table->tbl_masks_array = masks_array;
	rcu_replace_pointer_rtnl(table->tbl_free_masks_bitmap,
				 tbl_free_masks_bitmap);

	p4tc_tbl_cache_insert(net, table->common.p_id, table);

	return 0;
}

static void free_table_cache_array(struct net *net,
				   struct p4tc_table **set_tables,
				   int num_tables)
{
	int i;

	for (i = 0; i < num_tables; i++) {
		struct p4tc_table_entry_mask __rcu **masks_array;
		struct p4tc_table *table = set_tables[i];
		unsigned long *free_masks_bitmap;

		masks_array = table->tbl_masks_array;

		kfree(masks_array);
		free_masks_bitmap =
			rtnl_dereference(table->tbl_free_masks_bitmap);
		bitmap_free(free_masks_bitmap);

		p4tc_tbl_cache_remove(net, table);
	}
}

int p4tc_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
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
		ret = __p4tc_table_try_set_state_ready(pipeline->net, table,
						       extack);
		if (ret < 0)
			goto free_set_tables;
		set_tables[i] = table;
		i++;
	}
	kfree(set_tables);

	return 0;

free_set_tables:
	free_table_cache_array(pipeline->net, set_tables, i);
	kfree(set_tables);
	return ret;
}

static const struct netlink_range_validation aging_range = {
	.min = 1,
	.max = P4TC_MAX_T_AGING_MS,
};

static const struct netlink_range_validation keysz_range = {
	.min = 1,
	.max = P4TC_MAX_KEYSZ,
};

static const struct netlink_range_validation max_entries_range = {
	.min = 1,
	.max = P4TC_MAX_TENTRIES,
};

static const struct netlink_range_validation max_masks_range = {
	.min = 1,
	.max = P4TC_MAX_TMASKS,
};

static const struct netlink_range_validation permissions_range = {
	.min = 0,
	.max = P4TC_MAX_PERMISSION,
};

static const struct nla_policy p4tc_table_policy[P4TC_TABLE_MAX + 1] = {
	[P4TC_TABLE_NAME] = { .type = NLA_STRING, .len = P4TC_TABLE_NAMSIZ },
	[P4TC_TABLE_KEYSZ] = NLA_POLICY_FULL_RANGE(NLA_U32, &keysz_range),
	[P4TC_TABLE_MAX_ENTRIES] =
		NLA_POLICY_FULL_RANGE(NLA_U32, &max_entries_range),
	[P4TC_TABLE_MAX_MASKS] =
		NLA_POLICY_FULL_RANGE(NLA_U32, &max_masks_range),
	[P4TC_TABLE_PERMISSIONS] =
		NLA_POLICY_FULL_RANGE(NLA_U16, &permissions_range),
	[P4TC_TABLE_TYPE] =
		NLA_POLICY_RANGE(NLA_U8, P4TC_TABLE_TYPE_EXACT,
				 P4TC_TABLE_TYPE_MAX),
	[P4TC_TABLE_DEFAULT_HIT] = { .type = NLA_NESTED },
	[P4TC_TABLE_DEFAULT_MISS] = { .type = NLA_NESTED },
	[P4TC_TABLE_ACTS_LIST] = { .type = NLA_NESTED },
	[P4TC_TABLE_NUM_TIMER_PROFILES] =
		NLA_POLICY_RANGE(NLA_U32, 1, P4TC_MAX_NUM_TIMER_PROFILES),
	[P4TC_TABLE_ENTRY] = { .type = NLA_NESTED },
};

static int _p4tc_table_fill_nlmsg(struct sk_buff *skb, struct p4tc_table *table)
{
	struct p4tc_table_timer_profile *timer_profile;
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_table_perm *tbl_perm;
	struct p4tc_table_act *table_act;
	struct nlattr *nested_profiles;
	struct nlattr *nested_tbl_acts;
	struct nlattr *default_missact;
	struct nlattr *default_hitact;
	struct nlattr *nested_count;
	unsigned long profile_id;
	struct nlattr *nest;
	int i = 1;

	if (nla_put_u32(skb, P4TC_PATH, table->tbl_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_TABLE_NAME, table->common.name))
		goto out_nlmsg_trim;

	if (table->tbl_dflt_hitact) {
		struct p4tc_table_defact *hitact;
		struct tcf_p4act *p4_hitact;

		default_hitact = nla_nest_start(skb, P4TC_TABLE_DEFAULT_HIT);
		rcu_read_lock();
		hitact = rcu_dereference_rtnl(table->tbl_dflt_hitact);
		p4_hitact = to_p4act(hitact->acts[0]);
		if (p4tc_table_defact_is_noaction(p4_hitact)) {
			if (nla_put_u8(skb,
				       P4TC_TABLE_DEFAULT_ACTION_NOACTION,
				       1) < 0) {
				rcu_read_unlock();
				goto out_nlmsg_trim;
			}
		} else if (hitact->acts[0]) {
			struct nlattr *nest_defact;

			nest_defact = nla_nest_start(skb,
						     P4TC_TABLE_DEFAULT_ACTION);
			if (tcf_action_dump(skb, hitact->acts, 0, 0,
					    false) < 0) {
				rcu_read_unlock();
				goto out_nlmsg_trim;
			}
			nla_nest_end(skb, nest_defact);
		}
		if (nla_put_u16(skb, P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS,
				hitact->perm) < 0) {
			rcu_read_unlock();
			goto out_nlmsg_trim;
		}
		rcu_read_unlock();
		nla_nest_end(skb, default_hitact);
	}

	if (table->tbl_dflt_missact) {
		struct p4tc_table_defact *missact;
		struct tcf_p4act *p4_missact;

		default_missact = nla_nest_start(skb, P4TC_TABLE_DEFAULT_MISS);
		rcu_read_lock();
		missact = rcu_dereference_rtnl(table->tbl_dflt_missact);
		p4_missact = to_p4act(missact->acts[0]);
		if (p4tc_table_defact_is_noaction(p4_missact)) {
			if (nla_put_u8(skb,
				       P4TC_TABLE_DEFAULT_ACTION_NOACTION,
				       1) < 0) {
				rcu_read_unlock();
				goto out_nlmsg_trim;
			}
		} else if (missact->acts[0]) {
			struct nlattr *nest_defact;

			nest_defact = nla_nest_start(skb,
						     P4TC_TABLE_DEFAULT_ACTION);
			if (tcf_action_dump(skb, missact->acts, 0, 0,
					    false) < 0) {
				rcu_read_unlock();
				goto out_nlmsg_trim;
			}
			nla_nest_end(skb, nest_defact);
		}
		if (nla_put_u16(skb, P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS,
				missact->perm) < 0) {
			rcu_read_unlock();
			goto out_nlmsg_trim;
		}
		rcu_read_unlock();
		nla_nest_end(skb, default_missact);
	}

	if (nla_put_u32(skb, P4TC_TABLE_NUM_TIMER_PROFILES,
			atomic_read(&table->tbl_num_timer_profiles)) < 0)
		goto out_nlmsg_trim;

	nested_profiles = nla_nest_start(skb, P4TC_TABLE_TIMER_PROFILES);
	i = 1;
	rcu_read_lock();
	xa_for_each(&table->tbl_profiles_xa, profile_id, timer_profile) {
		nested_count = nla_nest_start(skb, i);
		if (nla_put_u32(skb, P4TC_TIMER_PROFILE_ID,
				timer_profile->profile_id)) {
			rcu_read_unlock();
			goto out_nlmsg_trim;
		}

		if (nla_put(skb, P4TC_TIMER_PROFILE_AGING, sizeof(u64),
			    &timer_profile->aging_ms)) {
			rcu_read_unlock();
			goto out_nlmsg_trim;
		}

		nla_nest_end(skb, nested_count);
		i++;
	}
	rcu_read_unlock();
	nla_nest_end(skb, nested_profiles);

	nested_tbl_acts = nla_nest_start(skb, P4TC_TABLE_ACTS_LIST);
	list_for_each_entry(table_act, &table->tbl_acts_list, node) {
		nested_count = nla_nest_start(skb, i);
		if (nla_put_string(skb, P4TC_TABLE_ACT_NAME,
				   table_act->act->common.name) < 0)
			goto out_nlmsg_trim;
		if (nla_put_u32(skb, P4TC_TABLE_ACT_FLAGS,
				table_act->flags) < 0)
			goto out_nlmsg_trim;

		nla_nest_end(skb, nested_count);
		i++;
	}
	nla_nest_end(skb, nested_tbl_acts);

	if (table->tbl_entry) {
		struct nlattr *entry_nest;

		entry_nest = nla_nest_start(skb, P4TC_TABLE_ENTRY);
		if (p4tc_tbl_entry_fill(skb, table, table->tbl_entry,
					table->tbl_id, P4TC_ENTITY_UNSPEC) < 0)
			goto out_nlmsg_trim;

		nla_nest_end(skb, entry_nest);
	}
	table->tbl_entry = NULL;

	if (nla_put_u32(skb, P4TC_TABLE_KEYSZ, table->tbl_keysz))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_TABLE_MAX_ENTRIES, table->tbl_max_entries))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_TABLE_MAX_MASKS, table->tbl_max_masks))
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_TABLE_NUM_ENTRIES,
			atomic_read(&table->tbl_nelems)))
		goto out_nlmsg_trim;

	tbl_perm = rcu_dereference_rtnl(table->tbl_permissions);
	if (nla_put_u16(skb, P4TC_TABLE_PERMISSIONS, tbl_perm->permissions))
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int p4tc_table_fill_nlmsg(struct net *net, struct sk_buff *skb,
				 struct p4tc_template_common *template,
				 struct netlink_ext_ack *extack)
{
	struct p4tc_table *table = p4tc_to_table(template);

	if (_p4tc_table_fill_nlmsg(skb, table) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table");
		return -EINVAL;
	}

	return 0;
}

static void
p4tc_table_timer_profile_destroy(struct p4tc_table *table,
				 struct p4tc_table_timer_profile *table_profile)
{
	struct xarray *profiles_xa = &table->tbl_profiles_xa;

	atomic_dec(&table->tbl_num_timer_profiles);
	xa_erase(profiles_xa, table_profile->profile_id);

	kfree_rcu(table_profile, rcu);
}

static void p4tc_table_timer_profiles_destroy(struct p4tc_table *table)
{
	struct p4tc_table_timer_profile *table_profile;
	unsigned long profile_id;

	mutex_lock(&table->tbl_profiles_xa_lock);
	xa_for_each(&table->tbl_profiles_xa, profile_id, table_profile)
		p4tc_table_timer_profile_destroy(table, table_profile);

	xa_destroy(&table->tbl_profiles_xa);
	mutex_unlock(&table->tbl_profiles_xa_lock);
}

static const struct nla_policy
p4tc_timer_profile_policy[P4TC_TIMER_PROFILE_MAX + 1] = {
	[P4TC_TIMER_PROFILE_ID] =
		NLA_POLICY_RANGE(NLA_U32, 0, P4TC_MAX_NUM_TIMER_PROFILES),
	[P4TC_TIMER_PROFILE_AGING] =
		NLA_POLICY_FULL_RANGE(NLA_U64, &aging_range),
};

struct p4tc_table_timer_profile *
p4tc_table_timer_profile_find_byaging(struct p4tc_table *table, u64 aging_ms)
__must_hold(RCU)
{
	struct p4tc_table_timer_profile *timer_profile;
	unsigned long profile_id;

	xa_for_each(&table->tbl_profiles_xa, profile_id, timer_profile) {
		if (timer_profile->aging_ms == aging_ms)
			return timer_profile;
	}

	return NULL;
}

struct p4tc_table_timer_profile *
p4tc_table_timer_profile_find(struct p4tc_table *table, u32 profile_id)
__must_hold(RCU)
{
	return xa_load(&table->tbl_profiles_xa, profile_id);
}

/* This function will be exercised via a runtime command.
 * Note that two profile IDs can't have the same aging value
 */
int p4tc_table_timer_profile_update(struct p4tc_table *table,
				    struct nlattr *nla,
				    struct netlink_ext_ack *extack)
{
	struct p4tc_table_timer_profile *old_timer_profile;
	struct p4tc_table_timer_profile *timer_profile;
	struct nlattr *tb[P4TC_TIMER_PROFILE_MAX + 1];
	u32 profile_id;
	u64 aging_ms;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TIMER_PROFILE_MAX, nla,
			       p4tc_timer_profile_policy, extack);
	if (ret < 0)
		return ret;

	if (!tb[P4TC_TIMER_PROFILE_ID]) {
		NL_SET_ERR_MSG(extack, "Must specify table profile ID");
		return -EINVAL;
	}
	profile_id = nla_get_u32(tb[P4TC_TIMER_PROFILE_ID]);

	if (!tb[P4TC_TIMER_PROFILE_AGING]) {
		NL_SET_ERR_MSG(extack, "Must specify table profile aging");
		return -EINVAL;
	}
	aging_ms = nla_get_u64(tb[P4TC_TIMER_PROFILE_AGING]);

	rcu_read_lock();
	timer_profile = p4tc_table_timer_profile_find_byaging(table,
							      aging_ms);
	if (timer_profile && timer_profile->profile_id != profile_id) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Aging %llu was already specified by profile ID %u",
				   aging_ms, timer_profile->profile_id);
		rcu_read_unlock();
		return -EINVAL;
	}
	rcu_read_unlock();

	timer_profile = kzalloc(sizeof(*timer_profile), GFP_KERNEL);
	if (unlikely(!timer_profile))
		return -ENOMEM;

	timer_profile->profile_id = profile_id;
	timer_profile->aging_ms = aging_ms;

	mutex_lock(&table->tbl_profiles_xa_lock);
	old_timer_profile = xa_load(&table->tbl_profiles_xa, profile_id);
	if (!old_timer_profile) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Unable to find timer profile with ID %u\n",
				   profile_id);
		ret = -ENOENT;
		goto unlock;
	}

	old_timer_profile = xa_cmpxchg(&table->tbl_profiles_xa,
				       timer_profile->profile_id,
				       old_timer_profile,
				       timer_profile, GFP_KERNEL);
	kfree_rcu(old_timer_profile, rcu);
	mutex_unlock(&table->tbl_profiles_xa_lock);

	return 0;

unlock:
	mutex_unlock(&table->tbl_profiles_xa_lock);

	kfree(timer_profile);
	return ret;
}

/* From the template, the user may only specify the number of timer profiles
 * they want for the table. If this number is not specified during the table
 * creation command, the kernel will create 4 timer profiles:
 * - ID 0: 30000ms
 * - ID 1: 60000ms
 * - ID 2: 90000ms
 * - ID 3: 1200000ms
 * If the user specify the number of timer profiles, the aging for those
 * profiles will be assigned using the same pattern as shown above, i.e profile
 * ID 0 will have aging 30000ms and the rest will conform to the following
 * pattern:
 * Aging(IDn) = Aging(IDn-1) + 30000ms
 * These values may only be updated with the runtime command (p4ctrl) after the
 * pipeline is sealed.
 */
static int
p4tc_tmpl_timer_profiles_init(struct p4tc_table *table, const u32 num_profiles)
{
	struct xarray *profiles_xa = &table->tbl_profiles_xa;
	u64 aging_ms = P4TC_TIMER_PROFILE_ZERO_AGING_MS;
	struct p4tc_table_timer_profile *table_profile;
	int ret;
	int i;

	/* No need for locking here because the pipeline is sealed and we are
	 * protected by the RTNL lock
	 */
	xa_init(profiles_xa);
	for (i = P4TC_DEFAULT_TIMER_PROFILE_ID; i < num_profiles; i++) {
		table_profile = kzalloc(sizeof(*table_profile), GFP_KERNEL);
		if (unlikely(!table_profile))
			return -ENOMEM;

		table_profile->profile_id = i;
		table_profile->aging_ms = aging_ms;

		ret = xa_insert(profiles_xa, i, table_profile, GFP_KERNEL);
		if (ret < 0) {
			kfree(table_profile);
			goto profiles_destroy;
		}
		atomic_inc(&table->tbl_num_timer_profiles);
		aging_ms += P4TC_TIMER_PROFILE_ZERO_AGING_MS;
	}
	mutex_init(&table->tbl_profiles_xa_lock);

	return 0;

profiles_destroy:
	p4tc_table_timer_profiles_destroy(table);
	return ret;
}

static void p4tc_table_acts_list_destroy(struct list_head *acts_list)
{
	struct p4tc_table_act *table_act, *tmp;

	list_for_each_entry_safe(table_act, tmp, acts_list, node) {
		list_del(&table_act->node);
		if (!p4tc_table_act_is_noaction(table_act))
			p4tc_action_put_ref(table_act->act);
		kfree(table_act);
	}
}

static void p4tc_table_acts_list_replace(struct list_head *dst,
					 struct list_head *src)
{
	p4tc_table_acts_list_destroy(dst);
	list_splice_init(src, dst);
	kfree(src);
}

static void __p4tc_table_put_mask_array(struct p4tc_table *table)
{
	unsigned long *free_masks_bitmap;

	kfree(table->tbl_masks_array);

	free_masks_bitmap = rcu_dereference_rtnl(table->tbl_free_masks_bitmap);
	bitmap_free(free_masks_bitmap);
}

void p4tc_table_put_mask_array(struct p4tc_pipeline *pipeline)
{
	struct p4tc_table *table;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, id) {
		__p4tc_table_put_mask_array(table);
	}
}

static int _p4tc_table_put(struct net *net, struct nlattr **tb,
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
		hitact = rcu_dereference(table->tbl_dflt_hitact);
		if (hitact && !p4tc_ctrl_delete_ok(hitact->perm)) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete default hitact");
			rcu_read_unlock();
			return -EPERM;
		}
		rcu_read_unlock();
	}

	if (tb && tb[P4TC_TABLE_DEFAULT_MISS]) {
		struct p4tc_table_defact *missact;

		rcu_read_lock();
		missact = rcu_dereference(table->tbl_dflt_missact);
		if (missact && !p4tc_ctrl_delete_ok(missact->perm)) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete default missact");
			rcu_read_unlock();
			return -EPERM;
		}
		rcu_read_unlock();
	}

	if (!default_act_del || tb[P4TC_TABLE_DEFAULT_HIT]) {
		struct p4tc_table_defact *hitact;

		hitact = rtnl_dereference(table->tbl_dflt_hitact);
		if (hitact) {
			rcu_replace_pointer_rtnl(table->tbl_dflt_hitact, NULL);
			synchronize_rcu();
			p4tc_table_defact_destroy(hitact);
		}
	}

	if (!default_act_del || tb[P4TC_TABLE_DEFAULT_MISS]) {
		struct p4tc_table_defact *missact;

		missact = rtnl_dereference(table->tbl_dflt_missact);
		if (missact) {
			rcu_replace_pointer_rtnl(table->tbl_dflt_missact, NULL);
			synchronize_rcu();
			p4tc_table_defact_destroy(missact);
		}
	}

	if (default_act_del)
		return 0;

	p4tc_table_acts_list_destroy(&table->tbl_acts_list);
	p4tc_table_timer_profiles_destroy(table);

	rhltable_free_and_destroy(&table->tbl_entries,
				  p4tc_table_entry_destroy_hash, table);
	if (pipeline->p_state == P4TC_STATE_READY)
		p4tc_tbl_cache_remove(net, table);

	idr_destroy(&table->tbl_masks_idr);
	ida_destroy(&table->tbl_prio_ida);

	perm = rcu_replace_pointer_rtnl(table->tbl_permissions, NULL);
	kfree_rcu(perm, rcu);

	idr_remove(&pipeline->p_tbl_idr, table->tbl_id);
	pipeline->curr_tables -= 1;

	__p4tc_table_put_mask_array(table);

	kfree(table);

	return 0;
}

static int p4tc_table_put(struct p4tc_pipeline *pipeline,
			  struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_table *table = p4tc_to_table(tmpl);

	return _p4tc_table_put(pipeline->net, NULL, pipeline, table, extack);
}

struct p4tc_table *p4tc_table_find_byid(struct p4tc_pipeline *pipeline,
					const u32 tbl_id)
{
	return idr_find(&pipeline->p_tbl_idr, tbl_id);
}

static struct p4tc_table *p4tc_table_find_byname(const char *tblname,
						 struct p4tc_pipeline *pipeline)
{
	struct p4tc_table *table;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, id)
		if (strncmp(table->common.name, tblname,
			    P4TC_TABLE_NAMSIZ) == 0)
			return table;

	return NULL;
}

struct p4tc_table *p4tc_table_find_byany(struct p4tc_pipeline *pipeline,
					 const char *tblname, const u32 tbl_id,
					 struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;
	int err;

	if (tbl_id) {
		table = p4tc_table_find_byid(pipeline, tbl_id);
		if (!table) {
			NL_SET_ERR_MSG(extack, "Unable to find table by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (tblname) {
			table = p4tc_table_find_byname(tblname, pipeline);
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

struct p4tc_table *p4tc_table_find_get(struct p4tc_pipeline *pipeline,
				       const char *tblname, const u32 tbl_id,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;

	table = p4tc_table_find_byany(pipeline, tblname, tbl_id, extack);
	if (IS_ERR(table))
		return table;

	if (!p4tc_table_get(table)) {
		NL_SET_ERR_MSG(extack, "Table is marked for deletion");
		return ERR_PTR(-EBUSY);
	}

	return table;
}

static struct p4tc_act NoAction = {
	.common.p_id = 0,
	.common.name = "NoAction",
	.a_id = 0,
};

/* Permissions can also be updated by runtime command */
static struct p4tc_table_defact *
__p4tc_table_init_defact(struct net *net, struct nlattr **tb, u32 pipeid,
			 __u16 perm, struct netlink_ext_ack *extack)
{
	struct p4tc_table_defact *defact;
	int ret;

	defact = kzalloc(sizeof(*defact), GFP_KERNEL);
	if (!defact) {
		NL_SET_ERR_MSG(extack, "Failed to initialize default actions");
		return ERR_PTR(-ENOMEM);
	}

	if (tb[P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS]) {
		__u16 nperm;

		nperm = nla_get_u16(tb[P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS]);
		if (!p4tc_ctrl_read_ok(nperm)) {
			NL_SET_ERR_MSG(extack,
				       "Default action must have ctrl path read permissions");
			ret = -EINVAL;
			goto err;
		}
		if (!p4tc_data_read_ok(nperm)) {
			NL_SET_ERR_MSG(extack,
				       "Default action must have data path read permissions");
			ret = -EINVAL;
			goto err;
		}
		if (!p4tc_data_exec_ok(nperm)) {
			NL_SET_ERR_MSG(extack,
				       "Default action must have data path execute permissions");
			ret = -EINVAL;
			goto err;
		}
		defact->perm = nperm;
	} else {
		defact->perm = perm;
	}

	if (tb[P4TC_TABLE_DEFAULT_ACTION_NOACTION] &&
	    tb[P4TC_TABLE_DEFAULT_ACTION]) {
		NL_SET_ERR_MSG(extack,
			       "Specifying no action and action simultaneously is not allowed");
		ret = -EINVAL;
		goto err;
	}

	if (tb[P4TC_TABLE_DEFAULT_ACTION]) {
		if (!p4tc_ctrl_update_ok(perm)) {
			NL_SET_ERR_MSG(extack,
				       "Unable to update default action");
			ret = -EPERM;
			goto err;
		}

		ret = p4tc_action_init(net, tb[P4TC_TABLE_DEFAULT_ACTION],
				       defact->acts, pipeid, 0, extack);
		if (ret < 0)
			goto err;
	} else if (tb[P4TC_TABLE_DEFAULT_ACTION_NOACTION]) {
		struct p4tc_table_entry_act_bpf_kern *no_action_bpf_kern;
		struct tcf_p4act *p4_defact;

		if (!p4tc_ctrl_update_ok(perm)) {
			NL_SET_ERR_MSG(extack,
				       "Unable to update default action");
			ret = -EPERM;
			goto err;
		}

		no_action_bpf_kern = kzalloc(sizeof(*no_action_bpf_kern),
					     GFP_KERNEL);
		if (!no_action_bpf_kern) {
			ret = -ENOMEM;
			goto err;
		}

		p4_defact = kzalloc(sizeof(*p4_defact), GFP_KERNEL);
		if (!p4_defact) {
			kfree(no_action_bpf_kern);
			ret = -ENOMEM;
			goto err;
		}
		rcu_assign_pointer(p4_defact->act_bpf, no_action_bpf_kern);
		p4_defact->p_id = 0;
		p4_defact->act_id = 0;
		defact->acts[0] = (struct tc_action *)p4_defact;
	}

	return defact;

err:
	kfree(defact);
	return ERR_PTR(ret);
}

static int p4tc_table_check_defacts(struct tc_action *defact,
				    struct list_head *acts_list)
{
	struct tcf_p4act *p4_defact = to_p4act(defact);
	struct p4tc_table_act *table_act;

	list_for_each_entry(table_act, acts_list, node) {
		if (table_act->act->common.p_id == p4_defact->p_id &&
		    table_act->act->a_id == p4_defact->act_id &&
		    !(table_act->flags & BIT(P4TC_TABLE_ACTS_TABLE_ONLY)))
			return true;
	}

	return false;
}

static struct nla_policy
p4tc_table_default_policy[P4TC_TABLE_DEFAULT_ACTION_MAX + 1] = {
	[P4TC_TABLE_DEFAULT_ACTION] = { .type = NLA_NESTED },
	[P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS] =
		NLA_POLICY_MAX(NLA_U16, P4TC_MAX_PERMISSION),
	[P4TC_TABLE_DEFAULT_ACTION_NOACTION] =
		NLA_POLICY_RANGE(NLA_U8, 1, 1),
};

/* Runtime and template call this */
static struct p4tc_table_defact *
p4tc_table_init_default_act(struct net *net, struct nlattr *nla,
			    struct p4tc_table *table,
			    u16 perm, struct list_head *acts_list,
			    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_TABLE_DEFAULT_ACTION_MAX + 1];
	struct p4tc_table_defact *defact;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TABLE_DEFAULT_ACTION_MAX, nla,
			       p4tc_table_default_policy, extack);
	if (ret < 0)
		return ERR_PTR(ret);

	if (!tb[P4TC_TABLE_DEFAULT_ACTION] &&
	    !tb[P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS] &&
	    !tb[P4TC_TABLE_DEFAULT_ACTION_NOACTION]) {
		NL_SET_ERR_MSG(extack,
			       "Nested P4TC_TABLE_DEFAULT_ACTION attr is empty");
		return ERR_PTR(-EINVAL);
	}

	defact = __p4tc_table_init_defact(net, tb, table->common.p_id, perm,
					  extack);
	if (IS_ERR(defact))
		return defact;

	if (defact->acts[0] &&
	    !p4tc_table_check_defacts(defact->acts[0], acts_list)) {
		NL_SET_ERR_MSG(extack,
			       "Action is not allowed as default action");
		p4tc_table_defact_destroy(defact);
		return ERR_PTR(-EPERM);
	}

	return defact;
}

struct p4tc_table_perm *
p4tc_table_init_permissions(struct p4tc_table *table, u16 permissions,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_table_perm *tbl_perm;

	tbl_perm = kzalloc(sizeof(*tbl_perm), GFP_KERNEL);
	if (!tbl_perm)
		return ERR_PTR(-ENOMEM);

	tbl_perm->permissions = permissions;

	return tbl_perm;
}

void p4tc_table_replace_permissions(struct p4tc_table *table,
				    struct p4tc_table_perm *tbl_perm,
				    bool lock_rtnl)
{
	if (!tbl_perm)
		return;

	if (lock_rtnl)
		rtnl_lock();
	tbl_perm = rcu_replace_pointer_rtnl(table->tbl_permissions, tbl_perm);
	if (lock_rtnl)
		rtnl_unlock();
	kfree_rcu(tbl_perm, rcu);
}

int p4tc_table_init_default_acts(struct net *net,
				 struct p4tc_table_defact_params *dflt,
				 struct p4tc_table *table,
				 struct list_head *acts_list,
				 struct netlink_ext_ack *extack)
{
	int ret;

	dflt->missact = NULL;
	dflt->hitact = NULL;

	if (dflt->nla_hit) {
		struct p4tc_table_defact *hitact;
		u16 perm;

		perm = P4TC_CONTROL_PERMISSIONS | P4TC_DATA_PERMISSIONS;

		rcu_read_lock();
		if (table->tbl_dflt_hitact)
			perm = rcu_dereference(table->tbl_dflt_hitact)->perm;
		rcu_read_unlock();

		hitact = p4tc_table_init_default_act(net, dflt->nla_hit, table,
						     perm, acts_list, extack);
		if (IS_ERR(hitact))
			return PTR_ERR(hitact);

		if (hitact->acts[0]) {
			struct tc_action *_hitact = hitact->acts[0];

			ret = p4tc_table_entry_act_bpf_change_flags(_hitact, 1,
								    0, 1);
			if (ret < 0)
				goto default_hitacts_free;
		}
		dflt->hitact = hitact;
	}

	if (dflt->nla_miss) {
		struct p4tc_table_defact *missact;
		u16 perm;

		perm = P4TC_CONTROL_PERMISSIONS | P4TC_DATA_PERMISSIONS;

		rcu_read_lock();
		if (table->tbl_dflt_missact)
			perm = rcu_dereference(table->tbl_dflt_missact)->perm;
		rcu_read_unlock();

		missact = p4tc_table_init_default_act(net, dflt->nla_miss,
						      table, perm, acts_list,
						      extack);
		if (IS_ERR(missact)) {
			ret = PTR_ERR(missact);
			goto default_hitacts_free;
		}

		if (missact->acts[0]) {
			struct tc_action *_missact = missact->acts[0];

			ret = p4tc_table_entry_act_bpf_change_flags(_missact, 0,
								    1, 0);
			if (ret < 0)
				goto default_missacts_free;
		}
		dflt->missact = missact;
	}

	return 0;

default_missacts_free:
	p4tc_table_defact_destroy(dflt->missact);

default_hitacts_free:
	p4tc_table_defact_destroy(dflt->hitact);
	return ret;
}

static const struct nla_policy p4tc_acts_list_policy[P4TC_TABLE_MAX + 1] = {
	[P4TC_TABLE_ACT_FLAGS] =
		NLA_POLICY_RANGE(NLA_U8, 0, BIT(P4TC_TABLE_ACTS_FLAGS_MAX)),
	[P4TC_TABLE_ACT_NAME] = { .type = NLA_STRING, .len = ACTNAMSIZ },
};

static struct p4tc_table_act *
p4tc_table_act_init(struct nlattr *nla, struct p4tc_pipeline *pipeline,
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
		const char *fullname = nla_data(tb[P4TC_TABLE_ACT_NAME]);
		char *pname, *aname, actname[ACTNAMSIZ];
		struct p4tc_act *act;

		nla_strscpy(actname, tb[P4TC_TABLE_ACT_NAME], ACTNAMSIZ);
		aname = actname;

		pname = strsep(&aname, "/");
		if (!aname) {
			if (strcmp(pname, "NoAction") == 0) {
				table_act->act = &NoAction;
				return table_act;
			}

			NL_SET_ERR_MSG(extack,
				       "Action name must have format pname/actname");
			ret = -EINVAL;
			goto free_table_act;
		}

		if (strncmp(pipeline->common.name, pname,
			    P4TC_PIPELINE_NAMSIZ)) {
			NL_SET_ERR_MSG_FMT(extack, "Pipeline name must be %s\n",
					   pipeline->common.name);
			ret = -EINVAL;
			goto free_table_act;
		}

		act = p4a_tmpl_get(pipeline, fullname, 0, extack);
		if (IS_ERR(act)) {
			ret = PTR_ERR(act);
			goto free_table_act;
		}

		table_act->act = act;
	} else {
		NL_SET_ERR_MSG(extack,
			       "Must specify allowed table action name");
		ret = -EINVAL;
		goto free_table_act;
	}

	if (tb[P4TC_TABLE_ACT_FLAGS]) {
		u8 *flags = nla_data(tb[P4TC_TABLE_ACT_FLAGS]);

		if (*flags & BIT(P4TC_TABLE_ACTS_DEFAULT_ONLY) &&
		    *flags & BIT(P4TC_TABLE_ACTS_TABLE_ONLY)) {
			NL_SET_ERR_MSG(extack,
				       "defaultonly and tableonly are mutually exclusive");
			ret = -EINVAL;
			goto act_put;
		}

		table_act->flags = *flags;
	}

	return table_act;

act_put:
	p4tc_action_put_ref(table_act->act);

free_table_act:
	kfree(table_act);
	return ERR_PTR(ret);
}

void p4tc_table_replace_default_acts(struct p4tc_table *table,
				     struct p4tc_table_defact_params *dflt,
				     bool lock_rtnl)
{
	if (dflt->hitact) {
		bool updated_actions = !!dflt->hitact->acts[0];
		struct p4tc_table_defact *hitact;

		if (lock_rtnl)
			rtnl_lock();
		if (!updated_actions) {
			hitact = rcu_dereference_rtnl(table->tbl_dflt_hitact);
			p4tc_table_defacts_acts_copy(dflt->hitact, hitact);
		}

		hitact = rcu_replace_pointer_rtnl(table->tbl_dflt_hitact,
						  dflt->hitact);
		if (lock_rtnl)
			rtnl_unlock();
		if (hitact) {
			synchronize_rcu();
			if (updated_actions)
				p4tc_table_defact_destroy(hitact);
			else
				kfree(hitact);
		}
	}

	if (dflt->missact) {
		bool updated_actions = !!dflt->missact->acts[0];
		struct p4tc_table_defact *missact;

		if (lock_rtnl)
			rtnl_lock();
		if (!updated_actions) {
			missact = rcu_dereference_rtnl(table->tbl_dflt_missact);
			p4tc_table_defacts_acts_copy(dflt->missact, missact);
		}

		missact = rcu_replace_pointer_rtnl(table->tbl_dflt_missact,
						   dflt->missact);
		if (lock_rtnl)
			rtnl_unlock();
		if (missact) {
			synchronize_rcu();
			if (updated_actions)
				p4tc_table_defact_destroy(missact);
			else
				kfree(missact);
		}
	}
}

static int p4tc_table_acts_list_init(struct nlattr *nla,
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
		table_act = p4tc_table_act_init(tb[i], pipeline, extack);
		if (IS_ERR(table_act)) {
			ret = PTR_ERR(table_act);
			goto free_acts_list_list;
		}
		list_add_tail(&table_act->node, acts_list);
	}

	return 0;

free_acts_list_list:
	p4tc_table_acts_list_destroy(acts_list);

	return ret;
}

static struct p4tc_table *
p4tc_table_find_byanyattr(struct p4tc_pipeline *pipeline,
			  struct nlattr *name_attr, const u32 tbl_id,
			  struct netlink_ext_ack *extack)
{
	char *tblname = NULL;

	if (name_attr)
		tblname = nla_data(name_attr);

	return p4tc_table_find_byany(pipeline, tblname, tbl_id, extack);
}

static const struct p4tc_template_ops p4tc_table_ops;

static bool p4tc_table_entry_create_only(struct nlattr **tb)
{
	int i;

	/* Excluding table name on purpose */
	for (i = P4TC_TABLE_KEYSZ; i < P4TC_TABLE_MAX; i++)
		if (tb[i] && i != P4TC_TABLE_ENTRY)
			return false;

	return true;
}

static struct p4tc_table *
p4tc_table_entry_create(struct net *net, struct nlattr **tb,
			u32 tbl_id, struct p4tc_pipeline *pipeline,
			struct netlink_ext_ack *extack)
{
	struct p4tc_table *table;

	table = p4tc_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
					  extack);
	if (IS_ERR(table))
		return table;

	if (tb[P4TC_TABLE_ENTRY]) {
		struct p4tc_table_entry *entry;

		entry = p4tc_tmpl_table_entry_cu(net, tb[P4TC_TABLE_ENTRY],
						 pipeline, table, extack);
		if (IS_ERR(entry))
			return (struct p4tc_table *)entry;

		table->tbl_entry = entry;
	}

	return table;
}

static struct p4tc_table *p4tc_table_create(struct net *net, struct nlattr **tb,
					    u32 tbl_id,
					    struct p4tc_pipeline *pipeline,
					    struct netlink_ext_ack *extack)
{
	struct rhashtable_params table_hlt_params = entry_hlt_params;
	u32 num_profiles = P4TC_DEFAULT_NUM_TIMER_PROFILES;
	struct p4tc_table_perm *tbl_init_perms = NULL;
	struct p4tc_table_defact_params dflt = { 0 };
	struct p4tc_table *table;
	char *tblname;
	int ret;

	if (p4tc_table_entry_create_only(tb))
		return p4tc_table_entry_create(net, tb, tbl_id, pipeline,
					       extack);

	if (pipeline->curr_tables == pipeline->num_tables) {
		NL_SET_ERR_MSG(extack,
			       "Table range exceeded max allowed value");
		ret = -EINVAL;
		goto out;
	}

	/* Name has the following syntax cb/tname */
	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_TABLE_NAME)) {
		NL_SET_ERR_MSG(extack, "Must specify table name");
		ret = -EINVAL;
		goto out;
	}

	tblname =
		strnchr(nla_data(tb[P4TC_TABLE_NAME]), P4TC_TABLE_NAMSIZ, '/');
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

	table = p4tc_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
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
	strscpy(table->common.name, nla_data(tb[P4TC_TABLE_NAME]),
		P4TC_TABLE_NAMSIZ);

	if (tb[P4TC_TABLE_KEYSZ]) {
		table->tbl_keysz = nla_get_u32(tb[P4TC_TABLE_KEYSZ]);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify table keysz");
		ret = -EINVAL;
		goto free;
	}

	if (tb[P4TC_TABLE_MAX_ENTRIES])
		table->tbl_max_entries =
			nla_get_u32(tb[P4TC_TABLE_MAX_ENTRIES]);
	else
		table->tbl_max_entries = P4TC_DEFAULT_TENTRIES;

	if (tb[P4TC_TABLE_MAX_MASKS])
		table->tbl_max_masks = nla_get_u32(tb[P4TC_TABLE_MAX_MASKS]);
	else
		table->tbl_max_masks = P4TC_DEFAULT_TMASKS;

	if (tb[P4TC_TABLE_PERMISSIONS]) {
		u16 tbl_permissions = nla_get_u16(tb[P4TC_TABLE_PERMISSIONS]);

		tbl_init_perms = p4tc_table_init_permissions(table,
							     tbl_permissions,
							     extack);
		if (IS_ERR(tbl_init_perms)) {
			ret = PTR_ERR(tbl_init_perms);
			goto free;
		}
		rcu_assign_pointer(table->tbl_permissions, tbl_init_perms);
	} else {
		u16 tbl_permissions = P4TC_TABLE_DEFAULT_PERMISSIONS;

		tbl_init_perms = p4tc_table_init_permissions(table,
							     tbl_permissions,
							     extack);
		if (IS_ERR(tbl_init_perms)) {
			ret = PTR_ERR(tbl_init_perms);
			goto free;
		}
		rcu_assign_pointer(table->tbl_permissions, tbl_init_perms);
	}

	if (tb[P4TC_TABLE_TYPE])
		table->tbl_type = nla_get_u8(tb[P4TC_TABLE_TYPE]);
	else
		table->tbl_type = P4TC_TABLE_TYPE_EXACT;

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
		ret = p4tc_table_acts_list_init(tb[P4TC_TABLE_ACTS_LIST],
						pipeline, &table->tbl_acts_list,
						extack);
		if (ret < 0)
			goto idr_rm;
	}

	dflt.nla_hit = tb[P4TC_TABLE_DEFAULT_HIT];
	dflt.nla_miss = tb[P4TC_TABLE_DEFAULT_MISS];

	ret = p4tc_table_init_default_acts(net, &dflt, table,
					   &table->tbl_acts_list, extack);
	if (ret < 0)
		goto idr_rm;

	if (dflt.hitact && !dflt.hitact->acts[0]) {
		NL_SET_ERR_MSG(extack,
			       "Must specify defaults_hit_actions's action values");
		ret = -EINVAL;
		goto defaultacts_destroy;
	}

	if (dflt.missact && !dflt.missact->acts[0]) {
		NL_SET_ERR_MSG(extack,
			       "Must specify defaults_miss_actions's action values");
		ret = -EINVAL;
		goto defaultacts_destroy;
	}

	rcu_replace_pointer_rtnl(table->tbl_dflt_hitact, dflt.hitact);
	rcu_replace_pointer_rtnl(table->tbl_dflt_missact, dflt.missact);

	if (tb[P4TC_TABLE_NUM_TIMER_PROFILES])
		num_profiles = nla_get_u32(tb[P4TC_TABLE_NUM_TIMER_PROFILES]);

	atomic_set(&table->tbl_num_timer_profiles, 0);
	ret = p4tc_tmpl_timer_profiles_init(table, num_profiles);
	if (ret < 0)
		goto defaultacts_destroy;

	idr_init(&table->tbl_masks_idr);
	ida_init(&table->tbl_prio_ida);
	spin_lock_init(&table->tbl_masks_idr_lock);

	table_hlt_params.max_size = table->tbl_max_entries;
	if (table->tbl_max_entries > U16_MAX)
		table_hlt_params.nelem_hint = U16_MAX / 4 * 3;
	else
		table_hlt_params.nelem_hint = table->tbl_max_entries / 4 * 3;

	if (rhltable_init(&table->tbl_entries, &table_hlt_params) < 0) {
		ret = -EINVAL;
		goto profiles_destroy;
	}

	pipeline->curr_tables += 1;

	table->common.ops = (struct p4tc_template_ops *)&p4tc_table_ops;
	atomic_set(&table->tbl_nelems, 0);

	return table;

profiles_destroy:
	p4tc_table_timer_profiles_destroy(table);

defaultacts_destroy:
	p4tc_table_defact_destroy(dflt.hitact);
	p4tc_table_defact_destroy(dflt.missact);

idr_rm:
	idr_remove(&pipeline->p_tbl_idr, table->tbl_id);

free_permissions:
	kfree(tbl_init_perms);

	p4tc_table_acts_list_destroy(&table->tbl_acts_list);

free:
	kfree(table);

out:
	return ERR_PTR(ret);
}

static struct p4tc_table *p4tc_table_update(struct net *net, struct nlattr **tb,
					    u32 tbl_id,
					    struct p4tc_pipeline *pipeline,
					    u32 flags,
					    struct netlink_ext_ack *extack)
{
	u32 tbl_max_masks = 0, tbl_max_entries = 0, tbl_keysz = 0;
	struct p4tc_table_defact_params dflt = { 0 };
	struct p4tc_table_perm *perm = NULL;
	struct list_head *tbl_acts_list;
	struct p4tc_table *table;
	u8 tbl_type;
	int ret = 0;

	if (tb[P4TC_TABLE_ENTRY]) {
		NL_SET_ERR_MSG(extack,
			       "Entry update not supported from template");
		return ERR_PTR(-EOPNOTSUPP);
	}

	table = p4tc_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
					  extack);
	if (IS_ERR(table))
		return table;

	if (tb[P4TC_TABLE_NUM_TIMER_PROFILES]) {
		NL_SET_ERR_MSG(extack, "Num timer profiles is not updatable");
		return ERR_PTR(-EINVAL);
	}

	/* Check if we are replacing this at the end */
	if (tb[P4TC_TABLE_ACTS_LIST]) {
		tbl_acts_list = kzalloc(sizeof(*tbl_acts_list), GFP_KERNEL);
		if (!tbl_acts_list)
			return ERR_PTR(-ENOMEM);

		INIT_LIST_HEAD(tbl_acts_list);
		ret = p4tc_table_acts_list_init(tb[P4TC_TABLE_ACTS_LIST],
						pipeline, tbl_acts_list,
						extack);
		if (ret < 0)
			goto table_acts_destroy;
	} else {
		tbl_acts_list = &table->tbl_acts_list;
	}

	dflt.nla_hit = tb[P4TC_TABLE_DEFAULT_HIT];
	dflt.nla_miss = tb[P4TC_TABLE_DEFAULT_MISS];

	ret = p4tc_table_init_default_acts(net, &dflt, table, tbl_acts_list,
					   extack);
	if (ret < 0)
		goto table_acts_destroy;

	tbl_type = table->tbl_type;

	if (tb[P4TC_TABLE_KEYSZ])
		tbl_keysz = nla_get_u32(tb[P4TC_TABLE_KEYSZ]);

	if (tb[P4TC_TABLE_MAX_ENTRIES])
		tbl_max_entries = nla_get_u32(tb[P4TC_TABLE_MAX_ENTRIES]);

	if (tb[P4TC_TABLE_MAX_MASKS])
		tbl_max_masks = nla_get_u32(tb[P4TC_TABLE_MAX_MASKS]);

	if (tb[P4TC_TABLE_PERMISSIONS]) {
		__u16 nperm = nla_get_u16(tb[P4TC_TABLE_PERMISSIONS]);

		perm = p4tc_table_init_permissions(table, nperm, extack);
		if (IS_ERR(perm)) {
			ret = PTR_ERR(perm);
			goto defaultacts_destroy;
		}
	}

	if (tb[P4TC_TABLE_TYPE])
		tbl_type = nla_get_u8(tb[P4TC_TABLE_TYPE]);

	p4tc_table_replace_default_acts(table, &dflt, false);
	p4tc_table_replace_permissions(table, perm, false);

	if (tbl_keysz)
		table->tbl_keysz = tbl_keysz;
	if (tbl_max_entries)
		table->tbl_max_entries = tbl_max_entries;
	if (tbl_max_masks)
		table->tbl_max_masks = tbl_max_masks;
	table->tbl_type = tbl_type;

	if (tb[P4TC_TABLE_ACTS_LIST])
		p4tc_table_acts_list_replace(&table->tbl_acts_list,
					     tbl_acts_list);

	return table;

defaultacts_destroy:
	p4tc_table_defact_destroy(dflt.missact);
	p4tc_table_defact_destroy(dflt.hitact);

table_acts_destroy:
	if (tb[P4TC_TABLE_ACTS_LIST]) {
		p4tc_table_acts_list_destroy(tbl_acts_list);
		kfree(tbl_acts_list);
	}

	return ERR_PTR(ret);
}

static struct p4tc_template_common *
p4tc_table_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	      struct p4tc_path_nlattrs *nl_path_attrs,
	      struct netlink_ext_ack *extack)
{
	u32 *ids = nl_path_attrs->ids;
	u32 pipeid = ids[P4TC_PID_IDX], tbl_id = ids[P4TC_TBLID_IDX];
	struct nlattr *tb[P4TC_TABLE_MAX + 1];
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;
	int ret;

	pipeline = p4tc_pipeline_find_byany_unsealed(net, nl_path_attrs->pname,
						     pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	ret = nla_parse_nested(tb, P4TC_TABLE_MAX, nla, p4tc_table_policy,
			       extack);
	if (ret < 0)
		return ERR_PTR(ret);

	switch (n->nlmsg_type) {
	case RTM_CREATEP4TEMPLATE:
		table = p4tc_table_create(net, tb, tbl_id, pipeline, extack);
		break;
	case RTM_UPDATEP4TEMPLATE:
		table = p4tc_table_update(net, tb, tbl_id, pipeline,
					  n->nlmsg_flags, extack);
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (IS_ERR(table))
		goto out;

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TBLID_IDX])
		ids[P4TC_TBLID_IDX] = table->tbl_id;

out:
	return (struct p4tc_template_common *)table;
}

static int p4tc_table_flush(struct net *net, struct sk_buff *skb,
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
		if (_p4tc_table_put(net, NULL, pipeline, table, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	if (nla_put_u32(skb, P4TC_COUNT, i))
		goto out_nlmsg_trim;

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack, "Unable to flush any table");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG_FMT(extack,
					   "Flushed only %u tables", i);
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4tc_table_gd(struct net *net, struct sk_buff *skb,
			 struct nlmsghdr *n, struct nlattr *nla,
			 struct p4tc_path_nlattrs *nl_path_attrs,
			 struct netlink_ext_ack *extack)
{
	u32 *ids = nl_path_attrs->ids;
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

	if (n->nlmsg_type == RTM_GETP4TEMPLATE) {
		pipeline = p4tc_pipeline_find_byany(net,
						    nl_path_attrs->pname,
						    pipeid,
						    extack);
	} else {
		const char *pname = nl_path_attrs->pname;

		pipeline = p4tc_pipeline_find_byany_unsealed(net, pname,
							     pipeid, extack);
	}

	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (!nl_path_attrs->pname_passed)
		strscpy(nl_path_attrs->pname, pipeline->common.name,
			P4TC_PIPELINE_NAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return p4tc_table_flush(net, skb, pipeline, extack);

	table = p4tc_table_find_byanyattr(pipeline, tb[P4TC_TABLE_NAME], tbl_id,
					  extack);
	if (IS_ERR(table))
		return PTR_ERR(table);

	if (_p4tc_table_fill_nlmsg(skb, table) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _p4tc_table_put(net, tb, pipeline, table, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int p4tc_table_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			   struct nlattr *nla, char **p_name, u32 *ids,
			   struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline *pipeline;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = p4tc_pipeline_find_byany(net, *p_name,
						    ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = p4tc_pipeline_find_byid(net, ctx->ids[P4TC_PID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return p4tc_tmpl_generic_dump(skb, ctx, &pipeline->p_tbl_idr,
				      P4TC_TBLID_IDX, extack);
}

static int p4tc_table_dump_1(struct sk_buff *skb,
			     struct p4tc_template_common *common)
{
	struct nlattr *nest = nla_nest_start(skb, P4TC_PARAMS);
	struct p4tc_table *table = p4tc_to_table(common);

	if (!nest)
		return -ENOMEM;

	if (nla_put_string(skb, P4TC_TABLE_NAME, table->common.name)) {
		nla_nest_cancel(skb, nest);
		return -ENOMEM;
	}

	nla_nest_end(skb, nest);

	return 0;
}

static const struct p4tc_template_ops p4tc_table_ops = {
	.cu = p4tc_table_cu,
	.fill_nlmsg = p4tc_table_fill_nlmsg,
	.gd = p4tc_table_gd,
	.put = p4tc_table_put,
	.dump = p4tc_table_dump,
	.dump_1 = p4tc_table_dump_1,
	.obj_id = P4TC_OBJ_TABLE,
};

static int __init p4tc_table_init(void)
{
	p4tc_tmpl_register_ops(&p4tc_table_ops);

#if IS_ENABLED(CONFIG_DEBUG_INFO_BTF)
	register_p4tc_tbl_bpf();
#endif

	return 0;
}

subsys_initcall(p4tc_table_init);
