// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_tbl_api.c TC P4 TABLE API
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
#include <net/p4tc_ext_api.h>

#define SIZEOF_MASKID (sizeof(((struct p4tc_table_entry_key *)0)->maskid))

#define STARTOF_KEY(key) (&((key)->maskid))

static inline int p4tc_tbl_entry_get(struct p4tc_table_entry_value *value)
{
	return refcount_inc_not_zero(&value->entries_ref);
}

static inline bool p4tc_tbl_entry_put(struct p4tc_table_entry_value *value)
{
	return refcount_dec_if_one(&value->entries_ref);
}

static inline bool p4tc_tbl_entry_put_ref(struct p4tc_table_entry_value *value)
{
	return refcount_dec_not_one(&value->entries_ref);
}

static u32 p4tc_entry_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_table_entry_key *key = data;
	u32 keysz;

	/* The key memory area is always zero allocated aligned to 8 */
	keysz = round_up(SIZEOF_MASKID + (key->keysz >> 3), 4);

	return jhash2(STARTOF_KEY(key), keysz / sizeof(u32), seed);
}

static int p4tc_entry_hash_cmp(struct rhashtable_compare_arg *arg,
			       const void *ptr)
{
	const struct p4tc_table_entry_key *key = arg->key;
	const struct p4tc_table_entry *entry = ptr;
	u32 keysz;

	keysz = SIZEOF_MASKID + (entry->key.keysz >> 3);

	return memcmp(STARTOF_KEY(&entry->key), STARTOF_KEY(key), keysz);
}

static u32 p4tc_entry_obj_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_table_entry *entry = data;

	return p4tc_entry_hash_fn(&entry->key, len, seed);
}

const struct rhashtable_params entry_hlt_params = {
	.obj_cmpfn = p4tc_entry_hash_cmp,
	.obj_hashfn = p4tc_entry_obj_hash_fn,
	.hashfn = p4tc_entry_hash_fn,
	.head_offset = offsetof(struct p4tc_table_entry, ht_node),
	.key_offset = offsetof(struct p4tc_table_entry, key),
	.automatic_shrinking = true,
};

static inline struct rhlist_head *
p4tc_entry_lookup_bucket(struct p4tc_table *table,
			 struct p4tc_table_entry_key *key)
{
	return rhltable_lookup(&table->tbl_entries, key, entry_hlt_params);
}

static struct p4tc_table_entry *
__p4tc_entry_lookup_fast(struct p4tc_table *table, struct p4tc_table_entry_key *key)
	__must_hold(RCU)
{
	struct p4tc_table_entry *entry_curr;
	struct rhlist_head *bucket_list;

	bucket_list =
		p4tc_entry_lookup_bucket(table, key);
	if (!bucket_list)
		return NULL;

	rht_entry(entry_curr, bucket_list, ht_node);

	return entry_curr;
}

static struct p4tc_table_entry *
p4tc_entry_lookup(struct p4tc_table *table, struct p4tc_table_entry_key *key,
		  u32 prio) __must_hold(RCU)
{
	struct rhlist_head *tmp, *bucket_list;
	struct p4tc_table_entry *entry;

	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT)
		return __p4tc_entry_lookup_fast(table, key);

	bucket_list =
		p4tc_entry_lookup_bucket(table, key);
	if (!bucket_list)
		return NULL;

	rhl_for_each_entry_rcu(entry, tmp, bucket_list, ht_node) {
		struct p4tc_table_entry_value *value =
			p4tc_table_entry_value(entry);

		if (value->prio == prio)
			return entry;
	}

	return NULL;
}

static struct p4tc_table_entry *
__p4tc_entry_lookup(struct p4tc_table *table, struct p4tc_table_entry_key *key)
	__must_hold(RCU)
{
	struct p4tc_table_entry *entry = NULL;
	struct rhlist_head *tmp, *bucket_list;
	struct p4tc_table_entry *entry_curr;
	u32 smallest_prio = U32_MAX;

	bucket_list =
		rhltable_lookup(&table->tbl_entries, key, entry_hlt_params);
	if (!bucket_list)
		return NULL;

	rhl_for_each_entry_rcu(entry_curr, tmp, bucket_list, ht_node) {
		struct p4tc_table_entry_value *value =
			p4tc_table_entry_value(entry_curr);
		if (value->prio <= smallest_prio) {
			smallest_prio = value->prio;
			entry = entry_curr;
		}
	}

	return entry;
}

static void mask_key(const struct p4tc_table_entry_mask *mask, u8 *masked_key,
		     u8 *skb_key)
{
	int i;

	for (i = 0; i < BITS_TO_BYTES(mask->sz); i++)
		masked_key[i] = skb_key[i] & mask->fa_value[i];
}

static inline void update_last_used(struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_tm *entry_tm;
	struct p4tc_table_entry_value *value;

	value = p4tc_table_entry_value(entry);
	entry_tm = rcu_dereference(value->tm);
	WRITE_ONCE(entry_tm->lastused, get_jiffies_64());

	if (value->is_dyn && !hrtimer_active(&value->entry_timer))
		hrtimer_start(&value->entry_timer, ms_to_ktime(1000),
			      HRTIMER_MODE_REL);
}

struct p4tc_table_entry *
__p4tc_table_entry_lookup_direct(struct p4tc_table *table,
				 struct p4tc_table_entry_key *key)
{
	const struct p4tc_table_entry_mask **masks_array;
	struct p4tc_table_entry *entry = NULL;
	u32 smallest_prio = U32_MAX;
	int i;

	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT)
		return __p4tc_entry_lookup_fast(table, key);

	masks_array =
		(const struct p4tc_table_entry_mask **)rcu_dereference(table->tbl_masks_array);
	for (i = 0; i < table->tbl_curr_num_masks; i++) {
		u8 __mkey[sizeof(*key) + BITS_TO_BYTES(P4TC_MAX_KEYSZ)];
		const struct p4tc_table_entry_mask *mask = masks_array[i];
		struct p4tc_table_entry_key *mkey = (void *)&__mkey;
		struct p4tc_table_entry *entry_curr = NULL;

		mkey->keysz = key->keysz;
		mkey->maskid = mask->mask_id;
		mask_key(mask, mkey->fa_key, key->fa_key);

		if (table->tbl_type == P4TC_TABLE_TYPE_LPM) {
			entry_curr = __p4tc_entry_lookup_fast(table, mkey);
			if (entry_curr)
				return entry_curr;
		} else {
			entry_curr = __p4tc_entry_lookup(table, mkey);

			if (entry_curr) {
				struct p4tc_table_entry_value *value =
					p4tc_table_entry_value(entry_curr);
				if (value->prio <= smallest_prio) {
					smallest_prio = value->prio;
					entry = entry_curr;
				}
			}
		}
	}

	return entry;
}

struct p4tc_table_entry *
p4tc_table_entry_lookup_direct(struct p4tc_table *table,
			       struct p4tc_table_entry_key *key)
{
	struct p4tc_table_entry *entry;

	entry = __p4tc_table_entry_lookup_direct(table, key);

	if (entry)
		update_last_used(entry);

	return entry;
}

#define p4tc_table_entry_mask_find_byid(table, id) \
	(idr_find(&(table)->tbl_masks_idr, id))

static inline void gen_exact_mask(u8 *mask, u32 mask_size)
{
	memset(mask, 0xFF, mask_size);
}

static int p4tca_table_get_entry_keys(struct sk_buff *skb,
				      struct p4tc_table *table,
				      struct p4tc_table_entry *entry)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_table_entry_mask *mask;
	int ret = -ENOMEM;
	u32 key_sz_bytes;

	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT) {
		u8 mask_value[BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = { 0 };

		key_sz_bytes = BITS_TO_BYTES(entry->key.keysz);
		if (nla_put(skb, P4TC_ENTRY_KEY_BLOB, key_sz_bytes,
			    entry->key.fa_key))
			goto out_nlmsg_trim;

		gen_exact_mask(mask_value, key_sz_bytes);
		if (nla_put(skb, P4TC_ENTRY_MASK_BLOB, key_sz_bytes, mask_value))
			goto out_nlmsg_trim;
	} else {
		key_sz_bytes = BITS_TO_BYTES(entry->key.keysz);
		if (nla_put(skb, P4TC_ENTRY_KEY_BLOB, key_sz_bytes,
			    entry->key.fa_key))
			goto out_nlmsg_trim;

		mask = p4tc_table_entry_mask_find_byid(table,
						       entry->key.maskid);
		if (nla_put(skb, P4TC_ENTRY_MASK_BLOB, key_sz_bytes,
			    mask->fa_value))
			goto out_nlmsg_trim;
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static void p4tc_table_entry_tm_dump(struct p4tc_table_entry_tm *dtm,
				     struct p4tc_table_entry_tm *stm)
{
	unsigned long now = jiffies;
	u64 last_used;

	dtm->created = stm->created ?
		jiffies_to_clock_t(now - stm->created) : 0;

	last_used = READ_ONCE(stm->lastused);
	dtm->lastused = stm->lastused ?
		jiffies_to_clock_t(now - last_used) : 0;
	dtm->firstused = stm->firstused ?
		jiffies_to_clock_t(now - stm->firstused) : 0;
}

#define P4TC_ENTRY_MAX_IDS (P4TC_PATH_MAX - 1)

int p4tc_tbl_entry_fill(struct sk_buff *skb, struct p4tc_table *table,
			struct p4tc_table_entry *entry, u32 tbl_id,
			u16 who_deleted)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry_tm dtm, *tm;
	struct nlattr *nest, *nest_acts;
	u32 ids[P4TC_ENTRY_MAX_IDS];
	struct nlattr *nest_counter;
	int ret = -ENOMEM;

	ids[P4TC_TBLID_IDX - 1] = tbl_id;

	if (nla_put(skb, P4TC_PATH, P4TC_ENTRY_MAX_IDS * sizeof(u32), ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	value = p4tc_table_entry_value(entry);

	if (nla_put_u32(skb, P4TC_ENTRY_PRIO, value->prio))
		goto out_nlmsg_trim;

	if (p4tca_table_get_entry_keys(skb, table, entry) < 0)
		goto out_nlmsg_trim;

	if (value->acts) {
		nest_acts = nla_nest_start(skb, P4TC_ENTRY_ACT);
		if (tcf_action_dump(skb, value->acts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, nest_acts);
	}

	if (nla_put_u16(skb, P4TC_ENTRY_PERMISSIONS, value->permissions))
		goto out_nlmsg_trim;

	tm = rcu_dereference_protected(value->tm, 1);

	if (nla_put_u8(skb, P4TC_ENTRY_CREATE_WHODUNNIT, tm->who_created))
		goto out_nlmsg_trim;

	if (tm->who_updated) {
		if (nla_put_u8(skb, P4TC_ENTRY_UPDATE_WHODUNNIT,
			       tm->who_updated))
			goto out_nlmsg_trim;
	}

	if (who_deleted) {
		if (nla_put_u8(skb, P4TC_ENTRY_DELETE_WHODUNNIT,
			       who_deleted))
			goto out_nlmsg_trim;
	}

	p4tc_table_entry_tm_dump(&dtm, tm);
	if (nla_put_64bit(skb, P4TC_ENTRY_TM, sizeof(dtm), &dtm,
			  P4TC_ENTRY_PAD))
		goto out_nlmsg_trim;

	if (value->is_dyn) {
		if (nla_put_u8(skb, P4TC_ENTRY_DYNAMIC, 1))
			goto out_nlmsg_trim;
	}

	if (value->aging_ms) {
		if (nla_put_u64_64bit(skb, P4TC_ENTRY_AGING, value->aging_ms,
				      P4TC_ENTRY_PAD))
			goto out_nlmsg_trim;
	}
	nest_counter = nla_nest_start(skb, P4TC_ENTRY_COUNTER);
	if (value->counter)
		p4tc_ext_elem_dump_1(skb, value->counter);
	nla_nest_end(skb, nest_counter);

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static struct netlink_range_validation range_aging = {
	.min = 1,
	.max = P4TC_MAX_T_AGING,
};

static const struct nla_policy p4tc_entry_policy[P4TC_ENTRY_MAX + 1] = {
	[P4TC_ENTRY_TBLNAME] = { .type = NLA_STRING },
	[P4TC_ENTRY_KEY_BLOB] = { .type = NLA_BINARY },
	[P4TC_ENTRY_MASK_BLOB] = { .type = NLA_BINARY },
	[P4TC_ENTRY_PRIO] = { .type = NLA_U32 },
	[P4TC_ENTRY_ACT] = { .type = NLA_NESTED },
	[P4TC_ENTRY_TM] =
		NLA_POLICY_EXACT_LEN(sizeof(struct p4tc_table_entry_tm)),
	[P4TC_ENTRY_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_CREATE_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_UPDATE_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_DELETE_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_PERMISSIONS] = NLA_POLICY_MAX(NLA_U16, P4TC_MAX_PERMISSION),
	[P4TC_ENTRY_TBL_ATTRS] = { .type = NLA_NESTED },
	[P4TC_ENTRY_DYNAMIC] = NLA_POLICY_RANGE(NLA_U8, 1, 1),
	[P4TC_ENTRY_AGING] = NLA_POLICY_FULL_RANGE(NLA_U64, &range_aging),
};

static struct p4tc_table_entry_mask *
p4tc_table_entry_mask_find_byvalue(struct p4tc_table *table,
				   struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask *mask_cur;
	unsigned long mask_id, tmp;

	idr_for_each_entry_ul(&table->tbl_masks_idr, mask_cur, tmp, mask_id) {
		if (mask_cur->sz == mask->sz) {
			u32 mask_sz_bytes = BITS_TO_BYTES(mask->sz);
			void *curr_mask_value = mask_cur->fa_value;
			void *mask_value = mask->fa_value;

			if (memcmp(curr_mask_value, mask_value, mask_sz_bytes) == 0)
				return mask_cur;
		}
	}

	return NULL;
}

static void __p4tc_table_entry_mask_del(struct p4tc_table *table,
					struct p4tc_table_entry_mask *mask)
{
	if (table->tbl_type == P4TC_TABLE_TYPE_TERNARY) {
		table->tbl_masks_array[mask->mask_index] = NULL;
		bitmap_set(table->tbl_free_masks_bitmap, mask->mask_index, 1);
	} else if (table->tbl_type == P4TC_TABLE_TYPE_LPM) {
		int i;

		for (i = mask->mask_index; i < table->tbl_curr_num_masks - 1; i++)
			table->tbl_masks_array[i] = table->tbl_masks_array[i + 1];

		table->tbl_masks_array[table->tbl_curr_num_masks - 1] = NULL;
	}

	table->tbl_curr_num_masks--;
}

static void p4tc_table_entry_mask_del(struct p4tc_table *table,
				      struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_mask *mask_found;
	const u32 mask_id = entry->key.maskid;

	/* Will always be found */
	mask_found = p4tc_table_entry_mask_find_byid(table, mask_id);

	/* Last reference, can delete */
	if (refcount_dec_if_one(&mask_found->mask_ref)) {
		spin_lock_bh(&table->tbl_masks_idr_lock);
		idr_remove(&table->tbl_masks_idr, mask_found->mask_id);
		__p4tc_table_entry_mask_del(table, mask_found);
		spin_unlock_bh(&table->tbl_masks_idr_lock);
		kfree_rcu(mask_found, rcu);
	} else {
		if (!refcount_dec_not_one(&mask_found->mask_ref))
			pr_warn("Mask was deleted in parallel");
	}
}

static inline u32 p4tc_ffs(u8 *ptr, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		int pos = ffs(ptr[i]);

		if (pos)
			return (i * 8) + pos;
	}

	return 0;
}

static inline u32 p4tc_fls(u8 *ptr, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		int pos = fls(ptr[i]);

		if (pos)
			return (i * 8) + pos;
	}

	return 0;
}

static inline u32 find_lpm_mask(struct p4tc_table *table, u8 *ptr)
{
	u32 ret;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	ret = p4tc_fls(ptr, BITS_TO_BYTES(table->tbl_keysz));
#else
	ret = p4tc_ffs(ptr, BITS_TO_BYTES(table->tbl_keysz));
#endif
	return ret ?: table->tbl_keysz;
}

static inline int p4tc_table_lpm_mask_insert(struct p4tc_table *table,
					     struct p4tc_table_entry_mask *mask)
{
	const u32 nmasks = table->tbl_curr_num_masks ?: 1;
	int pos;

	for (pos = 0; pos < nmasks; pos++) {
		u32 mask_value = find_lpm_mask(table, mask->fa_value);

		if (table->tbl_masks_array[pos]) {
			u32 array_mask_value;

			array_mask_value =
				find_lpm_mask(table, table->tbl_masks_array[pos]->fa_value);

			if (mask_value > array_mask_value) {
				/* shift masks to the right (will keep invariant) */
				u32 tail = nmasks;

				while (tail > pos + 1) {
					table->tbl_masks_array[tail] =
						table->tbl_masks_array[tail - 1];
					tail--;
				}
				table->tbl_masks_array[pos + 1] =
					table->tbl_masks_array[pos];
				/* assign to pos */
				break;
			}
		} else {
			/* pos is empty, assign to pos */
			break;
		}
	}

	mask->mask_index = pos;
	table->tbl_masks_array[pos] = mask;
	table->tbl_curr_num_masks++;

	return 0;
}

static inline int
p4tc_table_ternary_mask_insert(struct p4tc_table *table,
			       struct p4tc_table_entry_mask *mask)
{
	unsigned long pos =
		find_first_bit(table->tbl_free_masks_bitmap, P4TC_MAX_TMASKS);
	if (pos == P4TC_MAX_TMASKS)
		return -ENOSPC;

	mask->mask_index = pos;
	table->tbl_masks_array[pos] = mask;
	bitmap_clear(table->tbl_free_masks_bitmap, pos, 1);
	table->tbl_curr_num_masks++;

	return 0;
}

static inline int p4tc_table_add_mask_array(struct p4tc_table *table,
					    struct p4tc_table_entry_mask *mask)
{
	if (table->tbl_max_masks < table->tbl_curr_num_masks + 1)
		return -ENOSPC;

	switch (table->tbl_type) {
	case P4TC_TABLE_TYPE_TERNARY:
		return p4tc_table_ternary_mask_insert(table, mask);
	case P4TC_TABLE_TYPE_LPM:
		return p4tc_table_lpm_mask_insert(table, mask);
	default:
		return -ENOSPC;
	}
}

/* TODO: Ordering optimisation for LPM */
static struct p4tc_table_entry_mask *
p4tc_table_entry_mask_add(struct p4tc_table *table,
			  struct p4tc_table_entry *entry,
			  struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask *mask_found;
	int ret;

	mask_found = p4tc_table_entry_mask_find_byvalue(table, mask);
	/* Only add mask if it was not already added */
	if (!mask_found) {
		struct p4tc_table_entry_mask *nmask;
		size_t mask_sz_bytes = BITS_TO_BYTES(mask->sz);

		nmask = kzalloc(struct_size(mask_found, fa_value, mask_sz_bytes), GFP_ATOMIC);
		if (unlikely(!nmask))
			return ERR_PTR(-ENOMEM);

		memcpy(nmask->fa_value, mask->fa_value, mask_sz_bytes);

		nmask->mask_id = 1;
		nmask->sz = mask->sz;
		refcount_set(&nmask->mask_ref, 1);

		spin_lock_bh(&table->tbl_masks_idr_lock);
		ret = idr_alloc_u32(&table->tbl_masks_idr, nmask,
				    &nmask->mask_id, UINT_MAX, GFP_ATOMIC);
		if (ret < 0)
			goto unlock;

		ret = p4tc_table_add_mask_array(table, nmask);
unlock:
		spin_unlock_bh(&table->tbl_masks_idr_lock);
		if (ret < 0) {
			kfree(nmask);
			return ERR_PTR(ret);
		}
		entry->key.maskid = nmask->mask_id;
		mask_found = nmask;
	} else {
		if (!refcount_inc_not_zero(&mask_found->mask_ref))
			return ERR_PTR(-EBUSY);
		entry->key.maskid = mask_found->mask_id;
	}

	return mask_found;
}

static int p4tc_tbl_entry_emit_event(struct p4tc_table_entry_work *entry_work,
				     int cmd, gfp_t alloc_flags)
{
	struct p4tc_pipeline *pipeline = entry_work->pipeline;
	struct p4tc_table_entry *entry = entry_work->entry;
	struct p4tc_table *table = entry_work->table;
	u16 who_deleted = entry_work->who_deleted;
	struct net *net = pipeline->net;
	struct sock *rtnl = net->rtnl;
	struct nlmsghdr *nlh;
	struct nlattr *nest;
	struct sk_buff *skb;
	struct nlattr *root;
	struct p4tcmsg *t;
	int err = -ENOMEM;

	if (!rtnl_has_listeners(net, RTNLGRP_TC))
		return 0;

	skb = alloc_skb(NLMSG_GOODSIZE, alloc_flags);
	if (!skb)
		return err;

	nlh = nlmsg_put(skb, 1, 1, cmd, sizeof(*t), NLM_F_REQUEST);
	if (!nlh)
		goto free_skb;

	t = nlmsg_data(nlh);
	if (!t)
		goto free_skb;

	t->pipeid = pipeline->common.p_id;
	t->obj = P4TC_OBJ_RUNTIME_TABLE;

	if (nla_put_string(skb, P4TC_ROOT_PNAME, pipeline->common.name))
		goto free_skb;

	root = nla_nest_start(skb, P4TC_ROOT);
	if (!root)
		goto free_skb;

	nest = nla_nest_start(skb, 1);
	if (p4tc_tbl_entry_fill(skb, table, entry, table->tbl_id,
				who_deleted) < 0)
		goto free_skb;
	nla_nest_end(skb, nest);

	nla_nest_end(skb, root);

	nlmsg_end(skb, nlh);

	return nlmsg_notify(rtnl, skb, 0, RTNLGRP_TC, 0, alloc_flags);

free_skb:
	kfree_skb(skb);
	return err;
}

static void __p4tc_table_entry_put(struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_tm __rcu *tm;
	struct p4tc_table_entry_value *value;

	value = p4tc_table_entry_value(entry);

	if (value->acts) {
		p4tc_action_destroy(value->acts);
		kfree(value->act_bpf);
	}

	kfree(value->entry_work);
	tm = rcu_dereference_protected(value->tm, 1);
	kfree(tm);

	kfree(entry);
}

static void p4tc_table_entry_del_work(struct work_struct *work)
{
	struct p4tc_table_entry_work *entry_work =
		container_of(work, typeof(*entry_work), work);
	struct p4tc_pipeline *pipeline = entry_work->pipeline;
	struct p4tc_table_entry *entry = entry_work->entry;
	struct p4tc_table_entry_value *value;

	if (entry_work->send_event)
		p4tc_tbl_entry_emit_event(entry_work, RTM_P4TC_DEL, GFP_KERNEL);

	value = p4tc_table_entry_value(entry);

	if (value->is_dyn)
		hrtimer_cancel(&value->entry_timer);

	put_net(pipeline->net);
	p4tc_pipeline_put(pipeline);

	__p4tc_table_entry_put(entry);
}

static void p4tc_table_entry_put(struct p4tc_table_entry *entry, bool deferred)
{
	struct p4tc_table_entry_value *value = p4tc_table_entry_value(entry);

	if (deferred) {
		struct p4tc_table_entry_work *entry_work = value->entry_work;
		/* We have to free tc actions
		 * in a sleepable context
		 */
		struct p4tc_pipeline *pipeline = entry_work->pipeline;

		/* Avoid pipeline del before deferral ends */
		p4tc_pipeline_get(pipeline);
		get_net(pipeline->net); /* avoid action cleanup */
		schedule_work(&entry_work->work);
	} else {
		if (value->is_dyn)
			hrtimer_cancel(&value->entry_timer);

		__p4tc_table_entry_put(entry);
	}
}

static void p4tc_table_entry_put_rcu(struct rcu_head *rcu)
{
	struct p4tc_table_entry *entry =
		container_of(rcu, struct p4tc_table_entry, rcu);
	struct p4tc_table_entry_work *entry_work =
		p4tc_table_entry_work(entry);
	struct p4tc_pipeline *pipeline = entry_work->pipeline;

	p4tc_table_entry_put(entry, true);

	p4tc_pipeline_put(pipeline);
	put_net(pipeline->net);
}

static void __p4tc_table_entry_destroy(struct p4tc_table *table,
				       struct p4tc_table_entry *entry,
				       bool remove_from_hash, bool send_event,
				       u16 who_deleted)
{
	/* !remove_from_hash and deferred deletion are incompatible
	 * as entries that defer deletion after a GP __must__
	 * be removed from the hash
	 */
	if (remove_from_hash)
		rhltable_remove(&table->tbl_entries, &entry->ht_node,
				entry_hlt_params);

	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		p4tc_table_entry_mask_del(table, entry);

	if (remove_from_hash) {
		struct p4tc_table_entry_work *entry_work =
			p4tc_table_entry_work(entry);

		entry_work->send_event = send_event;
		entry_work->who_deleted = who_deleted;
		/* guarantee net doesn't go down before async task runs */
		get_net(entry_work->pipeline->net);
		/* guarantee pipeline isn't deleted before async task runs */
		p4tc_pipeline_get(entry_work->pipeline);
		call_rcu(&entry->rcu, p4tc_table_entry_put_rcu);
	} else {
		p4tc_table_entry_put(entry, false);
	}
}

#define P4TC_TABLE_EXACT_PRIO 64000

static inline int p4tc_table_entry_exact_prio(void)
{
	return P4TC_TABLE_EXACT_PRIO;
}

static inline int p4tc_table_entry_alloc_new_prio(struct p4tc_table *table)
{
	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT)
		return p4tc_table_entry_exact_prio();

	return ida_alloc_min(&table->tbl_prio_idr, 1,
			     GFP_ATOMIC);
}

static inline void p4tc_table_entry_free_prio(struct p4tc_table *table, u32 prio)
{
	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		ida_free(&table->tbl_prio_idr, prio);
}

static int p4tc_table_entry_destroy(struct p4tc_table *table,
				    struct p4tc_table_entry *entry,
				    bool remove_from_hash,
				    bool send_event, u16 who_deleted)
{
	struct p4tc_table_entry_value *value = p4tc_table_entry_value(entry);

	/* Entry was deleted in parallel */
	if (!p4tc_tbl_entry_put(value))
		return -EBUSY;

	p4tc_table_entry_free_prio(table, value->prio);

	__p4tc_table_entry_destroy(table, entry, remove_from_hash, send_event,
				   who_deleted);

	atomic_dec(&table->tbl_nelems);

	return 0;
}

static inline void p4tc_table_entry_destroy_noida(struct p4tc_table *table,
						  struct p4tc_table_entry *entry)
{
	/* Entry refcount was already decremented */
	__p4tc_table_entry_destroy(table, entry, true, false, 0);
}

/* Only deletes entries when called from pipeline put */
void p4tc_table_entry_destroy_hash(void *ptr, void *arg)
{
	struct p4tc_table_entry *entry = ptr;
	struct p4tc_table *table = arg;

	p4tc_table_entry_destroy(table, entry, false, false,
				 P4TC_ENTITY_TC);
}

static void p4tc_table_entry_put_table(struct p4tc_pipeline *pipeline,
				       struct p4tc_table *table)
{
	p4tc_table_put_ref(table);
	p4tc_pipeline_put(pipeline);
}

static int p4tc_table_entry_get_table(struct net *net,
				      struct p4tc_pipeline **pipeline,
				      struct p4tc_table **table,
				      struct nlattr **tb, u32 *ids, char *p_name,
				      struct netlink_ext_ack *extack)
{
	/* The following can only race with user driven events
	 * Netns is guaranteed to be alive
	 */
	u32 pipeid, tbl_id;
	char *tblname;
	int ret;

	rcu_read_lock();

	pipeid = ids[P4TC_PID_IDX];

	*pipeline = p4tc_pipeline_find_get(net, p_name, pipeid, extack);
	if (IS_ERR(*pipeline)) {
		ret = PTR_ERR(*pipeline);
		goto out;
	}

	if (!pipeline_sealed(*pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Need to seal pipeline before issuing runtime command");
		ret = -EINVAL;
		goto put;
	}

	tbl_id = ids[P4TC_TBLID_IDX];
	tblname = tb[P4TC_ENTRY_TBLNAME] ? nla_data(tb[P4TC_ENTRY_TBLNAME]) : NULL;

	*table = p4tc_table_find_get(*pipeline, tblname, tbl_id, extack);
	if (IS_ERR(*table)) {
		ret = PTR_ERR(*table);
		goto put;
	}

	rcu_read_unlock();

	return 0;

put:
	p4tc_pipeline_put(*pipeline);

out:
	rcu_read_unlock();
	return ret;
}

static inline void
p4tc_table_entry_assign_key_exact(struct p4tc_table_entry_key *key, u8 *keyblob)
{
	memcpy(key->fa_key, keyblob, BITS_TO_BYTES(key->keysz));
}

static inline void
p4tc_table_entry_assign_key_generic(struct p4tc_table_entry_key *key,
				    struct p4tc_table_entry_mask *mask,
				    u8 *keyblob, u8 *maskblob)
{
	u32 keysz = BITS_TO_BYTES(key->keysz);

	memcpy(key->fa_key, keyblob, keysz);
	memcpy(mask->fa_value, maskblob, keysz);
}

static inline void
p4tc_table_entry_assign_key(struct p4tc_table *table,
			    struct p4tc_table_entry_key *key,
			    struct p4tc_table_entry_mask *mask,
			    u8 *keyblob, u8 *maskblob)
{
	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT)
		p4tc_table_entry_assign_key_exact(key, keyblob);
	else
		p4tc_table_entry_assign_key_generic(key, mask, keyblob,
						    maskblob);
}

static int p4tc_table_entry_extract_key(struct p4tc_table *table,
					struct nlattr **tb,
					struct p4tc_table_entry_key *key,
					struct p4tc_table_entry_mask *mask,
					struct netlink_ext_ack *extack)
{
	u32 keysz;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ENTRY_KEY_BLOB)) {
		NL_SET_ERR_MSG(extack, "Must specify key blobs");
		return -EINVAL;
	}

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ENTRY_MASK_BLOB)) {
		NL_SET_ERR_MSG(extack, "Must specify mask blobs");
		return -EINVAL;
	}

	keysz = nla_len(tb[P4TC_ENTRY_KEY_BLOB]);
	if (BITS_TO_BYTES(key->keysz) != keysz) {
		NL_SET_ERR_MSG(extack,
			       "Key blob size and table key size differ");
		return -EINVAL;
	}

	if (keysz != nla_len(tb[P4TC_ENTRY_MASK_BLOB])) {
		NL_SET_ERR_MSG(extack,
			       "Key and mask blob must have the same length");
		return -EINVAL;
	}

	p4tc_table_entry_assign_key(table, key, mask,
				    nla_data(tb[P4TC_ENTRY_KEY_BLOB]),
				    nla_data(tb[P4TC_ENTRY_MASK_BLOB]));

	return 0;
}

static void p4tc_table_entry_build_key(struct p4tc_table *table,
				       struct p4tc_table_entry_key *key,
				       struct p4tc_table_entry_mask *mask)
{
	int i;

	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT)
		return;

	key->maskid = mask->mask_id;

	for (i = 0; i < BITS_TO_BYTES(key->keysz); i++)
		key->fa_key[i] &= mask->fa_value[i];
}

static int ___p4tc_table_entry_del(struct p4tc_pipeline *pipeline,
				   struct p4tc_table *table,
				   struct p4tc_table_entry *entry,
				   bool from_control)
__must_hold(RCU)
{
	u16 who_deleted = from_control ? P4TC_ENTITY_UNSPEC : P4TC_ENTITY_KERNEL;
	struct p4tc_table_entry_value *value = p4tc_table_entry_value(entry);

	if (from_control) {
		if (!p4tc_ctrl_delete_ok(value->permissions))
			return -EPERM;
	} else {
		if (!p4tc_data_delete_ok(value->permissions))
			return -EPERM;
	}

	if (p4tc_table_entry_destroy(table, entry, true, !from_control,
				     who_deleted) < 0)
		return -EBUSY;

	return 0;
}

/* Internal function which will be called by the data path */
static int __p4tc_table_entry_del(struct p4tc_pipeline *pipeline,
				  struct p4tc_table *table,
				  struct p4tc_table_entry_key *key,
				  struct p4tc_table_entry_mask *mask, u32 prio)
{
	struct p4tc_table_entry *entry;
	int ret;

	p4tc_table_entry_build_key(table, key, mask);

	entry = p4tc_entry_lookup(table, key, prio);
	if (!entry)
		return -ENOENT;

	ret = ___p4tc_table_entry_del(pipeline, table, entry, false);

	return ret;
}

int p4tc_table_entry_del_bpf(struct p4tc_pipeline *pipeline,
			     struct p4tc_table *table,
			     struct p4tc_table_entry_key *key)
{
	u8 __mask[sizeof(struct p4tc_table_entry_mask) +
		  BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = { 0 };
	const u32 keysz_bytes = P4TC_KEYSZ_BYTES(table->tbl_keysz);
	struct p4tc_table_entry_mask *mask = (void *)&__mask;
	const u32 keysz_bits = table->tbl_keysz;
	struct p4tc_table_entry entry = {0};

	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		return -EINVAL;

	if (keysz_bytes != P4TC_KEYSZ_BYTES(key->keysz))
		return -EINVAL;

	entry.key.keysz = keysz_bits;

	return __p4tc_table_entry_del(pipeline, table, key, mask, 0);
}

static int p4tc_table_entry_gd(struct net *net, struct sk_buff *skb, bool del,
			       struct nlattr *arg, u32 *ids,
			       struct p4tc_nl_pname *nl_pname,
			       struct netlink_ext_ack *extack)
{
	struct p4tc_table_entry_mask *mask = NULL, *new_mask;
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry *entry = NULL;
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry_key *key;
	bool has_listener = !!skb;
	struct p4tc_table *table;
	u16 who_deleted = 0;
	bool get = !del;
	u32 keysz_bytes;
	u32 keysz_bits;
	u32 prio;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg, p4tc_entry_policy,
			       extack);
	if (ret < 0)
		return ret;

	ret = p4tc_table_entry_get_table(net, &pipeline, &table, tb, ids,
					 nl_pname->data, extack);
	if (ret < 0)
		return ret;

	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT) {
		prio = p4tc_table_entry_exact_prio();
	} else {
		if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_ENTRY_PRIO)) {
			NL_SET_ERR_MSG(extack, "Must specify table entry priority");
			return -EINVAL;
		}
		prio = nla_get_u32(tb[P4TC_ENTRY_PRIO]);
	}

	if (del && !pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Unable to delete table entry in unsealed pipeline");
		ret = -EINVAL;
		goto table_put;
	}

	keysz_bits = table->tbl_keysz;
	keysz_bytes = P4TC_KEYSZ_BYTES(table->tbl_keysz);

	key = kzalloc(struct_size(key, fa_key, keysz_bytes), GFP_KERNEL);
	if (unlikely(!key)) {
		NL_SET_ERR_MSG(extack, "Unable to allocate key");
		ret = -ENOMEM;
		goto table_put;
	}

	key->keysz = keysz_bits;

	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT) {
		mask = kzalloc(struct_size(mask, fa_value, keysz_bytes),
			       GFP_KERNEL);
		if (unlikely(!mask)) {
			NL_SET_ERR_MSG(extack, "Failed to allocate mask");
			ret = -ENOMEM;
			goto free_key;
		}
		mask->sz = key->keysz;
	}

	ret = p4tc_table_entry_extract_key(table, tb, key, mask, extack);
	if (unlikely(ret < 0)) {
		if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
			kfree(mask);

		goto free_key;
	}

	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT) {
		new_mask = p4tc_table_entry_mask_find_byvalue(table, mask);
		kfree(mask);
		if (!new_mask) {
			NL_SET_ERR_MSG(extack, "Unable to find entry mask");
			ret = -ENOENT;
			goto free_key;
		} else {
			mask = new_mask;
		}
	}

	p4tc_table_entry_build_key(table, key, mask);

	rcu_read_lock();
	entry = p4tc_entry_lookup(table, key, prio);
	if (!entry) {
		NL_SET_ERR_MSG(extack, "Unable to find entry");
		ret = -ENOENT;
		goto unlock;
	}

	/* As we can run delete/update in parallel we might
	 * get a soon to be purged entry from the lookup
	 */
	value = p4tc_table_entry_value(entry);
	if (get && !p4tc_tbl_entry_get(value)) {
		NL_SET_ERR_MSG(extack, "Entry deleted in parallel");
		ret = -EBUSY;
		goto unlock;
	}

	if (del) {
		if (tb[P4TC_ENTRY_WHODUNNIT])
			who_deleted = nla_get_u8(tb[P4TC_ENTRY_WHODUNNIT]);
	} else {
		if (!p4tc_ctrl_read_ok(value->permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Permission denied: Unable to read table entry");
			ret = -EINVAL;
			goto entry_put;
		}
	}

	if (has_listener &&
	    p4tc_tbl_entry_fill(skb, table, entry, table->tbl_id,
				who_deleted) <= 0) {
		NL_SET_ERR_MSG(extack, "Unable to fill table entry attributes");
		ret = -EINVAL;
		goto entry_put;
	}

	if (del) {
		ret = ___p4tc_table_entry_del(pipeline, table, entry, true);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Entry was deleted in parallel");
			goto entry_put;
		}

		if (!has_listener)
			goto out;
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

out:
	ret = 0;

entry_put:
	if (get)
		p4tc_tbl_entry_put_ref(value);

unlock:
	rcu_read_unlock();

free_key:
	kfree(key);

table_put:
	p4tc_table_entry_put_table(pipeline, table);

	return ret;
}

static int p4tc_table_entry_flush(struct net *net, struct sk_buff *skb,
				  struct nlattr *arg, u32 *ids,
				  struct p4tc_nl_pname *nl_pname,
				  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	u32 arg_ids[P4TC_PATH_MAX - 1];
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
	struct rhashtable_iter iter;
	bool has_listener = !!skb;
	struct p4tc_table *table;
	unsigned char *b;
	int ret = 0;
	int i = 0;

	if (arg) {
		ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg,
				       p4tc_entry_policy, extack);
		if (ret < 0)
			return ret;
	}

	ret = p4tc_table_entry_get_table(net, &pipeline, &table, tb, ids,
					 nl_pname->data, extack);
	if (ret < 0)
		return ret;

	if (has_listener)
		b = nlmsg_get_pos(skb);

	if (!ids[P4TC_TBLID_IDX])
		arg_ids[P4TC_TBLID_IDX - 1] = table->tbl_id;

	if (has_listener && nla_put(skb, P4TC_PATH, sizeof(arg_ids), arg_ids)) {
		ret = -ENOMEM;
		goto out_nlmsg_trim;
	}

	rhltable_walk_enter(&table->tbl_entries, &iter);
	do {
		rhashtable_walk_start(&iter);

		while ((entry = rhashtable_walk_next(&iter)) && !IS_ERR(entry)) {
			struct p4tc_table_entry_value *value =
				p4tc_table_entry_value(entry);

			if (!p4tc_ctrl_delete_ok(value->permissions)) {
				ret = -EPERM;
				continue;
			}

			if (p4tc_table_entry_destroy(table, entry, true, false,
						     P4TC_ENTITY_UNSPEC) < 0) {
				ret = -EINVAL;
				continue;
			}

			i++;
		}

		rhashtable_walk_stop(&iter);
	} while (entry == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);

	/* If another user creates a table entry in parallel with this flush,
	 * we may not be able to flush all the entries. So the user should
	 * verify after flush to check for this.
	 */

	if (has_listener)
		nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG_WEAK(extack,
					    "Unable to flush any entries");
			goto out_nlmsg_trim;
		} else {
			if (!extack->_msg)
				NL_SET_ERR_MSG_FMT(extack,
						   "Flush only %u table entries",
						   i);
		}
	}

	if (has_listener) {
		if (!ids[P4TC_PID_IDX])
			ids[P4TC_PID_IDX] = pipeline->common.p_id;

		if (!nl_pname->passed)
			strscpy(nl_pname->data, pipeline->common.name,
				PIPELINENAMSIZ);
	}

	ret = 0;
	goto table_put;

out_nlmsg_trim:
	if (has_listener)
		nlmsg_trim(skb, b);

table_put:
	p4tc_table_entry_put_table(pipeline, table);

	return ret;
}

static int
p4tc_table_tc_act_from_bpf_act(struct tcf_p4act *p4act,
			       struct p4tc_table_entry_value *value,
			       struct p4tc_table_entry_act_bpf *act_bpf)
{
	struct p4tc_table_entry_act_bpf_kern *new_act_bpf;
	struct p4tc_act_param *param;
	unsigned long param_id, tmp;
	u8 *params_cursor;
	int err;

	/* Skip act_id */
	params_cursor = (u8 *)act_bpf + sizeof(act_bpf->act_id);
	idr_for_each_entry_ul(&p4act->params->params_idr, param, tmp, param_id) {
		const struct p4tc_type *type = param->type;
		const u32 type_bytesz = BITS_TO_BYTES(type->container_bitsz);

		memcpy(param->value, params_cursor, type_bytesz);
		params_cursor += type_bytesz;
	}

	new_act_bpf = kzalloc(sizeof(*new_act_bpf), GFP_ATOMIC);
	if (unlikely(!new_act_bpf))
		return -ENOMEM;

	value->acts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
			      GFP_ATOMIC);
	if (unlikely(!value->acts)) {
		err = -ENOMEM;
		goto free_act_bpf;
	}

	new_act_bpf->act_bpf = *act_bpf;

	rcu_assign_pointer(p4act->act_bpf, new_act_bpf);
	value->num_acts = 1;
	value->acts[0] = (struct tc_action *)p4act;

	return 0;

free_act_bpf:
	kfree(new_act_bpf);
	return err;
}

static enum hrtimer_restart entry_timer_handle(struct hrtimer *timer)
{
	struct p4tc_table_entry_value *value =
		container_of(timer, struct p4tc_table_entry_value, entry_timer);
	struct p4tc_table_entry_tm *tm;
	struct p4tc_table_entry *entry;
	u64 aging_ms = value->aging_ms;
	struct p4tc_table *table;
	u64 tdiff, lastused;

	rcu_read_lock();
	tm = rcu_dereference(value->tm);
	lastused = tm->lastused;
	rcu_read_unlock();

	tdiff = jiffies64_to_msecs(get_jiffies_64() - lastused);

	if (tdiff < aging_ms) {
		hrtimer_forward_now(timer, ms_to_ktime(aging_ms));
		return HRTIMER_RESTART;
	}

	entry = value->entry_work->entry;
	table = value->entry_work->table;

	p4tc_table_entry_destroy(table, entry, true,
				 true, P4TC_ENTITY_TIMER);

	return HRTIMER_NORESTART;
}

static struct p4tc_table_entry_tm *
p4tc_table_entry_create_tm(const u16 whodunnit)
{
	struct p4tc_table_entry_tm *dtm;

	dtm = kzalloc(sizeof(*dtm), GFP_ATOMIC);
	if (unlikely(!dtm))
		return ERR_PTR(-ENOMEM);

	dtm->who_created = whodunnit;
	dtm->who_deleted = P4TC_ENTITY_UNSPEC;
	dtm->created = jiffies;
	dtm->firstused = 0;
	dtm->lastused = jiffies;

	return dtm;
}

/* Invoked from both control and data path */
static int __p4tc_table_entry_create(struct p4tc_pipeline *pipeline,
				     struct p4tc_table *table,
				     struct p4tc_table_entry *entry,
				     struct p4tc_table_entry_mask *mask,
				     u16 whodunnit, bool from_control)
__must_hold(RCU)
{
	struct p4tc_table_entry_mask *mask_found = NULL;
	struct p4tc_table_entry_work *entry_work;
	struct p4tc_table_entry_value *value;
	struct p4tc_table_perm *tbl_perm;
	struct p4tc_table_entry_tm *dtm;
	u16 permissions;
	int ret;

	value = p4tc_table_entry_value(entry);
	/* We set it to zero on create an update to avoid having entry
	 * deletion in parallel before we report to user space.
	 */
	refcount_set(&value->entries_ref, 0);

	tbl_perm = rcu_dereference(table->tbl_permissions);
	permissions = tbl_perm->permissions;
	if (from_control) {
		if (!p4tc_ctrl_create_ok(permissions))
			return -EPERM;
	} else {
		if (!p4tc_data_create_ok(permissions))
			return -EPERM;
	}

	/* From data plane we can only create entries on exact match */
	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT) {
		mask_found = p4tc_table_entry_mask_add(table, entry, mask);
		if (IS_ERR(mask_found)) {
			ret = PTR_ERR(mask_found);
			goto out;
		}
	}

	p4tc_table_entry_build_key(table, &entry->key, mask_found);

	if (p4tc_entry_lookup(table, &entry->key, value->prio)) {
		ret = -EEXIST;
		goto rm_masks_idr;
	}

	dtm = p4tc_table_entry_create_tm(whodunnit);
	if (IS_ERR(dtm)) {
		ret = PTR_ERR(dtm);
		goto rm_masks_idr;
	}

	rcu_assign_pointer(value->tm, dtm);

	entry_work = kzalloc(sizeof(*entry_work), GFP_ATOMIC);
	if (unlikely(!entry_work)) {
		ret = -ENOMEM;
		goto free_tm;
	}

	entry_work->pipeline = pipeline;
	entry_work->table = table;
	entry_work->entry = entry;
	value->entry_work = entry_work;

	INIT_WORK(&entry_work->work, p4tc_table_entry_del_work);

	if (atomic_inc_return(&table->tbl_nelems) > table->tbl_max_entries) {
		atomic_dec(&table->tbl_nelems);
		ret = -ENOSPC;
		goto free_work;
	}

	if (table->tbl_counter) {
		value->counter = p4tc_ext_elem_get(table->tbl_counter);
		if (!value->counter) {
			atomic_dec(&table->tbl_nelems);
			ret = -ENOENT;
			goto free_work;
		}
	}

	if (rhltable_insert(&table->tbl_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		atomic_dec(&table->tbl_nelems);
		ret = -EBUSY;
		goto put_ext;
	}

	if (value->is_dyn) {
		/* Only use table template aging if user didn't specify one */
		value->aging_ms = value->aging_ms ?: table->tbl_aging;

		hrtimer_init(&value->entry_timer, CLOCK_MONOTONIC,
			     HRTIMER_MODE_REL);
		value->entry_timer.function = &entry_timer_handle;
		hrtimer_start(&value->entry_timer, ms_to_ktime(value->aging_ms),
			      HRTIMER_MODE_REL);
	}

	if (!from_control)
		p4tc_tbl_entry_emit_event(entry_work, RTM_P4TC_CREATE,
					  GFP_ATOMIC);

	return 0;

put_ext:
	if (value->counter)
		p4tc_ext_elem_put_list(table->tbl_counter, value->counter);

free_work:
	kfree(entry_work);

free_tm:
	kfree(dtm);

rm_masks_idr:
	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		p4tc_table_entry_mask_del(table, entry);
out:
	return ret;
}

struct p4tc_table_entry_create_state {
	struct p4tc_act *act;
	struct tcf_p4act *p4_act;
	struct p4tc_table_entry *entry;
	u64 aging_ms;
	u16 permissions;
};

static int
p4tc_table_entry_init_bpf(struct p4tc_pipeline *pipeline,
			  struct p4tc_table *table, u32 entry_key_sz,
			  struct p4tc_table_entry_act_bpf *act_bpf,
			  struct p4tc_table_entry_create_state *state)
{
	const u32 keysz_bytes = P4TC_KEYSZ_BYTES(table->tbl_keysz);
	struct p4tc_table_entry_value *entry_value;
	const u32 keysz_bits = table->tbl_keysz;
	struct p4tc_table_entry *entry;
	u32 act_id = act_bpf->act_id;
	struct tcf_p4act *p4_act;
	struct p4tc_act *act;
	int err = -EINVAL;
	u32 entrysz;

	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		goto out;

	if (keysz_bytes != P4TC_KEYSZ_BYTES(entry_key_sz))
		goto out;

	if (atomic_read(&table->tbl_nelems) + 1 > table->tbl_max_entries)
		goto out;

	act = p4tc_action_find_get(pipeline, NULL, act_id, NULL);
	if (!act) {
		err = -ENOENT;
		goto out;
	}

	entrysz = sizeof(*entry) + keysz_bytes +
		  sizeof(struct p4tc_table_entry_value);

	entry = kzalloc(entrysz, GFP_ATOMIC);
	if (unlikely(!entry)) {
		err = -ENOMEM;
		goto act_put;
	}
	entry->key.keysz = keysz_bits;

	entry_value = p4tc_table_entry_value(entry);
	entry_value->prio = p4tc_table_entry_exact_prio();
	entry_value->permissions = state->permissions;
	entry_value->aging_ms = state->aging_ms;

	p4_act = tcf_p4_get_next_prealloc_act(act);
	if (!p4_act) {
		err = -ENOENT;
		goto idr_rm;
	}

	err = p4tc_table_tc_act_from_bpf_act(p4_act, entry_value, act_bpf);
	if (err < 0)
		goto free_prealloc;

	state->act = act;
	state->p4_act = p4_act;
	state->entry = entry;

	return 0;

free_prealloc:
	tcf_p4_put_prealloc_act(act, p4_act);

idr_rm:
	p4tc_table_entry_free_prio(table, entry_value->prio);

	kfree(entry);

act_put:
	p4tc_action_put_ref(act);
out:
	return err;
}

static inline void
p4tc_table_entry_create_state_put(struct p4tc_table *table,
				  struct p4tc_table_entry_create_state *state)
{
	struct p4tc_table_entry_value *value;

	tcf_p4_put_prealloc_act(state->act, state->p4_act);

	value = p4tc_table_entry_value(state->entry);
	p4tc_table_entry_free_prio(table, value->prio);

	kfree(value->act_bpf);
	kfree(value->acts);

	kfree(state->entry);

	p4tc_action_put_ref(state->act);
}

/* Invoked from both control and data path  */
static int __p4tc_table_entry_update(struct p4tc_pipeline *pipeline,
				     struct p4tc_table *table,
				     struct p4tc_table_entry *entry,
				     struct p4tc_table_entry_mask *mask,
				     u16 whodunnit, bool from_control)
__must_hold(RCU)
{
	struct p4tc_table_entry_mask *mask_found = NULL;
	struct p4tc_table_entry_work *entry_work;
	struct p4tc_table_entry_value *value_old;
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry *entry_old;
	struct p4tc_table_entry_tm *tm_old;
	struct p4tc_table_entry_tm *tm;
	int ret;

	value = p4tc_table_entry_value(entry);
	/* We set it to zero on create an update to avoid having entry
	 * deletion in parallel before we report to user space.
	 */
	refcount_set(&value->entries_ref, 0);

	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT) {
		mask_found = p4tc_table_entry_mask_add(table, entry, mask);
		if (IS_ERR(mask_found)) {
			ret = PTR_ERR(mask_found);
			goto out;
		}
	}

	p4tc_table_entry_build_key(table, &entry->key, mask_found);

	entry_old = p4tc_entry_lookup(table, &entry->key, value->prio);
	if (!entry_old) {
		ret = -ENOENT;
		goto rm_masks_idr;
	}

	/* In case of parallel update, the thread that arrives here first will
	 * get the right to update.
	 *
	 * In case of a parallel get/update, whoever is second will fail appropriately
	 */
	value_old = p4tc_table_entry_value(entry_old);
	if (!p4tc_tbl_entry_put(value_old)) {
		ret = -EAGAIN;
		goto rm_masks_idr;
	}

	if (from_control) {
		if (!p4tc_ctrl_update_ok(value_old->permissions)) {
			ret = -EPERM;
			goto set_entries_refcount;
		}
	} else {
		if (!p4tc_data_update_ok(value_old->permissions)) {
			ret = -EPERM;
			goto set_entries_refcount;
		}
	}

	tm = kzalloc(sizeof(*tm), GFP_ATOMIC);
	if (unlikely(!tm)) {
		ret = -ENOMEM;
		goto set_entries_refcount;
	}

	tm_old = rcu_dereference_protected(value_old->tm, 1);
	*tm = *tm_old;

	tm->lastused = jiffies;
	tm->who_updated = whodunnit;

	if (value->permissions == P4TC_PERMISSIONS_UNINIT)
		value->permissions = value_old->permissions;

	rcu_assign_pointer(value->tm, tm);

	entry_work = kzalloc(sizeof(*(entry_work)), GFP_ATOMIC);
	if (unlikely(!entry_work)) {
		ret = -ENOMEM;
		goto free_tm;
	}

	entry_work->pipeline = pipeline;
	entry_work->table = table;
	entry_work->entry = entry;
	value->entry_work = entry_work;
	if (!value->is_dyn)
		value->is_dyn = value_old->is_dyn;

	if (value->is_dyn) {
		/* Only use old entry value if user didn't specify new one */
		value->aging_ms = value->aging_ms ?: value_old->aging_ms;

		hrtimer_init(&value->entry_timer, CLOCK_MONOTONIC,
			     HRTIMER_MODE_REL);
		value->entry_timer.function = &entry_timer_handle;

		hrtimer_start(&value->entry_timer, ms_to_ktime(value->aging_ms),
			      HRTIMER_MODE_REL);
	}

	if (value_old->counter)
		value->counter = value_old->counter;

	INIT_WORK(&entry_work->work, p4tc_table_entry_del_work);

	if (rhltable_insert(&table->tbl_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		ret = -EEXIST;
		goto free_entry_work;
	}

	p4tc_table_entry_destroy_noida(table, entry_old);

	if (!from_control)
		p4tc_tbl_entry_emit_event(entry_work, RTM_P4TC_UPDATE,
					  GFP_ATOMIC);

	return 0;

free_entry_work:
	kfree(entry_work);

free_tm:
	kfree(tm);

set_entries_refcount:
	refcount_set(&value_old->entries_ref, 1);

rm_masks_idr:
	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		p4tc_table_entry_mask_del(table, entry);

out:
	return ret;
}

#define P4TC_DEFAULT_TENTRY_PERMISSIONS                           \
	(P4TC_CTRL_PERM_R | P4TC_CTRL_PERM_U | P4TC_CTRL_PERM_D | \
	 P4TC_DATA_PERM_R | P4TC_DATA_PERM_X)

static inline u16 p4tc_table_entry_tbl_permcpy(const u16 tblperm)
{
	return p4tc_ctrl_perm_rm_create(p4tc_data_perm_rm_create(tblperm));
}

int p4tc_table_entry_create_bpf(struct p4tc_pipeline *pipeline,
				struct p4tc_table *table,
				struct p4tc_table_entry_key *key,
				struct p4tc_table_entry_act_bpf *act_bpf,
				u64 aging_ms)
{
	u16 tblperm = rcu_dereference(table->tbl_permissions)->permissions;
	u8 __mask[sizeof(struct p4tc_table_entry_mask) +
		  BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = { 0 };
	struct p4tc_table_entry_mask *mask = (void *)&__mask;
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry_create_state state = {0};
	int err;

	state.aging_ms = aging_ms;
	state.permissions = p4tc_table_entry_tbl_permcpy(tblperm);
	err = p4tc_table_entry_init_bpf(pipeline, table, key->keysz,
					act_bpf, &state);
	if (err < 0)
		return err;

	p4tc_table_entry_assign_key_exact(&state.entry->key, key->fa_key);

	err = __p4tc_table_entry_create(pipeline, table, state.entry, mask,
					P4TC_ENTITY_KERNEL, false);
	if (err < 0)
		goto put_state;

	value = p4tc_table_entry_value(state.entry);
	refcount_set(&value->entries_ref, 1);
	tcf_p4_set_init_flags(state.p4_act);

	return 0;

put_state:
	p4tc_table_entry_create_state_put(table, &state);

	return err;
}

int p4tc_table_entry_update_bpf(struct p4tc_pipeline *pipeline,
				struct p4tc_table *table,
				struct p4tc_table_entry_key *key,
				struct p4tc_table_entry_act_bpf *act_bpf,
				u64 aging_ms)
{
	struct p4tc_table_entry_create_state state = {0};
	struct p4tc_table_entry_value *value;
	int err;

	state.aging_ms = aging_ms;
	state.permissions = P4TC_PERMISSIONS_UNINIT;
	err = p4tc_table_entry_init_bpf(pipeline, table, key->keysz, act_bpf,
					&state);
	if (err < 0)
		return err;

	p4tc_table_entry_assign_key_exact(&state.entry->key, key->fa_key);

	value = p4tc_table_entry_value(state.entry);
	value->is_dyn = !!aging_ms;
	err = __p4tc_table_entry_update(pipeline, table, state.entry, NULL,
					P4TC_ENTITY_KERNEL, false);

	if (err < 0)
		goto put_state;

	refcount_set(&value->entries_ref, 1);
	tcf_p4_set_init_flags(state.p4_act);

	return 0;

put_state:
	p4tc_table_entry_create_state_put(table, &state);

	return err;
}

static bool p4tc_table_check_entry_acts(struct p4tc_table *table,
					struct tc_action *entry_acts[],
					int num_entry_acts)
{
	struct p4tc_table_act *table_act;
	int i;

	for (i = 0; i < num_entry_acts; i++) {
		const struct tc_action *entry_act = entry_acts[i];

		list_for_each_entry(table_act, &table->tbl_acts_list, node) {
			if (table_act->ops->id != entry_act->ops->id)
				continue;

			if (!(table_act->flags &
			      BIT(P4TC_TABLE_ACTS_DEFAULT_ONLY)))
				return true;
		}
	}

	return false;
}

static struct nla_policy p4tc_table_attrs_policy[P4TC_ENTRY_TBL_ATTRS_MAX + 1] = {
	[P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT] = { .type = NLA_NESTED },
	[P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS] = { .type = NLA_NESTED },
	[P4TC_ENTRY_TBL_ATTRS_PERMISSIONS] = NLA_POLICY_MAX(NLA_U16, P4TC_MAX_PERMISSION),
};

static int
update_tbl_attrs(struct net *net, struct p4tc_table *table,
		 struct nlattr *table_attrs,
		 struct netlink_ext_ack *extack)
{
	struct p4tc_table_default_act_params def_params = {0};
	struct nlattr *tb[P4TC_ENTRY_TBL_ATTRS_MAX + 1];
	struct p4tc_table_perm *tbl_perm = NULL;
	int err;

	err = nla_parse_nested(tb, P4TC_ENTRY_TBL_ATTRS_MAX, table_attrs,
			       p4tc_table_attrs_policy, extack);
	if (err < 0)
		return err;

	if (tb[P4TC_ENTRY_TBL_ATTRS_PERMISSIONS]) {
		u16 permissions;

		if (atomic_read(&table->tbl_nelems) > 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to set table permissions if it already has entries");
			return -EINVAL;
		}

		permissions = nla_get_u16(tb[P4TC_ENTRY_TBL_ATTRS_PERMISSIONS]);
		tbl_perm = p4tc_table_init_permissions(table, permissions,
						       extack);
		if (IS_ERR(tbl_perm))
			return PTR_ERR(tbl_perm);
	}

	def_params.default_hit_attr = tb[P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT];
	def_params.default_miss_attr = tb[P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS];

	err = p4tc_table_init_default_acts(net, &def_params, table,
					   &table->tbl_acts_list, extack);
	if (err < 0)
		goto free_tbl_perm;

	p4tc_table_replace_default_acts(table, &def_params, true);
	p4tc_table_replace_permissions(table, tbl_perm, true);

	return 0;

free_tbl_perm:
	kfree(tbl_perm);
	return err;
}

static struct p4tc_table_entry *
__p4tc_table_entry_cu(struct net *net, bool replace, struct nlattr **tb,
		      struct p4tc_pipeline *pipeline, struct p4tc_table *table,
		      struct netlink_ext_ack *extack)
{
	u8 __mask[sizeof(struct p4tc_table_entry_mask) +
		BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = { 0 };
	struct p4tc_table_entry_mask *mask = (void *)&__mask;
	struct p4tc_table_entry_value *value;
	u8 whodunnit = P4TC_ENTITY_UNSPEC;
	struct p4tc_table_entry *entry;
	u32 keysz_bytes;
	u32 keysz_bits;
	u16 tblperm;
	int ret = 0;
	u32 entrysz;
	u32 prio;

	prio = tb[P4TC_ENTRY_PRIO] ? nla_get_u32(tb[P4TC_ENTRY_PRIO]) : 0;
	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT && replace) {
		if (!prio) {
			NL_SET_ERR_MSG(extack, "Must specify entry priority");
			return ERR_PTR(-EINVAL);
		}
	} else {
		if (table->tbl_type == P4TC_TABLE_TYPE_EXACT) {
			if (prio) {
				NL_SET_ERR_MSG(extack,
					       "Mustn't specify entry priority for exact");
				return ERR_PTR(-EINVAL);
			}
			prio = p4tc_table_entry_alloc_new_prio(table);
		} else {
			if (prio)
				ret = ida_alloc_range(&table->tbl_prio_idr,
						      prio, prio, GFP_ATOMIC);
			else
				ret = p4tc_table_entry_alloc_new_prio(table);
			if (ret < 0) {
				NL_SET_ERR_MSG(extack,
					       "Unable to allocate priority");
				return ERR_PTR(ret);
			}
			prio = ret;
		}
	}

	whodunnit = nla_get_u8(tb[P4TC_ENTRY_WHODUNNIT]);

	keysz_bits = table->tbl_keysz;
	keysz_bytes = P4TC_KEYSZ_BYTES(keysz_bits);

	/* Entry memory layout:
	 * { entry:key __aligned(8):value }
	 */
	entrysz = sizeof(*entry) + keysz_bytes +
		sizeof(struct p4tc_table_entry_value);

	entry = kzalloc(entrysz, GFP_KERNEL);
	if (unlikely(!entry)) {
		NL_SET_ERR_MSG(extack, "Unable to allocate table entry");
		ret = -ENOMEM;
		goto idr_rm;
	}

	entry->key.keysz = keysz_bits;
	mask->sz = keysz_bits;

	ret = p4tc_table_entry_extract_key(table, tb, &entry->key, mask, extack);
	if (ret < 0)
		goto free_entry;

	value = p4tc_table_entry_value(entry);
	value->prio = prio;

	rcu_read_lock();
	tblperm = rcu_dereference(table->tbl_permissions)->permissions;
	rcu_read_unlock();

	if (tb[P4TC_ENTRY_PERMISSIONS]) {
		u16 nlperm;

		nlperm = nla_get_u16(tb[P4TC_ENTRY_PERMISSIONS]);
		if (~tblperm & nlperm) {
			NL_SET_ERR_MSG(extack,
				       "Trying to set permission bits which aren't allowed by table");
			ret = -EINVAL;
			goto free_entry;
		}

		if (p4tc_ctrl_create_ok(nlperm) ||
		    p4tc_data_create_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Create permission for table entry doesn't make sense");
			ret = -EINVAL;
			goto free_entry;
		}
		if (!p4tc_ctrl_read_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Control path read permission must be set");
			ret = -EINVAL;
			goto free_entry;
		}
		if (!p4tc_data_read_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Data path read permission must be set");
			ret = -EINVAL;
			goto free_entry;
		}
		if (!p4tc_data_exec_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Data path execute permissions must be set");
			ret = -EINVAL;
			goto free_entry;
		}
		value->permissions = nlperm;
	} else {
		if (replace)
			value->permissions = P4TC_PERMISSIONS_UNINIT;
		else
			value->permissions =
				p4tc_table_entry_tbl_permcpy(tblperm);
	}

	if (tb[P4TC_ENTRY_ACT]) {
		value->acts = kcalloc(TCA_ACT_MAX_PRIO,
				      sizeof(struct tc_action *), GFP_KERNEL);
		if (unlikely(!value->acts)) {
			ret = -ENOMEM;
			goto free_entry;
		}

		ret = p4tc_action_init(net, tb[P4TC_ENTRY_ACT], value->acts,
				       table->common.p_id,
				       TCA_ACT_FLAGS_NO_RTNL, extack);
		if (unlikely(ret < 0)) {
			kfree(value->acts);
			value->acts = NULL;
			goto free_entry;
		}

		value->num_acts = ret;

		if (!p4tc_table_check_entry_acts(table, value->acts, ret)) {
			ret = -EPERM;
			NL_SET_ERR_MSG(extack,
				       "Action is not allowed as entry action");
			goto free_acts;
		}
	}

	if (!replace) {
		if ((!tb[P4TC_ENTRY_AGING] && tb[P4TC_ENTRY_DYNAMIC]) ||
		    (tb[P4TC_ENTRY_AGING] && !tb[P4TC_ENTRY_DYNAMIC])) {
			NL_SET_ERR_MSG(extack,
				       "Aging may only be set alongside dynamic");
			ret = -EINVAL;
			goto free_acts;
		}
	}

	if (tb[P4TC_ENTRY_AGING])
		value->aging_ms = nla_get_u64(tb[P4TC_ENTRY_AGING]);

	if (tb[P4TC_ENTRY_DYNAMIC])
		value->is_dyn = true;

	rcu_read_lock();
	if (replace)
		ret = __p4tc_table_entry_update(pipeline, table, entry, mask,
						whodunnit, true);
	else
		ret = __p4tc_table_entry_create(pipeline, table, entry, mask,
						whodunnit, true);
	rcu_read_unlock();
	if (ret < 0) {
		if (replace && ret == -EAGAIN)
			NL_SET_ERR_MSG(extack, "Entry was being updated in parallel");

		if (ret == -ENOSPC)
			NL_SET_ERR_MSG(extack, "Table max entries reached");

		goto free_acts;
	}

	return entry;

free_acts:
	p4tc_action_destroy(value->acts);

free_entry:
	kfree(entry);

idr_rm:
	if (!replace)
		p4tc_table_entry_free_prio(table, prio);

	return ERR_PTR(ret);
}

static int p4tc_table_entry_cu(struct net *net, struct sk_buff *skb,
			       bool replace, struct nlattr *arg, u32 *ids,
			       struct p4tc_nl_pname *nl_pname,
			       struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry_value *value;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
	bool has_listener = !!skb;
	struct p4tc_table *table;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg, p4tc_entry_policy,
			       extack);
	if (ret < 0)
		return ret;

	ret = p4tc_table_entry_get_table(net, &pipeline, &table, tb, ids,
					 nl_pname->data, extack);
	if (ret < 0)
		return ret;

	if (replace && tb[P4TC_ENTRY_TBL_ATTRS]) {
		/* Table attributes update */
		ret = update_tbl_attrs(net, table,
				       tb[P4TC_ENTRY_TBL_ATTRS],
				       extack);
		goto table_put;
	} else {
		/* Table entry create or update */
		if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_ENTRY_WHODUNNIT)) {
			NL_SET_ERR_MSG(extack,
				       "Must specify whodunnit attribute");
			ret = -EINVAL;
			goto table_put;
		}
	}

	entry = __p4tc_table_entry_cu(net, replace, tb, pipeline, table, extack);
	if (IS_ERR(entry)) {
		ret = PTR_ERR(entry);
		goto table_put;
	}

	if (has_listener) {
		if (p4tc_tbl_entry_fill(skb, table, entry, table->tbl_id,
					P4TC_ENTITY_UNSPEC) <= 0)
			NL_SET_ERR_MSG(extack,
				       "Unable to fill table entry attributes");

		if (!nl_pname->passed)
			strscpy(nl_pname->data, pipeline->common.name,
				PIPELINENAMSIZ);

		if (!ids[P4TC_PID_IDX])
			ids[P4TC_PID_IDX] = pipeline->common.p_id;
	}

	/* We set it to zero on create an update to avoid having the entry
	 * deleted in parallel before we report to user space.
	 * We only set it to 1 here, after reporting.
	 */
	value = p4tc_table_entry_value(entry);
	refcount_set(&value->entries_ref, 1);

table_put:
	p4tc_table_entry_put_table(pipeline, table);
	return ret;
}

struct p4tc_table_entry *
p4tc_table_const_entry_cu(struct net *net,
			  struct nlattr *arg,
			  struct p4tc_pipeline *pipeline,
			  struct p4tc_table *table,
			  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry *entry;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg, p4tc_entry_policy,
			       extack);
	if (ret < 0)
		return ERR_PTR(ret);

	if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_ENTRY_WHODUNNIT)) {
		NL_SET_ERR_MSG(extack, "Must specify whodunnit attribute");
		return ERR_PTR(-EINVAL);
	}

	entry = __p4tc_table_entry_cu(net, false, tb, pipeline, table, extack);
	if (IS_ERR(entry))
		return entry;

	value = p4tc_table_entry_value(entry);
	refcount_set(&value->entries_ref, 1);

	return entry;
}

static int p4tc_tbl_entry_get_1(struct net *net, struct sk_buff *skb, u32 *ids,
				struct nlattr *arg,
				struct p4tc_nl_pname *nl_pname,
				struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *arg_ids;
	int ret = 0;

	ret = nla_parse_nested(tb, P4TC_MAX, arg, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_PATH)) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_PARAMS)) {
		NL_SET_ERR_MSG(extack, "Must specify parameters");
		return -EINVAL;
	}

	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	return p4tc_table_entry_gd(net, skb, false, tb[P4TC_PARAMS], ids,
				   nl_pname, extack);
}

static int p4tc_tbl_entry_del_1(struct net *net, struct sk_buff *skb,
				bool flush, struct nlattr *arg, u32 *ids,
				struct p4tc_nl_pname *nl_pname,
				struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *arg_ids;
	int ret = 0;

	ret = nla_parse_nested(tb, P4TC_MAX, arg, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_PATH)) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	if (flush) {
		ret = p4tc_table_entry_flush(net, skb, tb[P4TC_PARAMS], ids,
					     nl_pname, extack);
	} else {
		if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_PARAMS)) {
			NL_SET_ERR_MSG(extack, "Must specify parameters");
			return -EINVAL;
		}
		ret = p4tc_table_entry_gd(net, skb, true, tb[P4TC_PARAMS], ids,
					  nl_pname, extack);
	}

	return ret;
}

static int p4tc_tbl_entry_cu_1(struct net *net, struct sk_buff *skb,
			       bool replace, u32 *ids, struct nlattr *nla,
			       struct p4tc_nl_pname *nl_pname,
			       struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *tbl_id;
	int ret = 0;

	ret = nla_parse_nested(tb, P4TC_MAX, nla, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, nla, tb, P4TC_PATH)) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if (NL_REQ_ATTR_CHECK(extack, nla, tb, P4TC_PARAMS)) {
		NL_SET_ERR_MSG(extack, "Must specify object attributes");
		return -EINVAL;
	}

	tbl_id = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], tbl_id, nla_len(tb[P4TC_PATH]));

	return p4tc_table_entry_cu(net, skb, replace, tb[P4TC_PARAMS], ids,
				   nl_pname, extack);
}

static int __p4tc_tbl_entry_crud(struct net *net, struct sk_buff *skb,
				 struct nlmsghdr *n, int cmd, char *p_name,
				 struct nlattr *p4tca[],
				 struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	u32 portid = NETLINK_CB(skb).portid;
	u32 ids[P4TC_PATH_MAX] = { 0 };
	struct p4tc_nl_pname nl_pname;
	int ret = 0, ret_send;
	struct p4tcmsg *t_new;
	struct sk_buff *nskb;
	struct nlmsghdr *nlh;
	struct nlattr *pn_att;
	struct nlattr *root;
	int i;

	nskb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!nskb))
		return -ENOBUFS;

	nlh = nlmsg_put(nskb, portid, n->nlmsg_seq, cmd, sizeof(*t),
			n->nlmsg_flags);
	if (unlikely(!nlh))
		goto out;

	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;
	ids[P4TC_PID_IDX] = t_new->pipeid;

	pn_att = nla_reserve(nskb, P4TC_ROOT_PNAME, PIPELINENAMSIZ);
	if (unlikely(!pn_att)) {
		ret = -ENOMEM;
		goto out;
	}

	nl_pname.data = nla_data(pn_att);
	if (!p_name) {
		/* Filled up by the operation or forced failure */
		memset(nl_pname.data, 0, PIPELINENAMSIZ);
		nl_pname.passed = false;
	} else {
		strscpy(nl_pname.data, p_name, PIPELINENAMSIZ);
		nl_pname.passed = true;
	}

	root = nla_nest_start(nskb, P4TC_ROOT);
	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i]; i++) {
		struct nlattr *nest = nla_nest_start(nskb, i);

		if (cmd == RTM_P4TC_GET)
			ret = p4tc_tbl_entry_get_1(net, nskb, ids, p4tca[i],
						   &nl_pname, extack);
		else if (cmd == RTM_P4TC_CREATE ||
			 cmd == RTM_P4TC_UPDATE) {
			bool replace = cmd == RTM_P4TC_UPDATE;

			ret = p4tc_tbl_entry_cu_1(net, nskb, replace, ids,
						  p4tca[i], &nl_pname, extack);
		} else if (cmd == RTM_P4TC_DEL) {
			bool flush = nlh->nlmsg_flags & NLM_F_ROOT;

			ret = p4tc_tbl_entry_del_1(net, nskb, flush, p4tca[i],
						   ids, &nl_pname, extack);
		}

		if (ret < 0) {
			if (i == 1) {
				goto out;
			} else {
				nla_nest_cancel(nskb, nest);
				break;
			}
		}
		nla_nest_end(nskb, nest);
	}
	nla_nest_end(nskb, root);

	if (!t_new->pipeid)
		t_new->pipeid = ids[P4TC_PID_IDX];

	nlmsg_end(nskb, nlh);

	if (cmd == RTM_P4TC_GET)
		ret_send = rtnl_unicast(nskb, net, portid);
	else
		ret_send = rtnetlink_send(nskb, net, portid, RTNLGRP_TC,
					  n->nlmsg_flags & NLM_F_ECHO);

	return ret_send ? ret_send : ret;

out:
	kfree_skb(nskb);
	return ret;
}

static int __p4tc_tbl_entry_crud_fast(struct net *net, struct nlmsghdr *n,
				      int cmd, char *p_name,
				      struct nlattr *p4tca[],
				      struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	u32 ids[P4TC_PATH_MAX] = { 0 };
	struct p4tc_nl_pname nl_pname;
	int ret = 0;
	int i;

	ids[P4TC_PID_IDX] = t->pipeid;

	/* Only read for searching the pipeline */
	nl_pname.data = p_name;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i]; i++) {
		if (cmd == RTM_P4TC_CREATE ||
		    cmd == RTM_P4TC_UPDATE) {
			bool replace = cmd == RTM_P4TC_UPDATE;

			ret = p4tc_tbl_entry_cu_1(net, NULL, replace, ids,
						  p4tca[i], &nl_pname, extack);
		} else if (cmd == RTM_P4TC_DEL) {
			bool flush = n->nlmsg_flags & NLM_F_ROOT;

			ret = p4tc_tbl_entry_del_1(net, NULL, flush, p4tca[i],
						   ids, &nl_pname, extack);
		}

		if (ret < 0)
			goto out;
	}

out:
	return ret;
}

int p4tc_tbl_entry_crud(struct net *net, struct sk_buff *skb,
			struct nlmsghdr *n, int cmd,
			struct netlink_ext_ack *extack)
{
	struct nlattr *p4tca[P4TC_MSGBATCH_SIZE + 1];
	int echo = n->nlmsg_flags & NLM_F_ECHO;
	struct nlattr *tb[P4TC_ROOT_MAX + 1];
	char *p_name = NULL;
	int listeners;
	int ret = 0;

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), tb, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ROOT)) {
		NL_SET_ERR_MSG(extack, "Netlink P4TC table attributes missing");
		return -EINVAL;
	}

	ret = nla_parse_nested(p4tca, P4TC_MSGBATCH_SIZE, tb[P4TC_ROOT], NULL,
			       extack);
	if (ret < 0)
		return ret;

	if (!p4tca[1]) {
		NL_SET_ERR_MSG(extack, "No elements in root table array");
		return -EINVAL;
	}

	if (tb[P4TC_ROOT_PNAME])
		p_name = nla_data(tb[P4TC_ROOT_PNAME]);

	listeners = rtnl_has_listeners(net, RTNLGRP_TC);

	if ((echo || listeners) || cmd == RTM_P4TC_GET)
		ret = __p4tc_tbl_entry_crud(net, skb, n, cmd, p_name, p4tca,
					    extack);
	else
		ret = __p4tc_tbl_entry_crud_fast(net, n, cmd, p_name, p4tca,
						 extack);
	return ret;
}

static int p4tc_table_entry_dump(struct net *net, struct sk_buff *skb,
				 struct nlattr *arg, u32 *ids,
				 struct netlink_callback *cb,
				 char **p_name, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_dump_ctx *ctx = (void *)cb->ctx;
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_table_entry *entry = NULL;
	struct p4tc_table *table;
	int i = 0;
	int ret;

	if (arg) {
		ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg,
				       p4tc_entry_policy, extack);
		if (ret < 0) {
			kfree(ctx->iter);
			return ret;
		}
	}

	ret = p4tc_table_entry_get_table(net, &pipeline, &table, tb, ids,
					 *p_name, extack);
	if (ret < 0) {
		kfree(ctx->iter);
		return ret;
	}

	if (!ctx->iter) {
		ctx->iter = kzalloc(sizeof(*ctx->iter), GFP_KERNEL);
		if (!ctx->iter) {
			ret = -ENOMEM;
			goto table_put;
		}

		rhltable_walk_enter(&table->tbl_entries, ctx->iter);
	}

	ret = -ENOMEM;
	rhashtable_walk_start(ctx->iter);
	do {
		for (i = 0; i < P4TC_MSGBATCH_SIZE &&
		     (entry = rhashtable_walk_next(ctx->iter)) &&
		     !IS_ERR(entry); i++) {
			struct p4tc_table_entry_value *value =
				p4tc_table_entry_value(entry);
			struct nlattr *count;

			if (!p4tc_ctrl_read_ok(value->permissions)) {
				i--;
				continue;
			}

			count = nla_nest_start(skb, i + 1);
			if (!count) {
				rhashtable_walk_stop(ctx->iter);
				goto table_put;
			}

			ret = p4tc_tbl_entry_fill(skb, table, entry,
						  table->tbl_id,
						  P4TC_ENTITY_UNSPEC);
			if (ret == 0) {
				NL_SET_ERR_MSG(extack,
					       "Failed to fill notification attributes for table entry");
				goto walk_done;
			} else if (ret == -ENOMEM) {
				ret = 1;
				nla_nest_cancel(skb, count);
				rhashtable_walk_stop(ctx->iter);
				goto table_put;
			}
			nla_nest_end(skb, count);
		}
	} while (entry == ERR_PTR(-EAGAIN));
	rhashtable_walk_stop(ctx->iter);

	if (!i) {
		rhashtable_walk_exit(ctx->iter);

		ret = 0;
		kfree(ctx->iter);

		goto table_put;
	}

	if (!*p_name)
		*p_name = pipeline->common.name;

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	ret = skb->len;

	goto table_put;

walk_done:
	rhashtable_walk_stop(ctx->iter);
	rhashtable_walk_exit(ctx->iter);
	kfree(ctx->iter);

	nlmsg_trim(skb, b);

table_put:
	p4tc_table_entry_put_table(pipeline, table);

	return ret;
}

int p4tc_tbl_entry_dumpit(struct net *net, struct sk_buff *skb,
			  struct netlink_callback *cb,
			  struct nlattr *arg, char *p_name)
{
	struct netlink_ext_ack *extack = cb->extack;
	u32 portid = NETLINK_CB(cb->skb).portid;
	const struct nlmsghdr *n = cb->nlh;
	struct nlattr *tb[P4TC_MAX + 1];
	u32 ids[P4TC_PATH_MAX] = { 0 };
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *root;
	struct p4tcmsg *t;
	u32 *arg_ids;
	int ret;

	ret = nla_parse_nested(tb, P4TC_MAX, arg, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	nlh = nlmsg_put(skb, portid, n->nlmsg_seq, RTM_P4TC_GET, sizeof(*t),
			n->nlmsg_flags);
	if (!nlh)
		return -ENOSPC;

	t = (struct p4tcmsg *)nlmsg_data(n);
	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;

	if (NL_REQ_ATTR_CHECK(extack, arg, tb, P4TC_PATH)) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	ids[P4TC_PID_IDX] = t_new->pipeid;
	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	root = nla_nest_start(skb, P4TC_ROOT);
	ret = p4tc_table_entry_dump(net, skb, tb[P4TC_PARAMS], ids, cb, &p_name,
				    extack);
	if (ret <= 0)
		goto out;
	nla_nest_end(skb, root);

	if (p_name) {
		if (nla_put_string(skb, P4TC_ROOT_PNAME, p_name)) {
			ret = -1;
			goto out;
		}
	}

	if (!t_new->pipeid)
		t_new->pipeid = ids[P4TC_PID_IDX];

	nlmsg_end(skb, nlh);

	return skb->len;

out:
	nlmsg_cancel(skb, nlh);
	return ret;
}
