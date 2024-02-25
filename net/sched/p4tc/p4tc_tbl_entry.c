// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_tbl_entry.c P4 TC TABLE ENTRY
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

#define SIZEOF_MASKID (sizeof(((struct p4tc_table_entry_key *)0)->maskid))

#define STARTOF_KEY(key) (&((key)->maskid))

/* In this code we avoid locks for create/updating/deleting table entries by
 * using a refcount (entries_ref). We also use RCU to avoid locks for reading.
 * Everytime we try to get the entry, we increment and check the refcount to see
 * whether a delete is happening in parallel.
 */

static bool p4tc_tbl_entry_put(struct p4tc_table_entry_value *value)
{
	return refcount_dec_if_one(&value->entries_ref);
}

static u32 p4tc_entry_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_table_entry_key *key = data;
	u32 keysz;

	/* The key memory area is always zero allocated aligned to 8 */
	keysz = round_up(SIZEOF_MASKID + BITS_TO_BYTES(key->keysz), 4);

	return jhash2(STARTOF_KEY(key), keysz / sizeof(u32), seed);
}

static int p4tc_entry_hash_cmp(struct rhashtable_compare_arg *arg,
			       const void *ptr)
{
	const struct p4tc_table_entry_key *key = arg->key;
	const struct p4tc_table_entry *entry = ptr;
	u32 keysz;

	keysz = SIZEOF_MASKID + BITS_TO_BYTES(entry->key.keysz);

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

static struct rhlist_head *
p4tc_entry_lookup_bucket(struct p4tc_table *table,
			 struct p4tc_table_entry_key *key)
{
	return rhltable_lookup(&table->tbl_entries, key, entry_hlt_params);
}

static struct p4tc_table_entry *
__p4tc_entry_lookup_fast(struct p4tc_table *table,
			 struct p4tc_table_entry_key *key)
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

#define p4tc_table_entry_mask_find_byid(table, id) \
	(idr_find(&(table)->tbl_masks_idr, id))

static void gen_exact_mask(u8 *mask, u32 mask_size)
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
		if (nla_put(skb, P4TC_ENTRY_MASK_BLOB, key_sz_bytes,
			    mask_value))
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
			struct p4tc_table_entry *entry, u32 tbl_id)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry_tm dtm, *tm;
	struct nlattr *nest, *nest_acts;
	u32 ids[P4TC_ENTRY_MAX_IDS];
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

	if (value->acts[0]) {
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

	p4tc_table_entry_tm_dump(&dtm, tm);
	if (nla_put_64bit(skb, P4TC_ENTRY_TM, sizeof(dtm), &dtm,
			  P4TC_ENTRY_PAD))
		goto out_nlmsg_trim;

	if (value->tmpl_created) {
		if (nla_put_u8(skb, P4TC_ENTRY_TMPL_CREATED, 1))
			goto out_nlmsg_trim;
	}

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

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

			if (memcmp(curr_mask_value, mask_value,
				   mask_sz_bytes) == 0)
				return mask_cur;
		}
	}

	return NULL;
}

static void __p4tc_table_entry_mask_del(struct p4tc_table *table,
					struct p4tc_table_entry_mask *mask)
{
	if (table->tbl_type == P4TC_TABLE_TYPE_TERNARY) {
		struct p4tc_table_entry_mask __rcu **masks_array;
		unsigned long *free_masks_bitmap;

		masks_array = table->tbl_masks_array;
		rcu_assign_pointer(masks_array[mask->mask_index], NULL);

		free_masks_bitmap =
			rcu_dereference_protected(table->tbl_free_masks_bitmap,
						  1);
		bitmap_set(free_masks_bitmap, mask->mask_index, 1);
	} else if (table->tbl_type == P4TC_TABLE_TYPE_LPM) {
		struct p4tc_table_entry_mask __rcu **masks_array;
		int i;

		masks_array = table->tbl_masks_array;

		for (i = mask->mask_index; i < table->tbl_curr_num_masks - 1;
		     i++) {
			struct p4tc_table_entry_mask *mask_tmp;

			mask_tmp = rcu_dereference_protected(masks_array[i + 1],
							     1);
			rcu_assign_pointer(masks_array[i + 1], mask_tmp);
		}

		rcu_assign_pointer(masks_array[table->tbl_curr_num_masks - 1],
				   NULL);
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

#if defined(__LITTLE_ENDIAN_BITFIELD)
static u32 p4tc_fls(u8 *ptr, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		int pos = fls(ptr[i]);

		if (pos)
			return (i * 8) + pos;
	}

	return 0;
}
#else
static u32 p4tc_ffs(u8 *ptr, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		int pos = ffs(ptr[i]);

		if (pos)
			return (i * 8) + pos;
	}

	return 0;
}
#endif

static u32 find_lpm_mask(struct p4tc_table *table, u8 *ptr)
{
	u32 ret;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	ret = p4tc_fls(ptr, BITS_TO_BYTES(table->tbl_keysz));
#else
	ret = p4tc_ffs(ptr, BITS_TO_BYTES(table->tbl_keysz));
#endif
	return ret ?: table->tbl_keysz;
}

static int p4tc_table_lpm_mask_insert(struct p4tc_table *table,
				      struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask __rcu **masks_array =
		table->tbl_masks_array;
	const u32 nmasks = table->tbl_curr_num_masks ?: 1;
	int pos;

	for (pos = 0; pos < nmasks; pos++) {
		u32 mask_value = find_lpm_mask(table, mask->fa_value);

		if (table->tbl_masks_array[pos]) {
			struct p4tc_table_entry_mask *mask_pos;
			u32 array_mask_value;

			mask_pos = rcu_dereference_protected(masks_array[pos],
							     1);
			array_mask_value =
				find_lpm_mask(table, mask_pos->fa_value);

			if (mask_value > array_mask_value) {
				/* shift masks to the right (will keep
				 * invariant)
				 */
				u32 tail = nmasks;

				while (tail > pos + 1) {
					rcu_assign_pointer(masks_array[tail],
							   masks_array[tail - 1]);
					table->tbl_masks_array[tail] =
						table->tbl_masks_array[tail - 1];
					tail--;
				}
				rcu_assign_pointer(masks_array[pos + 1],
						   masks_array[pos]);
				/* assign to pos */
				break;
			}
		} else {
			/* pos is empty, assign to pos */
			break;
		}
	}

	mask->mask_index = pos;
	rcu_assign_pointer(masks_array[pos], mask);
	table->tbl_curr_num_masks++;

	return 0;
}

static int
p4tc_table_ternary_mask_insert(struct p4tc_table *table,
			       struct p4tc_table_entry_mask *mask)
{
	unsigned long *free_masks_bitmap =
		rcu_dereference_protected(table->tbl_free_masks_bitmap, 1);
	unsigned long pos =
		find_first_bit(free_masks_bitmap, P4TC_MAX_TMASKS);
	struct p4tc_table_entry_mask __rcu **masks_array =
		table->tbl_masks_array;

	if (pos == P4TC_MAX_TMASKS)
		return -ENOSPC;

	mask->mask_index = pos;
	rcu_assign_pointer(masks_array[pos], mask);
	bitmap_clear(free_masks_bitmap, pos, 1);
	table->tbl_curr_num_masks++;

	return 0;
}

static int p4tc_table_add_mask_array(struct p4tc_table *table,
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

static struct p4tc_table_entry_mask *
p4tc_table_entry_mask_add(struct p4tc_table *table,
			  struct p4tc_table_entry *entry,
			  struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask *found;
	int ret;

	found = p4tc_table_entry_mask_find_byvalue(table, mask);
	/* Only add mask if it was not already added */
	if (!found) {
		struct p4tc_table_entry_mask *nmask;
		size_t masksz_bytes = BITS_TO_BYTES(mask->sz);

		nmask = kzalloc(struct_size(found, fa_value, masksz_bytes),
				GFP_ATOMIC);
		if (unlikely(!nmask))
			return ERR_PTR(-ENOMEM);

		memcpy(nmask->fa_value, mask->fa_value, masksz_bytes);

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
		found = nmask;
	} else {
		if (!refcount_inc_not_zero(&found->mask_ref))
			return ERR_PTR(-EBUSY);
		entry->key.maskid = found->mask_id;
	}

	return found;
}

static struct sk_buff *
alloc_and_fill_root_attrs(struct nlmsghdr **nlh, struct p4tc_pipeline *pipeline,
			  const u32 portid, const u32 seq, const int cmd,
			  gfp_t gfp_flags)
{
	struct sk_buff *skb;
	struct p4tcmsg *t;
	int err = -ENOMEM;

	skb = alloc_skb(NLMSG_GOODSIZE, gfp_flags);
	if (!skb)
		return ERR_PTR(err);

	*nlh = nlmsg_put(skb, portid, seq, cmd, sizeof(*t),
			 NLM_F_REQUEST);
	if (!*nlh)
		goto free_skb;

	t = nlmsg_data(*nlh);
	if (!t)
		goto free_skb;

	t->pipeid = pipeline->common.p_id;
	t->obj = P4TC_OBJ_RUNTIME_TABLE;

	if (nla_put_string(skb, P4TC_ROOT_PNAME, pipeline->common.name))
		goto free_skb;

	return skb;

free_skb:
	kfree_skb(skb);
	return ERR_PTR(err);
}

static int
p4tc_tbl_entry_emit_event(struct p4tc_table_entry_work *entry_work,
			  const u32 portid, const int cmd, const u32 seq,
			  const bool echo, const bool lock_rtnl)
{
	struct p4tc_pipeline *pipeline = entry_work->pipeline;
	struct p4tc_table_entry *entry = entry_work->entry;
	struct p4tc_table *table = entry_work->table;
	struct net *net = pipeline->net;
	struct nlmsghdr *nlh;
	struct nlattr *nest;
	struct sk_buff *skb;
	struct nlattr *root;
	int err = -ENOMEM;

	skb = alloc_and_fill_root_attrs(&nlh, pipeline, portid, seq, cmd,
					GFP_ATOMIC);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	root = nla_nest_start(skb, P4TC_ROOT);
	if (!root)
		goto free_skb;

	nest = nla_nest_start(skb, 1);
	if (p4tc_tbl_entry_fill(skb, table, entry, table->tbl_id) < 0)
		goto free_skb;
	nla_nest_end(skb, nest);
	nla_nest_end(skb, root);

	nlmsg_end(skb, nlh);

	err = nlmsg_notify(net->rtnl, skb, portid, RTNLGRP_TC, echo,
			   GFP_ATOMIC);
	if (!err)
		return 0;

free_skb:
	kfree_skb(skb);
	return err;
}

static void __p4tc_table_entry_put(struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry_tm *tm;

	value = p4tc_table_entry_value(entry);

	if (value->acts[0])
		p4tc_action_destroy(value->acts);

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

	value = p4tc_table_entry_value(entry);

	if (entry_work->send_event && p4tc_ctrl_pub_ok(value->permissions))
		p4tc_tbl_entry_emit_event(entry_work, 0, RTM_P4TC_DEL,
					  0, false, true);

	put_net(pipeline->net);
	p4tc_pipeline_put_ref(pipeline);

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

	p4tc_pipeline_put_ref(pipeline);
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

		/* get pipeline/net for async task */
		get_net(entry_work->pipeline->net);
		p4tc_pipeline_get(entry_work->pipeline);

		call_rcu(&entry->rcu, p4tc_table_entry_put_rcu);
	} else {
		p4tc_table_entry_put(entry, false);
	}
}

#define P4TC_TABLE_EXACT_PRIO 64000

static int p4tc_table_entry_exact_prio(void)
{
	return P4TC_TABLE_EXACT_PRIO;
}

static int p4tc_table_entry_alloc_new_prio(struct p4tc_table *table)
{
	if (table->tbl_type == P4TC_TABLE_TYPE_EXACT)
		return p4tc_table_entry_exact_prio();

	return ida_alloc_min(&table->tbl_prio_ida, 1, GFP_ATOMIC);
}

static void p4tc_table_entry_free_prio(struct p4tc_table *table, u32 prio)
{
	if (table->tbl_type != P4TC_TABLE_TYPE_EXACT)
		ida_free(&table->tbl_prio_ida, prio);
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

static void p4tc_table_entry_destroy_noida(struct p4tc_table *table,
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

struct p4tc_table_get_state {
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;
};

static void
p4tc_table_entry_put_table(struct p4tc_table_get_state *table_get_state)
{
	if (table_get_state->table)
		p4tc_table_put_ref(table_get_state->table);
	if (table_get_state->pipeline)
		p4tc_pipeline_put_ref(table_get_state->pipeline);
}

static int
p4tc_table_entry_get_table(struct net *net, int cmd,
			   struct p4tc_table_get_state *table_get_state,
			   struct nlattr **tb,
			   struct p4tc_path_nlattrs *nl_path_attrs,
			   struct netlink_ext_ack *extack)
{
	/* The following can only race with user driven events
	 * Netns is guaranteed to be alive
	 */
	struct p4tc_pipeline *pipeline;
	u32 *ids = nl_path_attrs->ids;
	struct p4tc_table *table;
	u32 pipeid, tbl_id;
	char *tblname;
	int ret;

	rcu_read_lock();

	pipeid = ids[P4TC_PID_IDX];

	pipeline = p4tc_pipeline_find_get(net, nl_path_attrs->pname, pipeid,
					  extack);
	if (IS_ERR(pipeline)) {
		ret = PTR_ERR(pipeline);
		goto out;
	}

	if (cmd != RTM_P4TC_GET && !p4tc_pipeline_sealed(pipeline)) {
		switch (cmd) {
		case RTM_P4TC_CREATE:
			NL_SET_ERR_MSG(extack,
				       "Pipeline must be sealed for runtime create");
			break;
		case RTM_P4TC_UPDATE:
			NL_SET_ERR_MSG(extack,
				       "Pipeline must be sealed for runtime update");
			break;
		case RTM_P4TC_DEL:
			NL_SET_ERR_MSG(extack,
				       "Pipeline must be sealed for runtime delete");
			break;
		default:
			/* Will never happen */
			break;
		}
		ret = -EINVAL;
		goto put;
	}

	tbl_id = ids[P4TC_TBLID_IDX];
	tblname = tb[P4TC_ENTRY_TBLNAME] ?
		nla_data(tb[P4TC_ENTRY_TBLNAME]) : NULL;

	table = p4tc_table_find_get(pipeline, tblname, tbl_id, extack);
	if (IS_ERR(table)) {
		ret = PTR_ERR(table);
		goto put;
	}

	rcu_read_unlock();

	table_get_state->pipeline = pipeline;
	table_get_state->table = table;

	return 0;

put:
	p4tc_pipeline_put_ref(pipeline);

out:
	rcu_read_unlock();
	return ret;
}

static void
p4tc_table_entry_assign_key_exact(struct p4tc_table_entry_key *key, u8 *keyblob)
{
	memcpy(key->fa_key, keyblob, BITS_TO_BYTES(key->keysz));
}

static void
p4tc_table_entry_assign_key_generic(struct p4tc_table_entry_key *key,
				    struct p4tc_table_entry_mask *mask,
				    u8 *keyblob, u8 *maskblob)
{
	u32 keysz = BITS_TO_BYTES(key->keysz);

	memcpy(key->fa_key, keyblob, keysz);
	memcpy(mask->fa_value, maskblob, keysz);
}

static int p4tc_table_entry_extract_key(struct p4tc_table *table,
					struct nlattr **tb,
					struct p4tc_table_entry_key *key,
					struct p4tc_table_entry_mask *mask,
					struct netlink_ext_ack *extack)
{
	bool is_exact = table->tbl_type == P4TC_TABLE_TYPE_EXACT;
	void *keyblob, *maskblob;
	u32 keysz;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ENTRY_KEY_BLOB)) {
		NL_SET_ERR_MSG(extack, "Must specify key blobs");
		return -EINVAL;
	}

	keysz = nla_len(tb[P4TC_ENTRY_KEY_BLOB]);
	if (BITS_TO_BYTES(key->keysz) != keysz) {
		NL_SET_ERR_MSG(extack,
			       "Key blob size and table key size differ");
		return -EINVAL;
	}

	if (!is_exact) {
		if (NL_REQ_ATTR_CHECK(extack, NULL, tb, P4TC_ENTRY_MASK_BLOB)) {
			NL_SET_ERR_MSG(extack, "Must specify mask blob");
			return -EINVAL;
		}

		if (keysz != nla_len(tb[P4TC_ENTRY_MASK_BLOB])) {
			NL_SET_ERR_MSG(extack,
				       "Key and mask blob must have the same length");
			return -EINVAL;
		}
	}

	keyblob = nla_data(tb[P4TC_ENTRY_KEY_BLOB]);
	if (is_exact) {
		p4tc_table_entry_assign_key_exact(key, keyblob);
	} else {
		maskblob = nla_data(tb[P4TC_ENTRY_MASK_BLOB]);
		p4tc_table_entry_assign_key_generic(key, mask, keyblob,
						    maskblob);
	}

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

	if (rhltable_insert(&table->tbl_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		atomic_dec(&table->tbl_nelems);
		ret = -EBUSY;
		goto free_work;
	}

	if (!from_control && p4tc_ctrl_pub_ok(value->permissions))
		p4tc_tbl_entry_emit_event(entry_work, 0, RTM_P4TC_CREATE, 0,
					  false, GFP_ATOMIC);

	return 0;

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
	/* We set it to zero on update to avoid having entry removed from the
	 * rhashtable in parallel before we report to user space.
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
	 * In case of a parallel get/update, whoever is second will fail
	 * appropriately.
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

	INIT_WORK(&entry_work->work, p4tc_table_entry_del_work);

	if (rhltable_insert(&table->tbl_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		ret = -EEXIST;
		goto free_entry_work;
	}

	p4tc_table_entry_destroy_noida(table, entry_old);

	if (!from_control && p4tc_ctrl_pub_ok(value->permissions))
		p4tc_tbl_entry_emit_event(entry_work, 0, RTM_P4TC_UPDATE,
					  0, false, false);

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

static bool p4tc_table_check_entry_act(struct p4tc_table *table,
				       struct tc_action *entry_act)
{
	struct tcf_p4act *entry_p4act = to_p4act(entry_act);
	struct p4tc_table_act *table_act;

	if (entry_p4act->num_runt_params > 0)
		return false;

	list_for_each_entry(table_act, &table->tbl_acts_list, node) {
		if (table_act->act->common.p_id != entry_p4act->p_id ||
		    table_act->act->a_id != entry_p4act->act_id)
			continue;

		if (!(table_act->flags &
		      BIT(P4TC_TABLE_ACTS_DEFAULT_ONLY)))
			return true;
	}

	return false;
}

static bool p4tc_table_check_no_act(struct p4tc_table *table)
{
	struct p4tc_table_act *table_act;

	if (list_empty(&table->tbl_acts_list))
		return false;

	list_for_each_entry(table_act, &table->tbl_acts_list, node) {
		if (p4tc_table_act_is_noaction(table_act))
			return true;
	}

	return false;
}

static struct nla_policy
p4tc_table_attrs_policy[P4TC_ENTRY_TBL_ATTRS_MAX + 1] = {
	[P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT] = { .type = NLA_NESTED },
	[P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS] = { .type = NLA_NESTED },
	[P4TC_ENTRY_TBL_ATTRS_PERMISSIONS] =
		NLA_POLICY_MAX(NLA_U16, P4TC_MAX_PERMISSION),
};

static int p4tc_tbl_attrs_update(struct net *net, struct p4tc_table *table,
				 struct nlattr *attrs,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_TBL_ATTRS_MAX + 1];
	struct p4tc_table_defact_params dflt = { 0 };
	struct p4tc_table_perm *tbl_perm = NULL;
	int err;

	err = nla_parse_nested(tb, P4TC_ENTRY_TBL_ATTRS_MAX, attrs,
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

	dflt.nla_hit = tb[P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT];
	dflt.nla_miss = tb[P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS];

	err = p4tc_table_init_default_acts(net, &dflt, table,
					   &table->tbl_acts_list, extack);
	if (err < 0)
		goto free_tbl_perm;

	p4tc_table_replace_default_acts(table, &dflt, true);
	p4tc_table_replace_permissions(table, tbl_perm, true);

	return 0;

free_tbl_perm:
	kfree(tbl_perm);
	return err;
}

static u16 p4tc_table_entry_tbl_permcpy(const u16 tblperm)
{
	return p4tc_ctrl_perm_rm_create(p4tc_data_perm_rm_create(tblperm));
}

#define P4TC_TBL_ENTRY_CU_FLAG_CREATE 0x1
#define P4TC_TBL_ENTRY_CU_FLAG_UPDATE 0x2
#define P4TC_TBL_ENTRY_CU_FLAG_SET 0x4

static struct p4tc_table_entry *
__p4tc_table_entry_cu(struct net *net, u8 cu_flags, struct nlattr **tb,
		      struct p4tc_pipeline *pipeline, struct p4tc_table *table,
		      struct netlink_ext_ack *extack)
{
	bool replace = cu_flags == P4TC_TBL_ENTRY_CU_FLAG_UPDATE;
	bool set = cu_flags == P4TC_TBL_ENTRY_CU_FLAG_SET;
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
				ret = ida_alloc_range(&table->tbl_prio_ida,
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

	ret = p4tc_table_entry_extract_key(table, tb, &entry->key, mask,
					   extack);
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
				       "Table perms mismatch");
			ret = -EINVAL;
			goto free_entry;
		}

		if (p4tc_ctrl_create_ok(nlperm) ||
		    p4tc_data_create_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Create perm for entry not allowed");
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
		ret = p4tc_action_init(net, tb[P4TC_ENTRY_ACT], value->acts,
				       table->common.p_id,
				       TCA_ACT_FLAGS_NO_RTNL, extack);
		if (unlikely(ret < 0))
			goto free_entry;

		if (!p4tc_table_check_entry_act(table, value->acts[0])) {
			ret = -EPERM;
			NL_SET_ERR_MSG(extack,
				       "Action not allowed as entry action");
			goto free_acts;
		}
	} else {
		if (!p4tc_table_check_no_act(table)) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Entry must have act associated with it");
			ret = -EPERM;
			goto free_entry;
		}
	}

	whodunnit = nla_get_u8(tb[P4TC_ENTRY_WHODUNNIT]);

	rcu_read_lock();
	if (replace) {
		ret = __p4tc_table_entry_update(pipeline, table, entry, mask,
						whodunnit, true);
	} else {
		ret = __p4tc_table_entry_create(pipeline, table, entry, mask,
						whodunnit, true);
		if (set && ret == -EEXIST)
			ret = __p4tc_table_entry_update(pipeline, table, entry,
							mask, whodunnit, true);
	}
	rcu_read_unlock();
	if (ret < 0) {
		if ((replace || set) && ret == -EAGAIN)
			NL_SET_ERR_MSG(extack,
				       "Entry was being updated in parallel");

		if (ret == -ENOSPC)
			NL_SET_ERR_MSG(extack, "Table max entries reached");
		else
			NL_SET_ERR_MSG(extack, "Failed to create/update entry");

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

#define RET_EVENT_FAILED 1

static int
p4tc_table_entry_cu(struct net *net, struct nlmsghdr *n, struct nlattr *arg,
		    struct p4tc_path_nlattrs *nl_path_attrs, const u32 portid,
		    struct netlink_ext_ack *extack)
{
	struct p4tc_table_get_state table_get_state = { NULL};
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry_value *value;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
	bool has_listener = !!portid;
	struct p4tc_table *table;
	bool replace;
	u8 cu_flags;
	int cmd;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg, p4tc_entry_policy,
			       extack);
	if (ret < 0)
		return ret;

	cmd = n->nlmsg_type;
	if (cmd == RTM_P4TC_UPDATE)
		cu_flags = P4TC_TBL_ENTRY_CU_FLAG_UPDATE;
	else
		if (n->nlmsg_flags & NLM_F_REPLACE)
			cu_flags = P4TC_TBL_ENTRY_CU_FLAG_SET;
		else
			cu_flags =
				P4TC_TBL_ENTRY_CU_FLAG_CREATE;

	replace = cu_flags == P4TC_TBL_ENTRY_CU_FLAG_UPDATE;

	ret = p4tc_table_entry_get_table(net, cmd, &table_get_state, tb,
					 nl_path_attrs, extack);
	if (ret < 0)
		return ret;

	pipeline = table_get_state.pipeline;
	table = table_get_state.table;

	if (replace && tb[P4TC_ENTRY_TBL_ATTRS]) {
		/* Table attributes update */
		ret = p4tc_tbl_attrs_update(net, table,
					    tb[P4TC_ENTRY_TBL_ATTRS], extack);
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

	entry = __p4tc_table_entry_cu(net, cu_flags, tb, pipeline, table,
				      extack);
	if (IS_ERR(entry)) {
		ret = PTR_ERR(entry);
		goto table_put;
	}

	value = p4tc_table_entry_value(entry);
	if (has_listener) {
		if (p4tc_ctrl_pub_ok(value->permissions)) {
			struct p4tc_table_entry_work *entry_work =
				value->entry_work;
			const bool echo = n->nlmsg_flags & NLM_F_ECHO;

			ret = p4tc_tbl_entry_emit_event(entry_work, portid,
							n->nlmsg_type,
							n->nlmsg_seq, echo,
							true);
			if (ret < 0)
				ret = RET_EVENT_FAILED;
		}
	}

	/* We set it to zero on create and update to avoid having the entry
	 * deleted in parallel before we report to user space.
	 * We only set it to 1 here, after reporting.
	 */
	refcount_set(&value->entries_ref, 1);
	p4tc_table_entry_put_table(&table_get_state);
	return ret;

table_put:
	p4tc_table_entry_put_table(&table_get_state);
	return ret;
}

struct p4tc_table_entry *
p4tc_tmpl_table_entry_cu(struct net *net, struct nlattr *arg,
			 struct p4tc_pipeline *pipeline,
			 struct p4tc_table *table,
			 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	u8 cu_flags = P4TC_TBL_ENTRY_CU_FLAG_CREATE;
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

	entry = __p4tc_table_entry_cu(net, cu_flags, tb, pipeline, table,
				      extack);
	if (IS_ERR(entry))
		return entry;

	value = p4tc_table_entry_value(entry);
	refcount_set(&value->entries_ref, 1);
	value->tmpl_created = true;

	return entry;
}

static int
p4tc_tbl_entry_cu_1(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		    struct p4tc_path_nlattrs *nl_path_attrs, const u32 portid,
		    struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MAX + 1];
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

	nla_memcpy(&nl_path_attrs->ids[P4TC_TBLID_IDX], tb[P4TC_PATH],
		   nla_len(tb[P4TC_PATH]));

	return p4tc_table_entry_cu(net, n, tb[P4TC_PARAMS],
				   nl_path_attrs, portid, extack);
}

static int __p4tc_entry_root_num_batched(struct nlattr *p4tca[])
{
	int i = 1;

	while (i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i])
		i++;

	return i - 1;
}

static int __p4tc_tbl_entry_root_1(struct net *net, struct sk_buff *skb,
				   struct nlmsghdr *n, int cmd, char *p_name,
				   struct nlattr *p4tca,
				   struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct p4tc_path_nlattrs nl_path_attrs = {0};
	const u32 portid = NETLINK_CB(skb).portid;
	u32 ids[P4TC_PATH_MAX] = {0};
	int ret = 0;

	if (p_name) {
		size_t pipenamsiz = strnlen(p_name, P4TC_PIPELINE_NAMSIZ) + 1;

		nl_path_attrs.pname = kzalloc(pipenamsiz, GFP_KERNEL);
		if (!nl_path_attrs.pname)
			return -ENOMEM;
		strscpy(nl_path_attrs.pname, p_name, pipenamsiz);
		nl_path_attrs.pname_passed = true;
	} else {
		nl_path_attrs.pname =
			kzalloc(P4TC_PIPELINE_NAMSIZ, GFP_KERNEL);
		if (!nl_path_attrs.pname)
			return -ENOMEM;
	}

	ids[P4TC_PID_IDX] = t->pipeid;
	nl_path_attrs.ids = ids;

	if (cmd == RTM_P4TC_CREATE || cmd == RTM_P4TC_UPDATE) {
		ret = p4tc_tbl_entry_cu_1(net, n,
					  p4tca, &nl_path_attrs,
					  portid, extack);
	} else {
		NL_SET_ERR_MSG_FMT(extack, "Unsupported cmd %u\n", cmd);
		ret = -EOPNOTSUPP;
	}

	if (ret < 0)
		goto free_pname;

free_pname:
	kfree(nl_path_attrs.pname);
	return ret;
}

static int __p4tc_tbl_entry_root(struct net *net, struct sk_buff *skb,
				 struct nlmsghdr *n, int cmd, char *p_name,
				 struct nlattr *p4tca[],
				 struct netlink_ext_ack *extack)
{
	int events_failed = 0;
	int num_batched;
	int ret = 0;
	int i;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i]; i++) {
		ret = __p4tc_tbl_entry_root_1(net, skb, n, cmd, p_name,
					      p4tca[i], extack);
		if (ret == RET_EVENT_FAILED)
			events_failed++;

		if (ret < 0) {
			num_batched = __p4tc_entry_root_num_batched(p4tca);
			int succeeded = i - events_failed - 1;

			/* Had to shorten message because it was being truncated
			 * in some cases, given that we are appending this to
			 * the original error message. S (s/b) means that s
			 * operations succeeded out of b. FE fe means that fe
			 * operations failed to send an event
			 */
			NL_SET_ERR_MSG_FMT(extack,
					   "%s\nS %d/%d(FE %d) entries",
					   extack->_msg, succeeded, num_batched,
					   events_failed);
			return ret;
		}
	}

	if (events_failed) {
		num_batched = __p4tc_entry_root_num_batched(p4tca);
		NL_SET_ERR_MSG_FMT(extack,
				   "S %d/%d(FE %d) entries",
				   num_batched, num_batched,
				   events_failed);
	}

	return ret;
}

static int __p4tc_tbl_entry_root_fast(struct net *net, struct nlmsghdr *n,
				      int cmd, char *p_name,
				      struct nlattr *p4tca[],
				      struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct p4tc_path_nlattrs nl_path_attrs = {0};
	u32 ids[P4TC_PATH_MAX] = { 0 };
	int ret = 0;
	int i;

	ids[P4TC_PID_IDX] = t->pipeid;
	nl_path_attrs.ids = ids;

	/* Only read for searching the pipeline */
	nl_path_attrs.pname = p_name;

	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i]; i++) {
		if (cmd == RTM_P4TC_CREATE ||
		    cmd == RTM_P4TC_UPDATE) {
			ret = p4tc_tbl_entry_cu_1(net, n,
						  p4tca[i], &nl_path_attrs,
						  0, extack);
		} else {
			NL_SET_ERR_MSG_FMT(extack, "Unsupported cmd %u\n", cmd);
			ret = -EOPNOTSUPP;
		}

		if (ret < 0) {
			int num_batched = __p4tc_entry_root_num_batched(p4tca);

			/* Had to shorten message because it was being truncated
			 * in some cases, given that we are appending this to
			 * the original error message. S (s/b) means that s
			 * operations succeeded out of b.
			 */
			NL_SET_ERR_MSG_FMT(extack,
					   "%s\nS %d/%d entries",
					   extack->_msg, i - 1, num_batched);
			goto out;
		}
	}

out:
	return ret;
}

int p4tc_tbl_entry_root(struct net *net, struct sk_buff *skb,
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

	if ((echo || listeners))
		ret = __p4tc_tbl_entry_root(net, skb, n, cmd, p_name, p4tca,
					    extack);
	else
		ret = __p4tc_tbl_entry_root_fast(net, n, cmd, p_name, p4tca,
						 extack);
	return ret;
}
