// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_tbl_api.c TC P4 TABLE API
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

#define KEY_MASK_ID_SZ (sizeof(u32))
#define KEY_MASK_ID_SZ_BITS (KEY_MASK_ID_SZ * BITS_PER_BYTE)

static u32 p4tc_entry_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_table_entry_key *key = data;

	return jhash(key->value, key->keysz >> 3, seed);
}

static int p4tc_entry_hash_cmp(struct rhashtable_compare_arg *arg,
			       const void *ptr)
{
	const struct p4tc_table_entry_key *key = arg->key;
	const struct p4tc_table_entry *entry = ptr;

	return memcmp(entry->key.value, key->value, entry->key.keysz >> 3);
}

static u32 p4tc_entry_obj_hash_fn(const void *data, u32 len, u32 seed)
{
	const struct p4tc_table_entry *entry = data;

	return p4tc_entry_hash_fn(&entry->key, 0, seed);
}

const struct rhashtable_params entry_hlt_params = {
	.obj_cmpfn = p4tc_entry_hash_cmp,
	.obj_hashfn = p4tc_entry_obj_hash_fn,
	.hashfn = p4tc_entry_hash_fn,
	.head_offset = offsetof(struct p4tc_table_entry, ht_node),
	.key_offset = offsetof(struct p4tc_table_entry, key),
	.automatic_shrinking = true,
};

static struct p4tc_table_entry *
p4tc_entry_lookup(struct p4tc_table *table, struct p4tc_table_entry_key *key,
		  u32 prio) __must_hold(RCU)
{
	struct p4tc_table_entry *entry;
	struct rhlist_head *tmp, *bucket_list;

	bucket_list =
		rhltable_lookup(&table->tbl_entries, key, entry_hlt_params);
	if (!bucket_list)
		return NULL;

	rhl_for_each_entry_rcu(entry, tmp, bucket_list, ht_node)
		if (entry->prio == prio)
			return entry;

	return NULL;
}

static struct p4tc_table_entry *
__p4tc_entry_lookup(struct p4tc_table *table, struct p4tc_table_entry_key *key)
	__must_hold(RCU)
{
	struct p4tc_table_entry *entry = NULL;
	u32 smallest_prio = U32_MAX;
	struct rhlist_head *tmp, *bucket_list;
	struct p4tc_table_entry *entry_curr;

	bucket_list =
		rhltable_lookup(&table->tbl_entries, key, entry_hlt_params);
	if (!bucket_list)
		return NULL;

	rhl_for_each_entry_rcu(entry_curr, tmp, bucket_list, ht_node) {
		if (entry_curr->prio <= smallest_prio) {
			smallest_prio = entry_curr->prio;
			entry = entry_curr;
		}
	}

	return entry;
}

static void mask_key(struct p4tc_table_entry_mask *mask, u8 *masked_key,
		     u8 *skb_key)
{
	int i;
	__u32 *mask_id;

	mask_id = (u32 *)&masked_key[0];
	*mask_id = mask->mask_id;

	for (i = KEY_MASK_ID_SZ; i < BITS_TO_BYTES(mask->sz); i++)
		masked_key[i] = skb_key[i - KEY_MASK_ID_SZ] & mask->value[i];
}

struct p4tc_table_entry *p4tc_table_entry_lookup(struct sk_buff *skb,
						 struct p4tc_table *table,
						 u32 keysz)
{
	struct p4tc_table_entry *entry_curr = NULL;
	u8 masked_key[KEY_MASK_ID_SZ + BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = { 0 };
	u32 smallest_prio = U32_MAX;
	struct p4tc_table_entry_mask *mask;
	struct p4tc_table_entry *entry = NULL;
	struct p4tc_skb_ext *p4tc_skb_ext;
	unsigned long tmp, mask_id;

	p4tc_skb_ext = skb_ext_find(skb, P4TC_SKB_EXT);
	if (unlikely(!p4tc_skb_ext))
		return ERR_PTR(-ENOENT);

	idr_for_each_entry_ul(&table->tbl_masks_idr, mask, tmp, mask_id) {
		struct p4tc_table_entry_key key = {};

		mask_key(mask, masked_key, p4tc_skb_ext->p4tc_ext->key);

		key.value = masked_key;
		key.keysz = keysz + KEY_MASK_ID_SZ_BITS;

		entry_curr = __p4tc_entry_lookup(table, &key);
		if (entry_curr) {
			if (entry_curr->prio <= smallest_prio) {
				smallest_prio = entry_curr->prio;
				entry = entry_curr;
			}
		}
	}

	return entry;
}

#define tcf_table_entry_mask_find_byid(table, id) \
	(idr_find(&(table)->tbl_masks_idr, id))

static int p4tca_table_get_entry_keys(struct sk_buff *skb,
				      struct p4tc_table *table,
				      struct p4tc_table_entry *entry)
{
	unsigned char *b = nlmsg_get_pos(skb);
	int ret = -ENOMEM;
	struct p4tc_table_entry_mask *mask;
	u32 key_sz_bytes;

	key_sz_bytes = (entry->key.keysz - KEY_MASK_ID_SZ_BITS) / BITS_PER_BYTE;
	if (nla_put(skb, P4TC_ENTRY_KEY_BLOB, key_sz_bytes,
		    entry->key.unmasked_key + KEY_MASK_ID_SZ))
		goto out_nlmsg_trim;

	mask = tcf_table_entry_mask_find_byid(table, entry->mask_id);
	if (nla_put(skb, P4TC_ENTRY_MASK_BLOB, key_sz_bytes,
		    mask->value + KEY_MASK_ID_SZ))
		goto out_nlmsg_trim;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static void p4tc_table_entry_tm_dump(struct p4tc_table_entry_tm *dtm,
				     struct p4tc_table_entry_tm *stm)
{
	unsigned long now = jiffies;

	dtm->created = stm->created ?
		jiffies_to_clock_t(now - stm->created) : 0;
	dtm->lastused = stm->lastused ?
		jiffies_to_clock_t(now - stm->lastused) : 0;
	dtm->firstused = stm->firstused ?
		jiffies_to_clock_t(now - stm->firstused) : 0;
}

#define P4TC_ENTRY_MAX_IDS (P4TC_PATH_MAX - 1)

int p4tca_table_get_entry_fill(struct sk_buff *skb, struct p4tc_table *table,
			       struct p4tc_table_entry *entry, u32 tbl_id)
{
	unsigned char *b = nlmsg_get_pos(skb);
	int ret = -ENOMEM;
	struct nlattr *nest, *nest_acts;
	struct p4tc_table_entry_tm dtm, *tm;
	u32 ids[P4TC_ENTRY_MAX_IDS];

	ids[P4TC_TBLID_IDX - 1] = tbl_id;

	if (nla_put(skb, P4TC_PATH, P4TC_ENTRY_MAX_IDS * sizeof(u32), ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_ENTRY_PRIO, entry->prio))
		goto out_nlmsg_trim;

	if (p4tca_table_get_entry_keys(skb, table, entry) < 0)
		goto out_nlmsg_trim;

	if (entry->acts) {
		nest_acts = nla_nest_start(skb, P4TC_ENTRY_ACT);
		if (tcf_action_dump(skb, entry->acts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, nest_acts);
	}

	if (nla_put_u8(skb, P4TC_ENTRY_CREATE_WHODUNNIT, entry->who_created))
		goto out_nlmsg_trim;

	if (entry->who_updated) {
		if (nla_put_u8(skb, P4TC_ENTRY_UPDATE_WHODUNNIT,
			       entry->who_updated))
			goto out_nlmsg_trim;
	}

	if (nla_put_u16(skb, P4TC_ENTRY_PERMISSIONS, entry->permissions))
		goto out_nlmsg_trim;

	tm = rtnl_dereference(entry->tm);
	p4tc_table_entry_tm_dump(&dtm, tm);
	if (nla_put_64bit(skb, P4TC_ENTRY_TM, sizeof(dtm), &dtm,
			  P4TC_ENTRY_PAD))
		goto out_nlmsg_trim;

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
	[P4TC_ENTRY_TM] = { .type = NLA_BINARY,
			    .len = sizeof(struct p4tc_table_entry_tm) },
	[P4TC_ENTRY_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_CREATE_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_UPDATE_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_PERMISSIONS] = { .type = NLA_U16 },
};

static void __tcf_table_entry_mask_destroy(struct p4tc_table_entry_mask *mask)
{
	kfree(mask->value);
	kfree(mask);
}

static void tcf_table_entry_mask_destroy(struct rcu_head *rcu)
{
	struct p4tc_table_entry_mask *mask;

	mask = container_of(rcu, struct p4tc_table_entry_mask, rcu);

	__tcf_table_entry_mask_destroy(mask);
}

static struct p4tc_table_entry_mask *
tcf_table_entry_mask_find_byvalue(struct p4tc_table *table,
				  struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask *mask_cur;
	unsigned long mask_id, tmp;

	idr_for_each_entry_ul(&table->tbl_masks_idr, mask_cur, tmp, mask_id) {
		if (mask_cur->sz == mask->sz) {
			u32 mask_sz_bytes = mask->sz / BITS_PER_BYTE - KEY_MASK_ID_SZ;
			void *curr_mask_value = mask_cur->value + KEY_MASK_ID_SZ;
			void *mask_value = mask->value + KEY_MASK_ID_SZ;

			if (memcmp(curr_mask_value, mask_value, mask_sz_bytes) == 0)
				return mask_cur;
		}
	}

	return NULL;
}

static void tcf_table_entry_mask_del(struct p4tc_table *table,
				     struct p4tc_table_entry *entry)
{
	const u32 mask_id = entry->mask_id;
	struct p4tc_table_entry_mask *mask_found;

	/* Will always be found*/
	mask_found = tcf_table_entry_mask_find_byid(table, mask_id);

	/* Last reference, can delete*/
	if (refcount_dec_if_one(&mask_found->mask_ref)) {
		spin_lock_bh(&table->tbl_masks_idr_lock);
		idr_remove(&table->tbl_masks_idr, mask_found->mask_id);
		spin_unlock_bh(&table->tbl_masks_idr_lock);
		call_rcu(&mask_found->rcu, tcf_table_entry_mask_destroy);
	} else {
		if (!refcount_dec_not_one(&mask_found->mask_ref))
			pr_warn("Mask was deleted in parallel");
	}
}

/* TODO: Ordering optimisation for LPM */
static struct p4tc_table_entry_mask *
tcf_table_entry_mask_add(struct p4tc_table *table,
			 struct p4tc_table_entry *entry,
			 struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask *mask_found;
	int ret;

	mask_found = tcf_table_entry_mask_find_byvalue(table, mask);
	/* Only add mask if it was not already added */
	if (!mask_found) {
		struct p4tc_table_entry_mask *mask_allocated;

		mask_allocated = kzalloc(sizeof(*mask_allocated), GFP_ATOMIC);
		if (!mask_allocated)
			return ERR_PTR(-ENOMEM);

		mask_allocated->value =
			kzalloc(BITS_TO_BYTES(mask->sz), GFP_ATOMIC);
		if (!mask_allocated->value) {
			kfree(mask_allocated);
			return ERR_PTR(-ENOMEM);
		}
		memcpy(mask_allocated->value, mask->value,
		       BITS_TO_BYTES(mask->sz));

		mask_allocated->mask_id = 1;
		refcount_set(&mask_allocated->mask_ref, 1);
		mask_allocated->sz = mask->sz;

		spin_lock_bh(&table->tbl_masks_idr_lock);
		ret = idr_alloc_u32(&table->tbl_masks_idr, mask_allocated,
				    &mask_allocated->mask_id, UINT_MAX,
				    GFP_ATOMIC);
		spin_unlock_bh(&table->tbl_masks_idr_lock);
		if (ret < 0) {
			kfree(mask_allocated->value);
			kfree(mask_allocated);
			return ERR_PTR(ret);
		}
		entry->mask_id = mask_allocated->mask_id;
		mask_found = mask_allocated;
	} else {
		if (!refcount_inc_not_zero(&mask_found->mask_ref))
			return ERR_PTR(-EBUSY);
		entry->mask_id = mask_found->mask_id;
	}

	return mask_found;
}

static void tcf_table_entry_del_act(struct p4tc_table_entry *entry)
{
	p4tc_action_destroy(entry->acts);
	kfree(entry);
}

static void tcf_table_entry_del_act_work(struct work_struct *work)
{
	struct p4tc_table_entry_work *entry_work =
		container_of(work, typeof(*entry_work), work);
	struct p4tc_pipeline *pipeline = entry_work->pipeline;

	tcf_table_entry_del_act(entry_work->entry);
	put_net(pipeline->net);

	refcount_dec(&entry_work->pipeline->p_entry_deferal_ref);

	kfree(entry_work);
}

static void tcf_table_entry_put(struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_tm *tm;

	tm = rcu_dereference(entry->tm);
	kfree(tm);

	kfree(entry->key.unmasked_key);
	kfree(entry->key.value);

	if (entry->acts) {
		struct p4tc_table_entry_work *entry_work = entry->entry_work;
		struct p4tc_pipeline *pipeline = entry_work->pipeline;
		struct net *net;

		if (entry_work->defer_deletion) {
			net = get_net(pipeline->net);
			refcount_inc(&entry_work->pipeline->p_entry_deferal_ref);
			schedule_work(&entry_work->work);
		} else {
			kfree(entry_work);
			tcf_table_entry_del_act(entry);
		}
	} else {
		kfree(entry->entry_work);
		kfree(entry);
	}
}

static void tcf_table_entry_put_rcu(struct rcu_head *rcu)
{
	struct p4tc_table_entry *entry;

	entry = container_of(rcu, struct p4tc_table_entry, rcu);

	tcf_table_entry_put(entry);
}

static int tcf_table_entry_destroy(struct p4tc_table *table,
				   struct p4tc_table_entry *entry,
				   bool remove_from_hash)
{
	/* Entry was deleted in parallel */
	if (!refcount_dec_if_one(&entry->entries_ref))
		return -EBUSY;

	if (remove_from_hash)
		rhltable_remove(&table->tbl_entries, &entry->ht_node,
				entry_hlt_params);

	tcf_table_entry_mask_del(table, entry);
	if (entry->entry_work->defer_deletion) {
		call_rcu(&entry->rcu, tcf_table_entry_put_rcu);
	} else {
		synchronize_rcu();
		tcf_table_entry_put(entry);
	}

	return 0;
}

/* Only deletes entries when called from pipeline delete, which means
 * pipeline->p_ref will already be 0, so no need to use that refcount.
 */
void tcf_table_entry_destroy_hash(void *ptr, void *arg)
{
	struct p4tc_table *table = arg;
	struct p4tc_table_entry *entry = ptr;

	refcount_dec(&table->tbl_entries_ref);

	entry->entry_work->defer_deletion = false;
	tcf_table_entry_destroy(table, entry, false);
}

static void tcf_table_entry_put_table(struct p4tc_pipeline *pipeline,
				      struct p4tc_table *table)
{
	/* If we are here, it means that this was just incremented, so it should be > 1 */
	WARN_ON(!refcount_dec_not_one(&table->tbl_ctrl_ref));
	WARN_ON(!refcount_dec_not_one(&pipeline->p_ctrl_ref));
}

static int tcf_table_entry_get_table(struct net *net,
				     struct p4tc_pipeline **pipeline,
				     struct p4tc_table **table,
				     struct nlattr **tb, u32 *ids, char *p_name,
				     struct netlink_ext_ack *extack)
	__must_hold(RCU)
{
	u32 pipeid, tbl_id;
	char *tblname;
	int ret;

	pipeid = ids[P4TC_PID_IDX];

	*pipeline = tcf_pipeline_find_byany(net, p_name, pipeid, extack);
	if (IS_ERR(*pipeline)) {
		ret = PTR_ERR(*pipeline);
		goto out;
	}

	if (!refcount_inc_not_zero(&((*pipeline)->p_ctrl_ref))) {
		NL_SET_ERR_MSG(extack, "Pipeline is stale");
		ret = -EBUSY;
		goto out;
	}

	tbl_id = ids[P4TC_TBLID_IDX];

	tblname = tb[P4TC_ENTRY_TBLNAME] ? nla_data(tb[P4TC_ENTRY_TBLNAME]) : NULL;
	*table = tcf_table_find_byany(*pipeline, tblname, tbl_id, extack);
	if (IS_ERR(*table)) {
		ret = PTR_ERR(*table);
		goto dec_pipeline_refcount;
	}
	if (!refcount_inc_not_zero(&((*table)->tbl_ctrl_ref))) {
		NL_SET_ERR_MSG(extack, "Table is marked for deletion");
		ret = -EBUSY;
		goto dec_pipeline_refcount;
	}

	return 0;

/* If we are here, it means that this was just incremented, so it should be > 1 */
dec_pipeline_refcount:
	WARN_ON(!refcount_dec_not_one(&((*pipeline)->p_ctrl_ref)));

out:
	return ret;
}

static void tcf_table_entry_assign_key(struct p4tc_table_entry_key *key,
				       struct p4tc_table_entry_mask *mask,
				       u8 *keyblob, u8 *maskblob, u32 keysz)
{
	/* Don't assign mask_id to key yet, because it has not been allocated */
	memcpy(key->unmasked_key + KEY_MASK_ID_SZ, keyblob, keysz);

	/* Don't assign mask_id to value yet, because it has not been allocated */
	memcpy(mask->value + KEY_MASK_ID_SZ, maskblob, keysz);
}

static int tcf_table_entry_extract_key(struct nlattr **tb,
				       struct p4tc_table_entry_key *key,
				       struct p4tc_table_entry_mask *mask,
				       struct netlink_ext_ack *extack)
{
	u32 internal_keysz;
	u32 keysz;

	if (!tb[P4TC_ENTRY_KEY_BLOB] || !tb[P4TC_ENTRY_MASK_BLOB]) {
		NL_SET_ERR_MSG(extack, "Must specify key and mask blobs");
		return -EINVAL;
	}

	keysz = nla_len(tb[P4TC_ENTRY_KEY_BLOB]);
	internal_keysz = (keysz + KEY_MASK_ID_SZ) * BITS_PER_BYTE;
	if (key->keysz != internal_keysz) {
		NL_SET_ERR_MSG(extack,
			       "Key blob size and table key size differ");
		return -EINVAL;
	}

	if (keysz != nla_len(tb[P4TC_ENTRY_MASK_BLOB])) {
		NL_SET_ERR_MSG(extack,
			       "Key and mask blob must have the same length");
		return -EINVAL;
	}

	tcf_table_entry_assign_key(key, mask, nla_data(tb[P4TC_ENTRY_KEY_BLOB]),
				   nla_data(tb[P4TC_ENTRY_MASK_BLOB]), keysz);

	return 0;
}

static void tcf_table_entry_build_key(struct p4tc_table_entry_key *key,
				      struct p4tc_table_entry_mask *mask)
{
	u32 *mask_id;
	int i;

	mask_id = (u32 *)&key->unmasked_key[0];
	*mask_id = mask->mask_id;

	mask_id = (u32 *)&mask->value[0];
	*mask_id = mask->mask_id;

	for (i = 0; i < BITS_TO_BYTES(key->keysz); i++)
		key->value[i] = key->unmasked_key[i] & mask->value[i];
}

static int ___tcf_table_entry_del(struct p4tc_pipeline *pipeline,
				  struct p4tc_table *table,
				  struct p4tc_table_entry *entry,
				  bool from_control)
	__must_hold(RCU)
{
	int ret = 0;

	if (from_control) {
		if (!p4tc_ctrl_delete_ok(entry->permissions))
			return -EPERM;
	} else {
		if (!p4tc_data_delete_ok(entry->permissions))
			return -EPERM;
	}

	if (!refcount_dec_not_one(&table->tbl_entries_ref))
		return -EBUSY;

	spin_lock_bh(&table->tbl_prio_idr_lock);
	idr_remove(&table->tbl_prio_idr, entry->prio);
	spin_unlock_bh(&table->tbl_prio_idr_lock);

	if (tcf_table_entry_destroy(table, entry, true) < 0) {
		ret = -EBUSY;
		goto inc_entries_ref;
	}

	goto out;

inc_entries_ref:
	WARN_ON(!refcount_dec_not_one(&table->tbl_entries_ref));

out:
	return ret;
}

/* Internal function which will be called by the data path */
static int __tcf_table_entry_del(struct p4tc_pipeline *pipeline,
				 struct p4tc_table *table,
				 struct p4tc_table_entry_key *key,
				 struct p4tc_table_entry_mask *mask, u32 prio,
				 struct netlink_ext_ack *extack)
{
	struct p4tc_table_entry *entry;
	int ret;

	tcf_table_entry_build_key(key, mask);

	entry = p4tc_entry_lookup(table, key, prio);
	if (!entry) {
		rcu_read_unlock();
		NL_SET_ERR_MSG(extack, "Unable to find entry");
		return -EINVAL;
	}

	entry->entry_work->defer_deletion = true;
	ret = ___tcf_table_entry_del(pipeline, table, entry, false);

	return ret;
}

static int tcf_table_entry_gd(struct net *net, struct sk_buff *skb,
			      struct nlmsghdr *n, struct nlattr *arg, u32 *ids,
			      struct p4tc_nl_pname *nl_pname,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry *entry = NULL;
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_table_entry_mask *mask, *new_mask;
	struct p4tc_table_entry_key *key;
	struct p4tc_table *table;
	u32 keysz_bytes;
	u32 prio;
	int ret;

	if (arg) {
		ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg,
				       p4tc_entry_policy, extack);

		if (ret < 0)
			return ret;
	}

	if (!tb[P4TC_ENTRY_PRIO]) {
		NL_SET_ERR_MSG(extack, "Must specify table entry priority");
		return -EINVAL;
	}
	prio = *((u32 *)nla_data(tb[P4TC_ENTRY_PRIO]));

	rcu_read_lock();
	ret = tcf_table_entry_get_table(net, &pipeline, &table, tb, ids,
					nl_pname->data, extack);
	rcu_read_unlock();
	if (ret < 0)
		return ret;

	if (n->nlmsg_type == RTM_DELP4TBENT && !pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Unable to delete table entry in unsealed pipeline");
		ret = -EINVAL;
		goto table_put;
	}

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		NL_SET_ERR_MSG(extack, "Unable to allocate key");
		ret = -ENOMEM;
		goto table_put;
	}
	key->keysz = table->tbl_keysz + KEY_MASK_ID_SZ_BITS;
	keysz_bytes = (key->keysz / BITS_PER_BYTE);

	mask = kzalloc(sizeof(*mask), GFP_KERNEL);
	if (!mask) {
		NL_SET_ERR_MSG(extack, "Failed to allocate mask");
		ret = -ENOMEM;
		goto free_key;
	}
	mask->value = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!mask->value) {
		NL_SET_ERR_MSG(extack, "Failed to allocate mask value");
		ret = -ENOMEM;
		kfree(mask);
		goto free_key;
	}
	mask->sz = key->keysz;

	key->value = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!key->value) {
		ret = -ENOMEM;
		kfree(mask->value);
		kfree(mask);
		goto free_key;
	}

	key->unmasked_key = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!key->unmasked_key) {
		ret = -ENOMEM;
		kfree(mask->value);
		kfree(mask);
		goto free_key_value;
	}

	ret = tcf_table_entry_extract_key(tb, key, mask, extack);
	if (ret < 0) {
		kfree(mask->value);
		kfree(mask);
		goto free_key_unmasked;
	}

	new_mask = tcf_table_entry_mask_find_byvalue(table, mask);
	kfree(mask->value);
	kfree(mask);
	if (!new_mask) {
		NL_SET_ERR_MSG(extack, "Unable to find entry");
		ret = -ENOENT;
		goto free_key_unmasked;
	} else {
		mask = new_mask;
	}

	tcf_table_entry_build_key(key, mask);

	rcu_read_lock();
	entry = p4tc_entry_lookup(table, key, prio);
	if (!entry) {
		NL_SET_ERR_MSG(extack, "Unable to find entry");
		ret = -EINVAL;
		goto unlock;
	}

	if (n->nlmsg_type == RTM_GETP4TBENT) {
		if (!p4tc_ctrl_read_ok(entry->permissions)) {
			NL_SET_ERR_MSG(extack,
				       "Permission denied: Unable to read table entry");
			ret = -EINVAL;
			goto unlock;
		}
	}

	if (p4tca_table_get_entry_fill(skb, table, entry, table->tbl_id) <= 0) {
		NL_SET_ERR_MSG(extack, "Unable to fill table entry attributes");
		ret = -EINVAL;
		goto unlock;
	}

	if (n->nlmsg_type == RTM_DELP4TBENT) {
		entry->entry_work->defer_deletion = true;
		ret = ___tcf_table_entry_del(pipeline, table, entry, true);
		if (ret < 0)
			goto unlock;
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	ret = 0;

	goto unlock;

unlock:
	rcu_read_unlock();

free_key_unmasked:
	kfree(key->unmasked_key);

free_key_value:
	kfree(key->value);

free_key:
	kfree(key);

table_put:
	tcf_table_entry_put_table(pipeline, table);

	return ret;
}

static int tcf_table_entry_flush(struct net *net, struct sk_buff *skb,
				 struct nlmsghdr *n, struct nlattr *arg,
				 u32 *ids, struct p4tc_nl_pname *nl_pname,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	unsigned char *b = nlmsg_get_pos(skb);
	int ret = 0;
	int i = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
	struct p4tc_table *table;
	u32 arg_ids[P4TC_PATH_MAX - 1];
	struct rhashtable_iter iter;

	if (arg) {
		ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg,
				       p4tc_entry_policy, extack);
		if (ret < 0)
			return ret;
	}

	rcu_read_lock();
	ret = tcf_table_entry_get_table(net, &pipeline, &table, tb, ids,
					nl_pname->data, extack);
	rcu_read_unlock();
	if (ret < 0)
		return ret;

	if (!ids[P4TC_TBLID_IDX])
		arg_ids[P4TC_TBLID_IDX - 1] = table->tbl_id;

	if (nla_put(skb, P4TC_PATH, sizeof(arg_ids), arg_ids)) {
		ret = -ENOMEM;
		goto out_nlmsg_trim;
	}

	rhltable_walk_enter(&table->tbl_entries, &iter);
	do {
		rhashtable_walk_start(&iter);

		while ((entry = rhashtable_walk_next(&iter)) && !IS_ERR(entry)) {
			if (!p4tc_ctrl_delete_ok(entry->permissions)) {
				ret = -EPERM;
				continue;
			}

			if (!refcount_dec_not_one(&table->tbl_entries_ref)) {
				NL_SET_ERR_MSG(extack, "Table entry is stale");
				ret = -EBUSY;
				rhashtable_walk_stop(&iter);
				goto walk_exit;
			}

			entry->entry_work->defer_deletion = true;
			if (tcf_table_entry_destroy(table, entry, true) < 0) {
				ret = -EBUSY;
				continue;
			}
			i++;
		}

		rhashtable_walk_stop(&iter);
	} while (entry == ERR_PTR(-EAGAIN));

walk_exit:
	rhashtable_walk_exit(&iter);

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			if (!extack->_msg)
				NL_SET_ERR_MSG(extack,
					       "Unable to flush any entries");
			goto out_nlmsg_trim;
		} else {
			if (!extack->_msg)
				NL_SET_ERR_MSG(extack,
					       "Unable to flush all entries");
		}
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	ret = 0;
	goto table_put;

out_nlmsg_trim:
	nlmsg_trim(skb, b);

/* If we are here, it means that this was just incremented, so it should be > 1 */
table_put:
	tcf_table_entry_put_table(pipeline, table);

	return ret;
}

/* Invoked from both control and data path */
static int __tcf_table_entry_create(struct p4tc_pipeline *pipeline,
				    struct p4tc_table *table,
				    struct p4tc_table_entry *entry,
				    struct p4tc_table_entry_mask *mask,
				    u16 whodunnit, bool from_control)
	__must_hold(RCU)
{
	struct p4tc_table_perm *tbl_perm;
	struct p4tc_table_entry_mask *mask_found;
	struct p4tc_table_entry_work *entry_work;
	struct p4tc_table_entry_tm *dtm;
	u16 permissions;
	int ret;

	refcount_set(&entry->entries_ref, 1);

	tbl_perm = rcu_dereference(table->tbl_permissions);
	permissions = tbl_perm->permissions;
	if (from_control) {
		if (!p4tc_ctrl_create_ok(permissions))
			return -EPERM;
	} else {
		if (!p4tc_data_create_ok(permissions))
			return -EPERM;
	}

	mask_found = tcf_table_entry_mask_add(table, entry, mask);
	if (IS_ERR(mask_found)) {
		ret = PTR_ERR(mask_found);
		goto out;
	}

	tcf_table_entry_build_key(&entry->key, mask_found);

	if (!refcount_inc_not_zero(&table->tbl_entries_ref)) {
		ret = -EBUSY;
		goto rm_masks_idr;
	}

	if (p4tc_entry_lookup(table, &entry->key, entry->prio)) {
		ret = -EEXIST;
		goto dec_entries_ref;
	}

	dtm = kzalloc(sizeof(*dtm), GFP_ATOMIC);
	if (!dtm) {
		ret = -ENOMEM;
		goto dec_entries_ref;
	}

	entry->who_created = whodunnit;

	dtm->created = jiffies;
	dtm->firstused = 0;
	dtm->lastused = jiffies;
	rcu_assign_pointer(entry->tm, dtm);

	entry_work = kzalloc(sizeof(*(entry_work)), GFP_ATOMIC);
	if (!entry_work) {
		ret = -ENOMEM;
		goto free_tm;
	}

	entry_work->pipeline = pipeline;
	entry_work->entry = entry;
	entry->entry_work = entry_work;

	INIT_WORK(&entry_work->work, tcf_table_entry_del_act_work);

	if (rhltable_insert(&table->tbl_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		ret = -EBUSY;
		goto free_entry_work;
	}

	return 0;

free_entry_work:
	kfree(entry_work);

free_tm:
	kfree(dtm);
/*If we are here, it means that this was just incremented, so it should be > 1 */
dec_entries_ref:
	WARN_ON(!refcount_dec_not_one(&table->tbl_entries_ref));

rm_masks_idr:
	tcf_table_entry_mask_del(table, entry);

out:
	return ret;
}

/* Invoked from both control and data path  */
static int __tcf_table_entry_update(struct p4tc_pipeline *pipeline,
				    struct p4tc_table *table,
				    struct p4tc_table_entry *entry,
				    struct p4tc_table_entry_mask *mask,
				    u16 whodunnit, bool from_control)
	__must_hold(RCU)
{
	struct p4tc_table_entry_mask *mask_found;
	struct p4tc_table_entry_work *entry_work;
	struct p4tc_table_entry *entry_old;
	struct p4tc_table_entry_tm *tm_old;
	struct p4tc_table_entry_tm *tm;
	int ret;

	refcount_set(&entry->entries_ref, 1);

	mask_found = tcf_table_entry_mask_add(table, entry, mask);
	if (IS_ERR(mask_found)) {
		ret = PTR_ERR(mask_found);
		goto out;
	}

	tcf_table_entry_build_key(&entry->key, mask_found);

	entry_old = p4tc_entry_lookup(table, &entry->key, entry->prio);
	if (!entry_old) {
		ret = -ENOENT;
		goto rm_masks_idr;
	}

	if (from_control) {
		if (!p4tc_ctrl_update_ok(entry_old->permissions)) {
			ret = -EPERM;
			goto rm_masks_idr;
		}
	} else {
		if (!p4tc_data_update_ok(entry_old->permissions)) {
			ret = -EPERM;
			goto rm_masks_idr;
		}
	}

	if (refcount_read(&entry_old->entries_ref) > 1) {
		ret = -EBUSY;
		goto rm_masks_idr;
	}

	tm = kzalloc(sizeof(*tm), GFP_ATOMIC);
	if (!tm) {
		ret = -ENOMEM;
		goto rm_masks_idr;
	}

	tm_old = rcu_dereference_protected(entry_old->tm, 1);
	tm->created = tm_old->created;
	tm->firstused = tm_old->firstused;
	tm->lastused = jiffies;

	entry->who_updated = whodunnit;

	entry->who_created = entry_old->who_created;

	if (entry->permissions == P4TC_PERMISSIONS_UNINIT)
		entry->permissions = entry_old->permissions;

	rcu_assign_pointer(entry->tm, tm);

	entry_work = kzalloc(sizeof(*(entry_work)), GFP_ATOMIC);
	if (!entry_work) {
		ret = -ENOMEM;
		goto free_tm;
	}

	entry_work->pipeline = pipeline;
	entry_work->entry = entry;
	entry->entry_work = entry_work;

	INIT_WORK(&entry_work->work, tcf_table_entry_del_act_work);

	if (rhltable_insert(&table->tbl_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		ret = -EEXIST;
		goto free_entry_work;
	}

	entry_old->entry_work->defer_deletion = true;
	if (tcf_table_entry_destroy(table, entry_old, true) < 0) {
		ret = -EBUSY;
		goto out;
	}

	return 0;

free_entry_work:
	kfree(entry_work);

free_tm:
	kfree(tm);

rm_masks_idr:
	tcf_table_entry_mask_del(table, entry);

out:
	return ret;
}

#define P4TC_DEFAULT_TENTRY_PERMISSIONS                           \
	(P4TC_CTRL_PERM_R | P4TC_CTRL_PERM_U | P4TC_CTRL_PERM_D | \
	 P4TC_DATA_PERM_R | P4TC_DATA_PERM_X)

static bool tcf_table_check_entry_acts(struct p4tc_table *table,
				       struct tc_action *entry_acts[],
				       struct list_head *allowed_acts,
				       int num_entry_acts)
{
	struct p4tc_table_act *table_act;
	int i;

	for (i = 0; i < num_entry_acts; i++) {
		const struct tc_action *entry_act = entry_acts[i];

		list_for_each_entry(table_act, allowed_acts, node) {
			if (table_act->ops->id == entry_act->ops->id &&
			    !(table_act->flags & BIT(P4TC_TABLE_ACTS_DEFAULT_ONLY)))
				return true;
		}
	}

	return false;
}

static int __tcf_table_entry_cu(struct net *net, u32 flags, struct nlattr **tb,
				struct p4tc_table_entry *entry_cpy,
				struct p4tc_pipeline *pipeline,
				struct p4tc_table *table,
				struct netlink_ext_ack *extack)
{
	u8 mask_value[KEY_MASK_ID_SZ + BITS_TO_BYTES(P4TC_MAX_KEYSZ)] = { 0 };
	struct p4tc_table_entry_mask mask = { 0 };
	u8 whodunnit = P4TC_ENTITY_UNSPEC;
	int ret = 0;
	struct p4tc_table_entry *entry;
	u32 keysz_bytes;
	u32 prio;

	prio = tb[P4TC_ENTRY_PRIO] ? *((u32 *)nla_data(tb[P4TC_ENTRY_PRIO])) : 0;
	if (flags & NLM_F_REPLACE) {
		if (!prio) {
			NL_SET_ERR_MSG(extack, "Must specify entry priority");
			return -EINVAL;
		}
	} else {
		if (!prio) {
			prio = 1;
			spin_lock(&table->tbl_prio_idr_lock);
			ret = idr_alloc_u32(&table->tbl_prio_idr,
					    ERR_PTR(-EBUSY), &prio, UINT_MAX,
					    GFP_ATOMIC);
			spin_unlock(&table->tbl_prio_idr_lock);
			if (ret < 0) {
				NL_SET_ERR_MSG(extack,
					       "Unable to allocate priority");
				return ret;
			}
		} else {
			rcu_read_lock();
			if (idr_find(&table->tbl_prio_idr, prio)) {
				rcu_read_unlock();
				NL_SET_ERR_MSG(extack,
					       "Priority already in use");
				return -EBUSY;
			}
			rcu_read_unlock();
		}

		if (refcount_read(&table->tbl_entries_ref) > table->tbl_max_entries) {
			NL_SET_ERR_MSG(extack,
				       "Table instance max entries reached");
			return -EINVAL;
		}
	}
	if (tb[P4TC_ENTRY_WHODUNNIT]) {
		whodunnit = *((u8 *)nla_data(tb[P4TC_ENTRY_WHODUNNIT]));
	} else {
		NL_SET_ERR_MSG(extack, "Must specify whodunnit attribute");
		ret = -EINVAL;
		goto idr_rm;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		NL_SET_ERR_MSG(extack, "Unable to allocate table entry");
		ret = -ENOMEM;
		goto idr_rm;
	}
	entry->prio = prio;

	entry->key.keysz = table->tbl_keysz + KEY_MASK_ID_SZ_BITS;
	keysz_bytes = entry->key.keysz / BITS_PER_BYTE;

	mask.sz = entry->key.keysz;
	mask.value = mask_value;

	entry->key.value = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!entry->key.value) {
		ret = -ENOMEM;
		goto free_entry;
	}

	entry->key.unmasked_key = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!entry->key.unmasked_key) {
		ret = -ENOMEM;
		goto free_key_value;
	}

	ret = tcf_table_entry_extract_key(tb, &entry->key, &mask, extack);
	if (ret < 0)
		goto free_key_unmasked;

	if (tb[P4TC_ENTRY_PERMISSIONS]) {
		const u16 tblperm =
			rcu_dereference(table->tbl_permissions)->permissions;
		u16 nlperm;

		nlperm = *((u16 *)nla_data(tb[P4TC_ENTRY_PERMISSIONS]));
		if (nlperm > P4TC_MAX_PERMISSION) {
			NL_SET_ERR_MSG(extack,
				       "Permission may only have 10 bits turned on");
			ret = -EINVAL;
			goto free_key_unmasked;
		}
		if (p4tc_ctrl_create_ok(nlperm) ||
		    p4tc_data_create_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Create permission for table entry doesn't make sense");
			ret = -EINVAL;
			goto free_key_unmasked;
		}
		if (!p4tc_data_read_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Data path read permission must be set");
			ret = -EINVAL;
			goto free_key_unmasked;
		}
		if (!p4tc_data_exec_ok(nlperm)) {
			NL_SET_ERR_MSG(extack,
				       "Data path execute permissions for entry must be set");
			ret = -EINVAL;
			goto free_key_unmasked;
		}

		if (~tblperm & nlperm) {
			NL_SET_ERR_MSG(extack,
				       "Trying to set permission bits which aren't allowed by table");
			ret = -EINVAL;
			goto free_key_unmasked;
		}
		entry->permissions = nlperm;
	} else {
		if (flags & NLM_F_REPLACE)
			entry->permissions = P4TC_PERMISSIONS_UNINIT;
		else
			entry->permissions = P4TC_DEFAULT_TENTRY_PERMISSIONS;
	}

	if (tb[P4TC_ENTRY_ACT]) {
		entry->acts = kcalloc(TCA_ACT_MAX_PRIO,
				      sizeof(struct tc_action *), GFP_KERNEL);
		if (!entry->acts) {
			ret = -ENOMEM;
			goto free_key_unmasked;
		}

		ret = p4tc_action_init(net, tb[P4TC_ENTRY_ACT], entry->acts,
				       table->common.p_id,
				       TCA_ACT_FLAGS_NO_RTNL, extack);
		if (ret < 0) {
			kfree(entry->acts);
			entry->acts = NULL;
			goto free_key_unmasked;
		}
		entry->num_acts = ret;

		if (!tcf_table_check_entry_acts(table, entry->acts,
						&table->tbl_acts_list, ret)) {
			ret = -EPERM;
			NL_SET_ERR_MSG(extack,
				       "Action is not allowed as entry action");
			goto free_acts;
		}
	}

	rcu_read_lock();
	if (flags & NLM_F_REPLACE)
		ret = __tcf_table_entry_update(pipeline, table, entry, &mask,
					       whodunnit, true);
	else
		ret = __tcf_table_entry_create(pipeline, table, entry, &mask,
					       whodunnit, true);
	if (ret < 0) {
		rcu_read_unlock();
		goto free_acts;
	}

	memcpy(entry_cpy, entry, sizeof(*entry));

	rcu_read_unlock();

	return 0;

free_acts:
	p4tc_action_destroy(entry->acts);

free_key_unmasked:
	kfree(entry->key.unmasked_key);

free_key_value:
	kfree(entry->key.value);

free_entry:
	kfree(entry);

idr_rm:
	if (!(flags & NLM_F_REPLACE)) {
		spin_lock(&table->tbl_prio_idr_lock);
		idr_remove(&table->tbl_prio_idr, prio);
		spin_unlock(&table->tbl_prio_idr_lock);
	}

	return ret;
}

static int tcf_table_entry_cu(struct sk_buff *skb, struct net *net, u32 flags,
			      struct nlattr *arg, u32 *ids,
			      struct p4tc_nl_pname *nl_pname,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry entry = { 0 };
	struct p4tc_pipeline *pipeline;
	struct p4tc_table *table;
	int ret;

	ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg, p4tc_entry_policy,
			       extack);
	if (ret < 0)
		return ret;

	rcu_read_lock();
	ret = tcf_table_entry_get_table(net, &pipeline, &table, tb, ids,
					nl_pname->data, extack);
	rcu_read_unlock();
	if (ret < 0)
		return ret;

	if (!pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Need to seal pipeline before issuing runtime command");
		ret = -EINVAL;
		goto table_put;
	}

	ret = __tcf_table_entry_cu(net, flags, tb, &entry, pipeline, table,
				   extack);
	if (ret < 0)
		goto table_put;

	if (p4tca_table_get_entry_fill(skb, table, &entry, table->tbl_id) <= 0)
		NL_SET_ERR_MSG(extack, "Unable to fill table entry attributes");

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

table_put:
	tcf_table_entry_put_table(pipeline, table);
	return ret;
}

int tcf_table_const_entry_cu(struct net *net, struct nlattr *arg,
			     struct p4tc_table_entry *entry,
			     struct p4tc_pipeline *pipeline,
			     struct p4tc_table *table,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	int ret;

	ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg, p4tc_entry_policy,
			       extack);
	if (ret < 0)
		return ret;

	return __tcf_table_entry_cu(net, 0, tb, entry, pipeline, table, extack);
}

static int tc_ctl_p4_get_1(struct net *net, struct sk_buff *skb,
			   struct nlmsghdr *n, u32 *ids, struct nlattr *arg,
			   struct p4tc_nl_pname *nl_pname,
			   struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *arg_ids;

	ret = nla_parse_nested(tb, P4TC_MAX, arg, NULL, extack);
	if (ret < 0)
		return ret;

	if (!tb[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if (nla_len(tb[P4TC_PATH]) > (P4TC_PATH_MAX - 1) * sizeof(u32)) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	return tcf_table_entry_gd(net, skb, n, tb[P4TC_PARAMS], ids, nl_pname,
				  extack);
}

static int tc_ctl_p4_delete_1(struct net *net, struct sk_buff *skb,
			      struct nlmsghdr *n, struct nlattr *arg, u32 *ids,
			      struct p4tc_nl_pname *nl_pname,
			      struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *arg_ids;

	ret = nla_parse_nested(tb, P4TC_MAX, arg, NULL, extack);
	if (ret < 0)
		return ret;

	if (!tb[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if ((nla_len(tb[P4TC_PATH])) > (P4TC_PATH_MAX - 1) * sizeof(u32)) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));
	if (n->nlmsg_flags & NLM_F_ROOT)
		ret = tcf_table_entry_flush(net, skb, n, tb[P4TC_PARAMS], ids,
					    nl_pname, extack);
	else
		ret = tcf_table_entry_gd(net, skb, n, tb[P4TC_PARAMS], ids,
					 nl_pname, extack);

	return ret;
}

static int tc_ctl_p4_cu_1(struct net *net, struct sk_buff *skb,
			  struct nlmsghdr *n, u32 *ids, struct nlattr *nla,
			  struct p4tc_nl_pname *nl_pname,
			  struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *p4tca[P4TC_MAX + 1];
	u32 *arg_ids;

	ret = nla_parse_nested(p4tca, P4TC_MAX, nla, NULL, extack);
	if (ret < 0)
		return ret;

	if (!p4tca[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if (nla_len(p4tca[P4TC_PATH]) > (P4TC_PATH_MAX - 1) * sizeof(u32)) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	if (!p4tca[P4TC_PARAMS]) {
		NL_SET_ERR_MSG(extack, "Must specify object attributes");
		return -EINVAL;
	}

	arg_ids = nla_data(p4tca[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(p4tca[P4TC_PATH]));

	return tcf_table_entry_cu(skb, net, n->nlmsg_flags, p4tca[P4TC_PARAMS],
				  ids, nl_pname, extack);
}

static int tc_ctl_p4_table_n(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
			     char *p_name, struct nlattr *nla,
			     struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	u32 ids[P4TC_PATH_MAX] = { 0 };
	int ret = 0, ret_send;
	struct nlattr *p4tca[P4TC_MSGBATCH_SIZE + 1];
	struct p4tc_nl_pname nl_pname;
	struct sk_buff *new_skb;
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *pnatt;
	struct nlattr *root;
	int i;

	ret = nla_parse_nested(p4tca, P4TC_MSGBATCH_SIZE, nla, NULL, extack);
	if (ret < 0)
		return ret;

	if (!p4tca[1]) {
		NL_SET_ERR_MSG(extack, "No elements in root table array");
		return -EINVAL;
	}

	new_skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!new_skb)
		return -ENOBUFS;

	nlh = nlmsg_put(new_skb, portid, n->nlmsg_seq, cmd, sizeof(*t),
			n->nlmsg_flags);
	if (!nlh)
		goto out;

	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;
	ids[P4TC_PID_IDX] = t_new->pipeid;

	pnatt = nla_reserve(new_skb, P4TC_ROOT_PNAME, PIPELINENAMSIZ);
	if (!pnatt) {
		ret = -ENOMEM;
		goto out;
	}

	nl_pname.data = nla_data(pnatt);
	if (!p_name) {
		/* Filled up by the operation or forced failure */
		memset(nl_pname.data, 0, PIPELINENAMSIZ);
		nl_pname.passed = false;
	} else {
		strscpy(nl_pname.data, p_name, PIPELINENAMSIZ);
		nl_pname.passed = true;
	}

	net = maybe_get_net(net);
	if (!net) {
		NL_SET_ERR_MSG(extack, "Net namespace is going down");
		ret = -EBUSY;
		goto out;
	}

	root = nla_nest_start(new_skb, P4TC_ROOT);
	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i]; i++) {
		struct nlattr *nest = nla_nest_start(new_skb, i);

		if (cmd == RTM_GETP4TBENT)
			ret = tc_ctl_p4_get_1(net, new_skb, nlh, ids, p4tca[i],
					      &nl_pname, extack);
		else if (cmd == RTM_CREATEP4TBENT)
			ret = tc_ctl_p4_cu_1(net, new_skb, nlh, ids, p4tca[i],
					     &nl_pname, extack);
		else if (cmd == RTM_DELP4TBENT)
			ret = tc_ctl_p4_delete_1(net, new_skb, nlh, p4tca[i],
						 ids, &nl_pname, extack);

		if (ret < 0) {
			if (i == 1) {
				goto put_net;
			} else {
				nla_nest_cancel(new_skb, nest);
				break;
			}
		}
		nla_nest_end(new_skb, nest);
	}
	nla_nest_end(new_skb, root);

	if (!t_new->pipeid)
		t_new->pipeid = ids[P4TC_PID_IDX];

	nlmsg_end(new_skb, nlh);

	if (cmd == RTM_GETP4TBENT)
		ret_send = rtnl_unicast(new_skb, net, portid);
	else
		ret_send = rtnetlink_send(new_skb, net, portid, RTNLGRP_TC,
					  n->nlmsg_flags & NLM_F_ECHO);

	put_net(net);

	return ret_send ? ret_send : ret;

put_net:
	put_net(net);

out:
	kfree_skb(new_skb);
	return ret;
}

static int tc_ctl_p4_root(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
			  struct netlink_ext_ack *extack)
{
	char *p_name = NULL;
	int ret = 0;
	struct nlattr *p4tca[P4TC_ROOT_MAX + 1];

	ret = nlmsg_parse(n, sizeof(struct p4tcmsg), p4tca, P4TC_ROOT_MAX,
			  p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (!p4tca[P4TC_ROOT]) {
		NL_SET_ERR_MSG(extack, "Netlink P4TC table attributes missing");
		return -EINVAL;
	}

	if (p4tca[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tca[P4TC_ROOT_PNAME]);

	return tc_ctl_p4_table_n(skb, n, cmd, p_name, p4tca[P4TC_ROOT], extack);
}

static int tc_ctl_p4_get(struct sk_buff *skb, struct nlmsghdr *n,
			 struct netlink_ext_ack *extack)
{
	return tc_ctl_p4_root(skb, n, RTM_GETP4TBENT, extack);
}

static int tc_ctl_p4_delete(struct sk_buff *skb, struct nlmsghdr *n,
			    struct netlink_ext_ack *extack)
{
	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	return tc_ctl_p4_root(skb, n, RTM_DELP4TBENT, extack);
}

static int tc_ctl_p4_cu(struct sk_buff *skb, struct nlmsghdr *n,
			struct netlink_ext_ack *extack)
{
	int ret;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = tc_ctl_p4_root(skb, n, RTM_CREATEP4TBENT, extack);

	return ret;
}

static int tcf_table_entry_dump(struct sk_buff *skb, struct nlattr *arg,
				u32 *ids, struct netlink_callback *cb,
				char **p_name, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_dump_ctx *ctx = (void *)cb->ctx;
	unsigned char *b = nlmsg_get_pos(skb);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_table_entry *entry = NULL;
	struct net *net = sock_net(skb->sk);
	int i = 0;
	struct p4tc_table *table;
	int ret;

	net = maybe_get_net(net);
	if (!net) {
		NL_SET_ERR_MSG(extack, "Net namespace is going down");
		return -EBUSY;
	}

	if (arg) {
		ret = nla_parse_nested(tb, P4TC_ENTRY_MAX, arg,
				       p4tc_entry_policy, extack);
		if (ret < 0) {
			kfree(ctx->iter);
			goto net_put;
		}
	}

	rcu_read_lock();
	ret = tcf_table_entry_get_table(net, &pipeline, &table, tb, ids,
					*p_name, extack);
	rcu_read_unlock();
	if (ret < 0) {
		kfree(ctx->iter);
		goto net_put;
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
			struct nlattr *count;

			if (!p4tc_ctrl_read_ok(entry->permissions)) {
				i--;
				continue;
			}

			count = nla_nest_start(skb, i + 1);
			if (!count) {
				rhashtable_walk_stop(ctx->iter);
				goto table_put;
			}
			ret = p4tca_table_get_entry_fill(skb, table, entry,
							 table->tbl_id);
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
	tcf_table_entry_put_table(pipeline, table);

net_put:
	put_net(net);

	return ret;
}

static int tc_ctl_p4_dump_1(struct sk_buff *skb, struct netlink_callback *cb,
			    struct nlattr *arg, char *p_name)
{
	struct netlink_ext_ack *extack = cb->extack;
	u32 portid = NETLINK_CB(cb->skb).portid;
	const struct nlmsghdr *n = cb->nlh;
	u32 ids[P4TC_PATH_MAX] = { 0 };
	struct nlattr *tb[P4TC_MAX + 1];
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *root;
	struct p4tcmsg *t;
	u32 *arg_ids;
	int ret;

	ret = nla_parse_nested(tb, P4TC_MAX, arg, p4tc_policy, extack);
	if (ret < 0)
		return ret;

	nlh = nlmsg_put(skb, portid, n->nlmsg_seq, RTM_GETP4TBENT, sizeof(*t),
			n->nlmsg_flags);
	if (!nlh)
		return -ENOSPC;

	t = (struct p4tcmsg *)nlmsg_data(n);
	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;

	if (!tb[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if ((nla_len(tb[P4TC_PATH])) > (P4TC_PATH_MAX - 1) * sizeof(u32)) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	ids[P4TC_PID_IDX] = t_new->pipeid;
	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBLID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	root = nla_nest_start(skb, P4TC_ROOT);
	ret = tcf_table_entry_dump(skb, tb[P4TC_PARAMS], ids, cb, &p_name,
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

static int tc_ctl_p4_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	char *p_name = NULL;
	int ret = 0;
	struct nlattr *p4tca[P4TC_ROOT_MAX + 1];

	ret = nlmsg_parse(cb->nlh, sizeof(struct p4tcmsg), p4tca, P4TC_ROOT_MAX,
			  p4tc_root_policy, cb->extack);
	if (ret < 0)
		return ret;

	if (!p4tca[P4TC_ROOT]) {
		NL_SET_ERR_MSG(cb->extack,
			       "Netlink P4TC table attributes missing");
		return -EINVAL;
	}

	if (p4tca[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tca[P4TC_ROOT_PNAME]);

	return tc_ctl_p4_dump_1(skb, cb, p4tca[P4TC_ROOT], p_name);
}

static int __init p4tc_tbl_init(void)
{
	rtnl_register(PF_UNSPEC, RTM_CREATEP4TBENT, tc_ctl_p4_cu, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	rtnl_register(PF_UNSPEC, RTM_DELP4TBENT, tc_ctl_p4_delete, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	rtnl_register(PF_UNSPEC, RTM_GETP4TBENT, tc_ctl_p4_get, tc_ctl_p4_dump,
		      RTNL_FLAG_DOIT_UNLOCKED);

	return 0;
}

subsys_initcall(p4tc_tbl_init);
