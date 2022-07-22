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
p4tc_entry_lookup(struct p4tc_table_instance *tinst,
		  struct p4tc_table_entry_key *key, u32 prio)
{
	struct p4tc_table_entry *entry;
	struct rhlist_head *tmp, *bucket_list;

	bucket_list = rhltable_lookup(&tinst->ti_entries, key,
				      entry_hlt_params);
	if (!bucket_list)
		return NULL;

	rhl_for_each_entry_rcu(entry, tmp, bucket_list, ht_node)
		if (entry->prio == prio)
			return entry;

	return NULL;
}

#define tcf_table_entry_mask_find_byid(tinst, id) \
	(idr_find(&(tinst)->ti_masks_idr, id))

static int p4tca_table_get_entry_keys(struct sk_buff *skb,
				      struct p4tc_table_instance *tinst,
				      struct p4tc_table_entry *entry)
{
	unsigned char *b = skb_tail_pointer(skb);
	int ret = -ENOMEM;
	struct p4tc_table_entry_mask *mask;
	u32 key_sz_bytes;

	key_sz_bytes = (entry->key.keysz - KEY_MASK_ID_SZ_BITS) / BITS_PER_BYTE;
	if (nla_put(skb, P4TC_ENTRY_KEY_BLOB, key_sz_bytes,
		    entry->key.unmasked_key + KEY_MASK_ID_SZ))
		goto out_nlmsg_trim;

	mask = tcf_table_entry_mask_find_byid(tinst, entry->mask_id);
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

static int p4tca_table_get_entry_fill(struct sk_buff *skb,
				      struct p4tc_table_instance *tinst,
				      struct p4tc_table_entry *entry,
				      u32 tbc_id)
{
	unsigned char *b = skb_tail_pointer(skb);
	int ret = -1;
	struct nlattr *nest, *nest_acts;
	struct p4tc_table_entry_tm dtm, *tm;
	u32 ids[P4TC_ENTRY_MAX_IDS];

	ids[P4TC_TBCID_IDX - 1] = tbc_id;
	ids[P4TC_TIID_IDX - 1] = tinst->ti_id;

	if (nla_put(skb, P4TC_PATH, P4TC_ENTRY_MAX_IDS * sizeof(u32), ids))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_u32(skb, P4TC_ENTRY_PRIO, entry->prio))
		goto out_nlmsg_trim;

	if (p4tca_table_get_entry_keys(skb, tinst, entry) < 0)
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
		if (nla_put_u8(skb, P4TC_ENTRY_UPDATE_WHODUNNIT, entry->who_updated))
			goto out_nlmsg_trim;
	}

	tm = rcu_dereference_protected(entry->tm, 1);
	p4tc_table_entry_tm_dump(&dtm, tm);
	if (nla_put_64bit(skb, P4TC_ENTRY_TM, sizeof(dtm), &dtm, P4TC_ENTRY_PAD))
		goto out_nlmsg_trim;

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static const struct nla_policy p4tc_entry_policy[P4TC_ENTRY_MAX + 1] = {
	[P4TC_ENTRY_TBCNAME] = { .type = NLA_STRING },
	[P4TC_ENTRY_TINAME] = { .type = NLA_STRING },
	[P4TC_ENTRY_KEY_BLOB] = { .type = NLA_BINARY },
	[P4TC_ENTRY_MASK_BLOB] = { .type = NLA_BINARY },
	[P4TC_ENTRY_PRIO] = { .type = NLA_U32 },
	[P4TC_ENTRY_ACT] = { .type = NLA_NESTED },
	[P4TC_ENTRY_TM] = { .len = sizeof(struct p4tc_table_entry_tm) },
	[P4TC_ENTRY_CREATE_WHODUNNIT] = { .type = NLA_U8 },
	[P4TC_ENTRY_UPDATE_WHODUNNIT] = { .type = NLA_U8 },
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
tcf_table_entry_mask_find_byvalue(struct p4tc_table_instance *tinst,
				  struct p4tc_table_entry_mask *mask)
{
	struct p4tc_table_entry_mask *mask_cur;
	unsigned long mask_id, tmp;

	idr_for_each_entry_ul(&tinst->ti_masks_idr, mask_cur, tmp, mask_id) {
		if (mask_cur->sz == mask->sz) {
			const u32 mask_sz_bytes = mask->sz / BITS_PER_BYTE;

			if (memcmp(mask_cur->value, mask->value, mask_sz_bytes) == 0)
				return mask_cur;
		}
	}

	return NULL;
}

/* Invoked under rcu_read_lock */
static void tcf_table_entry_mask_del(struct p4tc_table_instance *tinst,
				     struct p4tc_table_entry *entry)
{
	const u32 mask_id = entry->mask_id;
	struct p4tc_table_entry_mask *mask_found;

	/* Will always be found*/
	mask_found = tcf_table_entry_mask_find_byid(tinst, mask_id);

	/* Last reference, can delete*/
	if (refcount_dec_if_one(&mask_found->mask_ref)) {
		spin_lock_bh(&tinst->ti_masks_idr_lock);
		idr_remove(&tinst->ti_masks_idr, mask_found->mask_id);
		spin_unlock_bh(&tinst->ti_masks_idr_lock);
		call_rcu(&mask_found->rcu,
			 tcf_table_entry_mask_destroy);
	} else {
		if (!refcount_dec_not_one(&mask_found->mask_ref))
			pr_warn("Mask was deleted in parallel");
	}
}

/* TODO: Ordering optimisation for LPM */
static int tcf_table_entry_mask_add(struct p4tc_table_instance *tinst,
				    struct p4tc_table_entry *entry,
				    struct p4tc_table_entry_mask *mask,
				    gfp_t alloc_flag)
{
	struct p4tc_table_entry_mask *mask_found;
	int ret;

	mask_found = tcf_table_entry_mask_find_byvalue(tinst, mask);
	/* Only add mask if it was not already added */
	if (!mask_found) {
		mask->mask_id = 1;

		spin_lock_bh(&tinst->ti_masks_idr_lock);
		ret = idr_alloc_u32(&tinst->ti_masks_idr, mask, &mask->mask_id,
				    UINT_MAX, alloc_flag);
		spin_unlock_bh(&tinst->ti_masks_idr_lock);
		if (ret < 0)
			return ret;
		entry->mask_id = mask->mask_id;
	} else {
		if (!refcount_inc_not_zero(&mask_found->mask_ref))
			return -EBUSY;
		entry->mask_id = mask_found->mask_id;
		return -EEXIST;
	}

	return 0;
}

static void tcf_table_entry_put(struct rcu_head *rcu)
{
	struct p4tc_table_entry *entry;
	struct p4tc_table_entry_tm *tm;

	entry = container_of(rcu, struct p4tc_table_entry, rcu);
	if (entry->acts) {
		tcf_action_destroy(entry->acts, TCA_ACT_UNBIND);
		kfree(entry->acts);
	}

	tm = rcu_dereference_protected(entry->tm, 1);
	kfree(tm);

	kfree(entry->key.unmasked_key);
	kfree(entry->key.value);
	kfree(entry);
}

static int tcf_table_entry_destroy(struct p4tc_table_instance *tinst,
				   struct p4tc_table_entry *entry)
{
	/* Entry was deleted in parallel */
	if (!refcount_dec_if_one(&entry->entries_ref))
		return -EBUSY;
	rhltable_remove(&tinst->ti_entries, &entry->ht_node,
			entry_hlt_params);
	tcf_table_entry_mask_del(tinst, entry);
	call_rcu(&entry->rcu, tcf_table_entry_put);

	return 0;
}

/* Only deletes entries when called from pipeline delete, which means
 * pipeline->p_ref will already be 0, so no need to use that refcount.
 */
void tcf_table_entry_destroy_hash(void *ptr, void *arg)
{
	struct p4tc_table_instance *tinst = arg;
	struct p4tc_table_entry *entry = ptr;

	WARN_ON(refcount_dec_not_one(&tinst->ti_entries_ref));

	tcf_table_entry_destroy(tinst, entry);
}

static void tcf_table_entry_put_tinst(struct p4tc_pipeline *pipeline,
				      struct p4tc_table_class *tclass,
				      struct p4tc_table_instance *tinst)
{
	/* If we are here, it means that this was just incremented, so it should be > 1 */
	WARN_ON(!refcount_dec_not_one(&tinst->ti_ctrl_ref));
	WARN_ON(!refcount_dec_not_one(&tclass->tbc_ctrl_ref));
	WARN_ON(!refcount_dec_not_one(&pipeline->p_ctrl_ref));
}

static int tcf_table_entry_get_tinst(struct p4tc_pipeline **pipeline,
				     struct p4tc_table_class **tclass,
				     struct p4tc_table_instance **tinst,
				     struct nlattr **tb, u32 *ids,
				     char *p_name,
				     struct netlink_ext_ack *extack)
{
	u32 pipeid, tbc_id, ti_id;
	int ret;

	pipeid = ids[P4TC_PID_IDX];

	*pipeline = pipeline_find(p_name, pipeid, extack);
	if (IS_ERR(*pipeline)) {
		ret = PTR_ERR(*pipeline);
		goto out;
	}

	if (!refcount_inc_not_zero(&((*pipeline)->p_ctrl_ref))) {
		NL_SET_ERR_MSG(extack, "Pipeline is stale");
		ret = -EBUSY;
		goto out;
	}

	if (!pipeline_sealed(*pipeline)) {
		NL_SET_ERR_MSG(extack,
			       "Unsealed pipelines can't have table entries");
		ret = -EINVAL;
		goto dec_pipeline_refcount;
	}

	tbc_id = ids[P4TC_TBCID_IDX];
	ti_id = ids[P4TC_TIID_IDX];

	*tclass = tclass_find(*pipeline, tb[P4TC_ENTRY_TBCNAME], tbc_id,
			      extack);
	if (IS_ERR(*tclass)) {
		ret = PTR_ERR(*tclass);
		goto dec_pipeline_refcount;
	}
	if (!refcount_inc_not_zero(&((*tclass)->tbc_ctrl_ref))) {
		NL_SET_ERR_MSG(extack, "Table class is marked for deletion");
		ret = -EBUSY;
		goto dec_pipeline_refcount;
	}

	*tinst = tinst_find(tb[P4TC_ENTRY_TINAME], ti_id, *pipeline, *tclass,
			    extack);
	if (IS_ERR(*tinst)) {
		ret = PTR_ERR(*tinst);
		goto dec_tclass_refcount;
	}
	if (!refcount_inc_not_zero(&((*tinst)->ti_ctrl_ref))) {
		NL_SET_ERR_MSG(extack, "Table instance is marked for deletion");
		ret = -EBUSY;
		goto dec_tinst_refcount;
	}

	ret = 0;
	goto out;

/* If we are here, it means that this was just incremented, so it should be > 1 */
dec_tinst_refcount:
	WARN_ON(!refcount_dec_not_one(&((*tinst)->ti_ctrl_ref)));

dec_tclass_refcount:
	WARN_ON(!refcount_dec_not_one(&((*tclass)->tbc_ctrl_ref)));

dec_pipeline_refcount:
	WARN_ON(!refcount_dec_not_one(&((*pipeline)->p_ctrl_ref)));

out:
	return ret;
}

static void tcf_table_entry_assign_key(struct p4tc_table_entry_key *key,
				       struct p4tc_table_entry_mask *mask,
				       u8 *keyblob, u8 *maskblob, u32 keysz)
{
	memcpy(key->unmasked_key, &mask->mask_id, KEY_MASK_ID_SZ);
	memcpy(key->unmasked_key + KEY_MASK_ID_SZ, keyblob, keysz);

	memcpy(mask->value, &mask->mask_id, KEY_MASK_ID_SZ);
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
			       "Key blob size and table class key size differ");
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
	int i;

	for (i = 0; i < (key->keysz >> 3); i++)
		key->value[i] = key->unmasked_key[i] & mask->value[i];
}

/* Must be called with RCU read lock */
static int ___tcf_table_entry_del(struct p4tc_pipeline *pipeline,
				  struct p4tc_table_instance *tinst,
				  struct p4tc_table_entry *entry,
				  struct netlink_ext_ack *extack)
{
	int ret = 0;

	if (!refcount_dec_not_one(&pipeline->p_ref)) {
		NL_SET_ERR_MSG(extack, "Pipeline is stale");
		ret = -EBUSY;
		goto out;
	}

	if (!refcount_dec_not_one(&tinst->ti_entries_ref)) {
		NL_SET_ERR_MSG(extack, "Table entry is stale");
		ret = -EBUSY;
		goto inc_p_ref;
	}

	if (tcf_table_entry_destroy(tinst, entry) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Unable to destroy referenced entry");
		goto inc_entries_ref;
	}

	goto out;

inc_entries_ref:
	WARN_ON(!refcount_dec_not_one(&tinst->ti_entries_ref));

inc_p_ref:
	WARN_ON(refcount_inc_not_zero(&pipeline->p_ref));

out:
	return ret;
}

/* Internal function which will be called by the data path */
static int __tcf_table_entry_del(struct p4tc_pipeline *pipeline,
				 struct p4tc_table_instance *tinst,
				 struct p4tc_table_entry_key *key,
				 struct p4tc_table_entry_mask *mask,
				 u32 prio,
				 struct netlink_ext_ack *extack)
{
	struct p4tc_table_entry *entry;
	int ret;

	tcf_table_entry_build_key(key, mask);

	rcu_read_lock();
	entry = p4tc_entry_lookup(tinst, key, prio);
	if (!entry) {
		rcu_read_unlock();
		NL_SET_ERR_MSG(extack, "Unable to find entry");
		return -EINVAL;
	}

	ret = ___tcf_table_entry_del(pipeline, tinst, entry, extack);
	rcu_read_unlock();

	return ret;
}

static int tcf_table_entry_gd(struct sk_buff *skb, struct nlmsghdr *n,
			      struct nlattr *arg, u32 *ids, char **p_name,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	struct p4tc_table_entry *entry = NULL;
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_table_instance *tinst = NULL;
	struct p4tc_table_entry_mask *mask;
	struct p4tc_table_entry_key *key;
	struct p4tc_table_class *tclass;
	u32 keysz_bytes;
	u32 prio;
	int ret;

	if (arg) {
		ret = nla_parse_nested_deprecated(tb, P4TC_ENTRY_MAX, arg,
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
	ret = tcf_table_entry_get_tinst(&pipeline, &tclass, &tinst, tb, ids,
					*p_name, extack);
	rcu_read_unlock();
	if (ret < 0)
		return ret;

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		NL_SET_ERR_MSG(extack, "Unable to allocate key");
		ret = -ENOMEM;
		goto tinst_put;
	}
	key->keysz = tclass->tbc_keysz + KEY_MASK_ID_SZ_BITS;
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
		goto free_mask;
	}
	mask->sz = key->keysz;

	key->value = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!key->value) {
		ret = -ENOMEM;
		goto free_mask_value;
	}

	key->unmasked_key = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!key->unmasked_key) {
		ret = -ENOMEM;
		goto free_key_value;
	}

	ret = tcf_table_entry_extract_key(tb, key, mask, extack);
	if (ret < 0)
		goto free_key_unmasked;

	tcf_table_entry_build_key(key, mask);

	rcu_read_lock();
	entry = p4tc_entry_lookup(tinst, key, prio);
	if (!entry) {
		NL_SET_ERR_MSG(extack, "Unable to find entry");
		ret = -EINVAL;
		goto unlock;
	}

	if (p4tca_table_get_entry_fill(skb, tinst, entry, tclass->tbc_id) <= 0) {
		NL_SET_ERR_MSG(extack, "Unable to fill table entry attributes");
		ret = -EINVAL;
		goto unlock;
	}

	if (n->nlmsg_type == RTM_DELP4TBENT) {
		ret = ___tcf_table_entry_del(pipeline, tinst, entry,
					     extack);
		if (ret < 0)
			goto unlock;
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!*p_name)
		*p_name = pipeline->common.name;

	ret = 0;

	goto unlock;

unlock:
	rcu_read_unlock();

free_key_unmasked:
	kfree(key->unmasked_key);

free_key_value:
	kfree(key->value);

free_mask_value:
	kfree(mask->value);

free_mask:
	kfree(mask);

free_key:
	kfree(key);

tinst_put:
	tcf_table_entry_put_tinst(pipeline, tclass, tinst);

	return ret;
}

static int tcf_table_entry_flush(struct sk_buff *skb, struct nlmsghdr *n,
				 struct nlattr *arg, u32 *ids, char **p_name,
				 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = { NULL };
	unsigned char *b = skb_tail_pointer(skb);
	int ret = 0;
	int i = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
	struct p4tc_table_instance *tinst;
	struct p4tc_table_class *tclass;
	u32 arg_ids[P4TC_PATH_MAX - 1];
	struct rhashtable_iter iter;

	if (arg) {
		ret = nla_parse_nested_deprecated(tb, P4TC_ENTRY_MAX, arg,
						  p4tc_entry_policy, extack);
		if (ret < 0)
			return ret;
	}

	rcu_read_lock();
	ret = tcf_table_entry_get_tinst(&pipeline, &tclass, &tinst, tb, ids,
					*p_name, extack);
	if (ret < 0) {
		rcu_read_unlock();
		return ret;
	}

	if (!ids[P4TC_TBCID_IDX])
		arg_ids[P4TC_TBCID_IDX - 1] = tclass->tbc_id;
	if (!ids[P4TC_TIID_IDX])
		arg_ids[P4TC_TIID_IDX - 1] = tinst->ti_id;

	if (nla_put(skb, P4TC_PATH, sizeof(arg_ids), arg_ids)) {
		rcu_read_unlock();
		ret = -ENOMEM;
		goto out_nlmsg_trim;
	}

	rhltable_walk_enter(&tinst->ti_entries, &iter);
	do {
		rhashtable_walk_start(&iter);

		while ((entry = rhashtable_walk_next(&iter)) && !IS_ERR(entry)) {
			if (!refcount_dec_not_one(&pipeline->p_ref)) {
				NL_SET_ERR_MSG(extack, "Pipeline is stale");
				ret = -EBUSY;
				rhashtable_walk_stop(&iter);
				goto walk_exit;
			}

			if (!refcount_dec_not_one(&tinst->ti_entries_ref)) {
				NL_SET_ERR_MSG(extack, "Table entry is stale");
				ret = -EBUSY;
				rhashtable_walk_stop(&iter);
				goto walk_exit;
			}

			if (tcf_table_entry_destroy(tinst, entry) < 0) {
				ret = -EBUSY;
				continue;
			}
			i++;
		}

		rhashtable_walk_stop(&iter);
	} while (entry == ERR_PTR(-EAGAIN));

walk_exit:
	rhashtable_walk_exit(&iter);
	rcu_read_unlock();

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
	if (!*p_name)
		*p_name = pipeline->common.name;

	ret = 0;
	goto tinst_put;

out_nlmsg_trim:
	nlmsg_trim(skb, b);

/* If we are here, it means that this was just incremented, so it should be > 1 */
tinst_put:
	tcf_table_entry_put_tinst(pipeline, tclass, tinst);

	return ret;
}

/* Invoked from both control and data path */
static int __tcf_table_entry_create(struct p4tc_pipeline *pipeline,
				    struct p4tc_table_instance *tinst,
				    struct p4tc_table_entry *entry,
				    struct p4tc_table_entry_mask *mask,
				    u16 whodunnit,
				    gfp_t alloc_flag)
{
	struct p4tc_table_entry_tm *dtm;
	int ret;

	refcount_set(&entry->entries_ref, 1);

	tcf_table_entry_build_key(&entry->key, mask);

	rcu_read_lock();
	ret = tcf_table_entry_mask_add(tinst, entry, mask, alloc_flag);
	if (ret < 0) {
		if (ret != -EEXIST)
			goto unlock;
		__tcf_table_entry_mask_destroy(mask);
	}

	if (!refcount_inc_not_zero(&pipeline->p_ref))  {
		ret = -EBUSY;
		goto rm_masks_idr;
	}

	if (!refcount_inc_not_zero(&tinst->ti_entries_ref))  {
		ret = -EBUSY;
		goto dec_p_ref;
	}

	if (p4tc_entry_lookup(tinst, &entry->key, entry->prio)) {
		ret = -EEXIST;
		goto dec_entries_ref;
	}

	dtm = kzalloc(sizeof(*dtm), alloc_flag);
	if (!dtm) {
		ret = -ENOMEM;
		goto dec_entries_ref;
	}

	entry->who_created = whodunnit;

	dtm->created = jiffies;
	dtm->firstused = 0;
	dtm->lastused = jiffies;
	rcu_assign_pointer(entry->tm, dtm);

	if (rhltable_insert(&tinst->ti_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		ret = -EBUSY;
		goto free_tm;
	}

	rcu_read_unlock();

	return 0;

free_tm:
	kfree(dtm);
/*If we are here, it means that this was just incremented, so it should be > 1 */
dec_entries_ref:
	WARN_ON(!refcount_dec_not_one(&tinst->ti_entries_ref));

dec_p_ref:
	WARN_ON(!refcount_dec_not_one(&pipeline->p_ref));

rm_masks_idr:
	tcf_table_entry_mask_del(tinst, entry);

unlock:
	rcu_read_unlock();
	return ret;
}

/* Invoked from both control and data path  */
static int __tcf_table_entry_update(struct p4tc_pipeline *pipeline,
				    struct p4tc_table_instance *tinst,
				    struct p4tc_table_entry *entry,
				    struct p4tc_table_entry_mask *mask,
				    u16 whodunnit,
				    gfp_t alloc_flag)
{
	struct p4tc_table_entry *entry_old;
	struct p4tc_table_entry_tm *tm_old;
	struct p4tc_table_entry_tm *tm;
	int ret;

	refcount_set(&entry->entries_ref, 1);

	tcf_table_entry_build_key(&entry->key, mask);

	rcu_read_lock();
	ret = tcf_table_entry_mask_add(tinst, entry, mask, alloc_flag);
	if (ret < 0) {
		if (ret != -EEXIST)
			goto unlock;
		__tcf_table_entry_mask_destroy(mask);
	}

	entry_old = p4tc_entry_lookup(tinst, &entry->key, entry->prio);
	if (!entry_old) {
		ret = -ENOENT;
		goto rm_masks_idr;
	}

	if (refcount_read(&entry_old->entries_ref) > 1) {
		ret = -EBUSY;
		goto rm_masks_idr;
	}

	tm = kzalloc(sizeof(*tm), alloc_flag);
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

	rcu_assign_pointer(entry->tm, tm);

	if (rhltable_insert(&tinst->ti_entries, &entry->ht_node,
			    entry_hlt_params) < 0) {
		ret = -EEXIST;
		goto free_tm;
	}

	if (tcf_table_entry_destroy(tinst, entry_old) < 0) {
		kfree(tm);
		ret = -EBUSY;
		goto unlock;
	}

	rcu_read_unlock();

	return 0;

free_tm:
	kfree(tm);

rm_masks_idr:
	tcf_table_entry_mask_del(tinst, entry);

unlock:
	rcu_read_unlock();
	return ret;
}

static int tcf_table_entry_cu(struct sk_buff *skb, struct net *net,
			      u32 flags, struct nlattr *arg, u32 *ids,
			      char **p_name, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_ENTRY_MAX + 1] = {NULL};
	u8 whodunnit = P4TC_ENTITY_UNSPEC;
	int ret = 0;
	struct p4tc_table_entry *entry;
	struct p4tc_table_entry_mask *mask;
	struct p4tc_table_instance *tinst;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;
	u32 keysz_bytes;
	u32 prio;

	ret = nla_parse_nested_deprecated(tb, P4TC_ENTRY_MAX, arg,
					  p4tc_entry_policy, extack);
	if (ret < 0)
		return ret;

	rcu_read_lock();
	ret = tcf_table_entry_get_tinst(&pipeline, &tclass, &tinst, tb, ids,
					*p_name, extack);
	rcu_read_unlock();
	if (ret < 0)
		return ret;

	prio = tb[P4TC_ENTRY_PRIO] ? *((u32 *)nla_data(tb[P4TC_ENTRY_PRIO])) : 0;
	if (flags & NLM_F_REPLACE) {
		if (!prio) {
			NL_SET_ERR_MSG(extack, "Must specify entry priority");
			ret = -EINVAL;
			goto tinst_put;
		}

	} else {
		if (!prio)
			prio = TC_H_MAKE(0x80000000U, 0U);

		if (refcount_read(&tinst->ti_entries_ref) > tinst->ti_max_entries) {
			NL_SET_ERR_MSG(extack,
				       "Table instance max entries reached");
			ret = -EINVAL;
			goto tinst_put;
		}
	}
	if (tb[P4TC_ENTRY_WHODUNNIT])
		whodunnit = *((u8 *)nla_data(tb[P4TC_ENTRY_WHODUNNIT]));
	else
		NL_SET_ERR_MSG(extack, "Must specify whodunnit attribute");

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		NL_SET_ERR_MSG(extack, "Unable to allocate table entry");
		ret = -ENOMEM;
		goto tinst_put;
	}
	entry->prio = prio;

	entry->key.keysz = tclass->tbc_keysz + KEY_MASK_ID_SZ_BITS;
	keysz_bytes = entry->key.keysz / BITS_PER_BYTE;

	mask = kzalloc(sizeof(*mask), GFP_KERNEL);
	if (!mask) {
		NL_SET_ERR_MSG(extack, "Failed to allocate mask");
		ret = -ENOMEM;
		goto free_entry;
	}
	mask->value = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!mask->value) {
		NL_SET_ERR_MSG(extack, "Failed to allocate mask value");
		ret = -ENOMEM;
		kfree(mask);
		goto free_entry;
	}
	mask->sz = entry->key.keysz;

	refcount_set(&mask->mask_ref, 1);

	entry->key.value = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!entry->key.value) {
		ret = -ENOMEM;
		__tcf_table_entry_mask_destroy(mask);
		goto free_entry;
	}

	entry->key.unmasked_key = kzalloc(keysz_bytes, GFP_KERNEL);
	if (!entry->key.unmasked_key) {
		ret = -ENOMEM;
		__tcf_table_entry_mask_destroy(mask);
		goto free_key_value;
	}

	ret = tcf_table_entry_extract_key(tb, &entry->key, mask, extack);
	if (ret < 0) {
		__tcf_table_entry_mask_destroy(mask);
		goto free_key_unmasked;
	}

	if (tb[P4TC_ENTRY_ACT]) {
		entry->acts = kcalloc(TCA_ACT_MAX_PRIO,
				      sizeof(struct tc_action *),
				      GFP_KERNEL);
		if (!entry->acts) {
			ret = -ENOMEM;
			__tcf_table_entry_mask_destroy(mask);
			goto free_key_unmasked;
		}

		ret = p4tc_action_init(net, tb[P4TC_ENTRY_ACT], entry->acts,
				       TCA_ACT_FLAGS_NO_RTNL, extack);
		if (ret < 0) {
			kfree(entry->acts);
			entry->acts = NULL;
			__tcf_table_entry_mask_destroy(mask);
			goto free_key_unmasked;
		}
	}

	rcu_read_lock();
	if (flags & NLM_F_REPLACE)
		ret = __tcf_table_entry_update(pipeline, tinst, entry, mask,
					       whodunnit, GFP_ATOMIC);
	else
		ret = __tcf_table_entry_create(pipeline, tinst, entry, mask,
					       whodunnit, GFP_ATOMIC);
	if (ret < 0)
		goto free_acts;

	if (p4tca_table_get_entry_fill(skb, tinst, entry, tclass->tbc_id) <= 0)
		NL_SET_ERR_MSG(extack, "Unable to fill table entry attributes");

	rcu_read_unlock();

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!*p_name)
		*p_name = pipeline->common.name;

	ret = 0;
	goto tinst_put;

free_acts:
	rcu_read_unlock();
	if (entry->acts) {
		tcf_action_destroy(entry->acts, TCA_ACT_UNBIND);
		kfree(entry->acts);
	}

free_key_unmasked:
	kfree(entry->key.unmasked_key);

free_key_value:
	kfree(entry->key.value);

free_entry:
	kfree(entry);

tinst_put:
	tcf_table_entry_put_tinst(pipeline, tclass, tinst);

	return ret;
}

static int tc_ctl_p4_get_1(struct sk_buff *skb, struct nlmsghdr *n,
			   u32 *ids, struct nlattr *arg, char **p_name,
			   struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *arg_ids;

	ret = nla_parse_nested_deprecated(tb, P4TC_MAX, arg, NULL, extack);
	if (ret < 0)
		return ret;

	if (!tb[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if ((nla_len(tb[P4TC_PATH]) / sizeof(u32)) > P4TC_PATH_MAX - 1) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	arg_ids =  nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBCID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	return tcf_table_entry_gd(skb, n, tb[P4TC_PARAMS], ids, p_name, extack);
}

static int tc_ctl_p4_delete_1(struct sk_buff *skb, struct nlmsghdr *n,
			      struct nlattr *arg, u32 *ids, char **p_name,
			      struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *tb[P4TC_MAX + 1];
	u32 *arg_ids;

	ret = nla_parse_nested_deprecated(tb, P4TC_MAX, arg, NULL, extack);
	if (ret < 0)
		return ret;

	if (!tb[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if ((nla_len(tb[P4TC_PATH]) / sizeof(u32)) > P4TC_PATH_MAX - 1) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBCID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));
	if (n->nlmsg_flags & NLM_F_ROOT)
		ret = tcf_table_entry_flush(skb, n, tb[P4TC_PARAMS],
					    ids, p_name, extack);
	else
		ret = tcf_table_entry_gd(skb, n, tb[P4TC_PARAMS], ids, p_name,
					 extack);

	return ret;
}

static int tc_ctl_p4_cu_1(struct sk_buff *skb, struct net *net,
			  struct nlmsghdr *n, u32 *ids, struct nlattr *nla,
			  char **p_name, struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct nlattr *p4tca[P4TC_MAX + 1];
	u32 *arg_ids;

	ret = nla_parse_nested_deprecated(p4tca, P4TC_MAX, nla, NULL, extack);
	if (ret < 0)
		return ret;

	if (!p4tca[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if ((nla_len(p4tca[P4TC_PATH]) / sizeof(u32)) > P4TC_PATH_MAX - 1) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	if (!p4tca[P4TC_PARAMS]) {
		NL_SET_ERR_MSG(extack, "Must specify object attributes");
		return -EINVAL;
	}

	arg_ids = nla_data(p4tca[P4TC_PATH]);
	memcpy(&ids[P4TC_TBCID_IDX], arg_ids,
	       nla_len(p4tca[P4TC_PATH]));

	return tcf_table_entry_cu(skb, net, n->nlmsg_flags,
				  p4tca[P4TC_PARAMS], ids,
				  p_name, extack);
}

static int tc_ctl_p4_table_n(struct sk_buff *skb, struct nlmsghdr *n,
			     int cmd, char *p_name, struct nlattr *nla,
			     struct netlink_ext_ack *extack)
{
	struct p4tcmsg *t = (struct p4tcmsg *)nlmsg_data(n);
	struct net *net = sock_net(skb->sk);
	u32 portid = NETLINK_CB(skb).portid;
	u32 ids[P4TC_PATH_MAX] = {0};
	char *p_name_out = p_name;
	int ret = 0, ret_send;
	struct nlattr *p4tca[P4TC_MSGBATCH_SIZE + 1];
	struct sk_buff *new_skb;
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *root;
	unsigned char *b;
	int i;

	ret = nla_parse_nested_deprecated(p4tca, P4TC_MSGBATCH_SIZE, nla, NULL,
					  extack);
	if (ret < 0)
		return ret;

	if (!p4tca[1]) {
		NL_SET_ERR_MSG(extack, "No elements in root table array");
		return -EINVAL;
	}

	new_skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!new_skb)
		return -ENOBUFS;

	b = skb_tail_pointer(new_skb);

	nlh = nlmsg_put(new_skb, portid, n->nlmsg_seq, cmd, sizeof(*t),
			n->nlmsg_flags);
	if (!nlh)
		goto out;

	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;
	ids[P4TC_PID_IDX] = t_new->pipeid;

	root = nla_nest_start(new_skb, P4TC_ROOT);
	for (i = 1; i < P4TC_MSGBATCH_SIZE + 1 && p4tca[i]; i++) {
		struct nlattr *nest = nla_nest_start(new_skb, i);

		if (cmd == RTM_GETP4TBENT)
			ret = tc_ctl_p4_get_1(new_skb, nlh, ids, p4tca[i],
					      &p_name_out, extack);
		else if (cmd == RTM_CREATEP4TBENT)
			ret = tc_ctl_p4_cu_1(new_skb, net, nlh, ids, p4tca[i],
					     &p_name_out, extack);
		else if (cmd == RTM_DELP4TBENT)
			ret = tc_ctl_p4_delete_1(new_skb, nlh, p4tca[i], ids,
						 &p_name_out, extack);

		if (ret < 0) {
			if (i == 1) {
				goto out;
			} else {
				nla_nest_cancel(new_skb, nest);
				break;
			}
		}
		nla_nest_end(new_skb, nest);
	}
	nla_nest_end(new_skb, root);

	if (nla_put_string(new_skb, P4TC_ROOT_PNAME, p_name_out))
		ret = ret ? ret : -ENOMEM;

	if (!t_new->pipeid)
		t_new->pipeid = ids[P4TC_PID_IDX];

	nlh->nlmsg_len = skb_tail_pointer(new_skb) - b;

	if (cmd == RTM_GETP4TBENT)
		ret_send = rtnl_unicast(new_skb, net, portid);
	else
		ret_send = rtnetlink_send(new_skb, net, portid, RTNLGRP_TC,
					  n->nlmsg_flags & NLM_F_ECHO);

	return ret_send ? ret_send : ret;

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

	ret = nlmsg_parse_deprecated(n, sizeof(struct p4tcmsg), p4tca,
				     P4TC_ROOT_MAX, p4tc_root_policy, extack);
	if (ret < 0)
		return ret;

	if (!p4tca[P4TC_ROOT]) {
		NL_SET_ERR_MSG(extack,
			       "Netlink P4TC table attributes missing");
		return -EINVAL;
	}

	if (p4tca[P4TC_ROOT_PNAME])
		p_name = nla_data(p4tca[P4TC_ROOT_PNAME]);

	return tc_ctl_p4_table_n(skb, n, cmd, p_name, p4tca[P4TC_ROOT],
				 extack);
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
	struct p4tc_table_instance *tinst = NULL;
	struct p4tc_dump_ctx *ctx = (void *)cb->ctx;
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_table_entry *entry = NULL;
	int i = 0;
	struct p4tc_table_class *tclass;
	int ret;

	if (arg) {
		ret = nla_parse_nested_deprecated(tb, P4TC_ENTRY_MAX, arg,
						  p4tc_entry_policy, extack);
		if (ret < 0) {
			kfree(ctx->iter);
			return ret;
		}
	}

	rcu_read_lock();
	ret = tcf_table_entry_get_tinst(&pipeline, &tclass, &tinst, tb, ids,
					*p_name, extack);
	rcu_read_unlock();
	if (ret < 0) {
		kfree(ctx->iter);
		return ret;
	}

	rcu_read_lock();
	if (!ctx->iter) {
		ctx->iter = kzalloc(sizeof(*ctx->iter), GFP_ATOMIC);
		if (!ctx->iter) {
			ret = -ENOMEM;
			rcu_read_unlock();
			goto tinst_put;
		}

		rhltable_walk_enter(&tinst->ti_entries, ctx->iter);
	}

	ret = -ENOMEM;
	rhashtable_walk_start(ctx->iter);
	do {
		for (i = 0; i < P4TC_MSGBATCH_SIZE &&
		     (entry = rhashtable_walk_next(ctx->iter)) &&
		     !IS_ERR(entry); i++) {
			struct nlattr *count;

			count = nla_nest_start(skb, i + 1);
			if (!count)
				goto out_nlmsg_trim;
			if (p4tca_table_get_entry_fill(skb, tinst, entry,
						       tclass->tbc_id) <= 0) {
				NL_SET_ERR_MSG(extack,
					       "Failed to fill notification attributes for table entry");
				goto out_nlmsg_trim;
			}
			nla_nest_end(skb, count);
		}
	} while (entry == ERR_PTR(-EAGAIN));
	rhashtable_walk_stop(ctx->iter);

	if (!i) {
		rhashtable_walk_exit(ctx->iter);
		rcu_read_unlock();

		ret = 0;
		kfree(ctx->iter);

		goto tinst_put;
	}

	if (!*p_name)
		*p_name = pipeline->common.name;

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	rcu_read_unlock();

	ret = skb->len;

	goto tinst_put;

out_nlmsg_trim:
	rhashtable_walk_stop(ctx->iter);
	rhashtable_walk_exit(ctx->iter);
	rcu_read_unlock();
	nlmsg_trim(skb, b);

tinst_put:
	tcf_table_entry_put_tinst(pipeline, tclass, tinst);

	return ret;
}

static int tc_ctl_p4_dump_1(struct sk_buff *skb,
			    struct netlink_callback *cb,
			    struct nlattr *arg,
			    char *p_name)
{
	struct netlink_ext_ack *extack = cb->extack;
	unsigned char *b = skb_tail_pointer(skb);
	u32 portid = NETLINK_CB(cb->skb).portid;
	const struct nlmsghdr *n = cb->nlh;
	u32 ids[P4TC_PATH_MAX] = {0};
	struct nlattr *tb[P4TC_MAX + 1];
	struct p4tcmsg *t_new;
	struct nlmsghdr *nlh;
	struct nlattr *root;
	struct p4tcmsg *t;
	u32 *arg_ids;
	int ret;

	ret = nla_parse_nested_deprecated(tb, P4TC_MAX, arg, p4tc_policy,
					  extack);
	if (ret < 0)
		return ret;

	nlh = nlmsg_put(skb, portid, n->nlmsg_seq, RTM_GETP4TBENT, sizeof(*t),
			n->nlmsg_flags);
	if (!nlh)
		goto out;

	t = (struct p4tcmsg *)nlmsg_data(n);
	t_new = nlmsg_data(nlh);
	t_new->pipeid = t->pipeid;
	t_new->obj = t->obj;

	if (!tb[P4TC_PATH]) {
		NL_SET_ERR_MSG(extack, "Must specify object path");
		return -EINVAL;
	}

	if ((nla_len(tb[P4TC_PATH]) / sizeof(u32)) > P4TC_PATH_MAX - 1) {
		NL_SET_ERR_MSG(extack, "Path is too big");
		return -E2BIG;
	}

	ids[P4TC_PID_IDX] = t_new->pipeid;
	arg_ids = nla_data(tb[P4TC_PATH]);
	memcpy(&ids[P4TC_TBCID_IDX], arg_ids, nla_len(tb[P4TC_PATH]));

	root = nla_nest_start(skb, P4TC_ROOT);
	ret = tcf_table_entry_dump(skb, tb[P4TC_PARAMS], ids,
				   cb, &p_name, extack);
	if (ret <= 0)
		goto out;
	nla_nest_end(skb, root);

	if (p_name) {
		if (nla_put_string(skb, P4TC_ROOT_PNAME, p_name)) {
			ret = -1;
			goto out;
		}
	}

	nlh->nlmsg_len = skb_tail_pointer(skb) - b;

	if (!t_new->pipeid)
		t_new->pipeid = ids[P4TC_PID_IDX];

	return skb->len;

out:
	nlmsg_trim(skb, b);
	return ret;
}

static int tc_ctl_p4_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	char *p_name = NULL;
	int ret = 0;
	struct nlattr *p4tca[P4TC_ROOT_MAX + 1];

	ret = nlmsg_parse_deprecated(cb->nlh, sizeof(struct p4tcmsg), p4tca,
				     P4TC_ROOT_MAX, p4tc_root_policy,
				     cb->extack);
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
