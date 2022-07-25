// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_tclass.c	P4 TC TABLE CLASS
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

static const struct nla_policy p4tc_tclass_policy[P4TC_TCLASS_MAX + 1] = {
	[P4TC_TCLASS_NAME] = { .type = NLA_STRING, .len = TCLASSNAMSIZ },
	[P4TC_TCLASS_INFO] = { .type = NLA_BINARY,
			       .len = sizeof(struct p4tc_table_class_parm) },
	[P4TC_TCLASS_PREACTIONS] = { .type = NLA_NESTED },
	[P4TC_TCLASS_KEYS] = { .type = NLA_NESTED },
	[P4TC_TCLASS_POSTACTIONS] = { .type = NLA_NESTED },
};

static const struct nla_policy p4tc_tclass_key_policy[P4TC_MAXPARSE_KEYS + 1] = {
	[P4TC_KEY_ID] = { .type = NLA_U32 },
	[P4TC_KEY_ACT] = { .type = NLA_NESTED },
};

static int tcf_tclass_key_fill_nlmsg(struct sk_buff *skb,
				     struct p4tc_table_key *key,
				     int key_num)
{
	int ret = 0;
	struct nlattr *nest_keys = nla_nest_start(skb, key_num);
	struct nlattr *nest_action;

	if (nla_put_u32(skb, P4TC_KEY_ID, key->key_id))
		return -1;

	nest_action = nla_nest_start(skb, P4TC_KEY_ACT);
	ret = tcf_action_dump(skb, key->key_acts, 0, 0, false);
	if (ret < 0)
		return ret;
	nla_nest_end(skb, nest_action);

	nla_nest_end(skb, nest_keys);

	return ret;
}

static int _tcf_tclass_fill_nlmsg(struct sk_buff *skb,
				  struct p4tc_table_class *tclass)
{
	unsigned char *b = skb_tail_pointer(skb);
	int i = 1;
	unsigned long tbc_id, tmp;
	struct p4tc_table_class_parm parm;
	struct p4tc_table_key *key;
	struct nlattr *nest_key;
	struct nlattr *nest;
	struct nlattr *preacts;
	struct nlattr *postacts;
	int err;

	if (nla_put_u32(skb, P4TC_PATH, tclass->tbc_id))
		goto out_nlmsg_trim;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;

	if (nla_put_string(skb, P4TC_TCLASS_NAME, tclass->common.name))
		goto out_nlmsg_trim;

	parm.tbc_keysz = tclass->tbc_keysz;
	parm.tbc_count = tclass->tbc_count;
	parm.tbc_max_entries = tclass->tbc_max_entries;
	parm.tbc_max_masks = tclass->tbc_max_masks;
	parm.tbc_default_key = tclass->tbc_default_key;

	nest_key = nla_nest_start(skb, P4TC_TCLASS_KEYS);
	idr_for_each_entry_ul(&tclass->tbc_keys_idr, key, tmp, tbc_id) {
		err = tcf_tclass_key_fill_nlmsg(skb, key, i);
		if (err < 0)
			goto out_nlmsg_trim;

		i++;
	}
	nla_nest_end(skb, nest_key);

	if (tclass->tbc_preacts) {
		preacts = nla_nest_start(skb, P4TC_TCLASS_PREACTIONS);
		if (tcf_action_dump(skb, tclass->tbc_preacts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, preacts);
	}

	postacts = nla_nest_start(skb, P4TC_TCLASS_POSTACTIONS);
	if (tcf_action_dump(skb, tclass->tbc_postacts, 0, 0, false) < 0)
		goto out_nlmsg_trim;
	nla_nest_end(skb, postacts);

	if (nla_put(skb, P4TC_TCLASS_INFO, sizeof(parm), &parm))
		goto out_nlmsg_trim;
	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_tclass_fill_nlmsg(struct net *net, struct sk_buff *skb,
				 struct p4tc_template_common *template,
				 struct netlink_ext_ack *extack)
{
	struct p4tc_table_class *tclass = to_tclass(template);

	if (_tcf_tclass_fill_nlmsg(skb, tclass) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table class");
		return -EINVAL;
	}

	return 0;
}

static inline void tcf_tclass_key_put(struct p4tc_table_key *key)
{
	tcf_action_destroy(key->key_acts, TCA_ACT_UNBIND);
	kfree(key->key_acts);

	kfree(key);
}

static inline void tcf_tclass_key_put_many(struct p4tc_table_key **keys,
					   struct p4tc_table_class *tclass,
					   int *cu_res,
					   int total_keys)
{
	int i;

	for (i = 0; i < total_keys; i++) {
		if (cu_res[i] == P4TC_P_CREATED) {
			idr_remove(&tclass->tbc_keys_idr, keys[i]->key_id);
			tclass->tbc_keys_count--;
		}
		tcf_tclass_key_put(keys[i]);
	}
}

static inline void tcf_tclass_key_replace_many(struct p4tc_table_key **keys,
					       struct p4tc_table_class *tclass,
					       int *cu_res,
					       int total_keys)
{
	int i;

	for (i = 0; i < total_keys; i++) {
		struct p4tc_table_key *key;

		key = idr_replace(&tclass->tbc_keys_idr, keys[i],
				  keys[i]->key_id);
		if (cu_res[i] != P4TC_P_CREATED)
			tcf_tclass_key_put(key);
	}
}

static inline int _tcf_tclass_put(struct net *net,
				  struct p4tc_pipeline *pipeline,
				  struct p4tc_table_class *tclass,
				  struct netlink_ext_ack *extack)
{
	struct p4tc_table_instance *tinst;
	unsigned long tmp, tbc_id, ti_id;
	struct p4tc_table_key *key;

	if (!refcount_dec_if_one(&tclass->tbc_ref))
		return -EBUSY;

	idr_for_each_entry_ul(&tclass->tbc_keys_idr, key, tmp, tbc_id) {
		tcf_tclass_key_put(key);
		idr_remove(&tclass->tbc_keys_idr, tbc_id);
	}

	idr_for_each_entry_ul(&tclass->tbc_ti_idr, tinst, tmp, ti_id)
		tinst->common.ops->put(net, &tinst->common, extack);

	if (tclass->tbc_preacts) {
		tcf_action_destroy(tclass->tbc_preacts, TCA_ACT_UNBIND);
		kfree(tclass->tbc_preacts);
	}
	tcf_action_destroy(tclass->tbc_postacts, TCA_ACT_UNBIND);
	kfree(tclass->tbc_postacts);

	idr_destroy(&tclass->tbc_keys_idr);
	idr_destroy(&tclass->tbc_ti_idr);

	idr_remove(&pipeline->p_tbc_idr, tclass->tbc_id);
	pipeline->curr_table_classes -= 1;

	kfree(tclass);

	return 0;
}

static int tcf_tclass_put(struct net *net, struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = tcf_pipeline_find_byid(tmpl->p_id);
	struct p4tc_table_class *tclass = to_tclass(tmpl);
	int ret;

	ret = _tcf_tclass_put(net, pipeline, tclass, extack);
	if (ret < 0)
		NL_SET_ERR_MSG(extack, "Unable to delete referenced table class");

	return ret;
}

void *tcf_tclass_fetch(struct sk_buff *skb, void *tbc_value_ops)
{
	struct p4tc_table_class *tclass;

	tclass = container_of(tbc_value_ops, struct p4tc_table_class,
			      tbc_value_ops);

	return tclass;
}

struct p4tc_table_key *
tcf_table_key_find(struct p4tc_table_class *tclass, const u32 key_id)
{
	return idr_find(&tclass->tbc_keys_idr, key_id);
}

static inline struct p4tc_table_key *
tcf_table_key_add_1(struct net *net,
		    struct p4tc_table_class *tclass,
		    struct nlattr *nla,
		    struct nlattr **tb_args,
		    struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct p4tc_table_key *key;
	struct nlattr **tb;
	u32 *id;

	if (tclass->tbc_keys_count == P4TC_MAXPARSE_KEYS) {
		NL_SET_ERR_MSG(extack,
			       "Exceeded max keys limit for table class");
		ret = -EINVAL;
		goto out;
	}

	/* tb_args implies this call is being made during an update and not a
	 * create. It also means the key specified in the keyid here was not
	 * created in the original table class create; also note that even in
	 * this case the key/id may still be missing.
	 */
	if (tb_args) {
		tb = tb_args;
	} else {
		struct nlattr *tb_local[P4TC_TKEY_MAX + 1];

		ret = nla_parse_nested(tb_local, P4TC_TKEY_MAX, nla,
				       p4tc_tclass_key_policy, extack);
		if (ret < 0)
			goto out;

		tb = tb_local;
	}

	if (tb[P4TC_KEY_ID]) {
		id = nla_data(tb[P4TC_KEY_ID]);

		if (idr_find(&tclass->tbc_keys_idr, *id)) {
			NL_SET_ERR_MSG(extack, "Key id was already created");
			ret = -EEXIST;
			goto out;
		}
	}

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		NL_SET_ERR_MSG(extack, "Failed to allocate table class key");
		ret = -ENOMEM;
		goto out;
	}

	if (tb[P4TC_KEY_ID]) {
		key->key_id = *id;
		ret = idr_alloc_u32(&tclass->tbc_keys_idr, ERR_PTR(-EBUSY), id,
				    *id, GFP_KERNEL);
	} else {
		key->key_id = 1;
		ret = idr_alloc_u32(&tclass->tbc_keys_idr, ERR_PTR(-EBUSY),
				    &key->key_id, UINT_MAX, GFP_KERNEL);
	}
	if (ret < 0)
		goto free;

	if (tb[P4TC_KEY_ACT]) {
		key->key_acts = kcalloc(TCA_ACT_MAX_PRIO,
					sizeof(struct tc_action *),
					GFP_KERNEL);
		if (!key->key_acts) {
			ret = -ENOMEM;
			goto free;
		}

		ret = p4tc_action_init(net, tb[P4TC_KEY_ACT], key->key_acts,
				       extack);
		if (ret < 0) {
			kfree(key->key_acts);
			goto free;
		}
		key->key_num_acts = ret;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify table class key action");
		ret = -EINVAL;
		goto free;
	}

	tclass->tbc_keys_count++;

	return key;

free:
	idr_remove(&tclass->tbc_keys_idr, key->key_id);
	kfree(key);
out:
	return ERR_PTR(ret);
}

static inline struct p4tc_table_key *
tcf_table_key_update_1(struct net *net,
		       struct p4tc_table_class *tclass,
		       struct nlattr *nla,
		       int *cu_res,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_table_key *curr_key = NULL;
	int ret = 0;
	struct nlattr *tb_key[P4TC_TKEY_MAX + 1];
	struct p4tc_table_key *key;

	ret = nla_parse_nested(tb_key, P4TC_TKEY_MAX, nla,
			       p4tc_tclass_key_policy, extack);
	if (ret < 0)
		goto out;

	if (tb_key[P4TC_KEY_ID]) {
		const u32 *id = nla_data(tb_key[P4TC_KEY_ID]);

		curr_key = idr_find(&tclass->tbc_keys_idr, *id);
	}

	/* This means that this is a key creation */
	if (!curr_key) {
		*cu_res = P4TC_P_CREATED;
		return tcf_table_key_add_1(net, tclass, nla, tb_key, extack);
	}

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		goto out;
	}
	key->key_id = curr_key->key_id;

	if (tb_key[P4TC_KEY_ACT]) {
		key->key_acts = kcalloc(TCA_ACT_MAX_PRIO,
					sizeof(struct tc_action *),
					GFP_KERNEL);
		if (!key->key_acts) {
			ret = -ENOMEM;
			goto free;
		}

		ret = p4tc_action_init(net, tb_key[P4TC_KEY_ACT], key->key_acts,
				       extack);
		if (ret < 0) {
			kfree(key->key_acts);
			goto free;
		}
		key->key_num_acts = ret;
	}

	return key;

free:
	kfree(key);

out:
	return ERR_PTR(ret);
}

static int tcf_tclass_key_cu(struct net *net, struct nlattr *nla,
			     struct p4tc_table_class *tclass,
			     struct p4tc_table_key **keys,
			     int *cu_res, bool update,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[P4TC_MAXPARSE_KEYS + 1];
	struct p4tc_table_key *key;
	int ret;
	int i;

	ret = nla_parse_nested(tb, P4TC_MAXPARSE_KEYS, nla, NULL, extack);
	if (ret < 0)
		return ret;

	for (i = 1; i <= P4TC_MAXPARSE_KEYS && tb[i]; i++) {
		if (update) {
			key = tcf_table_key_update_1(net, tclass, tb[i],
						     &cu_res[i - 1], extack);
		} else {
			key = tcf_table_key_add_1(net, tclass, tb[i], NULL,
						  extack);
			cu_res[i - 1] = P4TC_P_CREATED;
		}
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto err;
		}

		keys[i - 1] = key;
	}

	return i - 1;

err:
	tcf_tclass_key_put_many(keys, tclass, cu_res, i - 1);
	return ret;
}

struct p4tc_table_class *tcf_tclass_find_byid(struct p4tc_pipeline *pipeline,
					      const u32 tbc_id)
{
	return idr_find(&pipeline->p_tbc_idr, tbc_id);
}

static struct p4tc_table_class *
tclass_find_name(struct nlattr *name_attr, struct p4tc_pipeline *pipeline)
{
	const char *tbcname = nla_data(name_attr);
	struct p4tc_table_class *tclass;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipeline->p_tbc_idr, tclass, tmp, id)
		if (strncmp(tclass->common.name, tbcname, TCLASSNAMSIZ) == 0)
			return tclass;

	return NULL;
}

#define SEPARATOR '/'
struct p4tc_table_class *
tcf_tclass_find_byany(struct p4tc_pipeline *pipeline, struct nlattr *name_attr,
	    const u32 tbc_id, struct netlink_ext_ack *extack)
{
	struct p4tc_table_class *tclass;
	int err;

	if (tbc_id) {
		tclass = tcf_tclass_find_byid(pipeline, tbc_id);
		if (!tclass) {
			NL_SET_ERR_MSG(extack,
				       "Unable to find table class by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (name_attr) {
			tclass = tclass_find_name(name_attr, pipeline);
			if (!tclass) {
				NL_SET_ERR_MSG(extack,
					       "Table class name not found");
				err = -EINVAL;
				goto out;
			}
		} else {
			NL_SET_ERR_MSG(extack,
				       "Must specify table class name or id");
			err = -EINVAL;
			goto out;
		}
	}

	return tclass;
out:
	return ERR_PTR(err);
}

static struct p4tc_table_class *
tcf_tclass_create(struct net *net, struct nlmsghdr *n,
		  struct nlattr *nla, u32 tbc_id,
		  struct p4tc_pipeline *pipeline,
		  struct netlink_ext_ack *extack)
{
	struct p4tc_table_key *keys[P4TC_MAXPARSE_KEYS] = {NULL};
	int cu_res[P4TC_MAXPARSE_KEYS] = {P4TC_P_UNSPEC};
	char *tbcname;
	int num_keys = 0;
	struct nlattr *tb[P4TC_TCLASS_MAX + 1];
	struct p4tc_table_class_parm *parm;
	struct p4tc_table_class *tclass;
	int ret;

	ret = nla_parse_nested(tb, P4TC_TCLASS_MAX, nla, p4tc_tclass_policy,
			       extack);
	if (ret < 0)
		goto out;

	if (pipeline->curr_table_classes == pipeline->num_table_classes) {
		NL_SET_ERR_MSG(extack,
			       "Table class range exceeded max allowed value");
		ret = -EINVAL;
		goto out;
	}

	if (!tb[P4TC_TCLASS_NAME]) {
		NL_SET_ERR_MSG(extack, "Must specify table class name");
		ret = -EINVAL;
		goto out;
	}

	tbcname = strnchr(nla_data(tb[P4TC_TCLASS_NAME]), TCLASSNAMSIZ,
			  SEPARATOR);
	if (!tbcname) {
		NL_SET_ERR_MSG(extack,
			       "Table class name must contain control block");
		ret = -EINVAL;
		goto out;
	}

	tbcname += 1;
	if (tbcname[0] == '\0') {
		NL_SET_ERR_MSG(extack, "Control block name is too big");
		ret = -EINVAL;
		goto out;
	}

	if (tclass_find_name(tb[P4TC_TCLASS_NAME], pipeline) ||
	    tcf_tclass_find_byid(pipeline, tbc_id)) {
		NL_SET_ERR_MSG(extack, "Table class already exists");
		ret = -EEXIST;
		goto out;
	}

	tclass = kmalloc(sizeof(*tclass), GFP_KERNEL);
	if (!tclass) {
		NL_SET_ERR_MSG(extack, "Unable to create table class");
		ret = -ENOMEM;
		goto out;
	}

	tclass->common.p_id = pipeline->common.p_id;
	strscpy(tclass->common.name, nla_data(tb[P4TC_TCLASS_NAME]), TCLASSNAMSIZ);

	if (tb[P4TC_TCLASS_INFO]) {
		parm = nla_data(tb[P4TC_TCLASS_INFO]);
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Missing table class info");
		goto free;
	}

	if (parm->tbc_flags & P4TC_TCLASS_FLAGS_KEYSZ) {
		if (!parm->tbc_keysz) {
			NL_SET_ERR_MSG(extack,
				       "Table class keysz cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbc_keysz > P4TC_MAX_KEYSZ) {
			NL_SET_ERR_MSG(extack,
				       "Table class keysz exceeds maximum keysz");
			ret = -EINVAL;
			goto free;
		}
		tclass->tbc_keysz = parm->tbc_keysz;
	} else {
		NL_SET_ERR_MSG(extack, "Must specify table class key size");
		ret = -EINVAL;
		goto free;
	}

	if (parm->tbc_flags & P4TC_TCLASS_FLAGS_COUNT) {
		if (!parm->tbc_count) {
			NL_SET_ERR_MSG(extack,
				       "Table class tbc_count cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbc_count > P4TC_MAX_TINSTS) {
			NL_SET_ERR_MSG(extack,
				       "Table class tbc_count exceeds maximum tbc_count");
			ret = -EINVAL;
			goto free;
		}
		tclass->tbc_count = parm->tbc_count;
	} else {
		tclass->tbc_count = P4TC_DEFAULT_TINST_COUNT;
	}

	if (parm->tbc_flags & P4TC_TCLASS_FLAGS_MAX_ENTRIES) {
		if (!parm->tbc_max_entries) {
			NL_SET_ERR_MSG(extack,
				       "Table class tc_max_entries cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbc_max_entries > P4TC_MAX_TENTRIES) {
			NL_SET_ERR_MSG(extack,
				       "Table class tc_max_entries exceeds maximum value");
			ret = -EINVAL;
			goto free;
		}
		tclass->tbc_max_entries = parm->tbc_max_entries;
	} else {
		tclass->tbc_max_entries = P4TC_DEFAULT_TENTRIES;
	}

	if (parm->tbc_flags & P4TC_TCLASS_FLAGS_MAX_MASKS) {
		if (!parm->tbc_max_masks) {
			NL_SET_ERR_MSG(extack,
				       "Table class tc_max_masks cannot be zero");
			ret = -EINVAL;
			goto free;
		}
		if (parm->tbc_max_masks > P4TC_MAX_TMASKS) {
			NL_SET_ERR_MSG(extack,
				       "Table class tc_max_masks exceeds maximum value");
			ret = -EINVAL;
			goto free;
		}
		tclass->tbc_max_masks = parm->tbc_max_masks;
	} else {
		tclass->tbc_max_masks = P4TC_DEFAULT_TMASKS;
	}

	refcount_set(&tclass->tbc_ref, 1);

	if (tbc_id) {
		tclass->tbc_id = tbc_id;
		ret = idr_alloc_u32(&pipeline->p_tbc_idr, tclass,
				    &tclass->tbc_id, tclass->tbc_id,
				    GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate table class id");
			goto free;
		}
	} else {
		tclass->tbc_id = 1;
		ret = idr_alloc_u32(&pipeline->p_tbc_idr, tclass, &tclass->tbc_id,
				    UINT_MAX, GFP_KERNEL);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack, "Unable to allocate table class id");
			goto free;
		}
	}

	if (tb[P4TC_TCLASS_PREACTIONS]) {
		tclass->tbc_preacts = kcalloc(TCA_ACT_MAX_PRIO,
					      sizeof(struct tc_action *),
					      GFP_KERNEL);
		if (!tclass->tbc_preacts) {
			ret = -ENOMEM;
			goto idr_rm;
		}

		ret = p4tc_action_init(net, tb[P4TC_TCLASS_PREACTIONS],
				       tclass->tbc_preacts, extack);
		if (ret < 0) {
			kfree(tclass->tbc_preacts);
			goto idr_rm;
		}
		tclass->tbc_num_preacts = ret;
	} else {
		tclass->tbc_preacts = NULL;
	}

	if (tb[P4TC_TCLASS_POSTACTIONS]) {
		tclass->tbc_postacts = kcalloc(TCA_ACT_MAX_PRIO,
					       sizeof(struct tc_action *),
					       GFP_KERNEL);
		if (!tclass->tbc_postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_TCLASS_POSTACTIONS],
				       tclass->tbc_postacts, extack);
		if (ret < 0) {
			kfree(tclass->tbc_postacts);
			goto preactions_destroy;
		}
		tclass->tbc_num_postacts = ret;
	} else {
		ret = -EINVAL;
		NL_SET_ERR_MSG(extack, "Must specify table class postactions");
		goto preactions_destroy;
	}

	idr_init(&tclass->tbc_keys_idr);
	tclass->tbc_keys_count = 0;
	if (tb[P4TC_TCLASS_KEYS]) {
		num_keys = tcf_tclass_key_cu(net, tb[P4TC_TCLASS_KEYS],
					     tclass, keys, cu_res, false,
					     extack);
		if (num_keys < 0) {
			ret = num_keys;
			goto idr_dest;
		}

		tcf_tclass_key_replace_many(keys, tclass, cu_res, num_keys);
	} else {
		NL_SET_ERR_MSG(extack, "Must specify table class keys");
		ret = -EINVAL;
		goto idr_dest;
	}

	if (parm->tbc_flags & P4TC_TCLASS_FLAGS_DEFAULT_KEY) {
		struct p4tc_table_key *default_key;

		if (!parm->tbc_default_key) {
			NL_SET_ERR_MSG(extack, "default_key cannot be zero");
			ret = -EINVAL;
			goto idr_dest;
		}

		if (num_keys < parm->tbc_default_key) {
			NL_SET_ERR_MSG(extack,
				       "tc_default_key field is inconsistent with keys nested field");
			ret = -EINVAL;
			goto idr_dest;
		}

		default_key = keys[parm->tbc_default_key - 1];
		tclass->tbc_default_key = default_key->key_id;
	} else {
		tclass->tbc_default_key = 1;
	}

	idr_init(&tclass->tbc_ti_idr);
	tclass->tbc_curr_used_entries = 0;
	tclass->tbc_curr_count = 0;
	/* Create table instance with name of table class */
	if (tclass->tbc_count == 1) {
		struct p4tc_table_instance *tinst;

		tinst = kmalloc(sizeof(*tinst), GFP_KERNEL);
		if (!tinst) {
			NL_SET_ERR_MSG(extack, "Unable to create table instance");
			ret = -ENOMEM;
			goto keys_put;
		}

		tinst->ti_id = 1;

		ret = idr_alloc_u32(&tclass->tbc_ti_idr, tinst, &tinst->ti_id,
				    tinst->ti_id, GFP_KERNEL);
		if (ret < 0) {
			kfree(tinst);
			goto keys_put;
		}

		ret = p4tc_tinst_init(tinst, pipeline, tbcname,
				      tclass, P4TC_DEFAULT_TIENTRIES);
		if (ret < 0) {
			tinst->common.ops->put(net, &tinst->common, extack);
			goto keys_put;
		}
	}

	pipeline->curr_table_classes += 1;

	tclass->common.ops = (struct p4tc_template_ops *)&p4tc_tclass_ops;

	tclass->tbc_value_ops.fetch = tcf_tclass_fetch;

	return tclass;

keys_put:
	if (num_keys)
		tcf_tclass_key_put_many(keys, tclass, cu_res, num_keys);

	idr_destroy(&tclass->tbc_ti_idr);

idr_dest:
	idr_destroy(&tclass->tbc_keys_idr);

	tcf_action_destroy(tclass->tbc_postacts, TCA_ACT_UNBIND);
	kfree(tclass->tbc_postacts);

preactions_destroy:
	if (tclass->tbc_preacts) {
		tcf_action_destroy(tclass->tbc_preacts, TCA_ACT_UNBIND);
		kfree(tclass->tbc_preacts);
	}

idr_rm:
	idr_remove(&pipeline->p_tbc_idr, tclass->tbc_id);

free:
	kfree(tclass);

out:
	return ERR_PTR(ret);
}

static struct p4tc_table_class *
tcf_tclass_update(struct net *net, struct nlmsghdr *n,
		  struct nlattr *nla, u32 tbc_id,
		  struct p4tc_pipeline *pipeline,
		  struct netlink_ext_ack *extack)
{
	struct p4tc_table_key *keys[P4TC_MAXPARSE_KEYS] = {NULL};
	int cu_res[P4TC_MAXPARSE_KEYS] = {P4TC_P_UNSPEC};
	struct p4tc_table_class_parm *parm = NULL;
	struct tc_action **postacts = NULL;
	struct tc_action **preacts = NULL;
	int num_keys = 0;
	int ret = 0;
	struct nlattr *tb[P4TC_TCLASS_MAX + 1];
	struct p4tc_table_class *tclass;

	ret = nla_parse_nested(tb, P4TC_TCLASS_MAX, nla, p4tc_tclass_policy,
			       extack);
	if (ret < 0)
		goto out;

	tclass = tcf_tclass_find_byany(pipeline, tb[P4TC_TCLASS_NAME], tbc_id, extack);
	if (IS_ERR(tclass))
		return tclass;

	if (tb[P4TC_TCLASS_PREACTIONS]) {
		preacts = kcalloc(TCA_ACT_MAX_PRIO,
				  sizeof(struct tc_action *),
				  GFP_KERNEL);
		if (!preacts) {
			ret = -ENOMEM;
			goto out;
		}

		ret = p4tc_action_init(net, tb[P4TC_TCLASS_PREACTIONS],
				       preacts, extack);
		if (ret < 0) {
			kfree(preacts);
			goto out;
		}
	}

	if (tb[P4TC_TCLASS_POSTACTIONS]) {
		postacts = kcalloc(TCA_ACT_MAX_PRIO,
				   sizeof(struct tc_action *),
				   GFP_KERNEL);
		if (!postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_TCLASS_POSTACTIONS],
				       postacts, extack);
		if (ret < 0) {
			kfree(postacts);
			goto preactions_destroy;
		}
	}

	if (tb[P4TC_TCLASS_KEYS]) {
		num_keys = tcf_tclass_key_cu(net, tb[P4TC_TCLASS_KEYS],
					     tclass, keys, cu_res, true,
					     extack);
		if (num_keys < 0) {
			ret = num_keys;
			goto postactions_destroy;
		}
	}

	if (tb[P4TC_TCLASS_INFO]) {
		parm = nla_data(tb[P4TC_TCLASS_INFO]);
		if (parm->tbc_flags & P4TC_TCLASS_FLAGS_KEYSZ) {
			if (!parm->tbc_keysz) {
				NL_SET_ERR_MSG(extack,
					       "Table class keysz cannot be zero");
				ret = -EINVAL;
				goto keys_destroy;
			}
			if (parm->tbc_keysz > P4TC_MAX_KEYSZ) {
				NL_SET_ERR_MSG(extack,
					       "Table class keysz exceeds maximum keysz");
				ret = -EINVAL;
				goto keys_destroy;
			}
			tclass->tbc_keysz = parm->tbc_keysz;
		}

		if (parm->tbc_flags & P4TC_TCLASS_FLAGS_COUNT) {
			if (!parm->tbc_count) {
				NL_SET_ERR_MSG(extack,
					       "Table class tbc_count cannot be zero");
				ret = -EINVAL;
				goto keys_destroy;
			}
			if (parm->tbc_count > P4TC_MAX_TINSTS) {
				NL_SET_ERR_MSG(extack,
					       "Table class tbc_count exceeds maximum tbc_count");
				ret = -EINVAL;
				goto keys_destroy;
			}
			tclass->tbc_count = parm->tbc_count;
		}

		if (parm->tbc_flags & P4TC_TCLASS_FLAGS_MAX_ENTRIES) {
			if (!parm->tbc_max_entries) {
				NL_SET_ERR_MSG(extack,
					       "Table class tc_max_entries cannot be zero");
				ret = -EINVAL;
				goto keys_destroy;
			}
			if (parm->tbc_max_entries > P4TC_MAX_TENTRIES) {
				NL_SET_ERR_MSG(extack,
					       "Table class tc_max_entries exceeds maximum value");
				ret = -EINVAL;
				goto keys_destroy;
			}
			tclass->tbc_max_entries = parm->tbc_max_entries;
		}

		if (parm->tbc_flags & P4TC_TCLASS_FLAGS_MAX_MASKS) {
			if (!parm->tbc_max_masks) {
				NL_SET_ERR_MSG(extack,
					       "Table class tc_max_masks cannot be zero");
				ret = -EINVAL;
				goto keys_destroy;
			}
			if (parm->tbc_max_masks > P4TC_MAX_TMASKS) {
				NL_SET_ERR_MSG(extack,
					       "Table class tc_max_masks exceeds maximum value");
				ret = -EINVAL;
				goto keys_destroy;
			}
			tclass->tbc_max_masks = parm->tbc_max_masks;
		}
	}

	if (parm && parm->tbc_flags & P4TC_TCLASS_FLAGS_DEFAULT_KEY) {
		struct p4tc_table_key *default_key;

		if (!parm->tbc_default_key) {
			NL_SET_ERR_MSG(extack, "default_key cannot be zero");
			ret = -EINVAL;
			goto keys_destroy;
		}

		if (num_keys < parm->tbc_default_key) {
			NL_SET_ERR_MSG(extack,
				       "tc_default_key field is inconsistent with keys nested field");
			ret = -EINVAL;
			goto keys_destroy;
		}

		default_key = keys[parm->tbc_default_key - 1];
		tclass->tbc_default_key = default_key->key_id;
	}

	if (preacts) {
		tcf_action_destroy(tclass->tbc_preacts, TCA_ACT_UNBIND);
		kfree(tclass->tbc_preacts);
		tclass->tbc_preacts = preacts;
	}

	if (postacts) {
		tcf_action_destroy(tclass->tbc_postacts, TCA_ACT_UNBIND);
		kfree(tclass->tbc_postacts);
		tclass->tbc_postacts = postacts;
	}

	if (tb[P4TC_TCLASS_KEYS])
		tcf_tclass_key_replace_many(keys, tclass, cu_res, num_keys);

	return tclass;

keys_destroy:
	if (tb[P4TC_TCLASS_KEYS])
		tcf_tclass_key_put_many(keys, tclass, cu_res, num_keys);

postactions_destroy:
	if (postacts) {
		tcf_action_destroy(postacts, TCA_ACT_UNBIND);
		kfree(postacts);
	}

preactions_destroy:
	if (preacts) {
		tcf_action_destroy(preacts, TCA_ACT_UNBIND);
		kfree(preacts);
	}

out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_tclass_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
	      char **p_name, u32 *ids, struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], tbc_id = ids[P4TC_TBCID_IDX];
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;

	pipeline = tcf_pipeline_find_byany_unsealed(*p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return (void *)pipeline;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		tclass = tcf_tclass_update(net, n, nla, tbc_id, pipeline, extack);
	else
		tclass = tcf_tclass_create(net, n, nla, tbc_id, pipeline, extack);

	if (IS_ERR(tclass))
		goto out;

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!ids[P4TC_TBCID_IDX])
		ids[P4TC_TBCID_IDX] = tclass->tbc_id;

out:
	return (struct p4tc_template_common *)tclass;
}

static int tcf_tclass_flush(struct net *net, struct sk_buff *skb,
			    struct p4tc_pipeline *pipeline,
			    struct netlink_ext_ack *extack)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct p4tc_table_class *tclass;
	unsigned long tmp, tbc_id;
	int ret = 0;
	int i = 0;

	if (nla_put_u32(skb, P4TC_PATH, 0))
		goto out_nlmsg_trim;

	if (idr_is_empty(&pipeline->p_tbc_idr)) {
		NL_SET_ERR_MSG(extack, "There are not table classes to flush");
		goto out_nlmsg_trim;
	}

	idr_for_each_entry_ul(&pipeline->p_tbc_idr, tclass, tmp, tbc_id) {
		if (_tcf_tclass_put(net, pipeline, tclass, extack) < 0) {
			ret = -EBUSY;
			continue;
		}
		i++;
	}

	nla_put_u32(skb, P4TC_COUNT, i);

	if (ret < 0) {
		if (i == 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush any table class");
			goto out_nlmsg_trim;
		} else {
			NL_SET_ERR_MSG(extack,
				       "Unable to flush all table classes");
		}
	}

	return i;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_tclass_gd(struct net *net, struct sk_buff *skb,
			 struct nlmsghdr *n, struct nlattr *nla,
			 char **p_name, u32 *ids,
			 struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX], tbc_id = ids[P4TC_MID_IDX];
	struct nlattr *tb[P4TC_TCLASS_MAX + 1] = {};
	unsigned char *b = skb_tail_pointer(skb);
	int ret = 0;
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_class *tclass;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		pipeline = tcf_pipeline_find_byany_unsealed(*p_name, pipeid, extack);
	} else {
		pipeline = tcf_pipeline_find_byany(*p_name, pipeid, extack);
	}
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	if (nla) {
		ret = nla_parse_nested(tb, P4TC_TCLASS_MAX, nla,
				       p4tc_tclass_policy, extack);

		if (ret < 0)
			return ret;
	}

	if (*p_name)
		strscpy(*p_name, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE && (n->nlmsg_flags & NLM_F_ROOT))
		return tcf_tclass_flush(net, skb, pipeline, extack);

	tclass = tcf_tclass_find_byany(pipeline, tb[P4TC_TCLASS_NAME], tbc_id, extack);
	if (IS_ERR(tclass))
		return PTR_ERR(tclass);

	if (_tcf_tclass_fill_nlmsg(skb, tclass) < 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for table class");
		return -EINVAL;
	}

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = _tcf_tclass_put(net, pipeline, tclass, extack);
		if (ret < 0) {
			NL_SET_ERR_MSG(extack,
				       "Unable to delete referenced table class");
			goto out_nlmsg_trim;
		}
	}

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_tclass_dump(struct sk_buff *skb,
			   struct p4tc_dump_ctx *ctx,
			   struct nlattr *nla,
			   char **p_name, u32 *ids,
			   struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline;

	if (!ctx->ids[P4TC_PID_IDX]) {
		pipeline = tcf_pipeline_find_byany(*p_name, ids[P4TC_PID_IDX], extack);
		if (IS_ERR(pipeline))
			return PTR_ERR(pipeline);
		ctx->ids[P4TC_PID_IDX] = pipeline->common.p_id;
	} else {
		pipeline = tcf_pipeline_find_byid(ctx->ids[P4TC_PID_IDX]);
	}

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!(*p_name))
		*p_name = pipeline->common.name;

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipeline->p_tbc_idr,
					P4TC_TBCID_IDX, extack);
}

static int tcf_tclass_dump_1(struct sk_buff *skb,
			     struct p4tc_template_common *common)
{
	struct p4tc_table_class *tclass = to_tclass(common);
	unsigned char *b = skb_tail_pointer(skb);
	struct nlattr *param = nla_nest_start(skb, P4TC_PARAMS);

	if (!param)
		goto out_nlmsg_trim;
	if (nla_put_string(skb, P4TC_TCLASS_NAME, tclass->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

const struct p4tc_template_ops p4tc_tclass_ops = {
	.init = NULL,
	.cu = tcf_tclass_cu,
	.fill_nlmsg = tcf_tclass_fill_nlmsg,
	.gd = tcf_tclass_gd,
	.put = tcf_tclass_put,
	.dump = tcf_tclass_dump,
	.dump_1 = tcf_tclass_dump_1,
};
