// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_cmds_ops.c - kParser KMOD-CLI netlink request operations handlers
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <linux/slab.h>
#include <linux/sort.h>
#include <net/kparser.h>
#include <linux/netlink.h>

#include "kparser.h"

/* global netlink cmd handler mutex, all handlers must run within protection of this mutex
 * NOTE: never use this mutex on data path operations since they can run under interrupt contexts
 */
static DEFINE_MUTEX(kparser_config_lock);

/* global counter config, shared among all the parsers */
static struct kparser_cntrs_conf cntrs_conf = {};
static __u8 cntrs_conf_idx;

void *kparser_fast_lookup_array[KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_STOP -
	KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_START + 1];

/* common pre-process code for create handlers */
static inline bool
kparser_cmd_create_pre_process(const char *op,
			       const struct kparser_conf_cmd *conf,
			       const struct kparser_hkey *argkey, struct kparser_hkey *newkey,
			       void **kobj, size_t kobjsize, struct kparser_cmd_rsp_hdr *rsp,
			       size_t glueoffset,
			       void *extack, int *err)
{
	struct kparser_glue *glue;

	if (kparser_conf_key_manager(conf->namespace_id, argkey, newkey, rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		return false;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OP:%s Key{%s:%d}:{%s:%d}\n",
				 op, argkey->name, argkey->id,
				 newkey->name, newkey->id);

	if (kparser_namespace_lookup(conf->namespace_id, newkey)) {
		rsp->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Duplicate object HKey:{%s:%u}",
				       op, newkey->name, newkey->id);
		return false;
	}

	*kobj = kzalloc(kobjsize, GFP_KERNEL);
	if (!(*kobj)) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object allocation failed for size:%lu",
				       op, kobjsize);
		return false;
	}

	glue = (*kobj) + glueoffset;
	glue->key = *newkey;

	rsp->op_ret_code = kparser_namespace_insert(conf->namespace_id,
						    &glue->ht_node_id, &glue->ht_node_name);
	if (rsp->op_ret_code) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Htbl insert err:%d",
				       op, rsp->op_ret_code);
		return false;
	}

	glue->config = *conf;
	kref_init(&glue->refcount);

	rsp->key = *newkey;
	rsp->object.conf_keys_bv = conf->conf_keys_bv;
	rsp->object = *conf;

	return true;
}

/* Following functions create kParser object handlers for netlink msgs
 * create handler for object conditionals
 * NOTE: All handlers startting from here must hold mutex kparser_config_lock
 * before any work can be done and must release that mutex before return.
 */
int kparser_create_cond_exprs(const struct kparser_conf_cmd *conf,
			      size_t conf_len,
			      struct kparser_cmd_rsp_hdr **rsp,
			      size_t *rsp_len, const char *op,
			      void *extack, int *err)
{
	struct kparser_glue_condexpr_expr *kobj = NULL;
	const struct kparser_conf_condexpr *arg;
	struct kparser_hkey key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->cond_conf;

	if (!kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
					    (void **)&kobj, sizeof(*kobj), *rsp,
					    offsetof(struct
						     kparser_glue_condexpr_expr,
						     glue), extack, err))
		goto done;

	kobj->expr = arg->config;

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.cond_conf = kobj->glue.config.cond_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(kobj);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS);
}

/* read handler for object conditionals */
int kparser_read_cond_exprs(const struct kparser_hkey *key,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, __u8 recursive_read,
			    const char *op,
			    void *extack, int *err)
{
	struct kparser_glue_condexpr_expr *kobj;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kobj = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS, key);
	if (!kobj) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found:{%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kobj->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kobj->glue.config.conf_keys_bv;
	(*rsp)->object.cond_conf = kobj->glue.config.cond_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS);
}

/* create handler for object conditionals table entry */
static bool kparser_create_cond_table_ent(const struct kparser_conf_table *arg,
					  struct kparser_glue_condexpr_table **proto_table,
					  struct kparser_cmd_rsp_hdr *rsp,
					  const char *op,
					  void *extack, int *err)
{
	const struct kparser_glue_condexpr_expr *kcondent;
	void *realloced_mem;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLE, &arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found:{%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	kcondent = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS, &arg->elem_key);
	if (!kcondent) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found:{%s:%u}",
				       op, arg->elem_key.name, arg->elem_key.id);
		return false;
	}

	(*proto_table)->table.num_ents++;
	realloced_mem = krealloc((*proto_table)->table.entries,
				 (*proto_table)->table.num_ents *
				 sizeof(struct kparser_condexpr_expr *),
				 GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:krealloc() err, ents:%d, size:%lu",
				       op, (*proto_table)->table.num_ents,
				       sizeof(struct kparser_condexpr_expr));
		return false;
	}
	rcu_assign_pointer((*proto_table)->table.entries, realloced_mem);

	(*proto_table)->table.entries[(*proto_table)->table.num_ents - 1] = &kcondent->expr;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return true;
}

/* create handler for object conditionals table */
int kparser_create_cond_table(const struct kparser_conf_cmd *conf,
			      size_t conf_len,
			      struct kparser_cmd_rsp_hdr **rsp,
			      size_t *rsp_len, const char *op,
			      void *extack, int *err)
{
	struct kparser_glue_condexpr_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	/* create a table entry */
	if (arg->add_entry) {
		if (kparser_create_cond_table_ent(arg, &proto_table, *rsp, op,
						  extack, err) == false)
			goto done;
		goto skip_table_create;
	}

	if (!kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
					    (void **)&proto_table, sizeof(*proto_table), *rsp,
					    offsetof(struct
						     kparser_glue_condexpr_table,
						     glue), extack, err))
		goto done;

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);
	proto_table->table.default_fail = arg->optional_value1;
	proto_table->table.type = arg->optional_value2;

skip_table_create:
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (proto_table && !arg->add_entry)
			kparser_free(proto_table);
	}

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLE);
}

/* read handler for object conditionals table */
int kparser_read_cond_table(const struct kparser_hkey *key,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, __u8 recursive_read,
			    const char *op,
			    void *extack, int *err)
{
	const struct kparser_glue_condexpr_table *proto_table;
	const struct kparser_glue_condexpr_expr *kcondent;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found, key:{%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n",
				 (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;
	(*rsp)->object.table_conf.optional_value1 = proto_table->table.default_fail;
	(*rsp)->object.table_conf.optional_value2 = proto_table->table.type;

	for (i = 0; i < proto_table->table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		if (!proto_table->table.entries)
			continue;
		kcondent = container_of(proto_table->table.entries[i],
					struct kparser_glue_condexpr_expr, expr);
		objects[i].table_conf.elem_key = kcondent->glue.key;
	}
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLE);
}

/* create handler for object conditionals table's list entry */
static bool kparser_create_cond_tables_ent(const struct kparser_conf_table *arg,
					   struct kparser_glue_condexpr_tables **proto_table,
					   struct kparser_cmd_rsp_hdr *rsp,
					   const char *op,
					   void *extack, int *err)
{
	const struct kparser_glue_condexpr_table *kcondent;
	void *realloced_mem;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES, &arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found, key:{%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	kcondent = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLE, &arg->elem_key);
	if (!kcondent) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found, key:{%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	(*proto_table)->table.num_ents++;
	realloced_mem = krealloc((*proto_table)->table.entries, (*proto_table)->table.num_ents *
				 sizeof(struct kparser_condexpr_table *), GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: krealloc() err, ents:%d, size:%lu",
				       op, (*proto_table)->table.num_ents,
				       sizeof(struct kparser_condexpr_table *));
		return false;
	}
	rcu_assign_pointer((*proto_table)->table.entries, realloced_mem);

	(*proto_table)->table.entries[(*proto_table)->table.num_ents - 1] = &kcondent->table;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return true;
}

/* create handler for object conditionals table's list */
int kparser_create_cond_tables(const struct kparser_conf_cmd *conf,
			       size_t conf_len,
			       struct kparser_cmd_rsp_hdr **rsp,
			       size_t *rsp_len, const char *op,
			       void *extack, int *err)
{
	struct kparser_glue_condexpr_tables *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	/* create a table entry */
	if (arg->add_entry) {
		if (kparser_create_cond_tables_ent(arg, &proto_table, *rsp, op,
						   extack, err) == false)
			goto done;
		goto skip_table_create;
	}

	if (!kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
					    (void **)&proto_table, sizeof(*proto_table), *rsp,
					    offsetof(struct
						     kparser_glue_condexpr_tables,
						     glue), extack, err))
		goto done;

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (proto_table && !arg->add_entry)
			kparser_free(proto_table);
	}

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLES);
}

/* read handler for object conditionals table's list */
int kparser_read_cond_tables(const struct kparser_hkey *key,
			     struct kparser_cmd_rsp_hdr **rsp,
			     size_t *rsp_len, __u8 recursive_read,
			     const char *op,
			     void *extack, int *err)

{
	const struct kparser_glue_condexpr_tables *proto_table;
	const struct kparser_glue_condexpr_table *kcondent;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object key not found, key:{%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 ":krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		if (!proto_table->table.entries)
			continue;
		kcondent = container_of(proto_table->table.entries[i],
					struct kparser_glue_condexpr_table, table);
		objects[i].table_conf.elem_key = kcondent->glue.key;
	}

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLES);
}

/* create handler for object counter */
int kparser_create_counter(const struct kparser_conf_cmd *conf,
			   size_t conf_len,
			   struct kparser_cmd_rsp_hdr **rsp,
			   size_t *rsp_len, const char *op,
			   void *extack, int *err)
{
	struct kparser_glue_counter *kcntr = NULL;
	const struct kparser_conf_cntr *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->cntr_conf;

	if (!arg->conf.valid_entry) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: counter entry is not valid", op);
		goto done;
	}

	if (cntrs_conf_idx >= KPARSER_CNTR_NUM_CNTRS) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: counter index %d can not be >= %d",
				       op, cntrs_conf_idx,
				       KPARSER_CNTR_NUM_CNTRS);
		goto done;
	}

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object key {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	kcntr = kzalloc(sizeof(*kcntr), GFP_KERNEL);
	if (!kcntr) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*kcntr));
		goto done;
	}

	kcntr->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kcntr->glue.ht_node_id, &kcntr->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err:%d",
				       op, rc);
		goto done;
	}

	kcntr->glue.config.namespace_id = conf->namespace_id;
	kcntr->glue.config.conf_keys_bv = conf->conf_keys_bv;
	kcntr->glue.config.cntr_conf = *arg;
	kcntr->glue.config.cntr_conf.key = key;
	kref_init(&kcntr->glue.refcount);

	kcntr->counter_cnf = arg->conf;
	kcntr->counter_cnf.index = cntrs_conf_idx;

	cntrs_conf.cntrs[cntrs_conf_idx] = kcntr->counter_cnf;

	cntrs_conf_idx++;

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.cntr_conf = kcntr->glue.config.cntr_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(kcntr);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER);
}

/* read handler for object counter */
int kparser_read_counter(const struct kparser_hkey *key,
			 struct kparser_cmd_rsp_hdr **rsp,
			 size_t *rsp_len, __u8 recursive_read,
			 const char *op,
			 void *extack, int *err)
{
	struct kparser_glue_counter *kcntr;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER, key);
	if (!kcntr) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key not found, key:{%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kcntr->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kcntr->glue.config.conf_keys_bv;
	(*rsp)->object.cntr_conf = kcntr->glue.config.cntr_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER);
}

/* create handler for object counter table */
int kparser_create_counter_table(const struct kparser_conf_cmd *conf,
				 size_t conf_len,
				 struct kparser_cmd_rsp_hdr **rsp,
				 size_t *rsp_len, const char *op,
				 void *extack, int *err)
{
	struct kparser_glue_counter_table *table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_glue_counter *kcntr;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	/* create a table entry */
	if (arg->add_entry) {
		table = kparser_namespace_lookup(conf->namespace_id, &arg->key);
		if (!table) {
			(*rsp)->op_ret_code = ENOENT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s:Object key not found, key:{%s:%u}",
					       op, arg->key.name, arg->key.id);
			goto done;
		}
		if (table->elems_cnt >= KPARSER_CNTR_NUM_CNTRS) {
			(*rsp)->op_ret_code = EINVAL;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s:table full, elem cnt:%u",
					       op, table->elems_cnt);
			goto done;
		}
		kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER,
						 &arg->elem_key);
		if (!kcntr) {
			(*rsp)->op_ret_code = ENOENT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s:Object key not found, key:{%s:%u}",
					       op, arg->elem_key.name,
					       arg->elem_key.id);
			goto done;
		}
		table->k_cntrs[table->elems_cnt++] = *kcntr;
		goto skip_table_create;
	}

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:Object key duplicate, key:{%s:%u}",
				       op, key.name, key.id);
		goto done;
	}

	/* create counter table */
	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*table));
		goto done;
	}

	table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &table->glue.ht_node_id, &table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc:%d",
				       op, rc);
		goto done;
	}

	table->glue.config.namespace_id = conf->namespace_id;
	table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	table->glue.config.table_conf = *arg;
	table->glue.config.table_conf.key = key;
	kref_init(&table->glue.refcount);

skip_table_create:
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (table && !arg->add_entry)
			kparser_free(table);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER_TABLE);
}

/* read handler for object counter table */
int kparser_read_counter_table(const struct kparser_hkey *key,
			       struct kparser_cmd_rsp_hdr **rsp,
			       size_t *rsp_len, __u8 recursive_read,
			       const char *op,
			       void *extack, int *err)
{
	const struct kparser_glue_counter_table *table;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	table = kparser_namespace_lookup(KPARSER_NS_COUNTER_TABLE, key);
	if (!table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object key not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = table->glue.config.table_conf;

	for (i = 0; i < KPARSER_CNTR_NUM_CNTRS; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = table->k_cntrs[i].glue.config.namespace_id;
		objects[i].cntr_conf = table->k_cntrs[i].glue.config.cntr_conf;
		objects[i].cntr_conf.conf = cntrs_conf.cntrs[i];
	}

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER_TABLE);
}

/* create handler for object metadata */
int kparser_create_metadata(const struct kparser_conf_cmd *conf,
			    size_t conf_len,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, const char *op,
			    void *extack, int *err)
{
	struct kparser_glue_metadata_extract *kmde = NULL;
	int rc, cntridx = 0, cntr_arr_idx = 0;
	const struct kparser_conf_metadata *arg;
	struct kparser_glue_counter *kcntr;
	struct kparser_hkey key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->md_conf;

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object key duplicate, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER, &arg->counterkey);
	if (kcntr)
		cntridx = kcntr->counter_cnf.index + 1;

	if (arg->type == KPARSER_METADATA_COUNTER) {
		/* In this case, one of the counters must be provided. If not,
		 * that is an error
		 */
		kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER,
						 &arg->counter_data_key);
		if (kcntr)
			cntr_arr_idx = kcntr->counter_cnf.index + 1;

		if (cntridx == 0 && cntr_arr_idx == 0) {
			(*rsp)->op_ret_code = -ENOENT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: both counteridx and"
					       " counterdata object keys are not"
					       " found", op);
			goto done;
		} else {
			if (cntr_arr_idx == 0)
				cntr_arr_idx = cntridx;
			else if (cntridx == 0)
				cntridx = cntr_arr_idx;
		}
	}

	kmde = kzalloc(sizeof(*kmde), GFP_KERNEL);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: kzalloc() failed, size:%lu",
				       op, sizeof(*kmde));
		goto done;
	}

	kmde->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kmde->glue.ht_node_id, &kmde->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: kparser_namespace_insert()"
				       " err, rc:%d", op, rc);
		goto done;
	}

	kmde->glue.config.namespace_id = conf->namespace_id;
	kmde->glue.config.conf_keys_bv = conf->conf_keys_bv;
	kmde->glue.config.md_conf = *arg;
	kmde->glue.config.md_conf.key = key;
	kref_init(&kmde->glue.refcount);
	INIT_LIST_HEAD(&kmde->glue.owner_list);
	INIT_LIST_HEAD(&kmde->glue.owned_list);

	if (!kparser_metadata_convert(arg, &kmde->mde, cntridx, cntr_arr_idx)) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: kparser_metadata_convert()"
				       " err, rc:%d", op, rc);
		goto done;
	}

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(kmde);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_METADATA);
}

/* read handler for object metadata */
int kparser_read_metadata(const struct kparser_hkey *key,
			  struct kparser_cmd_rsp_hdr **rsp,
			  size_t *rsp_len, __u8 recursive_read,
			  const char *op,
			  void *extack, int *err)
{
	const struct kparser_glue_metadata_extract *kmde;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, key);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: Object key not found,"
				       " key:{%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kmde->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmde->glue.config.conf_keys_bv;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_METADATA);
}

/* delete handler for object metadata */
int kparser_del_metadata(const struct kparser_hkey *key,
			 struct kparser_cmd_rsp_hdr **rsp,
			 size_t *rsp_len, __u8 recursive_read,
			 const char *op,
			 void *extack, int *err)
{
	struct kparser_glue_metadata_extract *kmde;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, key);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: Object key not found,"
				       " key:{%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	if (kref_read(&kmde->glue.refcount) != 0) {
		(*rsp)->op_ret_code = EBUSY;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: Metadata object is"
				       " associated with a metalist, delete"
				       " that metalist instead",
				       op);
		goto done;
	}

	rc = kparser_namespace_remove(KPARSER_NS_METADATA,
				      &kmde->glue.ht_node_id, &kmde->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack, "%s: namespace remove error, rc: %d",
				       op, rc);
		goto done;
	}

	(*rsp)->key = kmde->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmde->glue.config.conf_keys_bv;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;

	kparser_free(kmde);
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_METADATA);
}

/* free handler for object metadata */
void kparser_free_metadata(void *ptr, void *arg)
{
	/* TODO: */
}

/* create handler for object metadata list */
int kparser_create_metalist(const struct kparser_conf_cmd *conf,
			    size_t conf_len,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, const char *op,
			    void *extack, int *err)
{
	struct kparser_glue_metadata_extract *kmde = NULL;
	struct kparser_glue_metadata_table *kmdl = NULL;
	const struct kparser_conf_metadata_table *arg;
	struct kparser_conf_cmd *objects = NULL;
	struct kparser_hkey key;
	void *realloced_mem;
	int rc, i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->mdl_conf;

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object key, {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	kmdl = kzalloc(sizeof(*kmdl), GFP_KERNEL);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*kmdl));
		goto done;
	}

	kmdl->glue.key = key;
	kmdl->glue.config.namespace_id = conf->namespace_id;
	kmdl->glue.config.conf_keys_bv = conf->conf_keys_bv;
	kmdl->glue.config.mdl_conf = *arg;
	kmdl->glue.config.mdl_conf.key = key;
	kmdl->glue.config.mdl_conf.metadata_keys_count = 0;
	kref_init(&kmdl->glue.refcount);
	INIT_LIST_HEAD(&kmdl->glue.owner_list);
	INIT_LIST_HEAD(&kmdl->glue.owned_list);

	conf_len -= sizeof(*conf);

	for (i = 0; i < arg->metadata_keys_count; i++) {
		if (conf_len < sizeof(struct kparser_hkey)) {
			(*rsp)->op_ret_code = EINVAL;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: conf len/buffer incomplete",
					       op);
			goto done;
		}

		conf_len -= sizeof(struct kparser_hkey);

		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n",
					 arg->metadata_keys[i].id, arg->metadata_keys[i].name);

		kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, &arg->metadata_keys[i]);
		if (!kmde) {
			(*rsp)->op_ret_code = ENOENT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: Object not found, key: {%s:%u}",
					       op, arg->metadata_keys[i].name,
					       arg->metadata_keys[i].id);
			goto done;
		}
		kmdl->metadata_table.num_ents++;
		realloced_mem = krealloc(kmdl->metadata_table.entries,
					 kmdl->metadata_table.num_ents * sizeof(*kmde),
					 GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			(*rsp)->op_ret_code = ENOMEM;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: krealloc() err, ents:%d, size:%lu",
					       op,
					       kmdl->metadata_table.num_ents,
					       sizeof(*kmde));
			goto done;
		}
		rcu_assign_pointer(kmdl->metadata_table.entries, realloced_mem);

		kmdl->metadata_table.entries[i] = kmde->mde;
		kref_get(&kmde->glue.refcount);

		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			if (kmdl) {
				kparser_free(kmdl->metadata_table.entries);
				kparser_free(kmdl);
			}
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;

		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = kmde->glue.config.namespace_id;
		objects[i].conf_keys_bv = kmde->glue.config.conf_keys_bv;
		objects[i].md_conf = kmde->glue.config.md_conf;

		kmdl->md_configs_len++;
		realloced_mem = krealloc(kmdl->md_configs,
					 kmdl->md_configs_len *
					 sizeof(struct kparser_conf_cmd),
					 GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			(*rsp)->op_ret_code = ENOMEM;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: krealloc() err, ents:%lu, size:%lu",
					       op,
					       kmdl->md_configs_len,
					       sizeof(struct kparser_conf_cmd));
			goto done;
		}
		kmdl->md_configs = realloced_mem;
		kmdl->md_configs[i].namespace_id = kmde->glue.config.namespace_id;
		kmdl->md_configs[i].conf_keys_bv = kmde->glue.config.conf_keys_bv;
		kmdl->md_configs[i].md_conf = kmde->glue.config.md_conf;
	}

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kmdl->glue.ht_node_id, &kmdl->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc:%d",
				       op, rc);
		goto done;
	}

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;
	(*rsp)->object.mdl_conf.metadata_keys_count = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0 && kmdl) {
		kparser_free(kmdl->metadata_table.entries);
		kparser_free(kmdl->md_configs);
		kparser_free(kmdl);
	}

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_METALIST);
}

/* read handler for object metadata list */
int kparser_read_metalist(const struct kparser_hkey *key,
			  struct kparser_cmd_rsp_hdr **rsp,
			  size_t *rsp_len, __u8 recursive_read,
			  const char *op,
			  void *extack, int *err)
{
	const struct kparser_glue_metadata_table *kmdl;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST, key);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object key not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kmdl->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmdl->glue.config.conf_keys_bv;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;

	for (i = 0; i < kmdl->md_configs_len; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "%s:krealloc failed for rsp, len:%lu\n",
						 op, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = kmdl->md_configs[i].namespace_id;
		objects[i].conf_keys_bv = kmdl->md_configs[i].conf_keys_bv;
		objects[i].md_conf = kmdl->md_configs[i].md_conf;
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n",
					 objects[i].md_conf.key.id, objects[i].md_conf.key.name);
	}
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_METALIST);
}

/* delete handler for object metadata list */
int kparser_del_metalist(const struct kparser_hkey *key,
			 struct kparser_cmd_rsp_hdr **rsp,
			 size_t *rsp_len, __u8 recursive_read,
			 const char *op,
			 void *extack, int *err)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	struct kparser_obj_link_ctx *node_tmp_list_ref = NULL;
	struct kparser_obj_link_ctx *node_curr_ref = NULL;
	struct kparser_glue_glue_parse_node *kparsenode;
	struct kparser_glue_metadata_extract *kmde;
	struct kparser_glue_metadata_table *kmdl;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i, rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST, key);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object key not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	/* verify if there is any associated immutable parser */
	list_for_each_entry_safe(curr_ref, tmp_list_ref,
				 &kmdl->glue.owned_list, owned_obj.list_node) {
		if (curr_ref->owner_obj.nsid != KPARSER_NS_NODE_PARSE)
			continue;
		if (kref_read(curr_ref->owner_obj.refcount) == 0)
			continue;
		kparsenode = (struct kparser_glue_glue_parse_node *)curr_ref->owner_obj.obj;
		list_for_each_entry_safe(node_curr_ref, node_tmp_list_ref,
					 &kparsenode->glue.glue.owned_list, owned_obj.list_node) {
			if (node_curr_ref->owner_obj.nsid != KPARSER_NS_PARSER)
				continue;
			if (kref_read(node_curr_ref->owner_obj.refcount) != 0) {
				(*rsp)->op_ret_code = EBUSY;
				NL_SET_ERR_MSG_FMT_MOD(extack,
						       "%s: attached parser `%s` is immutable",
						       op,
						       ((struct kparser_glue_parser *)
							node_curr_ref->owner_obj.obj)->glue.key.name);
				goto done;
			}
		}
	}

	if (kparser_link_detach(kmdl, &kmdl->glue.owner_list,
				&kmdl->glue.owned_list, *rsp,
				extack, err) != 0)
		goto done;

	(*rsp)->key = kmdl->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmdl->glue.config.conf_keys_bv;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;

	for (i = 0; i < kmdl->md_configs_len; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = kmdl->md_configs[i].namespace_id;
		objects[i].conf_keys_bv = kmdl->md_configs[i].conf_keys_bv;
		objects[i].md_conf = kmdl->md_configs[i].md_conf;

		kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, &objects[i].md_conf.key);
		if (!kmde) {
			(*rsp)->op_ret_code = ENOENT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: Object not found, key: {%s:%u}",
					       op, objects[i].md_conf.key.name,
					       objects[i].md_conf.key.id);
			goto done;
		}

		rc = kparser_namespace_remove(KPARSER_NS_METADATA,
					      &kmde->glue.ht_node_id, &kmde->glue.ht_node_name);
		if (rc) {
			(*rsp)->op_ret_code = rc;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s: namespace remove error, rc:%d",
					       op, rc);
			goto done;
		}

		kparser_free(kmde);
	}

	rc = kparser_namespace_remove(KPARSER_NS_METALIST,
				      &kmdl->glue.ht_node_id, &kmdl->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: namespace remove error, rc:%d",
				       op, rc);
		goto done;
	}

	kparser_free(kmdl->metadata_table.entries);

	kmdl->metadata_table.num_ents = 0;

	kparser_free(kmdl->md_configs);

	kparser_free(kmdl);

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_METALIST);
}

/* free handler for object metadata list */
void kparser_free_metalist(void *ptr, void *arg)
{
	/* TODO:  */
}

/* handler to convert and map netlink node context to kParser KMOD's node context */
static inline bool kparser_conf_node_convert(const struct kparser_conf_node *conf,
					     void *node, size_t node_len)
{
	struct kparser_glue_proto_flag_fields_table *kflag_fields_proto_table;
	struct kparser_parse_flag_fields_node *flag_fields_parse_node;
	struct kparser_glue_parse_tlv_node *kparsetlvwildcardnode;
	struct kparser_glue_glue_parse_node *kparsewildcardnode;
	struct kparser_glue_proto_tlvs_table *kprototlvstbl;
	struct kparser_glue_condexpr_tables *kcond_tables;
	struct kparser_parse_tlvs_node *tlvs_parse_node;
	struct kparser_glue_flag_fields *kflag_fields;
	struct kparser_glue_protocol_table *kprototbl;
	struct kparser_parse_node *plain_parse_node;
	struct kparser_glue_metadata_table *kmdl;

	if (!conf || !node || node_len < sizeof(*plain_parse_node))
		return false;

	plain_parse_node = node;
	plain_parse_node->node_type = conf->type;
	plain_parse_node->unknown_ret = conf->plain_parse_node.unknown_ret;
	plain_parse_node->proto_node.encap = conf->plain_parse_node.proto_node.encap;
	plain_parse_node->proto_node.overlay = conf->plain_parse_node.proto_node.overlay;
	plain_parse_node->proto_node.min_len = conf->plain_parse_node.proto_node.min_len;
	plain_parse_node->proto_node.ops.len_parameterized =
		conf->plain_parse_node.proto_node.ops.len_parameterized;
	plain_parse_node->proto_node.ops.pflen = conf->plain_parse_node.proto_node.ops.pflen;
	plain_parse_node->proto_node.ops.pfnext_proto =
		conf->plain_parse_node.proto_node.ops.pfnext_proto;

	kcond_tables =
		kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES,
					 &conf->plain_parse_node.proto_node.ops.cond_exprs_table);
	if (kcond_tables) {
		plain_parse_node->proto_node.ops.cond_exprs = kcond_tables->table;
		plain_parse_node->proto_node.ops.cond_exprs_parameterized = true;
	}

	strcpy(plain_parse_node->name, conf->key.name);

	kprototbl = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE,
					     &conf->plain_parse_node.proto_table_key);
	if (kprototbl)
		rcu_assign_pointer(plain_parse_node->proto_table, &kprototbl->proto_table);

	kparsewildcardnode =
		kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
					 &conf->plain_parse_node.wildcard_parse_node_key);
	if (kparsewildcardnode)
		rcu_assign_pointer(plain_parse_node->wildcard_node,
				   &kparsewildcardnode->parse_node);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST,
					&conf->plain_parse_node.metadata_table_key);
	if (kmdl)
		rcu_assign_pointer(plain_parse_node->metadata_table, &kmdl->metadata_table);

	switch (conf->type) {
	case KPARSER_NODE_TYPE_PLAIN:
		break;

	case KPARSER_NODE_TYPE_TLVS:
		if (node_len < sizeof(*tlvs_parse_node))
			return false;

		tlvs_parse_node = node;

		tlvs_parse_node->parse_node.tlvs_proto_node.ops =
			conf->tlvs_parse_node.proto_node.ops;

		tlvs_parse_node->parse_node.tlvs_proto_node.start_offset =
			conf->tlvs_parse_node.proto_node.start_offset;
		tlvs_parse_node->parse_node.tlvs_proto_node.pad1_val =
			conf->tlvs_parse_node.proto_node.pad1_val;
		tlvs_parse_node->parse_node.tlvs_proto_node.padn_val =
			conf->tlvs_parse_node.proto_node.padn_val;
		tlvs_parse_node->parse_node.tlvs_proto_node.eol_val =
			conf->tlvs_parse_node.proto_node.eol_val;
		tlvs_parse_node->parse_node.tlvs_proto_node.pad1_enable =
			conf->tlvs_parse_node.proto_node.pad1_enable;
		tlvs_parse_node->parse_node.tlvs_proto_node.padn_enable =
			conf->tlvs_parse_node.proto_node.padn_enable;
		tlvs_parse_node->parse_node.tlvs_proto_node.eol_enable =
			conf->tlvs_parse_node.proto_node.eol_enable;
		tlvs_parse_node->parse_node.tlvs_proto_node.fixed_start_offset =
			conf->tlvs_parse_node.proto_node.fixed_start_offset;
		tlvs_parse_node->parse_node.tlvs_proto_node.min_len =
			conf->tlvs_parse_node.proto_node.min_len;

		kprototlvstbl =
			kparser_namespace_lookup(KPARSER_NS_TLV_PROTO_TABLE,
						 &conf->tlvs_parse_node.tlv_proto_table_key);
		if (kprototlvstbl)
			rcu_assign_pointer(tlvs_parse_node->tlv_proto_table,
					   &kprototlvstbl->tlvs_proto_table);

		kparsetlvwildcardnode =
			kparser_namespace_lookup(KPARSER_NS_TLV_NODE_PARSE,
						 &conf->tlvs_parse_node.tlv_wildcard_node_key);
		if (kparsetlvwildcardnode)
			rcu_assign_pointer(tlvs_parse_node->tlv_wildcard_node,
					   &kparsetlvwildcardnode->tlv_parse_node);

		tlvs_parse_node->unknown_tlv_type_ret =
			conf->tlvs_parse_node.unknown_tlv_type_ret;

		tlvs_parse_node->config =
			conf->tlvs_parse_node.config;
		break;

	case KPARSER_NODE_TYPE_FLAG_FIELDS:
		if (node_len < sizeof(*flag_fields_parse_node))
			return false;
		flag_fields_parse_node = node;

		flag_fields_parse_node->parse_node.flag_fields_proto_node.ops =
			conf->flag_fields_parse_node.proto_node.ops;

		kflag_fields =
			kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_TABLE,
						 &conf->flag_fields_parse_node.proto_node.
						 flag_fields_table_hkey);
		if (kflag_fields)
			rcu_assign_pointer(flag_fields_parse_node->
					   parse_node.flag_fields_proto_node.flag_fields,
					   &kflag_fields->flag_fields);

		kflag_fields_proto_table =
			kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
						 &conf->flag_fields_parse_node.
						 flag_fields_proto_table_key);
		if (kflag_fields_proto_table)
			rcu_assign_pointer(flag_fields_parse_node->flag_fields_proto_table,
					   &kflag_fields_proto_table->flags_proto_table);
		break;

	default:
		return false;
	}
	return true;
}

/* create handler for object parse node */
int kparser_create_parse_node(const struct kparser_conf_cmd *conf,
			      size_t conf_len,
			      struct kparser_cmd_rsp_hdr **rsp,
			      size_t *rsp_len, const char *op,
			      void *extack, int *err)
{
	struct kparser_glue_glue_parse_node *kparsenode = NULL;
	struct kparser_glue_protocol_table *proto_table;
	struct kparser_glue_metadata_table *mdl;
	const struct kparser_conf_node *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->node_conf;

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key:{%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	kparsenode = kzalloc(sizeof(*kparsenode), GFP_KERNEL);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size:%lu",
				       op, sizeof(*kparsenode));
		goto done;
	}

	kparsenode->glue.glue.key = key;
	INIT_LIST_HEAD(&kparsenode->glue.glue.owner_list);
	INIT_LIST_HEAD(&kparsenode->glue.glue.owned_list);

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kparsenode->glue.glue.ht_node_id,
				      &kparsenode->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc: %d",
				       op, rc);
		goto done;
	}

	kparsenode->glue.glue.config.namespace_id = conf->namespace_id;
	kparsenode->glue.glue.config.conf_keys_bv = conf->conf_keys_bv;
	kparsenode->glue.glue.config.node_conf = *arg;
	kparsenode->glue.glue.config.node_conf.key = key;
	kref_init(&kparsenode->glue.glue.refcount);

	if (!kparser_conf_node_convert(arg, &kparsenode->parse_node,
				       sizeof(kparsenode->parse_node))) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_conf_node_convert() err",
				       op);
		goto done;
	}

	if (kparsenode->parse_node.node.proto_table) {
		proto_table = container_of(kparsenode->parse_node.node.proto_table,
					   struct kparser_glue_protocol_table,
					   proto_table);
		if (kparser_link_attach(kparsenode,
					KPARSER_NS_NODE_PARSE,
					(const void **)&kparsenode->parse_node.node.proto_table,
					&kparsenode->glue.glue.refcount,
					&kparsenode->glue.glue.owner_list,
					proto_table,
					KPARSER_NS_PROTO_TABLE,
					&proto_table->glue.refcount,
					&proto_table->glue.owned_list,
					*rsp, op, extack, err) != 0)
			goto done;
	}

	if (kparsenode->parse_node.node.metadata_table) {
		mdl = container_of(kparsenode->parse_node.node.metadata_table,
				   struct kparser_glue_metadata_table,
				   metadata_table);
		if (kparser_link_attach(kparsenode,
					KPARSER_NS_NODE_PARSE,
					(const void **)&kparsenode->parse_node.node.metadata_table,
					&kparsenode->glue.glue.refcount,
					&kparsenode->glue.glue.owner_list,
					mdl,
					KPARSER_NS_METALIST,
					&mdl->glue.refcount,
					&mdl->glue.owned_list,
					*rsp, op, extack, err) != 0)
			goto done;
	}

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.node_conf = kparsenode->glue.glue.config.node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(kparsenode);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE);
}

/* read handler for object parse node */
int kparser_read_parse_node(const struct kparser_hkey *key,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, __u8 recursive_read,
			    const char *op,
			    void *extack, int *err)
{
	const struct kparser_glue_glue_parse_node *kparsenode;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, key);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kparsenode->glue.glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparsenode->glue.glue.config.conf_keys_bv;
	(*rsp)->object.node_conf = kparsenode->glue.glue.config.node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE);
}

/* delete handler for object parse node */
int kparser_del_parse_node(const struct kparser_hkey *key,
			   struct kparser_cmd_rsp_hdr **rsp,
			   size_t *rsp_len, __u8 recursive_read,
			   const char *op,
			   void *extack, int *err)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	struct kparser_glue_glue_parse_node *kparsenode;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, key);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	/* verify if there is any associated immutable parser */
	list_for_each_entry_safe(curr_ref, tmp_list_ref,
				 &kparsenode->glue.glue.owned_list,
				 owned_obj.list_node) {
		if (curr_ref->owner_obj.nsid != KPARSER_NS_PARSER)
			continue;
		if (kref_read(curr_ref->owner_obj.refcount) != 0) {
			(*rsp)->op_ret_code = EBUSY;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s:attached parser `%s` is immutable",
					       op,
					       ((struct kparser_glue_parser *)
						curr_ref->owner_obj.obj)->glue.key.name);
			goto done;
		}
	}

	if (kparser_link_detach(kparsenode, &kparsenode->glue.glue.owner_list,
				&kparsenode->glue.glue.owned_list, *rsp, extack,
				err) != 0)
		goto done;

	rc = kparser_namespace_remove(KPARSER_NS_NODE_PARSE,
				      &kparsenode->glue.glue.ht_node_id,
				      &kparsenode->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: namespace remove error, rc:%d",
				       op, rc);
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparsenode->glue.glue.config.conf_keys_bv;
	(*rsp)->object.node_conf = kparsenode->glue.glue.config.node_conf;

	kparser_free(kparsenode);
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE);
}

/* free handler for object parse node */
void kparser_free_node(void *ptr, void *arg)
{
	/* TODO: */
}

/* create handler for object protocol table entry */
static bool kparser_create_proto_table_ent(const struct kparser_conf_table *arg,
					   struct kparser_glue_protocol_table **proto_table,
					   struct kparser_cmd_rsp_hdr *rsp,
					   const char *op,
					   void *extack, int *err)
{
	struct kparser_glue_glue_parse_node *kparsenode;
	void *realloced_mem;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE, &arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, &arg->elem_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: parse node key:{%s:%u} not found",
				       op, arg->elem_key.name,
				       arg->elem_key.id);
		return false;
	}

	(*proto_table)->proto_table.num_ents++;
	realloced_mem = krealloc((*proto_table)->proto_table.entries,
				 (*proto_table)->proto_table.num_ents *
				 sizeof(struct kparser_proto_table_entry),
				 GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: krealloc() err, ents:%d, size:%lu",
				       op,
				       (*proto_table)->proto_table.num_ents,
				       sizeof(struct kparser_proto_table_entry));
		return false;
	}
	rcu_assign_pointer((*proto_table)->proto_table.entries, realloced_mem);

	if (kparser_link_attach(*proto_table,
				KPARSER_NS_PROTO_TABLE,
				NULL, /* due to realloc, can't cache pointer here */
				&(*proto_table)->glue.refcount,
				&(*proto_table)->glue.owner_list,
				kparsenode,
				KPARSER_NS_NODE_PARSE,
				&kparsenode->glue.glue.refcount,
				&kparsenode->glue.glue.owned_list,
				rsp, op, extack, err) != 0)
		return false;

	(*proto_table)->proto_table.entries[(*proto_table)->proto_table.num_ents - 1].value =
			arg->optional_value1;
	(*proto_table)->proto_table.entries[(*proto_table)->proto_table.num_ents - 1].encap =
			arg->optional_value2;
	(*proto_table)->proto_table.entries[(*proto_table)->proto_table.num_ents - 1].node =
			&kparsenode->parse_node.node;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return true;
}

/* create handler for object protocol table */
int kparser_create_proto_table(const struct kparser_conf_cmd *conf,
			       size_t conf_len,
			       struct kparser_cmd_rsp_hdr **rsp,
			       size_t *rsp_len, const char *op,
			       void *extack, int *err)
{
	struct kparser_glue_protocol_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	/* create a table entry */
	if (arg->add_entry) {
		if (kparser_create_proto_table_ent(arg, &proto_table, *rsp, op,
						   extack, err) == false)
			goto done;
		goto skip_table_create;
	}

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	/* create protocol table */
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*proto_table));
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &proto_table->glue.ht_node_id,
				      &proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc:%d",
				       op, rc);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);
	INIT_LIST_HEAD(&proto_table->glue.owner_list);
	INIT_LIST_HEAD(&proto_table->glue.owned_list);

skip_table_create:
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg;

done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kparser_free(proto_table);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE);
}

/* read handler for object protocol table */
int kparser_read_proto_table(const struct kparser_hkey *key,
			     struct kparser_cmd_rsp_hdr **rsp,
			     size_t *rsp_len, __u8 recursive_read,
			     const char *op,
			     void *extack, int *err)
{
	const struct kparser_glue_protocol_table *proto_table;
	const struct kparser_glue_glue_parse_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 = proto_table->proto_table.entries[i].value;
		if (!proto_table->proto_table.entries[i].node)
			continue;
		parse_node = container_of(proto_table->proto_table.entries[i].node,
					  struct kparser_glue_glue_parse_node,
					  parse_node.node);
		objects[i].table_conf.elem_key = parse_node->glue.glue.key;
	}

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE);
}

/* delete handler for object protocol table */
int kparser_del_proto_table(const struct kparser_hkey *key,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, __u8 recursive_read,
			    const char *op,
			    void *extack, int *err)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	struct kparser_obj_link_ctx *node_tmp_list_ref = NULL;
	struct kparser_obj_link_ctx *node_curr_ref = NULL;
	struct kparser_glue_protocol_table *proto_table;
	struct kparser_glue_glue_parse_node *kparsenode;
	struct kparser_glue_glue_parse_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i, rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	/* verify if there is any associated immutable parser */
	list_for_each_entry_safe(curr_ref, tmp_list_ref,
				 &proto_table->glue.owned_list, owned_obj.list_node) {
		if (curr_ref->owner_obj.nsid != KPARSER_NS_NODE_PARSE)
			continue;
		if (kref_read(curr_ref->owner_obj.refcount) == 0)
			continue;
		kparsenode = (struct kparser_glue_glue_parse_node *)
			curr_ref->owner_obj.obj;
		list_for_each_entry_safe(node_curr_ref, node_tmp_list_ref,
					 &kparsenode->glue.glue.owned_list, owned_obj.list_node) {
			if (node_curr_ref->owner_obj.nsid != KPARSER_NS_PARSER)
				continue;
			if (kref_read(node_curr_ref->owner_obj.refcount) != 0) {
				(*rsp)->op_ret_code = EBUSY;
				NL_SET_ERR_MSG_FMT_MOD(extack,
						       "%s:attached parser `%s` is immutable",
						       op,
						       ((struct kparser_glue_parser *)
							node_curr_ref->owner_obj.obj)->glue.key.name);
				goto done;
			}
		}
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 = proto_table->proto_table.entries[i].value;
		if (!proto_table->proto_table.entries[i].node)
			continue;
		parse_node = container_of(proto_table->proto_table.entries[i].node,
					  struct kparser_glue_glue_parse_node,
					  parse_node.node);
		objects[i].table_conf.elem_key = parse_node->glue.glue.key;
	}

	if (kparser_link_detach(proto_table, &proto_table->glue.owner_list,
				&proto_table->glue.owned_list, *rsp,
				extack, err) != 0)
		goto done;

	rc = kparser_namespace_remove(KPARSER_NS_PROTO_TABLE,
				      &proto_table->glue.ht_node_id,
				      &proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: namespace remove error, rc:%d",
				       op, rc);
		goto done;
	}

	kparser_free(proto_table->proto_table.entries);
	kparser_free(proto_table);
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE);
}

/* free handler for object protocol table */
void kparser_free_proto_tbl(void *ptr, void *arg)
{
	/* TODO: */
}

/* handler to convert and map from netlink tlv node to kParser KMOD's tlv node */
static inline bool kparser_conf_tlv_node_convert(const struct kparser_conf_node_parse_tlv *conf,
						 struct kparser_parse_tlv_node *node)
{
	struct kparser_glue_parse_tlv_node *kparsewildcardnode;
	struct kparser_glue_condexpr_tables *kcond_tables;
	struct kparser_glue_proto_tlvs_table *kprototbl;
	struct kparser_glue_metadata_table *kmdl;

	if (!conf || !node)
		return false;

	node->proto_tlv_node.min_len = conf->node_proto.min_len;
	node->proto_tlv_node.max_len = conf->node_proto.max_len;
	node->proto_tlv_node.is_padding = conf->node_proto.is_padding;

	node->proto_tlv_node.ops.pfoverlay_type = conf->node_proto.ops.pfoverlay_type;
	if (node->proto_tlv_node.ops.pfoverlay_type.src_off ||
	    node->proto_tlv_node.ops.pfoverlay_type.size ||
	    node->proto_tlv_node.ops.pfoverlay_type.right_shift)
		node->proto_tlv_node.ops.overlay_type_parameterized = true;

	kcond_tables = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES,
						&conf->node_proto.ops.cond_exprs_table);
	if (kcond_tables) {
		node->proto_tlv_node.ops.cond_exprs = kcond_tables->table;
		node->proto_tlv_node.ops.cond_exprs_parameterized = true;
	}

	kprototbl = kparser_namespace_lookup(KPARSER_NS_TLV_PROTO_TABLE,
					     &conf->overlay_proto_tlvs_table_key);
	if (kprototbl)
		rcu_assign_pointer(node->overlay_table, &kprototbl->tlvs_proto_table);

	kparsewildcardnode = kparser_namespace_lookup(KPARSER_NS_TLV_NODE_PARSE,
						      &conf->overlay_wildcard_parse_node_key);
	if (kparsewildcardnode)
		rcu_assign_pointer(node->overlay_wildcard_node,
				   &kparsewildcardnode->tlv_parse_node);

	node->unknown_overlay_ret = conf->unknown_ret;
	strcpy(node->name, conf->key.name);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST,
					&conf->metadata_table_key);
	if (kmdl)
		rcu_assign_pointer(node->metadata_table, &kmdl->metadata_table);

	return true;
}

/* create handler for object tlv node */
int kparser_create_parse_tlv_node(const struct kparser_conf_cmd *conf,
				  size_t conf_len,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len, const char *op,
				  void *extack, int *err)
{
	struct kparser_glue_parse_tlv_node *node = NULL;
	const struct kparser_conf_node_parse_tlv *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->tlv_node_conf;

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object key, {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*node));
		goto done;
	}

	node->glue.glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &node->glue.glue.ht_node_id,
				      &node->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc:%d",
				       op, rc);
		goto done;
	}

	node->glue.glue.config.namespace_id = conf->namespace_id;
	node->glue.glue.config.conf_keys_bv = conf->conf_keys_bv;
	node->glue.glue.config.tlv_node_conf = *arg;
	node->glue.glue.config.tlv_node_conf.key = key;
	kref_init(&node->glue.glue.refcount);

	if (!kparser_conf_tlv_node_convert(arg, &node->tlv_parse_node)) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_conf_tlv_node_convert() err",
				       op);
		goto done;
	}

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.tlv_node_conf = node->glue.glue.config.tlv_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(node);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_NODE_PARSE);
}

/* read handler for object tlv node */
int kparser_read_parse_tlv_node(const struct kparser_hkey *key,
				struct kparser_cmd_rsp_hdr **rsp,
				size_t *rsp_len, __u8 recursive_read,
				const char *op,
				void *extack, int *err)
{
	const struct kparser_glue_parse_tlv_node *node;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	node = kparser_namespace_lookup(KPARSER_NS_TLV_NODE_PARSE, key);
	if (!node) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = node->glue.glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = node->glue.glue.config.conf_keys_bv;
	(*rsp)->object.tlv_node_conf = node->glue.glue.config.tlv_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_NODE_PARSE);
}

/* create handler for object tlv proto table's entry */
static bool kparser_create_tlv_proto_table_ent(const struct kparser_conf_table *arg,
					       struct kparser_glue_proto_tlvs_table **proto_table,
					       struct kparser_cmd_rsp_hdr *rsp,
					       const char *op,
					       void *extack, int *err)
{
	const struct kparser_glue_parse_tlv_node *kparsenode;
	void *realloced_mem;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_TLV_PROTO_TABLE, &arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_TLV_NODE_PARSE, &arg->elem_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, arg->elem_key.name, arg->elem_key.id);
		return false;
	}

	(*proto_table)->tlvs_proto_table.num_ents++;
	realloced_mem = krealloc((*proto_table)->tlvs_proto_table.entries,
				 (*proto_table)->tlvs_proto_table.num_ents *
				 sizeof(struct kparser_proto_tlvs_table_entry),
				 GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: krealloc() err, ents:%d, size:%lu",
				       op,
				       (*proto_table)->tlvs_proto_table.num_ents,
				       sizeof(struct kparser_proto_tlvs_table_entry));
		return false;
	}
	rcu_assign_pointer((*proto_table)->tlvs_proto_table.entries, realloced_mem);

	(*proto_table)->tlvs_proto_table.entries[(*proto_table)->tlvs_proto_table.num_ents -
		1].type = arg->optional_value1;
	(*proto_table)->tlvs_proto_table.entries[(*proto_table)->tlvs_proto_table.num_ents -
		1].node = &kparsenode->tlv_parse_node;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return true;
}

/* create handler for object tlv proto table */
int kparser_create_tlv_proto_table(const struct kparser_conf_cmd *conf,
				   size_t conf_len,
				   struct kparser_cmd_rsp_hdr **rsp,
				   size_t *rsp_len, const char *op,
				   void *extack, int *err)
{
	struct kparser_glue_proto_tlvs_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	/* create a table entry */
	if (arg->add_entry) {
		if (kparser_create_tlv_proto_table_ent(arg, &proto_table, *rsp,
						       op, extack, err) == false)
			goto done;
		goto skip_table_create;
	}

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	/* create protocol table */
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*proto_table));
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &proto_table->glue.ht_node_id,
				      &proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc: %d",
				       op, rc);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kparser_free(proto_table);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_PROTO_TABLE);
}

/* read handler for object tlv proto table */
int kparser_read_tlv_proto_table(const struct kparser_hkey *key,
				 struct kparser_cmd_rsp_hdr **rsp,
				 size_t *rsp_len, __u8 recursive_read,
				 const char *op,
				 void *extack, int *err)
{
	const struct kparser_glue_proto_tlvs_table *proto_table;
	const struct kparser_glue_parse_tlv_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_TLV_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->tlvs_proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 =
			proto_table->tlvs_proto_table.entries[i].type;
		if (!proto_table->tlvs_proto_table.entries[i].node)
			continue;
		parse_node = container_of(proto_table->tlvs_proto_table.entries[i].node,
					  struct kparser_glue_parse_tlv_node, tlv_parse_node);
		objects[i].table_conf.elem_key = parse_node->glue.glue.key;
	}

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_PROTO_TABLE);
}

/* create handler for object flag field */
int kparser_create_flag_field(const struct kparser_conf_cmd *conf,
			      size_t conf_len,
			      struct kparser_cmd_rsp_hdr **rsp,
			      size_t *rsp_len, const char *op,
			      void *extack, int *err)
{
	struct kparser_glue_flag_field *kobj = NULL;
	const struct kparser_conf_flag_field *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->flag_field_conf;

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*kobj));
		goto done;
	}

	kobj->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kobj->glue.ht_node_id, &kobj->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc:%d",
				       op, rc);
		goto done;
	}

	kobj->glue.config.namespace_id = conf->namespace_id;
	kobj->glue.config.conf_keys_bv = conf->conf_keys_bv;
	kobj->glue.config.flag_field_conf = *arg;
	kobj->glue.config.flag_field_conf.key = key;
	kref_init(&kobj->glue.refcount);

	kobj->flag_field = arg->conf;

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.flag_field_conf = kobj->glue.config.flag_field_conf;

done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(kobj);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD);
}

/* read handler for object flag field */
int kparser_read_flag_field(const struct kparser_hkey *key,
			    struct kparser_cmd_rsp_hdr **rsp,
			    size_t *rsp_len, __u8 recursive_read,
			    const char *op,
			    void *extack, int *err)
{
	struct kparser_glue_flag_field *kobj;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kobj = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD, key);
	if (!kobj) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kobj->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kobj->glue.config.conf_keys_bv;
	(*rsp)->object.flag_field_conf = kobj->glue.config.flag_field_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD);
}

/* compare call back to sort flag fields using their flag values in qsort API */
static int compare(const void *lhs, const void *rhs)
{
	const struct kparser_flag_field *lhs_flag = lhs;
	const struct kparser_flag_field *rhs_flag = rhs;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "lflag:%x rflag:%x\n", lhs_flag->flag, rhs_flag->flag);

	if (lhs_flag->flag < rhs_flag->flag)
		return -1;
	if (lhs_flag->flag > rhs_flag->flag)
		return 1;

	return 0;
}

/* create handler for object flag field table entry */
static bool kparser_create_flag_field_table_ent(const struct kparser_conf_table *arg,
						struct kparser_glue_flag_fields **proto_table,
						struct kparser_cmd_rsp_hdr *rsp,
						const char *op,
						void *extack, int *err)
{
	const struct kparser_glue_flag_field *kflagent;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_TABLE, &arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	kflagent = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD, &arg->elem_key);
	if (!kflagent) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, arg->elem_key.name, arg->elem_key.id);
		return false;
	}

	(*proto_table)->flag_fields.num_idx++;

	realloced_mem = krealloc((*proto_table)->flag_fields.fields,
				 (*proto_table)->flag_fields.num_idx *
				 sizeof(struct kparser_flag_field),
				 GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: krealloc() err, ents:%lu, size:%lu",
				       op,
				       (*proto_table)->flag_fields.num_idx,
				       sizeof(struct kparser_flag_field));
		return false;
	}
	rcu_assign_pointer((*proto_table)->flag_fields.fields, realloced_mem);

	(*proto_table)->flag_fields.fields[(*proto_table)->flag_fields.num_idx - 1] =
		kflagent->flag_field;

	sort((*proto_table)->flag_fields.fields,
	     (*proto_table)->flag_fields.num_idx,
	     sizeof(struct kparser_flag_field), &compare, NULL);

	for (i = 0; i < (*proto_table)->flag_fields.num_idx; i++)
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "List[%d]:%x\n",
					 i, (*proto_table)->flag_fields.fields[i].flag);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return true;
}

/* create handler for object flag field */
int kparser_create_flag_field_table(const struct kparser_conf_cmd *conf,
				    size_t conf_len,
				    struct kparser_cmd_rsp_hdr **rsp,
				    size_t *rsp_len, const char *op,
				    void *extack, int *err)
{
	struct kparser_glue_flag_fields *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	if (arg->add_entry) {
		if (kparser_create_flag_field_table_ent(arg, &proto_table, *rsp,
							op, extack, err) == false)
			goto done;
		goto skip_table_create;
	}

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*proto_table));
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &proto_table->glue.ht_node_id,
				      &proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc: %d",
				       op, rc);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kparser_free(proto_table);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_TABLE);
}

/* read handler for object flag field */
int kparser_read_flag_field_table(const struct kparser_hkey *key,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len, __u8 recursive_read,
				  const char *op,
				  void *extack, int *err)
{
	const struct kparser_glue_flag_fields *proto_table;
	const struct kparser_glue_flag_field *kflagent;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name,  key->id);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n",
				 (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->flag_fields.num_idx; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;

		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 = i;
		if (!proto_table->flag_fields.fields)
			continue;
		kflagent = container_of(&proto_table->flag_fields.fields[i],
					struct kparser_glue_flag_field, flag_field);
		objects[i].table_conf.elem_key = kflagent->glue.key;
	}

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_TABLE);
}

/* handler to convert and map netlink's flag node to kParser KMOD's flag node */
static inline bool
kparser_create_parse_flag_field_node_convert(const struct kparser_conf_node_parse_flag_field *conf,
					     struct kparser_parse_flag_field_node *node)
{
	struct kparser_glue_condexpr_tables *kcond_tables;
	struct kparser_glue_metadata_table *kmdl;

	if (!conf || !node)
		return false;

	strcpy(node->name, conf->key.name);

	kcond_tables = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES,
						&conf->ops.cond_exprs_table_key);
	if (kcond_tables)
		node->ops.cond_exprs = kcond_tables->table;

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST, &conf->metadata_table_key);
	if (kmdl)
		rcu_assign_pointer(node->metadata_table, &kmdl->metadata_table);

	return true;
}

/* create handler for object flag field node */
int kparser_create_parse_flag_field_node(const struct kparser_conf_cmd *conf,
					 size_t conf_len,
					 struct kparser_cmd_rsp_hdr **rsp,
					 size_t *rsp_len, const char *op,
					 void *extack, int *err)
{
	const struct kparser_conf_node_parse_flag_field *arg;
	struct kparser_glue_flag_field_node *node = NULL;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->flag_field_node_conf;

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu",
				       op, sizeof(*node));
		goto done;
	}

	node->glue.glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &node->glue.glue.ht_node_id, &node->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc:%d",
				       op, rc);
		goto done;
	}

	node->glue.glue.config.namespace_id = conf->namespace_id;
	node->glue.glue.config.conf_keys_bv = conf->conf_keys_bv;
	node->glue.glue.config.flag_field_node_conf = *arg;
	node->glue.glue.config.flag_field_node_conf.key = key;
	kref_init(&node->glue.glue.refcount);

	if (!kparser_create_parse_flag_field_node_convert(arg, &node->node_flag_field)) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_conf_tlv_node_convert() err",
				       op);
		goto done;
	}

	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.flag_field_node_conf = node->glue.glue.config.flag_field_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		kparser_free(node);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_NODE_PARSE);
}

/* read handler for object flag field node */
int kparser_read_parse_flag_field_node(const struct kparser_hkey *key,
				       struct kparser_cmd_rsp_hdr **rsp,
				       size_t *rsp_len, __u8 recursive_read,
				       const char *op,
				       void *extack, int *err)
{
	const struct kparser_glue_flag_field_node *node;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	node = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_NODE_PARSE, key);
	if (!node) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = node->glue.glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = node->glue.glue.config.conf_keys_bv;
	(*rsp)->object.flag_field_node_conf = node->glue.glue.config.flag_field_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_NODE_PARSE);
}

/* create handler for object flag field proto table's entry */
static bool
kparser_create_flag_field_proto_table_ent(const struct kparser_conf_table *arg,
					  struct kparser_glue_proto_flag_fields_table **proto_table,
					  struct kparser_cmd_rsp_hdr *rsp,
					  const char *op,
					  void *extack, int *err)
{
	const struct kparser_glue_flag_field_node *kparsenode;
	void *realloced_mem;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_PROTO_TABLE, &arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, arg->key.name, arg->key.id);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_NODE_PARSE, &arg->elem_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op,
				       arg->elem_key.name,
				       arg->elem_key.id);
		return false;
	}

	(*proto_table)->flags_proto_table.num_ents++;
	realloced_mem = krealloc((*proto_table)->flags_proto_table.entries,
				 (*proto_table)->flags_proto_table.num_ents *
				 sizeof(struct kparser_proto_flag_fields_table_entry),
				 GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: krealloc() err, ents:%d, size:%lu",
				       op,
				       (*proto_table)->flags_proto_table.num_ents,
				       sizeof(struct kparser_proto_flag_fields_table_entry));
		return false;
	}
	rcu_assign_pointer((*proto_table)->flags_proto_table.entries, realloced_mem);

	(*proto_table)->flags_proto_table.entries[(*proto_table)->flags_proto_table.num_ents -
		1].flag = arg->optional_value1;
	(*proto_table)->flags_proto_table.entries[(*proto_table)->flags_proto_table.num_ents -
		1].node = &kparsenode->node_flag_field;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return true;
}

/* create handler for object flag field proto table */
int kparser_create_flag_field_proto_table(const struct kparser_conf_cmd *conf,
					  size_t conf_len,
					  struct kparser_cmd_rsp_hdr **rsp,
					  size_t *rsp_len, const char *op,
					  void *extack, int *err)
{
	struct kparser_glue_proto_flag_fields_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	/* create a table entry */
	if (arg->add_entry) {
		if (kparser_create_flag_field_proto_table_ent(arg, &proto_table,
							      *rsp,
							      op, extack, err) == false)
			goto done;
		goto skip_table_create;
	}

	if (kparser_conf_key_manager(conf->namespace_id, &arg->key, &key, *rsp,
				     op, extack, err) != 0) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "error");
		goto done;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Duplicate object, key {%s:%u}",
				       op, arg->key.name, arg->key.id);
		goto done;
	}

	/* create protocol table */
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size: %lu", op,
				       sizeof(*proto_table));
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &proto_table->glue.ht_node_id,
				      &proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kparser_namespace_insert() err, rc: %d",
				       op, rc);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kparser_free(proto_table);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_PROTO_TABLE);
}

/* read handler for object flag field proto table */
int kparser_read_flag_field_proto_table(const struct kparser_hkey *key,
					struct kparser_cmd_rsp_hdr **rsp,
					size_t *rsp_len, __u8 recursive_read,
					const char *op,
					void *extack, int *err)
{
	const struct kparser_glue_proto_flag_fields_table *proto_table;
	const struct kparser_glue_flag_field_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	void *realloced_mem;
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf = proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->flags_proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		realloced_mem = krealloc(*rsp, *rsp_len, GFP_KERNEL | ___GFP_ZERO);
		if (!realloced_mem) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
						 "krealloc failed for rsp, len:%lu\n",
						 *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		*rsp = realloced_mem;

		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id = proto_table->glue.config.namespace_id;
		objects[i].table_conf = proto_table->glue.config.table_conf;
		if (!proto_table->flags_proto_table.entries[i].node)
			continue;
		objects[i].table_conf.optional_value1 =
			proto_table->flags_proto_table.entries[i].flag;
		parse_node = container_of(proto_table->flags_proto_table.entries[i].node,
					  struct kparser_glue_flag_field_node,
					  node_flag_field);
		objects[i].table_conf.elem_key = parse_node->glue.glue.key;
	}

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_PROTO_TABLE);
}

/* conevrt and map from netlink's parser to kParser KMOD's parser */
static inline bool kparser_parser_convert(const struct kparser_conf_parser *conf,
					  struct kparser_parser *parser)
{
	struct kparser_glue_glue_parse_node *node;

	strcpy(parser->name, conf->key.name);

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, &conf->root_node_key);
	if (node)
		rcu_assign_pointer(parser->root_node, &node->parse_node.node);
	else
		return false;

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, &conf->ok_node_key);
	if (node)
		rcu_assign_pointer(parser->okay_node, &node->parse_node.node);

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, &conf->fail_node_key);
	if (node)
		rcu_assign_pointer(parser->fail_node, &node->parse_node.node);

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, &conf->atencap_node_key);
	if (node)
		rcu_assign_pointer(parser->atencap_node, &node->parse_node.node);

	parser->cntrs_conf = cntrs_conf;

	parser->config = conf->config;
	return true;
}

/* create handler for object parser */
int kparser_create_parser(const struct kparser_conf_cmd *conf,
			  size_t conf_len,
			  struct kparser_cmd_rsp_hdr **rsp,
			  size_t *rsp_len, const char *op,
			  void *extack, int *err)
{
	struct kparser_glue_glue_parse_node *parse_node;
	struct kparser_glue_parser *kparser = NULL;
	struct kparser_counters *cntrs = NULL;
	const struct kparser_conf_parser *arg;
	struct kparser_parser parser = {};
	struct kparser_hkey key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	arg = &conf->parser_conf;

	cntrs = kzalloc(sizeof(*cntrs), GFP_KERNEL);
	if (!cntrs) {
		(*rsp)->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc() failed, size:%lu",
				       op, sizeof(*cntrs));
		goto done;
	}
	rcu_assign_pointer(parser.cntrs, cntrs);
	parser.cntrs_len = sizeof(*cntrs);
	parser.kparser_start_signature = KPARSERSTARTSIGNATURE;
	parser.kparser_end_signature = KPARSERENDSIGNATURE;
	if (!kparser_parser_convert(arg, &parser)) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: parser arg convert error", op);
		goto done;
	}

	if (!kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
					    (void **)&kparser, sizeof(*kparser), *rsp,
					    offsetof(struct kparser_glue_parser,
						     glue), extack, err))
		goto done;

	kparser->parser = parser;

	INIT_LIST_HEAD(&kparser->glue.owner_list);
	INIT_LIST_HEAD(&kparser->glue.owned_list);

	if (kparser->parser.root_node) {
		parse_node = container_of(kparser->parser.root_node,
					  struct kparser_glue_glue_parse_node,
					  parse_node.node);
		if (kparser_link_attach(kparser,
					KPARSER_NS_PARSER,
					(const void **)&kparser->parser.root_node,
					&kparser->glue.refcount,
					&kparser->glue.owner_list,
					parse_node,
					KPARSER_NS_NODE_PARSE,
					&parse_node->glue.glue.refcount,
					&parse_node->glue.glue.owned_list,
					*rsp, op, extack, err) != 0)
			goto done;
	}

	if (kparser->parser.okay_node) {
		parse_node = container_of(kparser->parser.okay_node,
					  struct kparser_glue_glue_parse_node,
					  parse_node.node);
		if (kparser_link_attach(kparser,
					KPARSER_NS_PARSER,
					(const void **)&kparser->parser.okay_node,
					&kparser->glue.refcount,
					&kparser->glue.owner_list,
					parse_node,
					KPARSER_NS_NODE_PARSE,
					&parse_node->glue.glue.refcount,
					&parse_node->glue.glue.owned_list,
					*rsp, op, extack, err) != 0)
			goto done;
	}

	if (kparser->parser.fail_node) {
		parse_node = container_of(kparser->parser.fail_node,
					  struct kparser_glue_glue_parse_node,
					  parse_node.node);
		if (kparser_link_attach(kparser,
					KPARSER_NS_PARSER,
					(const void **)&kparser->parser.fail_node,
					&kparser->glue.refcount,
					&kparser->glue.owner_list,
					parse_node,
					KPARSER_NS_NODE_PARSE,
					&parse_node->glue.glue.refcount,
					&parse_node->glue.glue.owned_list,
					*rsp, op, extack, err) != 0)
			goto done;
	}

	if (kparser->glue.key.id >= KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_START &&
	    kparser->glue.key.id <= KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_STOP)
		rcu_assign_pointer(kparser_fast_lookup_array[kparser->glue.key.id], kparser);
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		kparser_free(kparser);
		kparser_free(cntrs);
	}

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_PARSER);
}

static bool kparser_dump_protocol_table(const struct kparser_proto_table *obj,
					struct kparser_cmd_rsp_hdr **rsp,
					size_t *rsp_len,
					void *extack, int *err);

/* dump metadata list to netlink msg rsp */
static bool kparser_dump_metadata_table(const struct kparser_metadata_table *obj,
					struct kparser_cmd_rsp_hdr **rsp,
					size_t *rsp_len,
					void *extack, int *err)
{
	const struct kparser_glue_metadata_table *glue_obj;
	struct kparser_cmd_rsp_hdr *new_rsp = NULL;
	size_t new_rsp_len = 0;
	void *realloced_mem;
	void *ptr;
	int rc;

	if (!obj)
		return true;

	rc = alloc_first_rsp(&new_rsp, &new_rsp_len, KPARSER_NS_METALIST);
	if (rc) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "alloc_first_rsp() failed, rc:%d\n",
					 rc);
		return false;
	}

	glue_obj = container_of(obj, struct kparser_glue_metadata_table, metadata_table);

	/* NOTE: TODO: kparser_config_lock should not be released and reacquired here. Fix later. */
	mutex_unlock(&kparser_config_lock);
	rc = kparser_read_metalist(&glue_obj->glue.key,
				   &new_rsp, &new_rsp_len, false, "read",
				   extack, err);
	mutex_lock(&kparser_config_lock);

	if (rc != KPARSER_ATTR_RSP(KPARSER_NS_METALIST))
		goto error;

	realloced_mem = krealloc(*rsp, *rsp_len + new_rsp_len, GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem)
		goto error;
	*rsp = realloced_mem;

	ptr = (*rsp);
	ptr += (*rsp_len);
	(*rsp_len) = (*rsp_len) + new_rsp_len;
	memcpy(ptr, new_rsp, new_rsp_len);
	kparser_free(new_rsp);
	new_rsp = NULL;

	return true;
error:
	kparser_free(new_rsp);

	return false;
}

/* dump parse node to netlink msg rsp */
static bool kparser_dump_parse_node(const struct kparser_parse_node *obj,
				    struct kparser_cmd_rsp_hdr **rsp,
				    size_t *rsp_len,
				    void *extack, int *err)
{
	const struct kparser_glue_glue_parse_node *glue_obj;
	struct kparser_cmd_rsp_hdr *new_rsp = NULL;
	size_t new_rsp_len = 0;
	void *realloced_mem;
	void *ptr;
	int rc;

	if (!obj)
		return true;

	rc = alloc_first_rsp(&new_rsp, &new_rsp_len, KPARSER_NS_NODE_PARSE);
	if (rc) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "alloc_first_rsp() failed, rc:%d\n", rc);
		return false;
	}

	glue_obj = container_of(obj, struct kparser_glue_glue_parse_node, parse_node.node);

	/* NOTE: TODO: kparser_config_lock should not be released and reacquired here. Fix later. */
	mutex_unlock(&kparser_config_lock);
	rc = kparser_read_parse_node(&glue_obj->glue.glue.key,
				     &new_rsp, &new_rsp_len, false, "read",
				     extack, err);
	mutex_lock(&kparser_config_lock);

	if (rc != KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE))
		goto error;

	realloced_mem = krealloc(*rsp, *rsp_len + new_rsp_len, GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem)
		goto error;
	*rsp = realloced_mem;

	ptr = (*rsp);
	ptr += (*rsp_len);
	(*rsp_len) = (*rsp_len) + new_rsp_len;
	memcpy(ptr, new_rsp, new_rsp_len);
	kparser_free(new_rsp);
	new_rsp = NULL;

	if (!kparser_dump_protocol_table(obj->proto_table, rsp, rsp_len, extack,
					 err))
		goto error;

	if (!kparser_dump_metadata_table(obj->metadata_table, rsp, rsp_len,
					 extack, err))
		goto error;

	return true;
error:
	kparser_free(new_rsp);

	return false;
}

/* dump protocol table to netlink msg rsp */
static bool kparser_dump_protocol_table(const struct kparser_proto_table *obj,
					struct kparser_cmd_rsp_hdr **rsp,
					size_t *rsp_len,
					void *extack, int *err)
{
	const struct kparser_glue_protocol_table *glue_obj;
	struct kparser_cmd_rsp_hdr *new_rsp = NULL;
	size_t new_rsp_len = 0;
	void *realloced_mem;
	void *ptr;
	int rc, i;

	if (!obj)
		return true;

	rc = alloc_first_rsp(&new_rsp, &new_rsp_len, KPARSER_NS_PROTO_TABLE);
	if (rc) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "alloc_first_rsp() failed, rc:%d\n", rc);
		return false;
	}

	glue_obj = container_of(obj, struct kparser_glue_protocol_table,
				proto_table);

	/* NOTE: TODO: kparser_config_lock should not be released and reacquired here. Fix later. */
	mutex_unlock(&kparser_config_lock);
	rc = kparser_read_proto_table(&glue_obj->glue.key,
				      &new_rsp, &new_rsp_len, false, "read",
				      extack, err);
	mutex_lock(&kparser_config_lock);

	if (rc != KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE))
		goto error;

	realloced_mem = krealloc(*rsp, *rsp_len + new_rsp_len, GFP_KERNEL | ___GFP_ZERO);
	if (!realloced_mem)
		goto error;
	*rsp = realloced_mem;

	ptr = (*rsp);
	ptr += (*rsp_len);
	(*rsp_len) = (*rsp_len) + new_rsp_len;
	memcpy(ptr, new_rsp, new_rsp_len);
	kparser_free(new_rsp);
	new_rsp = NULL;

	for (i = 0; i < glue_obj->proto_table.num_ents; i++)
		if (!kparser_dump_parse_node(glue_obj->proto_table.entries[i].node,
					     rsp, rsp_len, extack, err))
			goto error;

	return true;
error:
	kparser_free(new_rsp);

	return false;
}

/* dump parser to netlink msg rsp */
static bool kparser_dump_parser(const struct kparser_glue_parser *kparser,
				struct kparser_cmd_rsp_hdr **rsp,
				size_t *rsp_len,
				void *extack, int *err)
{
	/* DEBUG code, if(0) avoids warning for both compiler and checkpatch */
	if (0)
		kparser_dump_parser_tree(&kparser->parser);

	kparser_start_new_tree_traversal();

	if (!kparser_dump_parse_node(kparser->parser.root_node, rsp, rsp_len,
				     extack, err))
		goto error;

	return true;
error:
	return false;
}

/* read handler for object parser */
int kparser_read_parser(const struct kparser_hkey *key,
			struct kparser_cmd_rsp_hdr **rsp,
			size_t *rsp_len, __u8 recursive_read,
			const char *op,
			void *extack, int *err)
{
	const struct kparser_glue_parser *kparser;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparser = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparser) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = kparser->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparser->glue.config.conf_keys_bv;
	(*rsp)->object.parser_conf = kparser->glue.config.parser_conf;

	if (recursive_read &&
	    kparser_dump_parser(kparser, rsp, rsp_len, extack, err) == false)
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "kparser_dump_parser failed");

done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_PARSER);
}

/* delete handler for object parser */
int kparser_del_parser(const struct kparser_hkey *key,
		       struct kparser_cmd_rsp_hdr **rsp,
		       size_t *rsp_len, __u8 recursive_read,
		       const char *op,
		       void *extack, int *err)
{
	struct kparser_glue_parser *kparser;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparser = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparser) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	if (kparser_link_detach(kparser, &kparser->glue.owner_list,
				&kparser->glue.owned_list, *rsp,
				extack, err) != 0)
		goto done;

	rc = kparser_namespace_remove(KPARSER_NS_PARSER,
				      &kparser->glue.ht_node_id, &kparser->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: namespace remove error, rc:%d",
				       op, rc);
		goto done;
	}

	(*rsp)->key = kparser->glue.key;
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
				 "Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparser->glue.config.conf_keys_bv;
	(*rsp)->object.parser_conf = kparser->glue.config.parser_conf;

	if (kparser->glue.key.id >= KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_START &&
	    kparser->glue.key.id <= KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_STOP)
		rcu_assign_pointer(kparser_fast_lookup_array[kparser->glue.key.id], NULL);

	kparser_free(kparser->parser.cntrs);
	kparser_free(kparser);
done:
	mutex_unlock(&kparser_config_lock);
	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_PARSER);
}

/* free handler for object parser */
void kparser_free_parser(void *ptr, void *arg)
{
	/* TODO: */
}

/* handler for object parser lock */
int kparser_parser_lock(const struct kparser_conf_cmd *conf,
			size_t conf_len,
			struct kparser_cmd_rsp_hdr **rsp,
			size_t *rsp_len, const char *op,
			void *extack, int *err)
{
	const struct kparser_parser *parser;
	const struct kparser_hkey *key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	mutex_lock(&kparser_config_lock);

	key = &conf->obj_key;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	parser = kparser_get_parser(key, false);
	if (!parser) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	(*rsp)->key = *key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.obj_key = *key;
done:
	mutex_unlock(&kparser_config_lock);

	synchronize_rcu();

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_OP_PARSER_LOCK_UNLOCK);
}

/* handler for object parser unlock */
int kparser_parser_unlock(const struct kparser_hkey *key,
			  struct kparser_cmd_rsp_hdr **rsp,
			  size_t *rsp_len, __u8 recursive_read,
			  const char *op,
			  void *extack, int *err)
{
	const struct kparser_glue_parser *kparser;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparser = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparser) {
		(*rsp)->op_ret_code = ENOENT;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: object not found, key: {%s:%u}",
				       op, key->name, key->id);
		goto done;
	}

	if (!kparser_put_parser(&kparser->parser, false)) {
		(*rsp)->op_ret_code = EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: Parser unlock failed",
				       op);
		goto done;
	}

	(*rsp)->key = *key;
	(*rsp)->object.obj_key = *key;
done:
	mutex_unlock(&kparser_config_lock);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return KPARSER_ATTR_RSP(KPARSER_NS_OP_PARSER_LOCK_UNLOCK);
}
