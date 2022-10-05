// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_cmds.c - kParser KMOD-CLI management API layer
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <linux/bitops.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/netlink.h>

#include "kparser.h"

#define KREF_INIT_VALUE		1

/* These are used to track node loops in parse tree traversal operations */
static __u64 curr_traversal_ts_id_ns;

/* This function marks a start of a new parse tree traversal operation */
void kparser_start_new_tree_traversal(void)
{
	curr_traversal_ts_id_ns = ktime_get_ns();
}

/* A simple wrapper for kfree for additional future internal debug info, particularly to
 * track memleaks
 */
void kparser_free(void *ptr)
{
	if (ptr)
		kfree(ptr);
}

/* Kernel API kref_put() must have a non-NULL callback, since we don't need to do anything during
 * refcount release, kparser_release_ref() is just empty.
 */
static void kparser_release_ref(struct kref *kref)
{
}

/* Consumer of this is datapath */
void kparser_ref_get(struct kref *refcount)
{
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "refcnt:%u\n", kref_read(refcount));

	kref_get(refcount);
}

/* Consumer of this is datapath */
void kparser_ref_put(struct kref *refcount)
{
	unsigned int refcnt;

	refcnt = kref_read(refcount);
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "refcnt:%u\n", refcnt);

	if (refcnt > KREF_INIT_VALUE)
		kref_put(refcount, kparser_release_ref);
	else
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "refcount violation detected, val:%u", refcnt);
}

/* These are to track/bookkeep owner/owned relationships(both ways) when refcount is involved among
 * various different types of namespace objects
 */
int kparser_link_attach(const void *owner_obj,
			int owner_nsid,
			const void **owner_obj_link_ptr,
			struct kref *owner_obj_refcount,
			struct list_head *owner_list,
			const void *owned_obj,
			int owned_nsid,
			struct kref *owned_obj_refcount,
			struct list_head *owned_list,
			struct kparser_cmd_rsp_hdr *rsp,
			const char *op,
			void *extack, int *err)
{
	struct kparser_obj_link_ctx *reflist = NULL;

	reflist = kzalloc(sizeof(*reflist), GFP_KERNEL);
	if (!reflist) {
		rsp->op_ret_code = ENOMEM;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s: kzalloc failed, size: %lu",
				       op, sizeof(*reflist));
		return -ENOMEM;
	}

	reflist->sig = KPARSER_LINK_OBJ_SIGNATURE;
	reflist->owner_obj.nsid = owner_nsid;
	reflist->owner_obj.obj = owner_obj;
	reflist->owner_obj.link_ptr = owner_obj_link_ptr;
	reflist->owner_obj.list = owner_list;
	reflist->owner_obj.refcount = owner_obj_refcount;

	reflist->owned_obj.nsid = owned_nsid;
	reflist->owned_obj.obj = owned_obj;
	reflist->owned_obj.list = owned_list;
	reflist->owned_obj.refcount = owned_obj_refcount;

	/* reflist is a bookkeeping tracker which maps an owner with owned, both ways.
	 * hence for both owner and owned map contexts, it is kept in their respective lists.
	 */
	list_add_tail(&reflist->owner_obj.list_node, reflist->owner_obj.list);
	list_add_tail(&reflist->owned_obj.list_node, reflist->owned_obj.list);

	if (reflist->owned_obj.refcount)
		kref_get(reflist->owned_obj.refcount);

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "owner:%p owned:%p ref:%p\n",
				 owner_obj, owned_obj, reflist);

	synchronize_rcu();

	return 0;
}

/* It is reverse bookkeeping action of kparser_link_attach(). when an object is detached (be it
 * owner or owned, the respective map links needs be properly updated to indicate this detachment.
 * kparser_link_break() is responsible for this removal update.
 */
static inline int kparser_link_break(const void *owner, const void *owned,
				     struct kparser_obj_link_ctx *ref,
				     struct kparser_cmd_rsp_hdr *rsp,
				     void *extack, int *err)
{
	if (!ref) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "link is NULL!");
		}
		return -EFAULT;
	}

	if (ref->sig != KPARSER_LINK_OBJ_SIGNATURE) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "link is corrupt!");
		}
		return -EFAULT;
	}

	if (owner && ref->owner_obj.obj != owner) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "link owner corrupt!");
		}
		return -EFAULT;
	}

	if (owned && ref->owned_obj.obj != owned) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "link owned corrupt!");
		}
		return -EFAULT;
	}

	if (ref->owned_obj.refcount)
		kref_put(ref->owned_obj.refcount, kparser_release_ref);

	if (ref->owner_obj.link_ptr)
		rcu_assign_pointer(*ref->owner_obj.link_ptr, NULL);

	list_del_init_careful(&ref->owner_obj.list_node);
	list_del_init_careful(&ref->owned_obj.list_node);

	synchronize_rcu();

	return 0;
}

/* when a detachment happens, from owner object perspective, it needs to remove the bookkeeping
 * map contexts with respect to mapped owned objects.
 */
static inline int kparser_link_detach_owner(const void *obj,
					    struct list_head *list,
					    struct kparser_cmd_rsp_hdr *rsp,
					    void *extack, int *err)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;

	list_for_each_entry_safe(curr_ref, tmp_list_ref, list, owner_obj.list_node) {
		if (kparser_link_break(obj, NULL, curr_ref, rsp, extack, err) != 0)
			return -EFAULT;
		kparser_free(curr_ref);
	}

	return 0;
}

/* when a detachment happens, from owned object perspective, it needs to remove the bookkeeping
 * map contexts with respect to mapped owner objects.
 */
static inline int kparser_link_detach_owned(const void *obj,
					    struct list_head *list,
					    struct kparser_cmd_rsp_hdr *rsp,
					    void *extack, int *err)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	const struct kparser_glue_glue_parse_node *kparsenode;
	const struct kparser_glue_protocol_table *proto_table;
	int i;

	list_for_each_entry_safe(curr_ref, tmp_list_ref, list, owned_obj.list_node) {
		/* Special case handling:
		 * if this is parse node and owned by a prototable, make sure
		 * to remove that table's entry from array separately
		 */
		if (curr_ref->owner_obj.nsid == KPARSER_NS_PROTO_TABLE &&
		    curr_ref->owned_obj.nsid == KPARSER_NS_NODE_PARSE) {
			proto_table = curr_ref->owner_obj.obj;
			kparsenode = curr_ref->owned_obj.obj;
			for (i = 0; i < proto_table->proto_table.num_ents;
					i++) {
				if (proto_table->proto_table.entries[i].node !=
						&kparsenode->parse_node.node)
					continue;
				rcu_assign_pointer(proto_table->proto_table.entries[i].node, NULL);
				memset(&proto_table->proto_table.entries[i], 0,
				       sizeof(proto_table->proto_table.entries[i]));
				synchronize_rcu();
				break;
			}
		}

		if (kparser_link_break(NULL, obj, curr_ref, rsp, extack, err) != 0)
			return -EFAULT;
		kparser_free(curr_ref);
	}

	return 0;
}

/* bookkeeping function to break a link between an owner and owned object */
int kparser_link_detach(const void *obj,
			struct list_head *owner_list,
			struct list_head *owned_list,
			struct kparser_cmd_rsp_hdr *rsp,
			void *extack, int *err)
{
	if (kparser_link_detach_owner(obj, owner_list, rsp, extack, err) != 0)
		return -EFAULT;

	if (kparser_link_detach_owned(obj, owned_list, rsp, extack, err) != 0)
		return -EFAULT;

	return 0;
}

/* kParser KMOD's namespace definitions */
struct kparser_mod_namespaces {
	enum kparser_global_namespace_ids namespace_id;
	const char *name;
	struct kparser_htbl htbl_name;
	struct kparser_htbl htbl_id;
	kparser_obj_create_update *create_handler;
	kparser_obj_create_update *update_handler;
	kparser_obj_read_del *read_handler;
	kparser_obj_read_del *del_handler;
	kparser_free_obj *free_handler;
	size_t bv_len;
	unsigned long *bv;
};

/* Statically define kParser KMOD's namespaces with all the parameters */
#define KPARSER_DEFINE_MOD_NAMESPACE(g_ns_obj, NSID, OBJ_NAME, FIELD, CREATE,	\
				     READ, UPDATE, DELETE, FREE)		\
static struct kparser_mod_namespaces g_ns_obj = {				\
	.namespace_id = NSID,							\
	.name = #NSID,								\
	.htbl_name =	{							\
		.tbl_params = {							\
			.head_offset = offsetof(				\
					struct OBJ_NAME,			\
					FIELD.ht_node_name),			\
			.key_offset = offsetof(					\
					struct OBJ_NAME,			\
					FIELD.key.name),			\
			.key_len = sizeof(((struct kparser_hkey *)0)->name),	\
			.automatic_shrinking = true,				\
			.hashfn = kparser_generic_hash_fn_name,			\
			.obj_hashfn = kparser_generic_obj_hashfn_name,		\
			.obj_cmpfn = kparser_cmp_fn_name,			\
		}								\
	},									\
	.htbl_id =	{							\
		.tbl_params = {							\
			.head_offset = offsetof(				\
					struct OBJ_NAME,			\
					FIELD.ht_node_id),			\
			.key_offset = offsetof(					\
					struct OBJ_NAME,			\
					FIELD.key.id),				\
			.key_len = sizeof(((struct kparser_hkey *)0)->id),	\
			.automatic_shrinking = true,				\
			.hashfn = kparser_generic_hash_fn_id,			\
			.obj_hashfn = kparser_generic_obj_hashfn_id,		\
			.obj_cmpfn = kparser_cmp_fn_id,				\
		}								\
	},									\
										\
	.create_handler = CREATE,						\
	.read_handler = READ,							\
	.update_handler = UPDATE,						\
	.del_handler = DELETE,							\
	.free_handler = FREE,							\
}

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_condexprs,
			     KPARSER_NS_CONDEXPRS,
			     kparser_glue_condexpr_expr,
			     glue,
			     kparser_create_cond_exprs,
			     kparser_read_cond_exprs,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_condexprs_table,
			     KPARSER_NS_CONDEXPRS_TABLE,
			     kparser_glue_condexpr_table,
			     glue,
			     kparser_create_cond_table,
			     kparser_read_cond_table,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_condexprs_tables,
			     KPARSER_NS_CONDEXPRS_TABLES,
			     kparser_glue_condexpr_tables,
			     glue,
			     kparser_create_cond_tables,
			     kparser_read_cond_tables,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_counter,
			     KPARSER_NS_COUNTER,
			     kparser_glue_counter,
			     glue,
			     kparser_create_counter,
			     kparser_read_counter,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_counter_table,
			     KPARSER_NS_COUNTER_TABLE,
			     kparser_glue_counter_table,
			     glue,
			     kparser_create_counter_table,
			     kparser_read_counter_table,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_metadata,
			     KPARSER_NS_METADATA,
			     kparser_glue_metadata_extract,
			     glue,
			     kparser_create_metadata,
			     kparser_read_metadata,
			     NULL,
			     kparser_del_metadata,
			     kparser_free_metadata);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_metalist,
			     KPARSER_NS_METALIST,
			     kparser_glue_metadata_table,
			     glue,
			     kparser_create_metalist,
			     kparser_read_metalist,
			     NULL,
			     kparser_del_metalist,
			     kparser_free_metalist);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_node_parse,
			     KPARSER_NS_NODE_PARSE,
			     kparser_glue_glue_parse_node,
			     glue.glue,
			     kparser_create_parse_node,
			     kparser_read_parse_node,
			     NULL,
			     kparser_del_parse_node,
			     kparser_free_node);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_proto_table,
			     KPARSER_NS_PROTO_TABLE,
			     kparser_glue_protocol_table,
			     glue,
			     kparser_create_proto_table,
			     kparser_read_proto_table,
			     NULL,
			     kparser_del_proto_table,
			     kparser_free_proto_tbl);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_tlv_node_parse,
			     KPARSER_NS_TLV_NODE_PARSE,
			     kparser_glue_parse_tlv_node,
			     glue.glue,
			     kparser_create_parse_tlv_node,
			     kparser_read_parse_tlv_node,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_tlv_proto_table,
			     KPARSER_NS_TLV_PROTO_TABLE,
			     kparser_glue_proto_tlvs_table,
			     glue,
			     kparser_create_tlv_proto_table,
			     kparser_read_tlv_proto_table,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field,
			     KPARSER_NS_FLAG_FIELD,
			     kparser_glue_flag_field,
			     glue,
			     kparser_create_flag_field,
			     kparser_read_flag_field,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field_table,
			     KPARSER_NS_FLAG_FIELD_TABLE,
			     kparser_glue_flag_fields,
			     glue,
			     kparser_create_flag_field_table,
			     kparser_read_flag_field_table,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field_parse_node,
			     KPARSER_NS_FLAG_FIELD_NODE_PARSE,
			     kparser_glue_flag_field_node,
			     glue.glue,
			     kparser_create_parse_flag_field_node,
			     kparser_read_parse_flag_field_node,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field_proto_table,
			     KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
			     kparser_glue_proto_flag_fields_table,
			     glue,
			     kparser_create_flag_field_proto_table,
			     kparser_read_flag_field_proto_table,
			     NULL, NULL, NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_parser,
			     KPARSER_NS_PARSER,
			     kparser_glue_parser,
			     glue,
			     kparser_create_parser,
			     kparser_read_parser,
			     NULL,
			     kparser_del_parser,
			     kparser_free_parser);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_parser_lock_unlock,
			     KPARSER_NS_OP_PARSER_LOCK_UNLOCK,
			     kparser_glue_parser,
			     glue,
			     kparser_parser_lock,
			     NULL, NULL,
			     kparser_parser_unlock,
			     NULL);

static struct kparser_mod_namespaces *g_mod_namespaces[] = {
	[KPARSER_NS_INVALID] = NULL,
	[KPARSER_NS_CONDEXPRS] = &kparser_mod_namespace_condexprs,
	[KPARSER_NS_CONDEXPRS_TABLE] = &kparser_mod_namespace_condexprs_table,
	[KPARSER_NS_CONDEXPRS_TABLES] =
		&kparser_mod_namespace_condexprs_tables,
	[KPARSER_NS_COUNTER] = &kparser_mod_namespace_counter,
	[KPARSER_NS_COUNTER_TABLE] = &kparser_mod_namespace_counter_table,
	[KPARSER_NS_METADATA] = &kparser_mod_namespace_metadata,
	[KPARSER_NS_METALIST] = &kparser_mod_namespace_metalist,
	[KPARSER_NS_NODE_PARSE] = &kparser_mod_namespace_node_parse,
	[KPARSER_NS_PROTO_TABLE] = &kparser_mod_namespace_proto_table,
	[KPARSER_NS_TLV_NODE_PARSE] = &kparser_mod_namespace_tlv_node_parse,
	[KPARSER_NS_TLV_PROTO_TABLE] = &kparser_mod_namespace_tlv_proto_table,
	[KPARSER_NS_FLAG_FIELD] = &kparser_mod_namespace_flag_field,
	[KPARSER_NS_FLAG_FIELD_TABLE] =
		&kparser_mod_namespace_flag_field_table,
	[KPARSER_NS_FLAG_FIELD_NODE_PARSE] =
		&kparser_mod_namespace_flag_field_parse_node,
	[KPARSER_NS_FLAG_FIELD_PROTO_TABLE] =
		&kparser_mod_namespace_flag_field_proto_table,
	[KPARSER_NS_PARSER] = &kparser_mod_namespace_parser,
	[KPARSER_NS_OP_PARSER_LOCK_UNLOCK] =
		&kparser_mod_namespace_parser_lock_unlock,
	[KPARSER_NS_MAX] = NULL,
};

/* Function to allocate autogen IDs for hash keys if user did not allocate themselves
 * TODO: free ids
 */
static inline __u16 allocate_id(__u16 id, unsigned long *bv, size_t bvsize)
{
	int i;

	if (id != KPARSER_INVALID_ID) {
		/* try to allocate passed id */
		/* already allocated, conflict */
		if (!test_bit(id, bv))
			return KPARSER_INVALID_ID;
		__clear_bit(id, bv);
		return id;
	}

	/* allocate internally, scan bitvector */
	for (i = 0; i < bvsize; i++) {
		/* avoid bit vectors which are already full */
		if (bv[i]) {
			id = __builtin_ffsl(bv[i]);
			if (id) {
				id--;
				id += (i * BITS_PER_TYPE(unsigned long));
				__clear_bit(id, bv);
				return (id + KPARSER_KMOD_ID_MIN);
			}
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "ID alloc failed: {%d:%d}\n",
						 id, i);
			return KPARSER_INVALID_ID;
		}
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "ID alloc failed: {%d:%d}\n", id, i);
	return KPARSER_INVALID_ID;
}

/* allocate hash key's autogen ID */
static inline int kparser_allocate_key_id(enum kparser_global_namespace_ids ns_id,
					  const struct kparser_hkey *key,
					  struct kparser_hkey *new_key)
{
	*new_key = *key;
	new_key->id = allocate_id(KPARSER_INVALID_ID,
				  g_mod_namespaces[ns_id]->bv,
				  g_mod_namespaces[ns_id]->bv_len);

	if (new_key->id == KPARSER_INVALID_ID)
		return -ENOENT;

	return 0;
}

/* allocate hash key's autogen name */
static inline bool kparser_allocate_key_name(enum kparser_global_namespace_ids ns_id,
					     const struct kparser_hkey *key,
					     struct kparser_hkey *new_key)
{
	*new_key = *key;
	memset(new_key->name, 0, sizeof(new_key->name));
	snprintf(new_key->name, sizeof(new_key->name),
		 "%s-%s-%u", KPARSER_DEF_NAME_PREFIX,
		 g_mod_namespaces[ns_id]->name, key->id);
	new_key->name[sizeof(new_key->name) - 1] = '\0';
	return true;
}

/* check and decide which component of hash key needs to be allocated using autogen code */
int kparser_conf_key_manager(enum kparser_global_namespace_ids ns_id,
			     const struct kparser_hkey *key,
			     struct kparser_hkey *new_key,
			     struct kparser_cmd_rsp_hdr *rsp,
			     const char *op,
			     void *extack, int *err)
{
	if (kparser_hkey_empty(key)) {
		rsp->op_ret_code = -EINVAL;
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "%s:HKey missing", op);
		return -EINVAL;
	}

	if (kparser_hkey_id_empty(key) && new_key)
		return kparser_allocate_key_id(ns_id, key, new_key);

	if (kparser_hkey_user_id_invalid(key)) {
		rsp->op_ret_code = -EINVAL;
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "%s:HKey id invalid:%u",
				       op, key->id);
		return -EINVAL;
	}

	if (kparser_hkey_name_empty(key) && new_key)
		return kparser_allocate_key_name(ns_id, key, new_key);

	if (new_key)
		*new_key = *key;

	return 0;
}

/* remove an object from namespace */
int kparser_namespace_remove(enum kparser_global_namespace_ids ns_id,
			     struct rhash_head *obj_id,
			     struct rhash_head *obj_name)
{
	int rc;

	if (ns_id <= KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return -EINVAL;

	if (!g_mod_namespaces[ns_id])
		return -ENOENT;

	rc = rhashtable_remove_fast(&g_mod_namespaces[ns_id]->htbl_id.tbl, obj_id,
				    g_mod_namespaces[ns_id]->htbl_id.tbl_params);

	if (rc)
		return rc;

	rc = rhashtable_remove_fast(&g_mod_namespaces[ns_id]->htbl_name.tbl, obj_name,
				    g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return rc;
}

/* lookup an object using hash key from namespace */
void *kparser_namespace_lookup(enum kparser_global_namespace_ids ns_id,
			       const struct kparser_hkey *key)
{
	void *ret;

	if (ns_id <= KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return NULL;

	if (!g_mod_namespaces[ns_id])
		return NULL;

	ret = rhashtable_lookup(&g_mod_namespaces[ns_id]->htbl_id.tbl,
				&key->id,
				g_mod_namespaces[ns_id]->htbl_id.tbl_params);

	if (ret)
		return ret;

	ret = rhashtable_lookup(&g_mod_namespaces[ns_id]->htbl_name.tbl,
				key->name,
				g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return ret;
}

/* insert an object using hash key into namespace */
int kparser_namespace_insert(enum kparser_global_namespace_ids ns_id,
			     struct rhash_head *obj_id,
			     struct rhash_head *obj_name)
{
	int rc;

	if (ns_id <= KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return -EINVAL;

	if (!g_mod_namespaces[ns_id])
		return -ENOENT;

	rc = rhashtable_insert_fast(&g_mod_namespaces[ns_id]->htbl_id.tbl, obj_id,
				    g_mod_namespaces[ns_id]->htbl_id.tbl_params);
	if (rc)
		return rc;

	rc = rhashtable_insert_fast(&g_mod_namespaces[ns_id]->htbl_name.tbl, obj_name,
				    g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return rc;
}

/* allocate the manadatory very first response header (rsp) for netlink reply msg */
int alloc_first_rsp(struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len, int nsid)
{
	if (!rsp || *rsp || !rsp_len || (*rsp_len != 0))
		return -EINVAL;

	*rsp = kzalloc(sizeof(**rsp), GFP_KERNEL);
	if (!(*rsp)) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, ":kzalloc failed for rsp, size:%lu\n",
					 sizeof(**rsp));
		return -ENOMEM;
	}

	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);
	(*rsp)->object.namespace_id = nsid;
	(*rsp)->objects_len = 0;
	return 0;
}

/* initialize kParser's name space manager contexts */
int kparser_init(void)
{
	int err, i, j;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	for (i = 0; i < (sizeof(g_mod_namespaces) /
				sizeof(g_mod_namespaces[0])); i++) {
		if (!g_mod_namespaces[i])
			continue;

		err = rhashtable_init(&g_mod_namespaces[i]->htbl_name.tbl,
				      &g_mod_namespaces[i]->htbl_name.tbl_params);
		if (err)
			goto handle_error;

		err = rhashtable_init(&g_mod_namespaces[i]->htbl_id.tbl,
				      &g_mod_namespaces[i]->htbl_id.tbl_params);
		if (err)
			goto handle_error;

		g_mod_namespaces[i]->bv_len =
			((KPARSER_KMOD_ID_MAX - KPARSER_KMOD_ID_MIN) /
			 BITS_PER_TYPE(unsigned long)) + 1;

		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "bv_len:%lu, total_bytes:%lu, range:[%d:%d]\n",
					 g_mod_namespaces[i]->bv_len,
					 sizeof(unsigned long) * g_mod_namespaces[i]->bv_len,
					 KPARSER_KMOD_ID_MAX, KPARSER_KMOD_ID_MIN);

		g_mod_namespaces[i]->bv = kcalloc(g_mod_namespaces[i]->bv_len,
						  sizeof(unsigned long),
						  GFP_KERNEL);

		if (!g_mod_namespaces[i]->bv) {
			KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "kzalloc() failed");
			goto handle_error;
		}

		memset(g_mod_namespaces[i]->bv, 0xff,
		       g_mod_namespaces[i]->bv_len * sizeof(unsigned long));
	}

	memset(kparser_fast_lookup_array, 0, sizeof(kparser_fast_lookup_array));

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");

	return 0;

handle_error:
	for (j = 0; j < i; j++) {
		if (!g_mod_namespaces[j])
			continue;

		rhashtable_destroy(&g_mod_namespaces[j]->htbl_name.tbl);
		rhashtable_destroy(&g_mod_namespaces[j]->htbl_id.tbl);

		kparser_free(g_mod_namespaces[j]->bv);
		g_mod_namespaces[j]->bv_len = 0;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");

	return err;
}

/* de-initialize kParser's name space manager contexts and free and remove all entries */
int kparser_deinit(void)
{
	int i;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");
	for (i = 0; i < ARRAY_SIZE(g_mod_namespaces); i++) {
		if (!g_mod_namespaces[i])
			continue;

		rhashtable_destroy(&g_mod_namespaces[i]->htbl_name.tbl);
		rhashtable_free_and_destroy(&g_mod_namespaces[i]->htbl_id.tbl,
					    g_mod_namespaces[i]->free_handler, NULL);

		kparser_free(g_mod_namespaces[i]->bv);

		g_mod_namespaces[i]->bv_len = 0;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return 0;
}

/* pre-process handler for all the netlink msg processors */
static inline const struct kparser_conf_cmd
*kparser_config_handler_preprocess(const void *cmdarg,
				   size_t cmdarglen, struct kparser_cmd_rsp_hdr **rsp,
				   size_t *rsp_len)
{
	enum kparser_global_namespace_ids ns_id;
	const struct kparser_conf_cmd *conf;
	int rc;

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");

	conf = cmdarg;
	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
	    (*rsp_len != 0) || conf->namespace_id <= KPARSER_NS_INVALID ||
	    conf->namespace_id >= KPARSER_NS_MAX) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "[%p %lu %p %p %p %lu %d]\n",
					 conf, cmdarglen, rsp, *rsp, rsp_len,
					 *rsp_len, conf->namespace_id);
		goto err_return;
	}

	ns_id = conf->namespace_id;

	if (!g_mod_namespaces[ns_id])
		goto err_return;

	if (!g_mod_namespaces[ns_id]->create_handler)
		goto err_return;

	rc = alloc_first_rsp(rsp, rsp_len, conf->namespace_id);
	if (rc) {
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI,
					 "alloc_first_rsp() failed, rc:%d\n", rc);
		goto err_return;
	}

	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return cmdarg;

err_return:
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");
	return NULL;
}

#define KPARSER_CONFIG_HANDLER_PRE()					\
do {									\
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "IN: ");		\
	conf = kparser_config_handler_preprocess(cmdarg, cmdarglen,	\
			rsp, rsp_len);					\
	if (!conf)							\
		KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");	\
	KPARSER_KMOD_DEBUG_PRINT(KPARSER_F_DEBUG_CLI, "OUT: ");		\
}									\
while (0)

/* netlink msg processors for create */
int kparser_config_handler_add(const void *cmdarg, size_t cmdarglen,
			       struct kparser_cmd_rsp_hdr **rsp,
			       size_t *rsp_len,
			       void *extack, int *err)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE();

	if (!conf)
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[conf->namespace_id]->create_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->create_handler(conf, cmdarglen,
								    rsp,
								    rsp_len,
								    "create",
								    extack, err);
}

/* netlink msg processors for update */
int kparser_config_handler_update(const void *cmdarg, size_t cmdarglen,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len, void *extack, int *err)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE();

	if (!conf)
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[conf->namespace_id]->update_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->update_handler(conf, cmdarglen,
								    rsp,
								    rsp_len,
								    "update",
								    extack, err);
}

/* netlink msg processors for read */
int kparser_config_handler_read(const void *cmdarg, size_t cmdarglen,
				struct kparser_cmd_rsp_hdr **rsp,
				size_t *rsp_len, void *extack, int *err)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE();

	if (!conf)
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[conf->namespace_id]->read_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->read_handler(&conf->obj_key, rsp, rsp_len,
			conf->recursive_read_delete, "read", extack, err);
}

/* netlink msg processors for delete */
int kparser_config_handler_delete(const void *cmdarg, size_t cmdarglen,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len, void *extack, int *err)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE();

	if (!conf)
		return KPARSER_ATTR_UNSPEC;

	if (!g_mod_namespaces[conf->namespace_id]->del_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->del_handler(&conf->obj_key, rsp, rsp_len,
			conf->recursive_read_delete, "delete", extack, err);
}
