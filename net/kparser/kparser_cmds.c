/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_cmds.c - kParser KMOD-CLI management API layer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <net/kparser/kparser.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/sort.h>

static DEFINE_MUTEX(kparser_config_lock);

static void kparser_release_ref(struct kref *kref)
{
}

void kparser_locked_ref_get(struct kref *refcount)
{
	mutex_lock(&kparser_config_lock);
	kref_get(refcount);
	mutex_unlock(&kparser_config_lock);
}

void kparser_locked_ref_put(struct kref *refcount)
{
	mutex_lock(&kparser_config_lock);
	kref_put(refcount, kparser_release_ref);
	mutex_unlock(&kparser_config_lock);
}

static inline bool kparser_link_attach(const void *owner_obj,
		int owner_nsid,
		const void **owner_obj_link_ptr,
		struct kref *owner_obj_refcount,
		struct list_head *owner_list,
		const void *owned_obj,
		int owned_nsid,
		struct kref *owned_obj_refcount,
		struct list_head *owned_list,
		struct kparser_cmd_rsp_hdr *rsp,
		const char *op)
{
	struct kparser_obj_link_ctx *reflist = kzalloc(
			sizeof(*reflist), GFP_KERNEL);

	if (!reflist) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: kzalloc failed", op);
		return false;
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

	list_add_tail(&reflist->owner_obj.list_node, reflist->owner_obj.list);
	list_add_tail(&reflist->owned_obj.list_node, reflist->owned_obj.list);

	if (reflist->owned_obj.refcount)
		kref_get(reflist->owned_obj.refcount);

	pr_debug("{%s:%d}:owner:%p owned:%p ref:%p\n",
			__func__, __LINE__, owner_obj, owned_obj, reflist);

	synchronize_rcu();

	return true;
}

static inline bool kparser_link_break(const void *owner, const void *owned,
		struct kparser_obj_link_ctx *ref,
		struct kparser_cmd_rsp_hdr *rsp)
{
	if (!ref) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"link is NULL!");
		}
		return false;

	}

	if (ref->sig != KPARSER_LINK_OBJ_SIGNATURE) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"link is corrupt!");
		}
		return false;
	}

	if (owner && ref->owner_obj.obj != owner) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"link owner corrupt!");
		}
		return false;
	}

	if (owned && ref->owned_obj.obj != owned) {
		if (rsp) {
			rsp->op_ret_code = EFAULT;
			(void) snprintf(rsp->err_str_buf,
					sizeof(rsp->err_str_buf),
					"link owned corrupt!");
		}
		return false;
	}

	if (ref->owned_obj.refcount)
		kref_put(ref->owned_obj.refcount, kparser_release_ref);

	if (ref->owner_obj.link_ptr)
		rcu_assign_pointer(*ref->owner_obj.link_ptr, NULL);

	list_del_init_careful(&ref->owner_obj.list_node);
	list_del_init_careful(&ref->owned_obj.list_node);

	synchronize_rcu();

	return true;
}

static inline bool kparser_link_detach_owner(const void *obj,
		struct list_head *list, struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;

	list_for_each_entry_safe(curr_ref, tmp_list_ref, list,
			owner_obj.list_node) {
		if (kparser_link_break(obj, NULL, curr_ref, rsp) == false)
			return false;
		kfree(curr_ref);
	}

	return true;
}

static inline bool kparser_link_detach_owned(const void *obj,
		struct list_head *list, struct kparser_cmd_rsp_hdr *rsp)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	const struct kparser_glue_glue_parse_node *kparsenode;
	const struct kparser_glue_protocol_table *proto_table;
	int i;

	list_for_each_entry_safe(curr_ref, tmp_list_ref, list,
			owned_obj.list_node) {
		/* Special case handling:
		 * if this is parse node and owned by a prototable, make sure
		 * to remove that table's entry from array separately
		 */
		if ((curr_ref->owner_obj.nsid == KPARSER_NS_PROTO_TABLE) &&
			(curr_ref->owned_obj.nsid == KPARSER_NS_NODE_PARSE)) {
			proto_table = curr_ref->owner_obj.obj;
			kparsenode = curr_ref->owned_obj.obj;
			for (i = 0; i < proto_table->proto_table.num_ents;
					i++) {
				if (proto_table->proto_table.entries[i].node !=
						&kparsenode->parse_node.node)
					continue;
				rcu_assign_pointer(proto_table->proto_table.
						entries[i].node, NULL);
				memset(&proto_table->proto_table.entries[i], 0,
						sizeof(proto_table->proto_table.
							entries[i]));
				synchronize_rcu();
				break;
			}
		}

		if (kparser_link_break(NULL, obj, curr_ref, rsp) == false)
			return false;
		kfree(curr_ref);
	}

	return true;
}

static inline bool kparser_link_detach(const void *obj,
		struct list_head *owner_list,
		struct list_head *owned_list,
		struct kparser_cmd_rsp_hdr *rsp)
{
	if (kparser_link_detach_owner(obj, owner_list, rsp) == false)
		return false;

	if (kparser_link_detach_owned(obj, owned_list, rsp) == false)
		return false;

	return true;
}

typedef int kparser_obj_create_update(const struct kparser_conf_cmd *conf,
		size_t conf_len,
		struct kparser_cmd_rsp_hdr **rsp,
		size_t *rsp_len, const char *op);

typedef int kparser_obj_read_del(const struct kparser_hkey *key,
		struct kparser_cmd_rsp_hdr **rsp,
		size_t *rsp_len, __u8 recursive_read,
		const char *op);

typedef void kparser_free_obj(void *ptr, void *arg);

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
	__u32 *bv;
};

kparser_obj_create_update
	kparser_create_cond_exprs,
	kparser_create_cond_table,
	kparser_create_cond_tables,
	kparser_create_counter,
	kparser_create_counter_table,
	kparser_create_metadata,
	kparser_create_metalist,
	kparser_create_parse_node,
	kparser_create_proto_table,
	kparser_create_parse_tlv_node,
	kparser_create_tlv_proto_table,
	kparser_create_flag_field,
	kparser_create_flag_field_table,
	kparser_create_parse_flag_field_node,
	kparser_create_flag_field_proto_table,
	kparser_create_parser,
	kparser_parser_lock;

kparser_obj_read_del
	kparser_read_cond_exprs,
	kparser_read_cond_table,
	kparser_read_cond_tables,
	kparser_read_counter,
	kparser_read_counter_table,
	kparser_read_metadata,
	kparser_del_metadata,
	kparser_read_metalist,
	kparser_del_metalist,
	kparser_read_parse_node,
	kparser_del_parse_node,
	kparser_read_proto_table,
	kparser_del_proto_table,
	kparser_read_parse_tlv_node,
	kparser_read_tlv_proto_table,
	kparser_read_flag_field,
	kparser_read_flag_field_table,
	kparser_read_parse_flag_field_node,
	kparser_read_flag_field_proto_table,
	kparser_read_parser,
	kparser_del_parser,
	kparser_parser_unlock;

kparser_free_obj
	kparser_free_metadata,
	kparser_free_metalist,
	kparser_free_node,
	kparser_free_proto_tbl,
	kparser_free_parser;

#define KPARSER_DEFINE_MOD_NAMESPACE(g_ns_obj, nsid, obj_name, field, create,\
		read, update, delete, free)				     \
static struct kparser_mod_namespaces g_ns_obj = {			     \
	.namespace_id = nsid,						     \
	.name = #nsid,							     \
	.htbl_name =	{						     \
		.tbl_params = {						     \
			.head_offset = offsetof(			     \
					struct obj_name,		     \
					field.ht_node_name),		     \
			.key_offset = offsetof(				     \
					struct obj_name,		     \
					field.key.name),		     \
			.key_len = sizeof(((struct kparser_hkey *)0)->name), \
			.automatic_shrinking = true,			     \
			.hashfn = kparser_gnric_hash_fn_name,		     \
			.obj_hashfn = kparser_gnric_obj_hashfn_name,	     \
			.obj_cmpfn = kparser_cmp_fn_name,		     \
		}							     \
	},								     \
	.htbl_id =	{						     \
		.tbl_params = {						     \
			.head_offset = offsetof(			     \
					struct obj_name,		     \
					field.ht_node_id),		     \
			.key_offset = offsetof(				     \
					struct obj_name,		     \
					field.key.id),			     \
			.key_len = sizeof(((struct kparser_hkey *)0)->id),   \
			.automatic_shrinking = true,			     \
			.hashfn = kparser_gnric_hash_fn_id,		     \
			.obj_hashfn = kparser_gnric_obj_hashfn_id,	     \
			.obj_cmpfn = kparser_cmp_fn_id,			     \
		}							     \
	},								     \
									     \
	.create_handler = create,					     \
	.read_handler = read,						     \
	.update_handler = update,					     \
	.del_handler = delete,						     \
	.free_handler = free,						     \
}

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_condexprs,
			     KPARSER_NS_CONDEXPRS,
			     kparser_glue_condexpr_expr,
			     glue,
			     kparser_create_cond_exprs,
			     kparser_read_cond_exprs,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_condexprs_table,
			     KPARSER_NS_CONDEXPRS_TABLE,
			     kparser_glue_condexpr_table,
			     glue,
			     kparser_create_cond_table,
			     kparser_read_cond_table,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_condexprs_tables,
			     KPARSER_NS_CONDEXPRS_TABLES,
			     kparser_glue_condexpr_tables,
			     glue,
			     kparser_create_cond_tables,
			     kparser_read_cond_tables,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_counter,
			     KPARSER_NS_COUNTER,
			     kparser_glue_counter,
			     glue,
			     kparser_create_counter,
			     kparser_read_counter,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_counter_table,
			     KPARSER_NS_COUNTER_TABLE,
			     kparser_glue_counter_table,
			     glue,
			     kparser_create_counter_table,
			     kparser_read_counter_table,
			     NULL,
			     NULL,
			     NULL);

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
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_tlv_proto_table,
			     KPARSER_NS_TLV_PROTO_TABLE,
			     kparser_glue_proto_tlvs_table,
			     glue,
			     kparser_create_tlv_proto_table,
			     kparser_read_tlv_proto_table,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field,
			     KPARSER_NS_FLAG_FIELD,
			     kparser_glue_flag_field,
			     glue,
			     kparser_create_flag_field,
			     kparser_read_flag_field,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field_table,
			     KPARSER_NS_FLAG_FIELD_TABLE,
			     kparser_glue_flag_fields,
			     glue,
			     kparser_create_flag_field_table,
			     kparser_read_flag_field_table,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field_parse_node,
			     KPARSER_NS_FLAG_FIELD_NODE_PARSE,
			     kparser_glue_flag_field_node,
			     glue.glue,
			     kparser_create_parse_flag_field_node,
			     kparser_read_parse_flag_field_node,
			     NULL,
			     NULL,
			     NULL);

KPARSER_DEFINE_MOD_NAMESPACE(kparser_mod_namespace_flag_field_proto_table,
			     KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
			     kparser_glue_proto_flag_fields_table,
			     glue,
			     kparser_create_flag_field_proto_table,
			     kparser_read_flag_field_proto_table,
			     NULL,
			     NULL,
			     NULL);

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
			     NULL,
			     NULL,
			     kparser_parser_unlock,
			     NULL);

static struct kparser_mod_namespaces *g_mod_namespaces[] = 
{
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

static struct kparser_cntrs_conf cntrs_conf = {};
static __u8 cntrs_conf_idx = 0;

extern void rhashtable_destroy(struct rhashtable *ht);
extern void rhashtable_free_and_destroy(struct rhashtable *ht,
		void (*free_fn)(void *ptr, void *arg), void *arg);

// TODO: free ids 
static inline __u16 allocate_id(__u16 id, int *bv, size_t bvsize)
{
	int i;

	if (id != KPARSER_INVALID_ID) {
		// try to allocate passed id
		if (!kparsertestbit(bv, id)) // already allocated, conflict
			return KPARSER_INVALID_ID;
		kparserclearbit(bv, id);
		return id;
	}

	// allocate internally
	// scan bitvector
	for (i = 0; i < bvsize; i++) {
		// avoid bit vectors which are already full
		if (bv[i]) {
			id = __builtin_ffs(bv[i]);
			if (id) {
				id--;
				id += (i * BITS_IN_U32);
				kparserclearbit(bv, id);
				return (id + KPARSER_KMOD_ID_MIN);
			}
			printk("failed here:%d:%d\n", id, i);
			return KPARSER_INVALID_ID;
		}
	}

	printk("failed now here:%d\n", i);
	return KPARSER_INVALID_ID;
}

static inline bool kparser_allocate_key_id(
		enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key,
		struct kparser_hkey *new_key)
{
		*new_key = *key;
                new_key->id = allocate_id(KPARSER_INVALID_ID,
				g_mod_namespaces[ns_id]->bv,
				g_mod_namespaces[ns_id]->bv_len);

                if (new_key->id == KPARSER_INVALID_ID)
			return false;

		return true;
}

static inline bool kparser_allocate_key_name(
		enum kparser_global_namespace_ids ns_id,
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

static inline bool kparser_conf_key_manager(
		enum kparser_global_namespace_ids ns_id,
		const struct kparser_hkey *key, struct kparser_hkey *new_key,
		struct kparser_cmd_rsp_hdr *rsp, const char *op)
{
	if (kparser_hkey_empty(key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s:HKey missing", op);
		return false;
	}

	if (kparser_hkey_id_empty(key) && new_key) {
		return kparser_allocate_key_id(ns_id, key, new_key);
	}

	if (kparser_hkey_user_id_invalid(key)) {
		rsp->op_ret_code = -EINVAL;
		(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
				"%s:HKey id invalid:%u",
				op, key->id);
		return false;
	}

	if (kparser_hkey_name_empty(key) && new_key) {
		return kparser_allocate_key_name(ns_id, key, new_key);
	}

	if (new_key)
		*new_key = *key;

	return true;
}

static inline int kparser_namespace_remove(
		enum kparser_global_namespace_ids ns_id,
		struct rhash_head *obj_id,
		struct rhash_head *obj_name)
{
	int rc;

	if (ns_id <= KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return EINVAL;

	if (!g_mod_namespaces[ns_id])
		return ENOENT;

	rc = rhashtable_remove_fast(
			&g_mod_namespaces[ns_id]->htbl_id.tbl, obj_id,
			g_mod_namespaces[ns_id]->htbl_id.tbl_params);

	if (rc)
		return rc;

	rc = rhashtable_remove_fast(
			&g_mod_namespaces[ns_id]->htbl_name.tbl, obj_name,
			g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return rc;
}

void * kparser_namespace_lookup(
		enum kparser_global_namespace_ids ns_id,
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

static inline int kparser_namespace_insert(
		enum kparser_global_namespace_ids ns_id,
		struct rhash_head *obj_id,
		struct rhash_head *obj_name)
{
	int rc;

	if (ns_id <= KPARSER_NS_INVALID || ns_id >= KPARSER_NS_MAX)
		return EINVAL;

	if (!g_mod_namespaces[ns_id])
		return ENOENT;

	rc = rhashtable_insert_fast(
			&g_mod_namespaces[ns_id]->htbl_id.tbl, obj_id,
			g_mod_namespaces[ns_id]->htbl_id.tbl_params);

	if (rc)
		return rc;

	rc = rhashtable_insert_fast(
			&g_mod_namespaces[ns_id]->htbl_name.tbl, obj_name,
			g_mod_namespaces[ns_id]->htbl_name.tbl_params);

	return rc;
}

static inline int alloc_first_rsp(struct kparser_cmd_rsp_hdr **rsp,
		size_t *rsp_len, int nsid)
{
	if (!rsp || *rsp || !rsp_len || (*rsp_len != 0))
		return EINVAL;

	*rsp = kzalloc(sizeof(struct kparser_cmd_rsp_hdr), GFP_KERNEL);
	if (!(*rsp)) {
		printk("%s:kzalloc failed for rsp, size:%lu\n",
				__FUNCTION__,
				sizeof(struct kparser_cmd_rsp_hdr));
		return ENOMEM;
	}

	*rsp_len = sizeof(struct kparser_cmd_rsp_hdr);
	(*rsp)->object.namespace_id = nsid;
	(*rsp)->objects_len = 0;
	return 0;
}

static struct list_head g_parser_list;

int kparser_init(void)
{
	int err, i, j;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	for (i = 0; i < (sizeof(g_mod_namespaces) /
				sizeof(g_mod_namespaces[0])); i++) {

		if (!g_mod_namespaces[i])
			continue;

		err = rhashtable_init(&g_mod_namespaces[i]->htbl_name.tbl,
				&g_mod_namespaces[i]->htbl_name.tbl_params);
		if (err)
			break;

		err = rhashtable_init(&g_mod_namespaces[i]->htbl_id.tbl,
				&g_mod_namespaces[i]->htbl_id.tbl_params);
		if (err)
			break;

		g_mod_namespaces[i]->bv_len =
			((KPARSER_KMOD_ID_MAX - KPARSER_KMOD_ID_MIN) /
			 BITS_IN_U32) + 1;

		pr_debug("{%s:%d}:bv_len:%lu, total_bytes:%lu, range:[%d:%d]\n",
				__FUNCTION__, __LINE__,
				g_mod_namespaces[i]->bv_len,
				sizeof(__u32) * g_mod_namespaces[i]->bv_len,
				KPARSER_KMOD_ID_MAX, KPARSER_KMOD_ID_MIN);

		g_mod_namespaces[i]->bv = kzalloc(
				sizeof(__u32) * g_mod_namespaces[i]->bv_len,
				GFP_KERNEL);

		if (!g_mod_namespaces[i]->bv) {
			printk("%s: kzalloc() failed\n", __FUNCTION__);
			break;
		}

		memset(g_mod_namespaces[i]->bv, 0xff,
				g_mod_namespaces[i]->bv_len * sizeof(__u32));
	}

	pr_debug("OUT: %s:%s:%d:err:%d\n", __FILE__, __FUNCTION__,
			__LINE__, err);

	if (!err)
		return 0;

	for (j = 0; j < i; j++) {

		if (!g_mod_namespaces[j])
			continue;

		rhashtable_destroy(&g_mod_namespaces[j]->htbl_name.tbl);
		rhashtable_destroy(&g_mod_namespaces[j]->htbl_id.tbl);

		if (g_mod_namespaces[j]->bv)
			kfree(g_mod_namespaces[j]->bv);
		g_mod_namespaces[j]->bv_len = 0;
	}

	pr_debug("%s() failed, err: %d\n", __FUNCTION__, err);

	INIT_LIST_HEAD(&g_parser_list);

	return err;
}

int kparser_deinit(void)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	for (i = 0; i < (sizeof(g_mod_namespaces) /
				sizeof(g_mod_namespaces[0])); i++) {

		if (!g_mod_namespaces[i])
			continue;

		rhashtable_destroy(&g_mod_namespaces[i]->htbl_name.tbl);
		rhashtable_free_and_destroy(&g_mod_namespaces[i]->htbl_id.tbl,
				g_mod_namespaces[i]->free_handler,
				NULL);

		if (g_mod_namespaces[i]->bv)
			kfree(g_mod_namespaces[i]->bv);

		g_mod_namespaces[i]->bv_len = 0;
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return 0;
}


static void kparser_dump_node(const struct kparser_parse_node *obj);
static void kparser_dump_proto_table(const struct kparser_proto_table *obj);
static void kparser_dump_tlv_parse_node(
		const struct kparser_parse_tlv_node *obj);
static void kparser_dump_metadatatable(
		const struct kparser_metadata_table *obj);
static void kparser_dump_cond_tables(const struct kparser_condexpr_tables *obj);

static void kparser_dump_param_len(
		const struct kparser_parameterized_len *pflen)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!pflen) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("pflen.src_off:%u \n", pflen->src_off);
	pr_debug("pflen.size:%u \n", pflen->size);
	pr_debug("pflen.endian:%d \n", pflen->endian);
	pr_debug("pflen.mask:%u \n", pflen->mask);
	pr_debug("pflen.right_shift:%u \n", pflen->right_shift);
	pr_debug("pflen.multiplier:%u \n", pflen->multiplier);
	pr_debug("pflen.add_value:%u \n", pflen->add_value);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_param_next_proto(
		const struct kparser_parameterized_next_proto *pfnext_proto)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!pfnext_proto) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("pfnext_proto.src_off:%u \n", pfnext_proto->src_off);
	pr_debug("pfnext_proto.mask:%u \n", pfnext_proto->mask);
	pr_debug("pfnext_proto.size:%u \n", pfnext_proto->size);
	pr_debug("pfnext_proto.right_shift:%u \n", pfnext_proto->right_shift);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_cond_expr(const struct kparser_condexpr_expr *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("type:%u, src_off:%u, len:%u, mask:%04x value:%04x \n",
			obj->type, obj->src_off,
			obj->length, obj->mask, obj->value);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_cond_table(const struct kparser_condexpr_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("default_fail:%d, type:%u\n", obj->default_fail, obj->type);
	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);

	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		kparser_dump_cond_expr(obj->entries[i]);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_cond_tables(const struct kparser_condexpr_tables *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		kparser_dump_cond_table(obj->entries[i]);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_proto_node(const struct kparser_proto_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("encap:%u \n", obj->encap);
	pr_debug("overlay:%u \n", obj->overlay);
	pr_debug("min_len:%lu \n", obj->min_len);

	pr_debug("ops.flag_fields_length:%d \n", obj->ops.flag_fields_length);

	pr_debug("ops.len_parameterized:%d \n",
			obj->ops.len_parameterized);
	kparser_dump_param_len(&obj->ops.pflen);

	kparser_dump_param_next_proto(&obj->ops.pfnext_proto);

	pr_debug("ops.cond_exprs_parameterized:%d \n",
			obj->ops.cond_exprs_parameterized);
	kparser_dump_cond_tables(&obj->ops.cond_exprs);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_proto_tlvs_table(
		const struct kparser_proto_tlvs_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		pr_debug("[%d]: val: %04x\n", i, obj->entries[i].type);
		kparser_dump_tlv_parse_node(obj->entries[i].node);
	}

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_tlv_parse_node(
		const struct kparser_parse_tlv_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s\n", obj->name);
	pr_debug("unknown_tlv_type_ret:%d \n", obj->unknown_overlay_ret);

	pr_debug("proto_tlv_node.min_len: %lu\n", obj->proto_tlv_node.min_len);
	pr_debug("proto_tlv_node.max_len: %lu\n", obj->proto_tlv_node.max_len);
	pr_debug("proto_tlv_node.is_padding: %u\n",
			obj->proto_tlv_node.is_padding);
	pr_debug("proto_tlv_node.overlay_type_parameterized: %u\n",
			obj->proto_tlv_node.
			ops.overlay_type_parameterized);
	kparser_dump_param_next_proto(&obj->proto_tlv_node.ops.pfoverlay_type);
	pr_debug("proto_tlv_node.cond_exprs_parameterized: %u\n",
			obj->proto_tlv_node.ops.cond_exprs_parameterized);
	kparser_dump_cond_tables(&obj->proto_tlv_node.ops.cond_exprs);

	kparser_dump_proto_tlvs_table(obj->overlay_table);
	kparser_dump_tlv_parse_node(obj->overlay_wildcard_node);
	kparser_dump_metadatatable(obj->metadata_table);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_tlvs_parse_node(
		const struct kparser_parse_tlvs_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_tlvs_table(obj->tlv_proto_table);

	pr_debug("unknown_tlv_type_ret:%d \n", obj->unknown_tlv_type_ret);

	kparser_dump_tlv_parse_node(obj->tlv_wildcard_node);

	pr_debug("config:max_loop: %u \n", obj->config.max_loop);
	pr_debug("config:max_non: %u \n", obj->config.max_non);
	pr_debug("config:max_plen: %u \n", obj->config.max_plen);
	pr_debug("config:max_c_pad: %u \n", obj->config.max_c_pad);
	pr_debug("config:disp_limit_exceed: %u \n",
			obj->config.disp_limit_exceed);
	pr_debug("config:exceed_loop_cnt_is_err: %u \n",
			obj->config.exceed_loop_cnt_is_err);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_tlvs_proto_node(
		const struct kparser_proto_tlvs_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_node(&obj->proto_node);

	kparser_dump_param_len(&obj->ops.pfstart_offset);
	pr_debug("ops.len_parameterized:%d \n",
			obj->ops.len_parameterized);
	kparser_dump_param_len(&obj->ops.pflen);
	kparser_dump_param_next_proto(&obj->ops.pftype);

	pr_debug("start_offset:%lu \n", obj->start_offset);
	pr_debug("pad1_val:%u \n", obj->pad1_val);
	pr_debug("padn_val:%u \n", obj->padn_val);
	pr_debug("eol_val:%u \n", obj->eol_val);
	pr_debug("pad1_enable:%u \n", obj->pad1_enable);
	pr_debug("padn_enable:%u \n", obj->padn_enable);
	pr_debug("eol_enable:%u \n", obj->eol_enable);
	pr_debug("fixed_start_offset:%u \n", obj->fixed_start_offset);
	pr_debug("min_len:%lu \n", obj->min_len);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_flag_field(
		const struct kparser_flag_field *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("flag:%04x, mask:%04x size:%lu\n",
			obj->flag, obj->mask, obj->size);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_flag_fields(
		const struct kparser_flag_fields *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_idx:%lu, fields:%p\n", obj->num_idx, obj->fields);

	if (!obj->fields)
		goto done;

	for (i = 0; i < obj->num_idx; i++)
		kparser_dump_flag_field(&obj->fields[i]);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_parse_flag_field_node(
		const struct kparser_parse_flag_field_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s\n", obj->name);

	kparser_dump_metadatatable(obj->metadata_table);
	kparser_dump_cond_tables(&obj->ops.cond_exprs);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_proto_flag_fields_table(
		const struct kparser_proto_flag_fields_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%d, entries:%p\n", obj->num_ents, obj->entries);

	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		pr_debug("proto_flag_fields_table_entry_flag:%x\n",
			obj->entries[i].flag);
		kparser_dump_parse_flag_field_node(obj->entries[i].node);
	}
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}


static void kparser_dump_flags_parse_node(
		const struct kparser_parse_flag_fields_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_flag_fields_table(obj->flag_fields_proto_table);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_flags_proto_node(
		const struct kparser_proto_flag_fields_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	kparser_dump_proto_node(&obj->proto_node);

	pr_debug("ops.get_flags_parameterized:%d \n",
			obj->ops.get_flags_parameterized);
	pr_debug("ops.pfget_flags: src_off:%u mask:%04x size:%u \n",
			obj->ops.pfget_flags.src_off,
			obj->ops.pfget_flags.mask,
			obj->ops.pfget_flags.size);

	pr_debug("ops.start_fields_offset_parameterized:%d \n",
			obj->ops.start_fields_offset_parameterized);
	kparser_dump_param_len(&obj->ops.pfstart_fields_offset);

	pr_debug("ops.flag_feilds_len:%u ops.hdr_length:%u\n",
		obj->ops.flag_fields_len, obj->ops.hdr_length);

	kparser_dump_flag_fields(obj->flag_fields);
done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_metadatatable(
		const struct kparser_metadata_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++)
		pr_debug("mde[%d]:%04x\n", i, obj->entries[i].val);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_proto_table(
		const struct kparser_proto_table *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("num_ents:%u, entries:%p\n", obj->num_ents, obj->entries);
	if (!obj->entries)
		goto done;

	for (i = 0; i < obj->num_ents; i++) {
		pr_debug("[%d]: val: %d\n", i, obj->entries[i].value);
		kparser_dump_node(obj->entries[i].node);
	}

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_node(const struct kparser_parse_node *obj)
{
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s: type: %d\n", obj->name, obj->node_type);
	pr_debug("unknown_ret:%d \n", obj->unknown_ret);

	switch(obj->node_type) {
	case KPARSER_NODE_TYPE_PLAIN:
		kparser_dump_proto_node(&obj->proto_node);
		break;

	case KPARSER_NODE_TYPE_TLVS:
		kparser_dump_tlvs_proto_node(&obj->tlvs_proto_node);
		kparser_dump_tlvs_parse_node(
				(const struct kparser_parse_tlvs_node *) obj);
		break;

	case KPARSER_NODE_TYPE_FLAG_FIELDS:
		kparser_dump_flags_proto_node(&obj->flag_fields_proto_node);
		kparser_dump_flags_parse_node(
				(const struct kparser_parse_flag_fields_node *)
				obj);
		break;

	default:
		pr_debug("unknown node type:%d\n", obj->node_type);
		break;
	}

	kparser_dump_proto_table(obj->proto_table);

	kparser_dump_node(obj->wildcard_node);

	kparser_dump_metadatatable(obj->metadata_table);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void kparser_dump_parser_tree(const struct kparser_parser *obj)
{
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	if (!obj) {
		pr_debug("obj NULL");
		goto done;
	}

	pr_debug("name: %s\n", obj->name);

	pr_debug("config: flags:%02x \n", obj->config.flags);
	pr_debug("config: max_nodes:%u \n", obj->config.max_nodes);
	pr_debug("config: max_encaps:%u \n", obj->config.max_encaps);
	pr_debug("config: max_frames:%u \n", obj->config.max_frames);
	pr_debug("config: metameta_size:%lu \n", obj->config.metameta_size);
	pr_debug("config: frame_size:%lu \n", obj->config.frame_size);

	pr_debug("cntrs_len: %lu\n", obj->cntrs_len);
	for (i = 0; i < (sizeof(obj->cntrs_conf.cntrs) /
				sizeof (obj->cntrs_conf.cntrs[0])); i++) {
		pr_debug("cntrs:%d: max_value:%u\n", i,
				obj->cntrs_conf.cntrs[i].max_value);
		pr_debug("cntrs:%d: array_limit:%u\n", i,
				obj->cntrs_conf.cntrs[i].array_limit);
		pr_debug("cntrs:%d: el_size:%lu\n", i,
				obj->cntrs_conf.cntrs[i].el_size);
		pr_debug("cntrs:%d: reset_on_encap:%d\n", i,
				obj->cntrs_conf.cntrs[i].reset_on_encap);
		pr_debug("cntrs:%d: overwrite_last:%d\n", i,
				obj->cntrs_conf.cntrs[i].overwrite_last);
		pr_debug("cntrs:%d: error_on_exceeded:%d\n", i,
				obj->cntrs_conf.cntrs[i].error_on_exceeded);
		if (obj->cntrs) {
			pr_debug("cntr[%d]:%d", i, obj->cntrs->cntr[i]);
		}
	}

	kparser_dump_node(obj->root_node);
	kparser_dump_node(obj->okay_node);
	kparser_dump_node(obj->fail_node);
	kparser_dump_node(obj->atencap_node);

done:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
}

static inline bool kparser_cmd_create_pre_process(const char *op,
		const struct kparser_conf_cmd *conf,
		const struct kparser_hkey *argkey, struct kparser_hkey *newkey,
		void **kobj, size_t kobjsize, struct kparser_cmd_rsp_hdr *rsp,
		size_t glueoffset)
{
	struct kparser_glue *glue;

	if (!kparser_conf_key_manager(conf->namespace_id, argkey,
				newkey, rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		return false;
	}

	pr_debug("{%s:%d} OP:%s Key{%s:%d}:{%s:%d}\n",
			__FUNCTION__, __LINE__,
			op, argkey->name, argkey->id,
			newkey->name, newkey->id);

	if (kparser_namespace_lookup(conf->namespace_id, newkey)) {
		rsp->op_ret_code = EEXIST;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s:Duplicate object HKey:{%s:%u}",
				op, newkey->name, newkey->id);
		return false;
	}

	*kobj = kzalloc(kobjsize, GFP_KERNEL);
	if (!(*kobj)) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s:Object allocation failed for size:%lu",
				op, kobjsize);
		return false;
	}

	glue = (*kobj) + glueoffset;
	glue->key = *newkey;

	rsp->op_ret_code = kparser_namespace_insert(conf->namespace_id,
			&glue->ht_node_id, &glue->ht_node_name);
	if (rsp->op_ret_code) {
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s:Htbl insert err:%d", op, rsp->op_ret_code);
		return false;
	}

	glue->config = *conf;
	kref_init(&glue->refcount);

	(void) snprintf(rsp->err_str_buf, sizeof(rsp->err_str_buf),
			"%s:Success", op);
	rsp->key = *newkey;
	rsp->object.conf_keys_bv = conf->conf_keys_bv;
	rsp->object = *conf;

	return true;
}

int kparser_create_cond_exprs(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_condexpr_expr *kobj = NULL;
	const struct kparser_conf_condexpr *arg;
	struct kparser_hkey key;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->cond_conf;

	if (kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
		(void **) &kobj, sizeof(*kobj), *rsp,
		offsetof(struct kparser_glue_condexpr_expr, glue)) == false)
		goto done;

	kobj->expr = arg->config;

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf), "OK");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.cond_conf = kobj->glue.config.cond_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (kobj)
			kfree(kobj);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS);
}

int kparser_read_cond_exprs(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_glue_condexpr_expr *kobj;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kobj = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS, key);
	if (!kobj) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kobj->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kobj->glue.config.conf_keys_bv;
	(*rsp)->object.cond_conf = kobj->glue.config.cond_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS);
}

static bool kparser_create_cond_table_ent(
		const struct kparser_conf_table *arg,
		struct kparser_glue_condexpr_table **proto_table,
		struct kparser_cmd_rsp_hdr *rsp)
{
	const struct kparser_glue_condexpr_expr *kcondent;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLE,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		return false;
	}

	kcondent = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS,
			&arg->elem_key);
	if (!kcondent) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key:{%s:%u} not found",
				__FUNCTION__,
				arg->elem_key.name,
				arg->elem_key.id);
		return false;
	}

	(*proto_table)->table.num_ents++;
	rcu_assign_pointer((*proto_table)->table.entries,
			krealloc((*proto_table)->table.entries,
			(*proto_table)->table.num_ents *
			sizeof(struct kparser_condexpr_expr *),
			GFP_KERNEL | ___GFP_ZERO));
	if (!(*proto_table)->table.entries) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: krealloc() err, ents:%d, size:%lu",
				__FUNCTION__,
				(*proto_table)->table.num_ents,
				sizeof(struct kparser_condexpr_expr));
		return false;
	}

	(*proto_table)->table.entries[
		(*proto_table)->table.num_ents - 1] = &kcondent->expr;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_cond_table(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_condexpr_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	//create a table entry
	if (arg->add_entry) {
		if(kparser_create_cond_table_ent(arg,
					&proto_table, *rsp) == false)
			goto done;
		goto skip_table_create;
	}

	if (kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
		(void **) &proto_table, sizeof(*proto_table), *rsp,
		offsetof(struct kparser_glue_condexpr_table, glue)) == false)
		goto done;

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);
	proto_table->table.default_fail = arg->optional_value1;
	proto_table->table.type = arg->optional_value2;

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf), "OK");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (proto_table && !arg->add_entry)
			kfree(proto_table);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLE);
}

int kparser_read_cond_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_condexpr_table *proto_table;
	const struct kparser_glue_condexpr_expr *kcondent;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLE,
			key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;
	(*rsp)->object.table_conf.optional_value1 =
		proto_table->table.default_fail;
	(*rsp)->object.table_conf.optional_value2 =
		proto_table->table.type;

	for (i = 0; i < proto_table->table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *)(*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		if (!proto_table->table.entries)
			continue;
		kcondent = container_of(
				proto_table->table.entries[i],
				struct kparser_glue_condexpr_expr, expr);
		objects[i].table_conf.elem_key= kcondent->glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLE);
}

static bool kparser_create_cond_tables_ent(
		const struct kparser_conf_table *arg,
		struct kparser_glue_condexpr_tables **proto_table,
		struct kparser_cmd_rsp_hdr *rsp)
{
	const struct kparser_glue_condexpr_table *kcondent;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		return false;
	}

	kcondent = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLE,
			&arg->elem_key);
	if (!kcondent) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key:{%s:%u} not found",
				__FUNCTION__,
				arg->elem_key.name,
				arg->elem_key.id);
		return false;
	}

	(*proto_table)->table.num_ents++;
	rcu_assign_pointer((*proto_table)->table.entries,
			krealloc((*proto_table)->table.entries,
			(*proto_table)->table.num_ents *
			sizeof(struct kparser_condexpr_table *),
			GFP_KERNEL | ___GFP_ZERO));
	if (!(*proto_table)->table.entries) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: krealloc() err, ents:%d, size:%lu",
				__FUNCTION__,
				(*proto_table)->table.num_ents,
				sizeof(struct kparser_condexpr_table *));
		return false;
	}

	(*proto_table)->table.entries[
		(*proto_table)->table.num_ents - 1] =
			&kcondent->table;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_cond_tables(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_condexpr_tables *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	//create a table entry
	if (arg->add_entry) {
		if(kparser_create_cond_tables_ent(arg,
					&proto_table, *rsp) == false)
			goto done;
		goto skip_table_create;
	}

	if (kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
		(void **) &proto_table, sizeof(*proto_table), *rsp,
		offsetof(struct kparser_glue_condexpr_tables, glue)) == false)
		goto done;

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (proto_table && !arg->add_entry)
			kfree(proto_table);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLES);
}

int kparser_read_cond_tables(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_condexpr_tables *proto_table;
	const struct kparser_glue_condexpr_table *kcondent;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_CONDEXPRS_TABLES, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		if (!proto_table->table.entries)
			continue;
		kcondent = container_of(proto_table->table.entries[i],
				struct kparser_glue_condexpr_table, table);
		objects[i].table_conf.elem_key= kcondent->glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_CONDEXPRS_TABLES);
}

int kparser_create_counter(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	const struct kparser_conf_cntr *arg;
	struct kparser_glue_counter *kcntr = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->cntr_conf;

	if (!arg->conf.valid_entry) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: counter entry is not valid", __FUNCTION__);
		goto done;
	}

	if (cntrs_conf_idx >= KPARSER_CNTR_NUM_CNTRS) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: counter index %d can not be >= %d",
				__FUNCTION__, cntrs_conf_idx,
				KPARSER_CNTR_NUM_CNTRS);
		goto done;
	}

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kcntr = kzalloc(sizeof(*kcntr), GFP_KERNEL);
	if (!kcntr) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kcntr->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kcntr->glue.ht_node_id,
				      &kcntr->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
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

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.cntr_conf = kcntr->glue.config.cntr_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (kcntr)
			kfree(kcntr);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER);
}

int kparser_read_counter(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_glue_counter *kcntr;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER, key);
	if (!kcntr) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kcntr->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kcntr->glue.config.conf_keys_bv;
	(*rsp)->object.cntr_conf = kcntr->glue.config.cntr_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER);
}

int kparser_create_counter_table(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_counter_table *table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_glue_counter *kcntr;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	//create a table entry
	if (arg->add_entry) {
		table = kparser_namespace_lookup(conf->namespace_id,
				&arg->key);
		if (!table) {
			(*rsp)->op_ret_code = ENOENT;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: table key not found",
					__FUNCTION__);
			goto done;
		}
		if (table->elems_cnt >= KPARSER_CNTR_NUM_CNTRS) {
			(*rsp)->op_ret_code = EINVAL;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: table full:%u",
					__FUNCTION__, table->elems_cnt);
			goto done;
		}
		kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER,
				&arg->elem_key);
		if (!kcntr) {
			(*rsp)->op_ret_code = ENOENT;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: Object key not found",
					__FUNCTION__);
			goto done;
		}
		table->k_cntrs[table->elems_cnt++] = *kcntr;
		goto skip_table_create;
	}

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	/* create counter table */
	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
			&table->glue.ht_node_id,
			&table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	table->glue.config.namespace_id = conf->namespace_id;
	table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	table->glue.config.table_conf = *arg;
	table->glue.config.table_conf.key = key;
	kref_init(&table->glue.refcount);

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf =
		table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (table && !arg->add_entry)
			kfree(table);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER_TABLE);
}

int kparser_read_counter_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_counter_table *table;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	table = kparser_namespace_lookup(KPARSER_NS_COUNTER_TABLE, key);
	if (!table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		table->glue.config.table_conf;

	for (i = 0; i < KPARSER_CNTR_NUM_CNTRS; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			table->k_cntrs[i].glue.config.namespace_id;
		objects[i].cntr_conf =
			table->k_cntrs[i].glue.config.cntr_conf;
		objects[i].cntr_conf.conf = cntrs_conf.cntrs[i];
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_COUNTER_TABLE);
}

int kparser_create_metadata(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_metadata_extract *kmde = NULL;
	const struct kparser_conf_metadata *arg;
	struct kparser_glue_counter *kcntr;
	struct kparser_hkey key;
	int rc, cntridx = 0;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->md_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key", op);
		goto done;
	}

	if (arg->type == KPARSER_METADATA_COUNTER) {
		kcntr = kparser_namespace_lookup(KPARSER_NS_COUNTER,
				&arg->counterkey);
		if (!kcntr) {
			(*rsp)->op_ret_code = ENOENT;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: Counter object key not found", op);
			goto done;
		}
		cntridx = kcntr->counter_cnf.index + 1;
	}

	kmde = kzalloc(sizeof(*kmde), GFP_KERNEL);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", op);
		goto done;
	}

	kmde->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kmde->glue.ht_node_id,
				      &kmde->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err", op);
		goto done;
	}

	kmde->glue.config.namespace_id = conf->namespace_id;
	kmde->glue.config.conf_keys_bv = conf->conf_keys_bv;
	kmde->glue.config.md_conf = *arg;
	kmde->glue.config.md_conf.key = key;
	kref_init(&kmde->glue.refcount);
	INIT_LIST_HEAD(&kmde->glue.owner_list);
	INIT_LIST_HEAD(&kmde->glue.owned_list);

	if (!kparser_metadata_convert(arg, &kmde->mde, cntridx)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_metadata_convert() err", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (kmde)
			kfree(kmde);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_METADATA);
}

int kparser_read_metadata(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_metadata_extract *kmde;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, key);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kmde->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmde->glue.config.conf_keys_bv;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_METADATA);
}

int kparser_del_metadata(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_glue_metadata_extract *kmde;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmde = kparser_namespace_lookup(KPARSER_NS_METADATA, key);
	if (!kmde) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	if (kref_read(&kmde->glue.refcount) != 1) {
		(*rsp)->op_ret_code = EBUSY;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Metadata object is associated with a "
				"metalist, delete that metalist instead", op);
		goto done;
	}

	rc = kparser_namespace_remove(KPARSER_NS_METADATA,
			&kmde->glue.ht_node_id, &kmde->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: namespace remove error", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kmde->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmde->glue.config.conf_keys_bv;
	(*rsp)->object.md_conf = kmde->glue.config.md_conf;

	kfree(kmde);
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_METADATA);
}

void kparser_free_metadata(void *ptr, void *arg)
{
	return;
	if (ptr)
		kfree(ptr);
}

int kparser_create_metalist(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_metadata_extract *kmde = NULL;
	struct kparser_glue_metadata_table *kmdl = NULL;
	const struct kparser_conf_metadata_table *arg;
	struct kparser_conf_cmd *objects = NULL;
	struct kparser_hkey key;
	int rc, i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->mdl_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key", op);
		goto done;
	}

	kmdl = kzalloc(sizeof(*kmdl), GFP_KERNEL);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", op);
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
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: conf len/buffer incomplete",
					op);
			goto done;
		}

		conf_len -= sizeof(struct kparser_hkey);

		pr_debug("Key: {ID:%u Name:%s}\n",
				arg->metadata_keys[i].id,
				arg->metadata_keys[i].name);

		kmde = kparser_namespace_lookup(KPARSER_NS_METADATA,
						&arg->metadata_keys[i]);
		if (!kmde) {
			(*rsp)->op_ret_code = ENOENT;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: Object key {%s:%u} not found",
					op,
					arg->metadata_keys[i].name,
					arg->metadata_keys[i].id);
			goto done;
		}
		kmdl->metadata_table.num_ents++;
		rcu_assign_pointer(kmdl->metadata_table.entries,
				krealloc(kmdl->metadata_table.entries,
				kmdl->metadata_table.num_ents * sizeof(*kmde),
				GFP_KERNEL | ___GFP_ZERO));
		if (!kmdl->metadata_table.entries) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: krealloc() err, ents:%d, size:%lu",
					op,
					kmdl->metadata_table.num_ents,
					sizeof(*kmde));
			goto done;
		}
		kmdl->metadata_table.entries[i] = kmde->mde;
		kref_get(&kmde->glue.refcount);

		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
				__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			if (kmdl) {
				if (kmdl->metadata_table.entries)
					kfree(kmdl->metadata_table.entries);
				kfree(kmdl);
			}
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			kmde->glue.config.namespace_id;
		objects[i].conf_keys_bv =
			kmde->glue.config.conf_keys_bv;
		objects[i].md_conf = kmde->glue.config.md_conf;

		kmdl->md_configs_len++;
		kmdl->md_configs = krealloc(kmdl->md_configs,
				kmdl->md_configs_len *
				sizeof(struct kparser_conf_cmd),
				GFP_KERNEL | ___GFP_ZERO);
		if (!kmdl->md_configs) {
			(*rsp)->op_ret_code = ENOMEM;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: krealloc() err,ents:%lu, size:%lu",
					op,
					kmdl->md_configs_len,
					sizeof(struct kparser_conf_cmd));
			goto done;
		}
		kmdl->md_configs[i].namespace_id =
			kmde->glue.config.namespace_id;
		kmdl->md_configs[i].conf_keys_bv =
			kmde->glue.config.conf_keys_bv;
		kmdl->md_configs[i].md_conf = kmde->glue.config.md_conf; 
	}

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kmdl->glue.ht_node_id,
				      &kmdl->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;
	(*rsp)->object.mdl_conf.metadata_keys_count = 0;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kmdl) {
			if (kmdl->metadata_table.entries)
				kfree(kmdl->metadata_table.entries);
			if (kmdl->md_configs)
				kfree(kmdl->md_configs);
			kfree(kmdl);
		}
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_METALIST);
}

int kparser_read_metalist(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_metadata_table *kmdl;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST, key);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	(*rsp)->key = kmdl->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmdl->glue.config.conf_keys_bv;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;

	for (i = 0; i < kmdl->md_configs_len; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
				op, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			kmdl->md_configs[i].namespace_id;
		objects[i].conf_keys_bv = kmdl->md_configs[i].conf_keys_bv;
		objects[i].md_conf = kmdl->md_configs[i].md_conf;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_METALIST);
}

int kparser_del_metalist(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	struct kparser_obj_link_ctx *node_tmp_list_ref = NULL;
	struct kparser_obj_link_ctx *node_curr_ref = NULL;
	struct kparser_glue_glue_parse_node *kparsenode;
	struct kparser_glue_metadata_extract *kmde;
	struct kparser_glue_metadata_table *kmdl;
	struct kparser_conf_cmd *objects = NULL;
	int i, rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST, key);
	if (!kmdl) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

        // verify if there is any associated immutable parser
	list_for_each_entry_safe(curr_ref, tmp_list_ref,
			&kmdl->glue.owned_list, owned_obj.list_node) {
		if (curr_ref->owner_obj.nsid != KPARSER_NS_NODE_PARSE)
			continue;
		if (kref_read(curr_ref->owner_obj.refcount) == 0)
			continue;
		kparsenode = (struct kparser_glue_glue_parse_node *)
			curr_ref->owner_obj.obj;
		list_for_each_entry_safe(node_curr_ref, node_tmp_list_ref,
				&kparsenode->glue.glue.owned_list,
				owned_obj.list_node) {
			if (node_curr_ref->owner_obj.nsid != KPARSER_NS_PARSER)
				continue;
			if (kref_read(node_curr_ref->owner_obj.refcount) != 1) {
				(*rsp)->op_ret_code = EBUSY;
				(void) snprintf((*rsp)->err_str_buf,
						sizeof((*rsp)->err_str_buf),
						"%s:attached parser `%s` is "
						"immutable",
						op,
						((struct kparser_glue_parser *)
						 node_curr_ref->owner_obj.obj)
						->glue.key.name);
				goto done;
			}
		}
	}

        if (kparser_link_detach(kmdl, &kmdl->glue.owner_list,
                                &kmdl->glue.owned_list, *rsp) != true)
                goto done;

	(*rsp)->key = kmdl->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kmdl->glue.config.conf_keys_bv;
	(*rsp)->object.mdl_conf = kmdl->glue.config.mdl_conf;

	for (i = 0; i < kmdl->md_configs_len; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
				__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			kmdl->md_configs[i].namespace_id;
		objects[i].conf_keys_bv = kmdl->md_configs[i].conf_keys_bv;
		objects[i].md_conf = kmdl->md_configs[i].md_conf;

		kmde = kparser_namespace_lookup(KPARSER_NS_METADATA,
				&objects[i].md_conf.key);
		if (!kmde) {
			(*rsp)->op_ret_code = ENOENT;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: Object key not found", op);
			goto done;
		}

		rc = kparser_namespace_remove(KPARSER_NS_METADATA,
				&kmde->glue.ht_node_id,
				&kmde->glue.ht_node_name);
		if (rc) {
			(*rsp)->op_ret_code = rc;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s: namespace remove error", op);
			goto done;
		}

		kfree(kmde);
	}

	rc = kparser_namespace_remove(KPARSER_NS_METALIST,
			&kmdl->glue.ht_node_id,
			&kmdl->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: namespace remove error", op);
		goto done;
	}

	if (kmdl->metadata_table.entries)
		kfree(kmdl->metadata_table.entries);

	kmdl->metadata_table.num_ents = 0;

	if (kmdl->md_configs)
		kfree(kmdl->md_configs);

	if (kmdl)
		kfree(kmdl);

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_METALIST);
}

void kparser_free_metalist(void *ptr, void *arg)
{
	struct kparser_glue_metadata_table *kmdl = ptr;
	struct kparser_glue_metadata_extract *kmde;
	int i;

	return;

	if (!ptr)
		return;

	for (i = 0; i < kmdl->md_configs_len; i++) {
		kmde = kparser_namespace_lookup(KPARSER_NS_METADATA,
				&kmdl->md_configs[i].md_conf.key);
		if (!kmde)
			continue;

		(void) kparser_namespace_remove(KPARSER_NS_METADATA,
				&kmde->glue.ht_node_id,
				&kmde->glue.ht_node_name);
		kfree(kmde);
	}

	if (kmdl->md_configs)
		kfree(kmdl->md_configs);

	if (kmdl->metadata_table.entries)
		kfree(kmdl->metadata_table.entries);

	if (kmdl)
		kfree(kmdl);
}

static inline bool kparser_conf_node_convert(
		const struct kparser_conf_node *conf,
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

	if (!conf || !node || (node_len < sizeof(*plain_parse_node)))
		return false;

	plain_parse_node = node;
	plain_parse_node->node_type = conf->type;
	plain_parse_node->unknown_ret = conf->plain_parse_node.unknown_ret;

	plain_parse_node->proto_node.encap =
		conf->plain_parse_node.proto_node.encap;
	plain_parse_node->proto_node.overlay =
		conf->plain_parse_node.proto_node.overlay;
	plain_parse_node->proto_node.min_len =
		conf->plain_parse_node.proto_node.min_len;

	/*
	// TODO
	plain_parse_node->proto_node.ops.flag_fields_length =
		conf->plain_parse_node.proto_node.ops.flag_fields_length;
	*/
	plain_parse_node->proto_node.ops.len_parameterized =
		conf->plain_parse_node.proto_node.ops.len_parameterized;
	plain_parse_node->proto_node.ops.pflen =
		conf->plain_parse_node.proto_node.ops.pflen;

	plain_parse_node->proto_node.ops.pfnext_proto =
		conf->plain_parse_node.proto_node.ops.pfnext_proto;

	kcond_tables = kparser_namespace_lookup(
			KPARSER_NS_CONDEXPRS_TABLES,
			&conf->plain_parse_node.proto_node.
			ops.cond_exprs_table);
	if (kcond_tables) {
		plain_parse_node->proto_node.ops.cond_exprs =
			kcond_tables->table;
		plain_parse_node->proto_node.ops.cond_exprs_parameterized =
			true;
	}

	strcpy(plain_parse_node->name, conf->key.name);

	kprototbl = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE,
			&conf->plain_parse_node.proto_table_key);
	if (kprototbl)
		rcu_assign_pointer(plain_parse_node->proto_table,
				&kprototbl->proto_table);

	kparsewildcardnode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&conf->plain_parse_node.wildcard_parse_node_key);
	if (kparsewildcardnode)
		rcu_assign_pointer(plain_parse_node->wildcard_node,
				&kparsewildcardnode->parse_node);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST,
			&conf->plain_parse_node.metadata_table_key);
	if (kmdl)
		rcu_assign_pointer(plain_parse_node->metadata_table,
				&kmdl->metadata_table);

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

		kprototlvstbl = kparser_namespace_lookup(
				KPARSER_NS_TLV_PROTO_TABLE,
				&conf->tlvs_parse_node.tlv_proto_table_key);
		if (kprototlvstbl)
			rcu_assign_pointer(tlvs_parse_node->tlv_proto_table,
					&kprototlvstbl->tlvs_proto_table);

		kparsetlvwildcardnode = kparser_namespace_lookup(
				KPARSER_NS_TLV_NODE_PARSE,
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

		kflag_fields = kparser_namespace_lookup(
				KPARSER_NS_FLAG_FIELD_TABLE,
				&conf->flag_fields_parse_node.proto_node.
				flag_fields_table_hkey);
		if (kflag_fields)
			rcu_assign_pointer(flag_fields_parse_node->
					parse_node.flag_fields_proto_node.
					flag_fields,
					&kflag_fields->flag_fields);

		kflag_fields_proto_table = kparser_namespace_lookup(
				KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
				&conf->flag_fields_parse_node.
				flag_fields_proto_table_key);
		if (kflag_fields_proto_table)
			rcu_assign_pointer(flag_fields_parse_node->
					flag_fields_proto_table,
					&kflag_fields_proto_table->
					flags_proto_table);
		break;

	default:
		return false;
	}
	return true;
}

int kparser_create_parse_node(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_glue_parse_node *kparsenode = NULL;
	struct kparser_glue_protocol_table *proto_table;
	struct kparser_glue_metadata_table *mdl;
	const struct kparser_conf_node *arg;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->node_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kparsenode = kzalloc(sizeof(*kparsenode), GFP_KERNEL);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
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
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
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
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_conf_node_convert() err",
				__FUNCTION__);
		goto done;
	}

	if (kparsenode->parse_node.node.proto_table) {
		proto_table = container_of(
				kparsenode->parse_node.node.proto_table,
				struct kparser_glue_protocol_table,
				proto_table);
		if (kparser_link_attach(kparsenode,
					KPARSER_NS_NODE_PARSE,
					(const void**)&kparsenode->parse_node.
					node.proto_table,
					&kparsenode->glue.glue.refcount,
					&kparsenode->glue.glue.owner_list,
					proto_table,
					KPARSER_NS_PROTO_TABLE,
					&proto_table->glue.refcount,
					&proto_table->glue.owned_list,
					*rsp, op) == false)
			goto done;
	}

	if (kparsenode->parse_node.node.metadata_table) {
		mdl = container_of(kparsenode->parse_node.node.metadata_table,
				struct kparser_glue_metadata_table,
				metadata_table);
		if (kparser_link_attach(kparsenode,
					KPARSER_NS_NODE_PARSE,
					(const void**)&kparsenode->parse_node.
					node.metadata_table,
					&kparsenode->glue.glue.refcount,
					&kparsenode->glue.glue.owner_list,
					mdl,
					KPARSER_NS_METALIST,
					&mdl->glue.refcount,
					&mdl->glue.owned_list,
					*rsp, op) == false)
			goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.node_conf =
		kparsenode->glue.glue.config.node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kparsenode)
			kfree(kparsenode);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE);
}

int kparser_read_parse_node(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_glue_parse_node *kparsenode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, key);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kparsenode->glue.glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparsenode->glue.glue.config.conf_keys_bv;
	(*rsp)->object.node_conf =
		kparsenode->glue.glue.config.node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE);
}

int kparser_del_parse_node(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	struct kparser_glue_glue_parse_node *kparsenode;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE, key);
	if (!kparsenode) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	// verify if there is any associated immutable parser
	list_for_each_entry_safe(curr_ref, tmp_list_ref,
			&kparsenode->glue.glue.owned_list,
			owned_obj.list_node) {
		if (curr_ref->owner_obj.nsid != KPARSER_NS_PARSER)
			continue;
		if (kref_read(curr_ref->owner_obj.refcount) != 1) {
			(*rsp)->op_ret_code = EBUSY;
			(void) snprintf((*rsp)->err_str_buf,
					sizeof((*rsp)->err_str_buf),
					"%s:attached parser `%s` is immutable",
					op, ((struct kparser_glue_parser *)
					curr_ref->owner_obj.obj)->glue.key.name);
			goto done;
		}
	}

	if (kparser_link_detach(kparsenode, &kparsenode->glue.glue.owner_list,
				&kparsenode->glue.glue.owned_list,
				*rsp) != true)
		goto done;

	rc = kparser_namespace_remove(KPARSER_NS_NODE_PARSE,
			&kparsenode->glue.glue.ht_node_id,
			&kparsenode->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: namespace remove error", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparsenode->glue.glue.config.conf_keys_bv;
	(*rsp)->object.node_conf =
		kparsenode->glue.glue.config.node_conf;

	if (kparsenode)
		kfree(kparsenode);
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE);
}

void kparser_free_node(void *ptr, void *arg)
{
	return;

	if (ptr)
		kfree(ptr);
}

static bool kparser_create_proto_table_ent(
		const struct kparser_conf_table *arg,
		struct kparser_glue_protocol_table **proto_table,
		struct kparser_cmd_rsp_hdr *rsp, const char *op)
{
	struct kparser_glue_glue_parse_node *kparsenode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found", op);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&arg->elem_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: parse node key:{%s:%u} not found",
				op, arg->elem_key.name,
				arg->elem_key.id);
		return false;
	}

	(*proto_table)->proto_table.num_ents++;
	rcu_assign_pointer((*proto_table)->proto_table.entries,
			krealloc((*proto_table)->proto_table.entries,
			(*proto_table)->proto_table.num_ents *
			sizeof(struct kparser_proto_table_entry),
			GFP_KERNEL | ___GFP_ZERO));
	if (!(*proto_table)->proto_table.entries) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: krealloc() err, ents:%d, size:%lu",
				op,
				(*proto_table)->proto_table.num_ents,
				sizeof(struct kparser_proto_table_entry));
		return false;
	}

	if (kparser_link_attach(*proto_table,
				KPARSER_NS_PROTO_TABLE,
				NULL, // due to realloc, cant cache pointer here
				&(*proto_table)->glue.refcount,
				&(*proto_table)->glue.owner_list,
				kparsenode,
				KPARSER_NS_NODE_PARSE,
				&kparsenode->glue.glue.refcount,
				&kparsenode->glue.glue.owned_list,
				rsp, op) == false)
		return false;

	(*proto_table)->proto_table.entries[
		(*proto_table)->proto_table.num_ents - 1].value =
			arg->optional_value1;
	(*proto_table)->proto_table.entries[
		(*proto_table)->proto_table.num_ents - 1].encap =
			arg->optional_value2;
	(*proto_table)->proto_table.entries[
		(*proto_table)->proto_table.num_ents - 1].node =
			&kparsenode->parse_node.node; // TODO:

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_proto_table(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_protocol_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	//create a table entry
	if (arg->add_entry) {
		if(kparser_create_proto_table_ent(arg,
					&proto_table, *rsp, op) == false)
			goto done;
		goto skip_table_create;
	}

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key", op);
		goto done;
	}

	//create protocol table
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", op);
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
			&proto_table->glue.ht_node_id,
			&proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err", op);
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
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf = *arg; // proto_table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kfree(proto_table);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE);
}

int kparser_read_proto_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_protocol_table *proto_table;
	const struct kparser_glue_glue_parse_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 =
			proto_table->proto_table.entries[i].value;
		if (!proto_table->proto_table.entries[i].node)
			continue;
		parse_node = container_of(
				proto_table->proto_table.entries[i].node,
				struct kparser_glue_glue_parse_node,
				parse_node.node); /* TODO */
		objects[i].table_conf.elem_key=
			parse_node->glue.glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE);
}

int kparser_del_proto_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_obj_link_ctx *tmp_list_ref = NULL, *curr_ref = NULL;
	struct kparser_obj_link_ctx *node_tmp_list_ref = NULL;
	struct kparser_obj_link_ctx *node_curr_ref = NULL;
	struct kparser_glue_protocol_table *proto_table;
	struct kparser_glue_glue_parse_node *kparsenode;
	struct kparser_glue_glue_parse_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	int i, rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

        // verify if there is any associated immutable parser
	list_for_each_entry_safe(curr_ref, tmp_list_ref,
			&proto_table->glue.owned_list, owned_obj.list_node) {
		if (curr_ref->owner_obj.nsid != KPARSER_NS_NODE_PARSE)
			continue;
		if (kref_read(curr_ref->owner_obj.refcount) == 1)
			continue;
		kparsenode = (struct kparser_glue_glue_parse_node *)
			curr_ref->owner_obj.obj;
		list_for_each_entry_safe(node_curr_ref, node_tmp_list_ref,
				&kparsenode->glue.glue.owned_list,
				owned_obj.list_node) {
			if (node_curr_ref->owner_obj.nsid != KPARSER_NS_PARSER)
				continue;
			if (kref_read(node_curr_ref->owner_obj.refcount) != 1) {
				(*rsp)->op_ret_code = EBUSY;
				(void) snprintf((*rsp)->err_str_buf,
						sizeof((*rsp)->err_str_buf),
						"%s:attached parser `%s` is "
						"immutable",
						op,
						((struct kparser_glue_parser *)
						 node_curr_ref->owner_obj.obj)
						->glue.key.name);
				goto done;
			}
		}
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 =
			proto_table->proto_table.entries[i].value;
		if (!proto_table->proto_table.entries[i].node)
			continue;
		parse_node = container_of(
				proto_table->proto_table.entries[i].node,
				struct kparser_glue_glue_parse_node,
				parse_node.node); /* TODO */
		objects[i].table_conf.elem_key =
			parse_node->glue.glue.key;
	}

	if (kparser_link_detach(proto_table, &proto_table->glue.owner_list,
		&proto_table->glue.owned_list, *rsp) != true)
		goto done;

	rc = kparser_namespace_remove(KPARSER_NS_PROTO_TABLE,
			&proto_table->glue.ht_node_id,
			&proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: namespace remove error", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");

	if (proto_table->proto_table.entries)
		kfree(proto_table->proto_table.entries);

	if (proto_table)
		kfree(proto_table);
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE);
}

void kparser_free_proto_tbl(void *ptr, void *arg)
{
	struct kparser_glue_protocol_table *proto_table = ptr;

	return;

	if (!ptr)
		return;
	if (proto_table->proto_table.entries)
		kfree(proto_table->proto_table.entries);

	kfree(proto_table);
}

static inline bool kparser_conf_tlv_node_convert(
		const struct kparser_conf_node_parse_tlv *conf,
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

	node->proto_tlv_node.ops.pfoverlay_type =
		conf->node_proto.ops.pfoverlay_type;
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
					     &conf->
					     overlay_proto_tlvs_table_key);
	if (kprototbl)
		rcu_assign_pointer(node->overlay_table,
				   &kprototbl->tlvs_proto_table);

	kparsewildcardnode = kparser_namespace_lookup(
			KPARSER_NS_TLV_NODE_PARSE,
			&conf->overlay_wildcard_parse_node_key);
	if (kparsewildcardnode)
		rcu_assign_pointer(node->overlay_wildcard_node,
				   &kparsewildcardnode->tlv_parse_node);

	node->unknown_overlay_ret = conf->unknown_ret;

	strcpy(node->name, conf->key.name);

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST,
					&conf->metadata_table_key);
	if (kmdl)
		rcu_assign_pointer(node->metadata_table,
				   &kmdl->metadata_table);

	return true;
}

int kparser_create_parse_tlv_node(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	const struct kparser_conf_node_parse_tlv *arg;
	struct kparser_glue_parse_tlv_node *node = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->tlv_node_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	node->glue.glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &node->glue.glue.ht_node_id,
				      &node->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	node->glue.glue.config.namespace_id = conf->namespace_id;
	node->glue.glue.config.conf_keys_bv = conf->conf_keys_bv;
	node->glue.glue.config.tlv_node_conf = *arg;
	node->glue.glue.config.tlv_node_conf.key = key;
	kref_init(&node->glue.glue.refcount);

	if (!kparser_conf_tlv_node_convert(arg, &node->tlv_parse_node)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_conf_tlv_node_convert() err",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.tlv_node_conf =
		node->glue.glue.config.tlv_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (node)
			kfree(node);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_NODE_PARSE);
}

int kparser_read_parse_tlv_node(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_parse_tlv_node *node;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	node = kparser_namespace_lookup(KPARSER_NS_TLV_NODE_PARSE, key);
	if (!node) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = node->glue.glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = node->glue.glue.config.conf_keys_bv;
	(*rsp)->object.tlv_node_conf =
		node->glue.glue.config.tlv_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_NODE_PARSE);
}

static bool kparser_create_tlv_proto_table_ent(
		const struct kparser_conf_table *arg,
		struct kparser_glue_proto_tlvs_table **proto_table,
		struct kparser_cmd_rsp_hdr *rsp)
{
	const struct kparser_glue_parse_tlv_node *kparsenode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_TLV_PROTO_TABLE,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_TLV_NODE_PARSE,
			&arg->elem_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key:{%s:%u} not found",
				__FUNCTION__,
				arg->elem_key.name,
				arg->elem_key.id);
		return false;
	}

	(*proto_table)->tlvs_proto_table.num_ents++;
	rcu_assign_pointer((*proto_table)->tlvs_proto_table.entries,
			krealloc((*proto_table)->tlvs_proto_table.entries,
			(*proto_table)->tlvs_proto_table.num_ents *
			sizeof(struct kparser_proto_tlvs_table_entry),
			GFP_KERNEL | ___GFP_ZERO));
	if (!(*proto_table)->tlvs_proto_table.entries) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: krealloc() err, ents:%d, size:%lu",
				__FUNCTION__,
				(*proto_table)->tlvs_proto_table.num_ents,
				sizeof(struct kparser_proto_tlvs_table_entry));
		return false;
	}

	(*proto_table)->tlvs_proto_table.entries[
		(*proto_table)->tlvs_proto_table.num_ents - 1].type =
			arg->optional_value1;
	(*proto_table)->tlvs_proto_table.entries[
		(*proto_table)->tlvs_proto_table.num_ents - 1].node =
			&kparsenode->tlv_parse_node;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_tlv_proto_table(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_proto_tlvs_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	//create a table entry
	if (arg->add_entry) {
		if(kparser_create_tlv_proto_table_ent(arg,
					&proto_table, *rsp) == false)
			goto done;
		goto skip_table_create;
	}

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	//create protocol table
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
			&proto_table->glue.ht_node_id,
			&proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kfree(proto_table);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_PROTO_TABLE);
}

int kparser_read_tlv_proto_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_proto_tlvs_table *proto_table;
	const struct kparser_glue_parse_tlv_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(KPARSER_NS_TLV_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->tlvs_proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 =
			proto_table->tlvs_proto_table.entries[i].type;
		if (!proto_table->tlvs_proto_table.entries[i].node)
			continue;
		parse_node = container_of(
				proto_table->tlvs_proto_table.entries[i].node,
				struct kparser_glue_parse_tlv_node,
				tlv_parse_node);
		objects[i].table_conf.elem_key=
			parse_node->glue.glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_TLV_PROTO_TABLE);
}

int kparser_create_flag_field(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	const struct kparser_conf_flag_field *arg;
	struct kparser_glue_flag_field *kobj = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->flag_field_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	kobj->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &kobj->glue.ht_node_id,
				      &kobj->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	kobj->glue.config.namespace_id = conf->namespace_id;
	kobj->glue.config.conf_keys_bv = conf->conf_keys_bv;
	kobj->glue.config.flag_field_conf = *arg;
	kobj->glue.config.flag_field_conf.key = key;
	kref_init(&kobj->glue.refcount);

	kobj->flag_field = arg->conf;

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.flag_field_conf = kobj->glue.config.flag_field_conf;

done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (kobj)
			kfree(kobj);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD);
}

int kparser_read_flag_field(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_glue_flag_field *kobj;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kobj = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD, key);
	if (!kobj) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kobj->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kobj->glue.config.conf_keys_bv;
	(*rsp)->object.flag_field_conf = kobj->glue.config.flag_field_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD);
}

static int compare(const void *lhs, const void *rhs)
{
	const struct kparser_flag_field *lhs_flag = lhs;
	const struct kparser_flag_field *rhs_flag = rhs;

	pr_debug("lflag:%x rflag:%x\n", lhs_flag->flag, rhs_flag->flag);

	if (lhs_flag->flag < rhs_flag->flag) return -1;
	if (lhs_flag->flag > rhs_flag->flag) return 1;

	return 0;
}

static bool kparser_create_flag_field_table_ent(
		const struct kparser_conf_table *arg,
		struct kparser_glue_flag_fields **proto_table,
		struct kparser_cmd_rsp_hdr *rsp)
{
	const struct kparser_glue_flag_field *kflagent;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_TABLE,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		return false;
	}

	kflagent = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD,
			&arg->elem_key);
	if (!kflagent) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key:{%s:%u} not found",
				__FUNCTION__,
				arg->elem_key.name,
				arg->elem_key.id);
		return false;
	}

	(*proto_table)->flag_fields.num_idx++;

	rcu_assign_pointer((*proto_table)->flag_fields.fields,
			krealloc((*proto_table)->flag_fields.fields,
			(*proto_table)->flag_fields.num_idx *
			sizeof(struct kparser_flag_field),
			GFP_KERNEL | ___GFP_ZERO));
	if (!(*proto_table)->flag_fields.fields) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: krealloc() err, ents:%lu, size:%lu",
				__FUNCTION__,
				(*proto_table)->flag_fields.num_idx,
				sizeof(struct kparser_flag_field));
		return false;
	}

	(*proto_table)->flag_fields.fields[
		(*proto_table)->flag_fields.num_idx - 1] = kflagent->flag_field;

	sort((*proto_table)->flag_fields.fields,
			(*proto_table)->flag_fields.num_idx, 
			sizeof(struct kparser_flag_field),
			&compare, NULL);

	for (i = 0; i < (*proto_table)->flag_fields.num_idx; i++)
		pr_debug("List[%d]:%x\n",
				i, (*proto_table)->flag_fields.fields[i].flag);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_flag_field_table(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_flag_fields *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	//create a table entry
	if (arg->add_entry) {
		if(kparser_create_flag_field_table_ent(arg,
					&proto_table, *rsp) == false)
			goto done;
		goto skip_table_create;
	}

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	//create protocol table
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
			&proto_table->glue.ht_node_id,
			&proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kfree(proto_table);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_TABLE);
}

int kparser_read_flag_field_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_flag_fields *proto_table;
	const struct kparser_glue_flag_field *kflagent;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(
			KPARSER_NS_FLAG_FIELD_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->flag_fields.num_idx; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		objects[i].table_conf.optional_value1 = i;
		if (!proto_table->flag_fields.fields)
			continue;
		kflagent = container_of(
				&proto_table->flag_fields.fields[i],
				struct kparser_glue_flag_field, flag_field);
		objects[i].table_conf.elem_key=
			kflagent->glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_TABLE);
}

static inline bool kparser_create_parse_flag_field_node_convert(
		const struct kparser_conf_node_parse_flag_field *conf,
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

	kmdl = kparser_namespace_lookup(KPARSER_NS_METALIST,
					&conf->metadata_table_key);
	if (kmdl)
		rcu_assign_pointer(node->metadata_table,
				   &kmdl->metadata_table);

	return true;
}

int kparser_create_parse_flag_field_node(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	const struct kparser_conf_node_parse_flag_field *arg;
	struct kparser_glue_flag_field_node *node = NULL;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->flag_field_node_conf;

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	node->glue.glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
				      &node->glue.glue.ht_node_id,
				      &node->glue.glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	node->glue.glue.config.namespace_id = conf->namespace_id;
	node->glue.glue.config.conf_keys_bv = conf->conf_keys_bv;
	node->glue.glue.config.flag_field_node_conf = *arg;
	node->glue.glue.config.flag_field_node_conf.key = key;
	kref_init(&node->glue.glue.refcount);

	if (!kparser_create_parse_flag_field_node_convert(arg,
				&node->node_flag_field)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_conf_tlv_node_convert() err",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.flag_field_node_conf =
		node->glue.glue.config.flag_field_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (node)
			kfree(node);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_NODE_PARSE);
}

int kparser_read_parse_flag_field_node(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_flag_field_node *node;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	node = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_NODE_PARSE, key);
	if (!node) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = node->glue.glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = node->glue.glue.config.conf_keys_bv;
	(*rsp)->object.flag_field_node_conf =
		node->glue.glue.config.flag_field_node_conf;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_NODE_PARSE);
}

static bool kparser_create_flag_field_proto_table_ent(
		const struct kparser_conf_table *arg,
		struct kparser_glue_proto_flag_fields_table **proto_table,
		struct kparser_cmd_rsp_hdr *rsp)
{
	const struct kparser_glue_flag_field_node *kparsenode;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	*proto_table = kparser_namespace_lookup(
			KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
			&arg->key);
	if (!(*proto_table)) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		return false;
	}

	kparsenode = kparser_namespace_lookup(KPARSER_NS_FLAG_FIELD_NODE_PARSE,
			&arg->elem_key);
	if (!kparsenode) {
		rsp->op_ret_code = ENOENT;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: Object key:{%s:%u} not found",
				__FUNCTION__,
				arg->elem_key.name,
				arg->elem_key.id);
		return false;
	}

	(*proto_table)->flags_proto_table.num_ents++;
	rcu_assign_pointer((*proto_table)->flags_proto_table.entries,
			krealloc((*proto_table)->flags_proto_table.entries,
			(*proto_table)->flags_proto_table.num_ents *
			sizeof(struct kparser_proto_flag_fields_table_entry),
			GFP_KERNEL | ___GFP_ZERO));
	if (!(*proto_table)->flags_proto_table.entries) {
		rsp->op_ret_code = ENOMEM;
		(void) snprintf(rsp->err_str_buf,
				sizeof(rsp->err_str_buf),
				"%s: krealloc() err, ents:%d, size:%lu",
				__FUNCTION__,
				(*proto_table)->flags_proto_table.num_ents,
				sizeof(struct
					kparser_proto_flag_fields_table_entry));
		return false;
	}

	(*proto_table)->flags_proto_table.entries[
		(*proto_table)->flags_proto_table.num_ents - 1].flag =
			arg->optional_value1;
	(*proto_table)->flags_proto_table.entries[
		(*proto_table)->flags_proto_table.num_ents - 1].node =
			&kparsenode->node_flag_field;

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return true;
}

int kparser_create_flag_field_proto_table(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_proto_flag_fields_table *proto_table = NULL;
	const struct kparser_conf_table *arg;
	struct kparser_hkey key;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->table_conf;

	//create a table entry
	if (arg->add_entry) {
		if(kparser_create_flag_field_proto_table_ent(arg,
					&proto_table, *rsp) == false)
			goto done;
		goto skip_table_create;
	}

	if (!kparser_conf_key_manager(conf->namespace_id, &arg->key,
				&key, *rsp, op)) {
		printk("here:%s:%d\n", __FUNCTION__, __LINE__);
		goto done;
	}

	pr_debug("Key: {ID:%u Name:%s}\n", arg->key.id, arg->key.name);

	if (kparser_namespace_lookup(conf->namespace_id, &key)) {
		(*rsp)->op_ret_code = EEXIST;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Duplicate object key",
				__FUNCTION__);
		goto done;
	}

	//create protocol table
	proto_table = kzalloc(sizeof(*proto_table), GFP_KERNEL);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kzalloc() failed", __FUNCTION__);
		goto done;
	}

	proto_table->glue.key = key;

	rc = kparser_namespace_insert(conf->namespace_id,
			&proto_table->glue.ht_node_id,
			&proto_table->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: kparser_namespace_insert() err",
				__FUNCTION__);
		goto done;
	}

	proto_table->glue.config.namespace_id = conf->namespace_id;
	proto_table->glue.config.conf_keys_bv = conf->conf_keys_bv;
	proto_table->glue.config.table_conf = *arg;
	proto_table->glue.config.table_conf.key = key;
	kref_init(&proto_table->glue.refcount);

skip_table_create:
	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;
done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0)
		if (proto_table && !arg->add_entry)
			kfree(proto_table);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_PROTO_TABLE);
}

int kparser_read_flag_field_proto_table(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_proto_flag_fields_table *proto_table;
	const struct kparser_glue_flag_field_node *parse_node;
	struct kparser_conf_cmd *objects = NULL;
	int i;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	proto_table = kparser_namespace_lookup(
			KPARSER_NS_FLAG_FIELD_PROTO_TABLE, key);
	if (!proto_table) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	(*rsp)->key = proto_table->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = proto_table->glue.config.conf_keys_bv;
	(*rsp)->object.table_conf =
		proto_table->glue.config.table_conf;

	for (i = 0; i < proto_table->flags_proto_table.num_ents; i++) {
		(*rsp)->objects_len++;
		*rsp_len = *rsp_len + sizeof(struct kparser_conf_cmd);
		*rsp = krealloc(*rsp, *rsp_len,
				GFP_KERNEL | ___GFP_ZERO);
		if (!(*rsp)) {
			printk("%s:krealloc failed for rsp, len:%lu\n",
					__FUNCTION__, *rsp_len);
			*rsp_len = 0;
			mutex_unlock(&kparser_config_lock);
			return KPARSER_ATTR_UNSPEC;
		}
		objects = (struct kparser_conf_cmd *) (*rsp)->objects;
		objects[i].namespace_id =
			proto_table->glue.config.namespace_id;
		objects[i].table_conf =
			proto_table->glue.config.table_conf;
		if (!proto_table->flags_proto_table.entries[i].node)
			continue;
		objects[i].table_conf.optional_value1 =
			proto_table->flags_proto_table.entries[i].flag;
		parse_node = container_of(
				proto_table->flags_proto_table.entries[i].node,
				struct kparser_glue_flag_field_node,
				node_flag_field);
		objects[i].table_conf.elem_key=
			parse_node->glue.glue.key;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_FLAG_FIELD_PROTO_TABLE);
}

static inline bool kparser_parser_convert(
		const struct kparser_conf_parser *conf,
		struct kparser_parser *parser)
{
	struct kparser_glue_glue_parse_node *node;

	strcpy(parser->name, conf->key.name);

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&conf->root_node_key);
	if (node)
		rcu_assign_pointer(parser->root_node,
				   &node->parse_node.node);
	else
		return false;

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&conf->ok_node_key);
	if (node)
		rcu_assign_pointer(parser->okay_node,
				   &node->parse_node.node);

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&conf->fail_node_key);
	if (node)
		rcu_assign_pointer(parser->fail_node,
				   &node->parse_node.node);

	node = kparser_namespace_lookup(KPARSER_NS_NODE_PARSE,
			&conf->atencap_node_key);
	if (node)
		rcu_assign_pointer(parser->atencap_node,
				   &node->parse_node.node);

	parser->cntrs_conf = cntrs_conf;

	parser->config = conf->config;
	return true;
}

int kparser_create_parser(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	struct kparser_glue_glue_parse_node *parse_node;
	struct kparser_glue_parser *kparsr = NULL;
	struct kparser_counters *cntrs = NULL;
	const struct kparser_conf_parser *arg;
	struct kparser_parser parser = {};
	struct kparser_hkey key;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	arg = &conf->parser_conf;

	cntrs = kzalloc(sizeof(*cntrs), GFP_KERNEL);
	if (!cntrs) {
		(*rsp)->op_ret_code = ENOMEM;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
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
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: parser arg convert error", op);
		goto done;
	}

	if (kparser_cmd_create_pre_process(op, conf, &arg->key, &key,
		(void **) &kparsr, sizeof(*kparsr), *rsp,
		offsetof(struct kparser_glue_parser, glue)) == false)
		goto done;

	kparsr->parser = parser;

	INIT_LIST_HEAD(&kparsr->glue.owner_list);
	INIT_LIST_HEAD(&kparsr->glue.owned_list);

	if (kparsr->parser.root_node) {
		parse_node = container_of(kparsr->parser.root_node,
				struct kparser_glue_glue_parse_node,
				parse_node.node);
		if (kparser_link_attach(kparsr,
					KPARSER_NS_PARSER,
					(const void**)&kparsr->parser.root_node,
					&kparsr->glue.refcount,
					&kparsr->glue.owner_list,
					parse_node,
					KPARSER_NS_NODE_PARSE,
					&parse_node->glue.glue.refcount,
					&parse_node->glue.glue.owned_list,
					*rsp, op) == false)
			goto done;
	}

	if (kparsr->parser.okay_node) {
		parse_node = container_of(kparsr->parser.okay_node,
				struct kparser_glue_glue_parse_node,
				parse_node.node);
		if (kparser_link_attach(kparsr,
					KPARSER_NS_PARSER,
					(const void**)&kparsr->parser.okay_node,
					&kparsr->glue.refcount,
					&kparsr->glue.owner_list,
					parse_node,
					KPARSER_NS_NODE_PARSE,
					&parse_node->glue.glue.refcount,
					&parse_node->glue.glue.owned_list,
					*rsp, op) == false)
			goto done;
	}

	if (kparsr->parser.fail_node) {
		parse_node = container_of(kparsr->parser.fail_node,
				struct kparser_glue_glue_parse_node,
				parse_node.node);
		if (kparser_link_attach(kparsr,
					KPARSER_NS_PARSER,
					(const void**)&kparsr->parser.fail_node,
					&kparsr->glue.refcount,
					&kparsr->glue.owner_list,
					parse_node,
					KPARSER_NS_NODE_PARSE,
					&parse_node->glue.glue.refcount,
					&parse_node->glue.glue.owned_list,
					*rsp, op) == false)
			goto done;
	}

done:
	mutex_unlock(&kparser_config_lock);

	if ((*rsp)->op_ret_code != 0) {
		if (kparsr)
			kfree(kparsr);
		if (cntrs)
			kfree(cntrs);
	}

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_PARSER);
}

#if 0
static int kparser_iterate_parser(void)
{
	struct kparser_glue_parser *tmp_node, *node;

	list_for_each_entry_safe(node, tmp_node,
			&g_parser_list, list_node) {
		pr_debug("PK: %s:%02x\n", node->glue.key.name,
				node->glue.key.id);
	}
	return 0;
}
#endif

static bool kparser_dump_protocol_table(
		const struct kparser_proto_table *obj,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len);

static bool kparser_dump_metadata_table(
		const struct kparser_metadata_table *obj,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_glue_metadata_table *glue_obj;
	struct kparser_cmd_rsp_hdr *new_rsp = NULL;
	size_t new_rsp_len = 0;
	void *ptr;
	int rc;

	if (!obj)
		return true;

	rc = alloc_first_rsp(&new_rsp, &new_rsp_len, KPARSER_NS_METALIST);
	if (rc) {
		pr_debug("%s:alloc_first_rsp() failed, rc:%d\n",
				__FUNCTION__, rc);
		return false;
	}

	glue_obj = container_of(obj, struct kparser_glue_metadata_table,
			metadata_table); /* TODO */

	mutex_unlock(&kparser_config_lock);
	rc = kparser_read_metalist(&glue_obj->glue.key,
			&new_rsp, &new_rsp_len, false, "read");
	mutex_lock(&kparser_config_lock);

	if (rc != KPARSER_ATTR_RSP(KPARSER_NS_METALIST)) {
		goto error;
	}

	*rsp = krealloc(*rsp, *rsp_len + new_rsp_len,
			GFP_KERNEL | ___GFP_ZERO);
	ptr = (*rsp);
	ptr += (*rsp_len);
	(*rsp_len) = (*rsp_len) + new_rsp_len;
	memcpy(ptr, new_rsp, new_rsp_len);
	kfree(new_rsp);
	new_rsp = NULL;

	return true;
error:
	if (new_rsp)
		kfree(new_rsp);

	return false;
}

static bool kparser_dump_parse_node(
		const struct kparser_parse_node *obj,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_glue_glue_parse_node *glue_obj;
	struct kparser_cmd_rsp_hdr *new_rsp = NULL;
	size_t new_rsp_len = 0;
	void *ptr;
	int rc;

	if (!obj)
		return true;

	rc = alloc_first_rsp(&new_rsp, &new_rsp_len, KPARSER_NS_NODE_PARSE);
	if (rc) {
		pr_debug("%s:alloc_first_rsp() failed, rc:%d\n",
				__FUNCTION__, rc);
		return false;
	}

	glue_obj = container_of(obj, struct kparser_glue_glue_parse_node,
			parse_node.node); /* TODO */

	mutex_unlock(&kparser_config_lock);
	rc = kparser_read_parse_node(&glue_obj->glue.glue.key,
			&new_rsp, &new_rsp_len, false, "read");
	mutex_lock(&kparser_config_lock);

	if (rc != KPARSER_ATTR_RSP(KPARSER_NS_NODE_PARSE)) {
		goto error;
	}

	*rsp = krealloc(*rsp, *rsp_len + new_rsp_len,
			GFP_KERNEL | ___GFP_ZERO);
	ptr = (*rsp);
	ptr += (*rsp_len);
	(*rsp_len) = (*rsp_len) + new_rsp_len;
	memcpy(ptr, new_rsp, new_rsp_len);
	kfree(new_rsp);
	new_rsp = NULL;

	if (!kparser_dump_protocol_table(obj->proto_table, rsp, rsp_len))
		goto error;

	if (!kparser_dump_metadata_table(obj->metadata_table, rsp, rsp_len))
		goto error;

	return true;
error:
	if (new_rsp)
		kfree(new_rsp);

	return false;
}

static bool kparser_dump_protocol_table(
		const struct kparser_proto_table *obj,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_glue_protocol_table *glue_obj;
	struct kparser_cmd_rsp_hdr *new_rsp = NULL;
	size_t new_rsp_len = 0;
	void *ptr;
	int rc; // , i;

	if (!obj)
		return true;

	rc = alloc_first_rsp(&new_rsp, &new_rsp_len, KPARSER_NS_PROTO_TABLE);
	if (rc) {
		pr_debug("%s:alloc_first_rsp() failed, rc:%d\n",
				__FUNCTION__, rc);
		return false;
	}
	
	glue_obj = container_of(obj, struct kparser_glue_protocol_table,
			proto_table);

	mutex_unlock(&kparser_config_lock);
	rc = kparser_read_proto_table(&glue_obj->glue.key,
			&new_rsp, &new_rsp_len, false, "read");
	mutex_lock(&kparser_config_lock);

	if (rc != KPARSER_ATTR_RSP(KPARSER_NS_PROTO_TABLE)) {
		goto error;
	}

	*rsp = krealloc(*rsp, *rsp_len + new_rsp_len,
			GFP_KERNEL | ___GFP_ZERO);
	ptr = (*rsp);
	ptr += (*rsp_len);
	(*rsp_len) = (*rsp_len) + new_rsp_len;
	memcpy(ptr, new_rsp, new_rsp_len);
	kfree(new_rsp);
	new_rsp = NULL;
#if 0
	for (i = 0; i < glue_obj->proto_table.num_ents; i++) {
		if (!kparser_dump_parse_node(
					glue_obj->proto_table.entries[i].node,
					rsp, rsp_len))
			goto error;;
	}	
#endif

	return true;
error:
	if (new_rsp)
		kfree(new_rsp);

	return false;
}

static bool kparser_dump_parser(const struct kparser_glue_parser *kparsr,
		    struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	if (!kparser_dump_parse_node(
				kparsr->parser.root_node, rsp, rsp_len))
		goto error;

	return true;
error:
	return false;
}

int kparser_read_parser(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_parser *kparsr;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsr = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparsr) {
		// kparser_iterate_parser();
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kparsr->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparsr->glue.config.conf_keys_bv;
	(*rsp)->object.parser_conf =
		kparsr->glue.config.parser_conf;

	if (recursive_read &&
			kparser_dump_parser(kparsr, rsp, rsp_len) == false)
		pr_debug("kparser_dump_parser failed");
done:
	mutex_unlock(&kparser_config_lock);

	if (0) {
		kparser_dump_parser_tree(&kparsr->parser);
	}

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_PARSER);
}

int kparser_del_parser(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	struct kparser_glue_parser *kparsr;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsr = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparsr) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found", op);
		goto done;
	}

	if (kref_read(&kparsr->glue.refcount) != 1) {
		(*rsp)->op_ret_code = EBUSY;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Parser object is associated with a "
				" data path instance", op);
		goto done;
	}

	if (kparser_link_detach(kparsr, &kparsr->glue.owner_list,
				&kparsr->glue.owned_list, *rsp) != true)
		goto done;

	rc = kparser_namespace_remove(KPARSER_NS_PARSER,
			&kparsr->glue.ht_node_id, &kparsr->glue.ht_node_name);
	if (rc) {
		(*rsp)->op_ret_code = rc;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: namespace remove error", op);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = kparsr->glue.key;
	pr_debug("Key: {ID:%u Name:%s}\n", (*rsp)->key.id, (*rsp)->key.name);
	(*rsp)->object.conf_keys_bv = kparsr->glue.config.conf_keys_bv;
	(*rsp)->object.parser_conf = kparsr->glue.config.parser_conf;

	kfree(kparsr->parser.cntrs);
	kfree(kparsr);
done:
	mutex_unlock(&kparser_config_lock);


	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_PARSER);
}

void kparser_free_parser(void *ptr, void *arg)
{
	struct kparser_glue_parser *kparsr = ptr;

	return;

	if (!ptr)
		return;

	if (kparsr->parser.cntrs)
		kfree(kparsr->parser.cntrs);

	kfree(kparsr);
}

int kparser_parser_lock(const struct kparser_conf_cmd *conf,
		      size_t conf_len,
		      struct kparser_cmd_rsp_hdr **rsp,
		      size_t *rsp_len, const char *op)
{
	const struct kparser_parser *parser;
	const struct kparser_hkey *key;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	mutex_lock(&kparser_config_lock);

	key = &conf->obj_key;

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	parser = kparser_get_parser(key);
	if (!parser) {
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: object key not found",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = *key;
	(*rsp)->object.conf_keys_bv = conf->conf_keys_bv;
	(*rsp)->object.obj_key = *key;
done:
	mutex_unlock(&kparser_config_lock);

	synchronize_rcu();

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_OP_PARSER_LOCK_UNLOCK);
}

int kparser_parser_unlock(const struct kparser_hkey *key,
		    struct kparser_cmd_rsp_hdr **rsp,
		    size_t *rsp_len, __u8 recursive_read, const char *op)
{
	const struct kparser_glue_parser *kparsr;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	pr_debug("Key: {ID:%u Name:%s}\n", key->id, key->name);

	mutex_lock(&kparser_config_lock);

	kparsr = kparser_namespace_lookup(KPARSER_NS_PARSER, key);
	if (!kparsr) {
		// kparser_iterate_parser();
		(*rsp)->op_ret_code = ENOENT;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Object key not found",
				__FUNCTION__);
		goto done;
	}

	if (!kparser_put_parser(&kparsr->parser)) {
		(*rsp)->op_ret_code = EINVAL;
		(void) snprintf((*rsp)->err_str_buf,
				sizeof((*rsp)->err_str_buf),
				"%s: Parser unlock failed",
				__FUNCTION__);
		goto done;
	}

	(void) snprintf((*rsp)->err_str_buf, sizeof((*rsp)->err_str_buf),
			"Operation successful");
	(*rsp)->key = *key;
	(*rsp)->object.obj_key = *key;
done:
	mutex_unlock(&kparser_config_lock);

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return KPARSER_ATTR_RSP(KPARSER_NS_OP_PARSER_LOCK_UNLOCK);
}

static inline const struct kparser_conf_cmd *kparser_config_handler_preprocess(
		const void *cmdarg,
		size_t cmdarglen, struct kparser_cmd_rsp_hdr **rsp,
		size_t *rsp_len)
{
	enum kparser_global_namespace_ids ns_id;
	const struct kparser_conf_cmd *conf;
	int rc;

	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	conf = cmdarg;
	if (!conf || cmdarglen < sizeof(*conf) || !rsp || *rsp || !rsp_len ||
			(*rsp_len != 0) ||
			(conf->namespace_id <= KPARSER_NS_INVALID) ||
			(conf->namespace_id >= KPARSER_NS_MAX)) {
		pr_debug("{%s:%d}:[%p %lu %p %p %p %lu %d]\n",
				__FUNCTION__, __LINE__,
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
		pr_debug("%s:alloc_first_rsp() failed, rc:%d\n",
				__FUNCTION__, rc);
		goto err_return;
	} 

	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return cmdarg;

err_return:
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return NULL;
}

#define KPARSER_CONFIG_HANDLER_PRE					\
do {									\
	pr_debug("IN: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);	\
	conf = kparser_config_handler_preprocess(cmdarg, cmdarglen,	\
			rsp, rsp_len);					\
	if (!conf) {							\
		pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__,	\
				__LINE__);				\
		return KPARSER_ATTR_UNSPEC;				\
	}								\
	pr_debug("OUT: %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);	\
}									\
while(0)

int kparser_config_handler_add(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE;

	if (!g_mod_namespaces[conf->namespace_id]->create_handler)
		return KPARSER_ATTR_UNSPEC;
		
	return g_mod_namespaces[conf->namespace_id]->create_handler(
			conf, cmdarglen, rsp, rsp_len, "create");
}

int kparser_config_handler_update(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE;

	if (!g_mod_namespaces[conf->namespace_id]->update_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->update_handler(
			conf, cmdarglen, rsp, rsp_len, "update");
}

int kparser_config_handler_read(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE;

	if (!g_mod_namespaces[conf->namespace_id]->read_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->read_handler(
			&conf->obj_key, rsp, rsp_len,
			conf->recursive_read_delete, "read");
}

int kparser_config_handler_delete(const void *cmdarg, size_t cmdarglen,
		struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len)
{
	const struct kparser_conf_cmd *conf;

	KPARSER_CONFIG_HANDLER_PRE;

	if (!g_mod_namespaces[conf->namespace_id]->del_handler)
		return KPARSER_ATTR_UNSPEC;

	return g_mod_namespaces[conf->namespace_id]->del_handler(
			&conf->obj_key, rsp, rsp_len,
			conf->recursive_read_delete, "delete");
}
