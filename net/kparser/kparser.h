/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser.h - kParser local header file
 *
 * Author:      Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef __KPARSER_H
#define __KPARSER_H

#include <linux/hash.h>
#include <linux/kparser.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rhashtable-types.h>
#include <linux/skbuff.h>
#include <linux/xxhash.h>

#include "kparser_types.h"
#include "kparser_condexpr.h"
#include "kparser_metaextract.h"
#include "kparser_types.h"

/* These are used to track owner/owned relationship between different objects
 */
struct kparser_ref_ctx {
	int nsid;
	const void *obj;
	const void __rcu **link_ptr;
	struct kref *refcount;
	struct list_head *list;
	struct list_head list_node;
};

#define KPARSER_LINK_OBJ_SIGNATURE		0xffaabbff

/* bookkeeping structure to manage the above struct kparser_ref_ctx and map an owner with owned both
 * ways
 */
struct kparser_obj_link_ctx {
	int sig;
	struct kparser_ref_ctx owner_obj;
	struct kparser_ref_ctx owned_obj;
};

/* global hash table structures */
struct kparser_htbl {
	struct rhashtable tbl;
	struct rhashtable_params tbl_params;
};

/* it binds a netlink cli structure to an internal namespace object structure
 *
 * key: hash key, must be always the very first entry for hash functions to work correctly.
 * ht_node_id: ID based hash table's linking object.
 * ht_node_name: name based hash table's linking object.
 * refcount: tracks how many other objects are linked using refcount.
 * config: netlink msg's config structure cached, it is replayed back during read operations.
 * owner_list: list pointer for kparser_obj_link_ctx.owner_obj.list
 * owned_list: list pointer for kparser_obj_link_ctx.owned_obj.list
 */
struct kparser_glue {
	struct kparser_hkey key;
	struct rhash_head ht_node_id;
	struct rhash_head ht_node_name;
	struct kref refcount;
	struct kparser_conf_cmd config;
	struct list_head owner_list;
	struct list_head owned_list;
};

/* internal namespace structures for conditional expressions
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_condexpr_expr {
	struct kparser_glue glue;
	struct kparser_condexpr_expr expr;
};

/* internal namespace structures for conditional expressions table
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_condexpr_table {
	struct kparser_glue glue;
	struct kparser_condexpr_table table;
};

/* internal namespace structures for table of conditional expressions table
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_condexpr_tables {
	struct kparser_glue glue;
	struct kparser_condexpr_tables table;
};

/* internal namespace structures for counters
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_counter {
	struct kparser_glue glue;
	struct kparser_cntr_conf counter_cnf;
};

/* internal namespace structures for counter table
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_counter_table {
	struct kparser_glue glue;
	__u8 elems_cnt;
	struct kparser_glue_counter k_cntrs[KPARSER_CNTR_NUM_CNTRS];
};

/* internal namespace structures for metadata
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_metadata_extract {
	struct kparser_glue glue;
	struct kparser_metadata_extract mde;
};

/* internal namespace structures for metadata list
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_metadata_table {
	struct kparser_glue glue;
	size_t md_configs_len;
	struct kparser_conf_cmd *md_configs;
	struct kparser_metadata_table metadata_table;
};

/* internal namespace structures for node
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_node {
	struct kparser_glue glue;
};

struct kparser_glue_glue_parse_node {
	struct kparser_glue_node glue;
	union {
		struct kparser_parse_node node;
		struct kparser_parse_flag_fields_node flags_parse_node;
		struct kparser_parse_tlvs_node tlvs_parse_node;
	} parse_node;
};

/* internal namespace structures for table
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_protocol_table {
	struct kparser_glue glue;
	struct kparser_proto_table proto_table;
};

/* internal namespace structures for tlv nodes and tables
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_parse_tlv_node {
	struct kparser_glue_node glue;
	struct kparser_parse_tlv_node tlv_parse_node;
};

/* internal namespace structures for tlvs proto table
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_proto_tlvs_table {
	struct kparser_glue glue;
	struct kparser_proto_tlvs_table tlvs_proto_table;
};

/* internal namespace structures for flagfields and tables
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_flag_field {
	struct kparser_glue glue;
	struct kparser_flag_field flag_field;
};

/* internal namespace structures for flag field node
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_flag_fields {
	struct kparser_glue glue;
	struct kparser_flag_fields flag_fields;
};

struct kparser_glue_flag_field_node {
	struct kparser_glue_node glue;
	struct kparser_parse_flag_field_node node_flag_field;
};

/* internal namespace structures for flag field table
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_proto_flag_fields_table {
	struct kparser_glue glue;
	struct kparser_proto_flag_fields_table flags_proto_table;
};

/* internal namespace structures for parser
 * it binds a netlink cli structure to an internal namespace object structure
 */
struct kparser_glue_parser {
	struct kparser_glue glue;
	struct list_head list_node;
	struct kparser_parser parser;
};

/* name hash table's hash object comparison function callback */
static inline int kparser_cmp_fn_name(struct rhashtable_compare_arg *arg,
				      const void *ptr)
{
	const char *key2 = arg->key;
	const struct kparser_hkey *key1 = ptr;

	return strcmp(key1->name, key2);
}

/* ID hash table's hash object comparison function callback */
static inline int kparser_cmp_fn_id(struct rhashtable_compare_arg *arg,
				    const void *ptr)
{
	const __u16 *key2 = arg->key;
	const __u16 *key1 = ptr;

	return (*key1 != *key2);
}

/* name hash table's hash calculation function callback from hash key */
static inline __u32 kparser_generic_hash_fn_name(const void *hkey, __u32 key_len, __u32 seed)
{
	const char *key = hkey;

	/* TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 */
	return xxh32(hkey, strlen(key), 0);
}

/* ID hash table's hash calculation function callback from hash key */
static inline __u32 kparser_generic_hash_fn_id(const void *hkey, __u32 key_len, __u32 seed)
{
	const __u16 *key = hkey;
	/* TODO: check if seed needs to be used here
	 */
	return *key;
}

/* name hash table's hash calculation function callback from object */
static inline __u32 kparser_generic_obj_hashfn_name(const void *obj, __u32 key_len, __u32 seed)
{
	const struct kparser_hkey *key;

	key = obj;
	/* TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 * Note: this only works because key always in the start place
	 * of all the differnt kparser objects
	 */
	return xxh32(key->name, strlen(key->name), 0);
}

/* ID hash table's hash calculation function callback from object */
static inline __u32 kparser_generic_obj_hashfn_id(const void *obj, __u32 key_len, __u32 seed)
{
	/* TODO: check if seed needs to be used here
	 * TODO: replace xxh32() with siphash
	 * Note: this only works because key always is the very first object in all the differnt
	 * kparser objects
	 */
	return ((const struct kparser_hkey *)obj)->id;
}

/* internal shared functions */
int kparser_init(void);
int kparser_deinit(void);
int kparser_config_handler_add(const void *cmdarg, size_t cmdarglen,
			       struct kparser_cmd_rsp_hdr **rsp,
			       size_t *rsp_len,
			       void *extack, int *err);
int kparser_config_handler_update(const void *cmdarg, size_t cmdarglen,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len,
				  void *extack, int *err);
int kparser_config_handler_read(const void *cmdarg, size_t cmdarglen,
				struct kparser_cmd_rsp_hdr **rsp,
				size_t *rsp_len,
				void *extack, int *err);
int kparser_config_handler_delete(const void *cmdarg, size_t cmdarglen,
				  struct kparser_cmd_rsp_hdr **rsp,
				  size_t *rsp_len,
				  void *extack, int *err);
void *kparser_namespace_lookup(enum kparser_global_namespace_ids ns_id,
			       const struct kparser_hkey *key);
void kparser_ref_get(struct kref *refcount);
void kparser_ref_put(struct kref *refcount);
int kparser_conf_key_manager(enum kparser_global_namespace_ids ns_id,
			     const struct kparser_hkey *key,
			     struct kparser_hkey *new_key,
			     struct kparser_cmd_rsp_hdr *rsp,
			     const char *op,
			     void *extack, int *err);
void kparser_free(void *ptr);
int kparser_namespace_remove(enum kparser_global_namespace_ids ns_id,
			     struct rhash_head *obj_id,
			     struct rhash_head *obj_name);
int kparser_namespace_insert(enum kparser_global_namespace_ids ns_id,
			     struct rhash_head *obj_id,
			     struct rhash_head *obj_name);

/* Generic kParser KMOD's netlink msg handler's definitions for create */
typedef int kparser_obj_create_update(const struct kparser_conf_cmd *conf,
				      size_t conf_len,
				      struct kparser_cmd_rsp_hdr **rsp,
				      size_t *rsp_len, const char *op,
				      void *extack, int *err);
/* Generic kParser KMOD's netlink msg handler's definitions for read and delete */
typedef int kparser_obj_read_del(const struct kparser_hkey *key,
		struct kparser_cmd_rsp_hdr **rsp,
		size_t *rsp_len, __u8 recursive_read,
		const char *op, void *extack, int *err);
/* Generic kParser KMOD's netlink msg handler's free callbacks */
typedef void kparser_free_obj(void *ptr, void *arg);
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
			void *extack, int *err);
int kparser_link_detach(const void *obj,
			struct list_head *owner_list,
			struct list_head *owned_list,
			struct kparser_cmd_rsp_hdr *rsp,
			void *extack, int *err);
int alloc_first_rsp(struct kparser_cmd_rsp_hdr **rsp, size_t *rsp_len, int nsid);
void kparser_start_new_tree_traversal(void);
void kparser_dump_parser_tree(const struct kparser_parser *obj);

/* kParser KMOD's netlink msg/cmd handler's, these are innermost handlers */
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

#define KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_START	0
#define KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_STOP		255

extern void __rcu
	*kparser_fast_lookup_array[KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_STOP -
	KPARSER_PARSER_FAST_LOOKUP_RSVD_ID_START + 1];

#define KPARSER_KMOD_DEBUG_PRINT(PARSER_FLAG, FMT, ARGS...)			\
do {										\
	unsigned int parser_flag = PARSER_FLAG;					\
	if ((parser_flag) & KPARSER_F_DEBUG_DATAPATH)				\
		pr_alert("kParser:DATA:[%s:%d]" FMT, __func__, __LINE__, ## ARGS);\
	else if ((parser_flag) & KPARSER_F_DEBUG_CLI)				\
		pr_alert("kParser:CLI:[%s:%d]" FMT, __func__, __LINE__, ## ARGS);\
	else									\
		pr_debug("kParser:[%s:%d]" FMT, __func__, __LINE__, ## ARGS);	\
}										\
while (0)

#endif /* __KPARSER_H */
