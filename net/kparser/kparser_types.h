/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_types.h - kParser private data types header file
 *
 * Authors:     Tom Herbert <tom@sipanda.io>
 *              Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef __KPARSER_TYPES_H
#define __KPARSER_TYPES_H

#include <linux/hash.h>
#include <linux/kparser.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/rhashtable-types.h>
#include <linux/skbuff.h>
#include <linux/xxhash.h>

/* Sign extend an returned signed value */
#define KPARSER_EXTRACT_CODE(X) ((__s64)(short)(X))
#define KPARSER_IS_RET_CODE(X) (KPARSER_EXTRACT_CODE(X) < 0)
#define KPARSER_IS_NOT_OK_CODE(X) (KPARSER_EXTRACT_CODE(X) <= KPARSER_STOP_FAIL)
#define KPARSER_IS_OK_CODE(X)						\
	(KPARSER_IS_RET_CODE(X) && KPARSER_EXTRACT_CODE(X) > KPARSER_STOP_FAIL)

/* A table of conditional expressions, type indicates that the expressions
 * are or'ed of and'ed
 */
struct kparser_condexpr_table {
	int default_fail;
	enum kparser_condexpr_types type;
	unsigned int num_ents;
	const struct kparser_condexpr_expr __rcu **entries;
};

/* A table of tables of conditional expressions. This is used to create more
 * complex expressions using and's and or's
 */
struct kparser_condexpr_tables {
	unsigned int num_ents;
	const struct kparser_condexpr_table __rcu **entries;
};

/* Control data describing various values produced while parsing. This is
 * used an argument to metadata extraction and handler functions
 */
struct kparser_ctrl_data {
	int ret;
	size_t pkt_len;
	void *hdr_base;
	unsigned int node_cnt;
	unsigned int encap_levels;
};

/*****************************************************************************/

/* Protocol parsing operations:
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * len: Return length of protocol header. If value is NULL then the length of
 *	the header is taken from the min_len in the protocol node. If the
 *	return value < 0 (a KPARSER_STOP_* return code value) this indicates an
 *	error and parsing is stopped. A the return value greater than or equal
 *	to zero then gives the protocol length. If the returned length is less
 *	than the minimum protocol length, indicated in min_len by the protocol
 *	node, then this considered and error.
 * next_proto: Return next protocol. If value is NULL then there is no
 *	next protocol. If return value is greater than or equal to zero
 *	this indicates a protocol number that is used in a table lookup
 *	to get the next layer protocol node.
 * cond_exprs: Parameterization only. This describes a set of conditionals
 *	check before proceeding. In the case of functions being used, these
 *	conditionals would be in the next_proto or length function
 */

struct kparser_parse_ops {
	bool flag_fields_length;
	bool len_parameterized;
	struct kparser_parameterized_len pflen;
	struct kparser_parameterized_next_proto pfnext_proto;
	bool cond_exprs_parameterized;
	struct kparser_condexpr_tables cond_exprs;
};

/* Protocol node
 *
 * This structure contains the definitions to describe parsing of one type
 * of protocol header. Fields are:
 *
 * node_type: The type of the node (plain, TLVs, flag-fields)
 * encap: Indicates an encapsulation protocol (e.g. IPIP, GRE)
 * overlay: Indicates an overlay protocol. This is used, for example, to
 *	switch on version number of a protocol header (e.g. IP version number
 *	or GRE version number)
 * name: Text name of protocol node for debugging
 * min_len: Minimum length of the protocol header
 * ops: Operations to parse protocol header
 */
struct kparser_proto_node {
	__u8 encap;
	__u8 overlay;
	size_t min_len;
	struct kparser_parse_ops ops;
};

/* Protocol node and parse node operations ordering. When processing a
 * layer, operations are called in following order:
 *
 * protoop.len
 * parseop.extract_metadata
 * parseop.handle_proto
 * protoop.next_proto
 */
/* One entry in a protocol table:
 *	value: protocol number
 *	node: associated parse node for the protocol number
 */
struct kparser_proto_table_entry {
	int value;
	bool encap;
	const struct kparser_parse_node __rcu *node;
};

/* Protocol table
 *
 * Contains a protocol table that maps a protocol number to a parse
 * node
 */
struct kparser_proto_table {
	int num_ents;
	struct kparser_proto_table_entry __rcu *entries;
};

/*****************************************************************************/

struct kparser_cntrs_conf {
	struct kparser_cntr_conf cntrs[KPARSER_CNTR_NUM_CNTRS];
};

struct kparser_counters {
	__u16 cntr[KPARSER_CNTR_NUM_CNTRS];
};

/*****************************************************************************/

/* Definitions for parsing TLVs
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * TLVs are a common protocol header structure consisting of Type, Length,
 * Value tuple (e.g. for handling TCP or IPv6 HBH options TLVs)
 */

/* Descriptor for parsing operations of one type of TLV. Fields are:
 * For struct kparser_proto_tlvs_opts:
 * start_offset: Returns the offset of TLVs in a header
 * len: Return length of a TLV. Must be set. If the return value < 0 (a
 *	KPARSER_STOP_* return code value) this indicates an error and parsing
 *	is stopped. A the return value greater than or equal to zero then
 *	gives the protocol length. If the returned length is less than the
 *	minimum TLV option length, indicated by min_len by the TLV protocol
 *	node, then this considered and error.
 * type: Return the type of the TLV. If the return value is less than zero
 *	(KPARSER_STOP_* value) then this indicates and error and parsing stops
 */

/* A protocol node for parsing proto with TLVs
 *
 * proto_node: proto node
 * ops: Operations for parsing TLVs
 * start_offset: When there TLVs start relative the enapsulating protocol
 *	(e.g. would be twenty for TCP)
 * pad1_val: Type value indicating one byte of TLV padding (e.g. would be
 *	for IPv6 HBH TLVs)
 * pad1_enable: Pad1 value is used to detect single byte padding
 * eol_val: Type value that indicates end of TLV list
 * eol_enable: End of list value in eol_val is used
 * fixed_start_offset: Take start offset from start_offset
 * min_len: Minimal length of a TLV option
 */
struct kparser_proto_tlvs_node {
	struct kparser_proto_node proto_node;
	struct kparser_proto_tlvs_opts ops;
	size_t start_offset;
	__u8 pad1_val;
	__u8 padn_val;
	__u8 eol_val;
	bool pad1_enable;
	bool padn_enable;
	bool eol_enable;
	bool fixed_start_offset;
	size_t min_len;
};

/*****************************************************************************/

/* Definitions and functions for processing and parsing flag-fields */
/* Definitions for parsing flag-fields
 *
 * Flag-fields is a common networking protocol construct that encodes optional
 * data in a set of flags and data fields. The flags indicate whether or not a
 * corresponding data field is present. The data fields are fixed length per
 * each flag-field definition and ordered by the ordering of the flags
 * indicating the presence of the fields (e.g. GRE and GUE employ flag-fields)
 */

/* Flag-fields descriptors and tables
 *
 * A set of flag-fields is defined in a table of type struct kparser_flag_fields.
 * Each entry in the table is a descriptor for one flag-field in a protocol and
 * includes a flag value, mask (for the case of a multi-bit flag), and size of
 * the cooresponding field. A flag is matched if "(flags & mask) == flag"
 */

/* Descriptor for a protocol field with flag fields
 *
 * Defines the flags and their data fields for one instance a flag field in
 * a protocol header (e.g. GRE v0 flags):
 *
 * num_idx: Number of flag_field structures
 * fields: List of defined flag fields
 */
struct kparser_flag_fields {
	size_t num_idx;
	struct kparser_flag_field __rcu *fields;
};

/* Structure or parsing operations for flag-fields
 * For struct kparser_proto_flag_fields_ops
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * flags_offset: Offset of flags in the protocol header
 * start_fields_offset: Return the offset in the header of the start of the
 *	flag fields data
 */

/* A flag-fields protocol node. Note this is a super structure for aKPARSER
 * protocol node and type is KPARSER_NODE_TYPE_FLAG_FIELDS
 */
struct kparser_proto_flag_fields_node {
	struct kparser_proto_node proto_node;
	struct kparser_proto_flag_fields_ops ops;
	const struct kparser_flag_fields __rcu *flag_fields;
};

/*****************************************************************************/

/* Parse node definition. Defines parsing and processing for one node in
 * the parse graph of a parser. Contains:
 *
 * node_type: The type of the node (plain, TLVs, flag-fields)
 * unknown_ret: Code to return for a miss on the protocol table and the
 *	wildcard node is not set
 * proto_node: Protocol node
 * ops: Parse node operations
 * proto_table: Protocol table for next protocol. This must be non-null if
 *	next_proto is not NULL
 * wildcard_node: Node use for a miss on next protocol lookup
 * metadata_table: Table of parameterized metadata operations
 * thread_funcs: Thread functions
 */
struct kparser_parse_node {
	enum kparser_node_type node_type;
	char name[KPARSER_MAX_NAME];
	int unknown_ret;
	const struct kparser_proto_table __rcu *proto_table;
	const struct kparser_parse_node __rcu *wildcard_node;
	const struct kparser_metadata_table __rcu *metadata_table;
	union {
		struct kparser_proto_node proto_node;
		struct kparser_proto_tlvs_node tlvs_proto_node;
		struct kparser_proto_flag_fields_node flag_fields_proto_node;
	};
};

/*****************************************************************************/

/* TLV parse node operations
 *
 * Operations to process a single TLV
 *
 * Operations can be specified either as a function or a parameterization
 * of a parameterized function
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_tlv: Per TLV type handler which allows arbitrary processing
 *	of a TLV. Input is the TLV data and a parser defined metadata
 *	structure for the current frame. Return value is a parser
 *	return code: KPARSER_OKAY indicates no errors, KPARSER_STOP* return
 *	values indicate to stop parsing
 * check_tlv: Function to validate a TLV
 * cond_exprs: Parameterization of a set of conditionals to check before
 *	proceeding. In the case of functions being used, these
 *      conditionals would be in the check_tlv function
 */

/* One entry in a TLV table:
 *	type: TLV type
 *	node: associated TLV parse structure for the type
 */
struct kparser_proto_tlvs_table_entry {
	int type;
	const struct kparser_parse_tlv_node __rcu *node;
};

/* TLV table
 *
 * Contains a table that maps a TLV type to a TLV parse node
 */
struct kparser_proto_tlvs_table {
	int num_ents;
	struct kparser_proto_tlvs_table_entry __rcu *entries;
};

/* Parse node for parsing a protocol header that contains TLVs to be
 * parser:
 *
 * parse_node: Node for main protocol header (e.g. IPv6 node in case of HBH
 *	options) Note that node_type is set in parse_node to
 *	KPARSER_NODE_TYPE_TLVS and that the parse node can then be cast to a
 *	parse_tlv_node
 * tlv_proto_table: Lookup table for TLV type
 * unknown_tlv_type_ret: Code to return on a TLV type lookup miss and
 *	tlv_wildcard_node is NULL
 * tlv_wildcard_node: Node to use on a TLV type lookup miss
 * config: Loop configuration
 */
struct kparser_parse_tlvs_node {
	struct kparser_parse_node parse_node;
	const struct kparser_proto_tlvs_table __rcu *tlv_proto_table;
	int unknown_tlv_type_ret;
	const struct kparser_parse_tlv_node __rcu *tlv_wildcard_node;
	struct kparser_loop_node_config config;
};

struct kparser_proto_tlv_node_ops {
	bool overlay_type_parameterized;
	struct kparser_parameterized_next_proto pfoverlay_type;
	bool cond_exprs_parameterized;
	struct kparser_condexpr_tables cond_exprs;
};

/* A protocol node for parsing proto with TLVs
 *
 * min_len: Minimal length of TLV
 * max_len: Maximum size of a TLV option
 * is_padding: Indicates padding TLV
 */
struct kparser_proto_tlv_node {
	size_t min_len;
	size_t max_len;
	bool is_padding;
	struct kparser_proto_tlv_node_ops ops;
};

/* Parse node for a single TLV. Use common parse node operations
 * (extract_metadata and handle_proto)
 *
 * proto_tlv_node: TLV protocol node
 * tlv_ops: Operations on a TLV
 * overlay_table: Lookup table for an overlay TLV
 * overlay_wildcard_node: Wildcard node to an overlay lookup miss
 * unknown_overlay_ret: Code to return on an overlay lookup miss and
 *	overlay_wildcard_node is NULL
 * name: Name for debugging
 * metadata_table: Table of parameterized metadata operations
 * thread_funcs: Thread functions
 */
struct kparser_parse_tlv_node {
	struct kparser_proto_tlv_node proto_tlv_node;
	struct kparser_proto_tlvs_table __rcu *overlay_table;
	const struct kparser_parse_tlv_node __rcu *overlay_wildcard_node;
	int unknown_overlay_ret;
	char name[KPARSER_MAX_NAME];
	struct kparser_metadata_table __rcu *metadata_table;
};

/*****************************************************************************/

/* Flag-field parse node operations
 *
 * Operations to process a single flag-field
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_flag_field: Per flag-field handler which allows arbitrary processing
 *	of a flag-field. Input is the flag-field data and a parser defined
 *	metadata structure for the current frame. Return value is a parser
 *	return code: KPARSER_OKAY indicates no errors, KPARSER_STOP* return
 *	values indicate to stop parsing
 * check_flag_field: Function to validate a flag-field
 * cond_exprs: Parameterization of a set of conditionals to check before
 *      proceeding. In the case of functions being used, these
 *      conditionals would be in the check_flag_field function
 */
struct kparser_parse_flag_field_node_ops {
	struct kparser_condexpr_tables cond_exprs;
};

/* A parse node for a single flag field
 *
 * name: Text name for debugging
 * metadata_table: Table of parameterized metadata operations
 * ops: Operations
 * thread_funcs: Thread functions
 */
struct kparser_parse_flag_field_node {
	char name[KPARSER_MAX_NAME];
	struct kparser_metadata_table __rcu *metadata_table;
	struct kparser_parse_flag_field_node_ops ops;
};

/* One entry in a flag-fields protocol table:
 *	index: flag-field index (index in a flag-fields table)
 *	node: associated TLV parse structure for the type
 */
struct kparser_proto_flag_fields_table_entry {
	__u32 flag;
	const struct kparser_parse_flag_field_node __rcu *node;
};

/* Flag-fields table
 *
 * Contains a table that maps a flag-field index to a flag-field parse node.
 * Note that the index correlates to an entry in a flag-fields table that
 * describes the flag-fields of a protocol
 */
struct kparser_proto_flag_fields_table {
	int num_ents;
	struct kparser_proto_flag_fields_table_entry __rcu *entries;
};

/* A flag-fields parse node. Note this is a super structure for a KPARSER parse
 * node and type is KPARSER_NODE_TYPE_FLAG_FIELDS
 */
struct kparser_parse_flag_fields_node {
	struct kparser_parse_node parse_node;
	const struct kparser_proto_flag_fields_table __rcu
		*flag_fields_proto_table;
};

static inline ssize_t __kparser_flag_fields_offset(__u32 targ_idx, __u32 flags,
						   const struct kparser_flag_fields *flag_fields)
{
	ssize_t offset = 0;
	__u32 mask, flag;
	int i;

	for (i = 0; i < targ_idx; i++) {
		flag = flag_fields->fields[i].flag;
		if (flag_fields->fields[i].endian)
			flag = ntohs(flag);
		mask = flag_fields->fields[i].mask ? : flag;
		if ((flags & mask) == flag)
			offset += flag_fields->fields[i].size;
	}

	return offset;
}

/* Determine offset of a field given a set of flags */
static inline ssize_t kparser_flag_fields_offset(__u32 targ_idx, __u32 flags,
						 const struct kparser_flag_fields *flag_fields)
{
	__u32 mask, flag;

	flag = flag_fields->fields[targ_idx].flag;
	if (flag_fields->fields[targ_idx].endian)
		flag = ntohs(flag);
	mask = flag_fields->fields[targ_idx].mask ? : flag;
	if ((flags & mask) != flag) {
		/* Flag not set */
		return -1;
	}

	return __kparser_flag_fields_offset(targ_idx, flags, flag_fields);
}

/* Check flags are legal */
static inline bool kparser_flag_fields_check_invalid(__u32 flags, __u32 mask)
{
	return !!(flags & ~mask);
}

/* Retrieve a byte value from a flag field */
static inline __u8 kparser_flag_fields_get8(const __u8 *fields, __u32 targ_idx,
					    __u32 flags,
					    const struct kparser_flag_fields
					    *flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags,
			flag_fields);

	if (offset < 0)
		return 0;

	return *(__u8 *)&fields[offset];
}

/* Retrieve a short value from a flag field */
static inline __u16 kparser_flag_fields_get16(const __u8 *fields,
					      __u32 targ_idx,
		__u32 flags,
		const struct kparser_flag_fields
		*flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u16 *)&fields[offset];
}

/* Retrieve a 32 bit value from a flag field */
static inline __u32 kparser_get_flag_field32(const __u8 *fields, __u32 targ_idx,
					     __u32 flags,
		const struct kparser_flag_fields
		*flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u32 *)&fields[offset];
}

/* Retrieve a 64 bit value from a flag field */
static inline __u64 kparser_get_flag_field64(const __u8 *fields, __u32 targ_idx,
					     __u32 flags,
		const struct kparser_flag_fields
		*flag_fields)
{
	ssize_t offset = kparser_flag_fields_offset(targ_idx, flags,
			flag_fields);

	if (offset < 0)
		return 0;

	return *(__u64 *)&fields[offset];
}

/*****************************************************************************/

/* Definition of a KPARSER parser. Fields are:
 *
 * name: Text name for the parser
 * root_node: Root parse node of the parser. When the parser is invoked
 *	parsing commences at this parse node
 * okay_node: Processed at parser exit if no error
 * fail_node: Processed at parser exit if there was an error
 * parser_type: e.g. KPARSER_GENERIC, KPARSER_OPTIMIZED, KPARSER_KMOD, KPARSER_XDP
 * parser_entry_point: Function entry point for optimized parser
 * parser_xdp_entry_point: Function entry point for XDP parser
 * config: Parser conifguration
 */
#define KPARSERSTARTSIGNATURE 0xabcd
#define KPARSERENDSIGNATURE 0xdcba
struct kparser_parser {
	__u16 kparser_start_signature;
	char name[KPARSER_MAX_NAME];
	const struct kparser_parse_node __rcu *root_node;
	const struct kparser_parse_node __rcu *okay_node;
	const struct kparser_parse_node __rcu *fail_node;
	const struct kparser_parse_node __rcu *atencap_node;
	size_t cntrs_len;
	struct kparser_counters __rcu *cntrs;
	struct kparser_config config;
	struct kparser_cntrs_conf cntrs_conf;
	__u16 kparser_end_signature;
};

#endif /* __KPARSER_TYPES_H */
