/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser.h - kParser global Linux header file
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
 * Authors:     Tom Herbert <tom@sipanda.io>
 *              Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef _LINUX_KPARSER_H
#define _LINUX_KPARSER_H

#include <linux/string.h>
#include <linux/types.h>

#define BITS_IN_BYTE	8
#define BITS_IN_U32	(sizeof(__u32) * BITS_IN_BYTE)

#define kparsersetbit(A, k) (A[(k)/BITS_IN_U32] |= (1 << ((k) % BITS_IN_U32)))
#define kparserclearbit(A, k) (A[(k)/BITS_IN_U32] &= ~(1 << ((k) % BITS_IN_U32)))
#define kparsertestbit(A, k) (1 & (A[(k)/BITS_IN_U32] >> ((k) % BITS_IN_U32)))

/* *********************** NETLINK_GENERIC *********************** */
#define KPARSER_GENL_NAME		"kParser"
#define KPARSER_GENL_VERSION		0x1


/* *********************** NETLINK CLI *********************** */
#define KPARSER_ERR_STR_MAX_LEN		256
/* *********************** Namespaces/objects *********************** */
enum kparser_global_namespace_ids {
	KPARSER_NS_INVALID,

	KPARSER_NS_CONDEXPRS,
	KPARSER_NS_CONDEXPRS_TABLE,
	KPARSER_NS_CONDEXPRS_TABLES,

	KPARSER_NS_COUNTER,
	KPARSER_NS_COUNTER_TABLE,

	KPARSER_NS_METADATA,
	KPARSER_NS_METALIST,

	KPARSER_NS_NODE_PARSE,
	KPARSER_NS_PROTO_TABLE,

	KPARSER_NS_TLV_NODE_PARSE,
	KPARSER_NS_TLV_PROTO_TABLE,

	KPARSER_NS_FLAG_FIELD,
	KPARSER_NS_FLAG_FIELD_TABLE,
	KPARSER_NS_FLAG_FIELD_NODE_PARSE,
	KPARSER_NS_FLAG_FIELD_PROTO_TABLE,

	KPARSER_NS_PARSER,

	KPARSER_NS_OP_PARSER_LOCK_UNLOCK,

	KPARSER_NS_MAX
};

#define KPARSER_ATTR_RSP(id)		KPARSER_ATTR_RSP_##id

#define KPARSER_DEFINE_ATTR_IDS(id)			\
	KPARSER_ATTR_CREATE_##id,	/* NLA_BINARY */\
	KPARSER_ATTR_UPDATE_##id,	/* NLA_BINARY */\
	KPARSER_ATTR_READ_##id,		/* NLA_BINARY */\
	KPARSER_ATTR_DELETE_##id,	/* NLA_BINARY */\
	KPARSER_ATTR_RSP(id)

enum {
	KPARSER_ATTR_UNSPEC,	/* Add more entries after this */

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_CONDEXPRS),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_CONDEXPRS_TABLE),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_CONDEXPRS_TABLES),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_COUNTER),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_COUNTER_TABLE),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_METADATA),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_METALIST),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_NODE_PARSE),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_PROTO_TABLE),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_TLV_NODE_PARSE),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_TLV_PROTO_TABLE),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_FLAG_FIELD),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_FLAG_FIELD_TABLE),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_FLAG_FIELD_NODE_PARSE),
	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_FLAG_FIELD_PROTO_TABLE),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_PARSER),

	KPARSER_DEFINE_ATTR_IDS(KPARSER_NS_OP_PARSER_LOCK_UNLOCK),

	KPARSER_ATTR_MAX	/* Add more entries before this */
};

enum {
	KPARSER_CMD_UNSPEC,
	KPARSER_CMD_CONFIGURE,
	KPARSER_CMD_MAX
};

/* *********************** kparser hash key (hkey) *********************** */
#define KPARSER_INVALID_ID		0xffff

#define KPARSER_USER_ID_MIN		0
#define KPARSER_USER_ID_MAX		0x8000
#define KPARSER_KMOD_ID_MIN		0x8001
#define KPARSER_KMOD_ID_MAX		0xfffe

#define KPARSER_MAX_NAME		128
#define KPARSER_MAX_DIGIT_STR_LEN	16
#define KPARSER_DEF_NAME_PREFIX		"kparser_default_name"
#define KPARSER_USER_ID_MIN		0
#define KPARSER_USER_ID_MAX		0x8000
#define KPARSER_KMOD_ID_MIN		0x8001
#define KPARSER_KMOD_ID_MAX		0xfffe

struct kparser_hkey {
	__u16 id;
	char name[KPARSER_MAX_NAME];
};

/* *********************** conditional expressions *********************** */
enum kparser_condexpr_types {
	KPARSER_CONDEXPR_TYPE_OR,
	KPARSER_CONDEXPR_TYPE_AND,
};

enum kparser_expr_types {
	KPARSER_CONDEXPR_TYPE_EQUAL,
	KPARSER_CONDEXPR_TYPE_NOTEQUAL,
	KPARSER_CONDEXPR_TYPE_LT,
	KPARSER_CONDEXPR_TYPE_LTE,
	KPARSER_CONDEXPR_TYPE_GT,
	KPARSER_CONDEXPR_TYPE_GTE,
};

/* One boolean condition expressions */
struct kparser_condexpr_expr {
	enum kparser_expr_types type;
	__u16 src_off;
	__u8 length;
	__u32 mask;
	__u32 value;
};

struct kparser_conf_condexpr {
	struct kparser_hkey key;
	struct kparser_condexpr_expr config;
};

struct kparser_conf_condexpr_table {
	struct kparser_hkey key;
	int idx;
	int default_fail;
	enum kparser_condexpr_types type;
	struct kparser_hkey condexpr_expr_key;
};

struct kparser_conf_condexpr_tables {
	struct kparser_hkey key;
	int idx;
	struct kparser_hkey condexpr_expr_table_key;
};

/* *********************** counter *********************** */
#define KPARSER_CNTR_NUM_CNTRS		7

struct kparser_cntr_conf {
	bool valid_entry;
	__u8 index;
	__u32 max_value;
	__u32 array_limit;
	size_t el_size;
	bool reset_on_encap;
	bool overwrite_last;
	bool error_on_exceeded;
};

struct kparser_conf_cntr {
	struct kparser_hkey key;
	struct kparser_cntr_conf conf;
};

/* *********************** metadata *********************** */
enum kparser_metadata_type {
	KPARSER_METADATA_INVALID,
	KPARSER_METADATA_HDRDATA,
	KPARSER_METADATA_HDRLEN,
	KPARSER_METADATA_CONSTANT_BYTE,
	KPARSER_METADATA_CONSTANT_HALFWORD,
	KPARSER_METADATA_OFFSET,
	KPARSER_METADATA_BIT_OFFSET,
	KPARSER_METADATA_NUMENCAPS,
	KPARSER_METADATA_NUMNODES,
	KPARSER_METADATA_TIMESTAMP,
	KPARSER_METADATA_RETURN_CODE,
	KPARSER_METADATA_COUNTER,
	KPARSER_METADATA_NOOP,
	KPARSER_METADATA_MAX
};

enum kparser_metadata_counter_op_type {
	KPARSER_METADATA_COUNTEROP_NOOP,
	KPARSER_METADATA_COUNTEROP_INCR,
	KPARSER_METADATA_COUNTEROP_RST
};

#define KPARSER_METADATA_OFFSET_MIN		0
#define KPARSER_METADATA_OFFSET_MAX		0xffffff
#define KPARSER_METADATA_OFFSET_INVALID		0xffffffff

/* TODO: align and pack all struct members
 */
struct kparser_conf_metadata {
	struct kparser_hkey key;
	enum kparser_metadata_type type;
	enum kparser_metadata_counter_op_type cntr_op; // 3 bit
	bool frame;
	bool e_bit;
	__u8 cntr; // 3 bit
	__u8 cntr_data; // 3 bit
	__u8 constant_value;
	size_t soff;
	size_t doff;
	size_t len;
	size_t add_off;
	struct kparser_hkey counterkey;
};

/* *********************** metadata list/table *********************** */
struct kparser_conf_metadata_table {
	struct kparser_hkey key;
	size_t metadata_keys_count;
	struct kparser_hkey metadata_keys[0];
};

/* *********************** parse nodes *********************** */
/* kParser protocol node types */
enum kparser_node_type {
	/* Plain node, no super structure */
	KPARSER_NODE_TYPE_PLAIN,
	/* TLVs node with super structure for TLVs */
	KPARSER_NODE_TYPE_TLVS,
	/* Flag-fields with super structure for flag-fields */
	KPARSER_NODE_TYPE_FLAG_FIELDS,
	/* It represents the limit value */
	KPARSER_NODE_TYPE_MAX,
};

/* Types for parameterized functions */
struct kparser_parameterized_len {
	__u16 src_off;
	__u8 size;
	bool endian;
	__u32 mask;
	__u8 right_shift;
	__u8 multiplier;
	__u8 add_value;
};

struct kparser_parameterized_next_proto {
	__u16 src_off;
	__u16 mask;
	__u8 size;
	__u8 right_shift;
};

struct kparser_conf_parse_ops {
	// bool flag_fields_length; // TODO
	bool len_parameterized;
	struct kparser_parameterized_len pflen;
	struct kparser_parameterized_next_proto pfnext_proto;
	bool cond_exprs_parameterized;
	struct kparser_hkey cond_exprs_table;
};

/* base nodes */
struct kparser_conf_node_proto {
	bool encap;
	bool overlay;
	size_t min_len;
	struct kparser_conf_parse_ops ops;
};

struct kparser_conf_node_parse {
	int unknown_ret;
	struct kparser_hkey proto_table_key;
	struct kparser_hkey wildcard_parse_node_key;
	struct kparser_hkey metadata_table_key;
	struct kparser_conf_node_proto proto_node;
};

/* TLVS */
struct kparser_proto_tlvs_opts {
	struct kparser_parameterized_len pfstart_offset;
	bool len_parameterized;
	struct kparser_parameterized_len pflen;
	struct kparser_parameterized_next_proto pftype;
};

struct kparser_conf_proto_tlvs_node {
	struct kparser_proto_tlvs_opts ops;
	bool tlvsstdfmt;
	bool fixed_start_offset;
	size_t start_offset;
	__u8 pad1_val;
	__u8 padn_val;
	__u8 eol_val;
	bool pad1_enable;
	bool padn_enable;
	bool eol_enable;
	size_t min_len;
};

#define KPARSER_DEFAULT_TLV_MAX_LOOP			255
#define KPARSER_DEFAULT_TLV_MAX_NON_PADDING		255
#define KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_BYTES	255
#define KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_OPTS		255
#define KPARSER_DEFAULT_TLV_DISP_LIMIT_EXCEED		0
#define KPARSER_DEFAULT_TLV_EXCEED_LOOP_CNT_ERR		false

/* Two bit code that describes the action to take when a loop node
 * exceeds a limit
 */
enum {
	KPARSER_LOOP_DISP_STOP_OKAY = 0,
	KPARSER_LOOP_DISP_STOP_NODE_OKAY = 1,
	KPARSER_LOOP_DISP_STOP_SUB_NODE_OKAY = 2,
	KPARSER_LOOP_DISP_STOP_FAIL = 3,
};

/* Configuration for a TLV node (generally loop nodes)
 *
 * max_loop: Maximum number of TLVs to process
 * max_non: Maximum number of non-padding TLVs to process
 * max_plen: Maximum consecutive padding bytes
 * max_c_pad: Maximum number of consecutive padding options
 * disp_limit_exceed: Disposition when a TLV parsing limit is exceeded. See
 *	KPARSER_LOOP_DISP_STOP_* in parser.h
 * exceed_loop_cnt_is_err: True is exceeding maximum number of TLVS is an error
 */
struct kparser_loop_node_config {
	__u16 max_loop;
	__u16 max_non;
	__u8 max_plen;
	__u8 max_c_pad;
	__u8 disp_limit_exceed;
	bool exceed_loop_cnt_is_err;
};

/* TODO:
 * disp_limit_exceed: 2;
 * exceed_loop_cnt_is_err: 1;
 */
struct kparser_conf_parse_tlvs {
	struct kparser_conf_proto_tlvs_node proto_node;
	struct kparser_hkey tlv_proto_table_key;
	int unknown_tlv_type_ret;
	struct kparser_hkey tlv_wildcard_node_key;
	struct kparser_loop_node_config config;
};

/* flag fields */
struct kparser_parameterized_get_value {
	__u16 src_off;
	__u32 mask;
	__u8 size;
};

struct kparser_proto_flag_fields_ops {
	bool get_flags_parameterized;
	struct kparser_parameterized_get_value pfget_flags;
	bool start_fields_offset_parameterized;
	struct kparser_parameterized_len pfstart_fields_offset;
	bool flag_fields_len;
	__u16 hdr_length;
};

struct kparser_conf_node_proto_flag_fields {
	struct kparser_proto_flag_fields_ops ops;
	struct kparser_hkey flag_fields_table_hkey;
};

struct kparser_conf_parse_flag_fields {
	struct kparser_conf_node_proto_flag_fields proto_node;
	struct kparser_hkey flag_fields_proto_table_key;
};

struct kparser_conf_node {
	struct kparser_hkey key;
	enum kparser_node_type type;
	struct kparser_conf_node_parse plain_parse_node;
	struct kparser_conf_parse_tlvs tlvs_parse_node;
	struct kparser_conf_parse_flag_fields flag_fields_parse_node;
};

/* *********************** tlv parse node *********************** */
struct kparser_conf_proto_tlv_node_ops {
	bool overlay_type_parameterized;
	struct kparser_parameterized_next_proto pfoverlay_type;
	bool cond_exprs_parameterized;
	struct kparser_hkey cond_exprs_table;
};

struct kparser_conf_node_proto_tlv {
	size_t min_len;
	size_t max_len;
	bool is_padding;
	struct kparser_conf_proto_tlv_node_ops ops;
};

struct kparser_conf_node_parse_tlv {
	struct kparser_hkey key;
	struct kparser_conf_node_proto_tlv node_proto;
	struct kparser_hkey overlay_proto_tlvs_table_key;
	struct kparser_hkey overlay_wildcard_parse_node_key;
	int unknown_ret;
	struct kparser_hkey metadata_table_key;
};

/* *********************** flag field *********************** */
/* One descriptor for a flag
 *
 * flag: protocol value
 * mask: mask to apply to field
 * size: size for associated field data
 */
struct kparser_flag_field {
	__u32 flag;
	__u32 networkflag;
	__u32 mask;
	size_t size;
	bool endian;
};

struct kparser_conf_flag_field {
	struct kparser_hkey key;
	struct kparser_flag_field conf;
};

/* *********************** flag field parse node *********************** */
struct kparser_parse_flag_field_node_ops_conf {
	struct kparser_hkey cond_exprs_table_key;
};

struct kparser_conf_node_parse_flag_field {
	struct kparser_hkey key;
	struct kparser_hkey metadata_table_key;
	struct kparser_parse_flag_field_node_ops_conf ops;
};

/* *********************** generic tables *********************** */
struct kparser_conf_table {
	struct kparser_hkey key;
	bool add_entry;
	__u16 elems_cnt;
	int optional_value1;
	int optional_value2;
	struct kparser_hkey elem_key;
};

/* *********************** parser *********************** */
/* Flags for parser configuration */
#define KPARSER_F_DEBUG		(1 << 0)

#define KPARSER_MAX_NODES	10
#define KPARSER_MAX_ENCAPS	1
#define KPARSER_MAX_FRAMES	255

/* Configuration for a KPARSER parser
 *
 * flags: Flags KPARSER_F_* in parser.h
 * max_nodes: Maximum number of nodes to parse
 * max_encaps: Maximum number of encapsulations to parse
 * max_frames: Maximum number of metadata frames
 * metameta_size: Size of metameta data. The metameta data is at the head
 *	of the user defined metadata structure. This also serves as the
 *	offset of the first metadata frame
 * frame_size: Size of one metadata frame
 */
struct kparser_config {
	__u16 flags;
	__u16 max_nodes;
	__u16 max_encaps;
	__u16 max_frames;
	size_t metameta_size;
	size_t frame_size;
};

struct kparser_conf_parser {
	struct kparser_hkey key;
	struct kparser_config config;
	struct kparser_hkey root_node_key;
	struct kparser_hkey ok_node_key;
	struct kparser_hkey fail_node_key;
	struct kparser_hkey atencap_node_key;
};

/* *********************** CLI config interface *********************** */
#define KPARSER_CONFIG_MAX_KEYS				128
#define KPARSER_CONFIG_MAX_KEYS_BV_LEN ((KPARSER_CONFIG_MAX_KEYS / BITS_IN_U32) + 1)
struct kparser_config_set_keys_bv {
	__u32 ns_keys_bvs[KPARSER_CONFIG_MAX_KEYS_BV_LEN];
};

struct kparser_conf_cmd {
	enum kparser_global_namespace_ids namespace_id;
	struct kparser_config_set_keys_bv conf_keys_bv;
	__u8 recursive_read_delete;
	union {
		/* for read/delete commands */
		/* KPARSER_NS_OP_PARSER_LOCK_UNLOCK */
		struct kparser_hkey obj_key;

		/* KPARSER_NS_CONDEXPRS */
		struct kparser_conf_condexpr cond_conf;

		/* KPARSER_NS_COUNTER */
		struct kparser_conf_cntr cntr_conf;

		/* KPARSER_NS_METADATA */
		struct kparser_conf_metadata md_conf;

		/* KPARSER_NS_METALIST */
		struct kparser_conf_metadata_table mdl_conf;

		/* KPARSER_NS_NODE_PARSE */
		struct kparser_conf_node node_conf;

		/* KPARSER_NS_TLV_NODE_PARSE */
		struct kparser_conf_node_parse_tlv tlv_node_conf;

		/* KPARSER_NS_FLAG_FIELD */
		struct kparser_conf_flag_field flag_field_conf;

		/* KPARSER_NS_FLAG_FIELD_NODE_PARSE */
		struct kparser_conf_node_parse_flag_field flag_field_node_conf;

		/* KPARSER_NS_PROTO_TABLE */
		/* KPARSER_NS_TLV_PROTO_TABLE */
		/* KPARSER_NS_FLAG_FIELD_TABLE */
		/* KPARSER_NS_FLAG_FIELD_PROTO_TABLE */
		/* KPARSER_NS_CONDEXPRS_TABLE */
		/* KPARSER_NS_CONDEXPRS_TABLES */
		/* KPARSER_NS_COUNTER_TABLE */
		struct kparser_conf_table table_conf;

		/* KPARSER_NS_PARSER */
		struct kparser_conf_parser parser_conf;
	};
};

struct kparser_cmd_rsp_hdr {
	int op_ret_code;
	__u8 err_str_buf[KPARSER_ERR_STR_MAX_LEN];
	struct kparser_hkey key;
	struct kparser_conf_cmd object;
	size_t objects_len;
	/* array of fixed size kparser_conf_cmd objects */
	struct kparser_conf_cmd objects[0];
};

/* ***********************  kParser error code *********************** */
/*
 * There are two variants of the KPARSER return codes. The normal variant is
 * a number between -15 and 0 inclusive where the name for the code is
 * prefixed by KPARSER_. There is also a special 16-bit encoding which is
 * 0xfff0 + -val where val is the negative number for the code so that
 * corresponds to values 0xfff0 to 0xffff. Names for the 16-bit encoding
 * are prefixed by KPARSER_16BIT_
 */
enum {
	KPARSER_OKAY = 0,		/* Okay and continue */
	KPARSER_RET_OKAY = -1,		/* Encoding of OKAY in ret code */

	KPARSER_OKAY_USE_WILD = -2,	/* cam instruction */
	KPARSER_OKAY_USE_ALT_WILD = -3,	/* cam instruction */

	KPARSER_STOP_OKAY = -4,		/* Okay and stop parsing */
	KPARSER_STOP_NODE_OKAY = -5,	/* Stop parsing current node */
	KPARSER_STOP_SUB_NODE_OKAY = -6,/* Stop parsing currnet sub-node */

	/* Parser failure */
	KPARSER_STOP_FAIL = -12,
	KPARSER_STOP_LENGTH = -13,
	KPARSER_STOP_UNKNOWN_PROTO = -14,
	KPARSER_STOP_ENCAP_DEPTH = -15,
	KPARSER_STOP_UNKNOWN_TLV = -16,
	KPARSER_STOP_TLV_LENGTH = -17,
	KPARSER_STOP_BAD_FLAG = -18,
	KPARSER_STOP_FAIL_CMP = -19,
	KPARSER_STOP_LOOP_CNT = -20,
	KPARSER_STOP_TLV_PADDING = -21,
	KPARSER_STOP_OPTION_LIMIT = -22,
	KPARSER_STOP_MAX_NODES = -23,
	KPARSER_STOP_COMPARE = -24,
	KPARSER_STOP_BAD_EXTRACT = -25,
	KPARSER_STOP_BAD_CNTR = -26,
	KPARSER_STOP_CNTR1 = -27,
	KPARSER_STOP_CNTR2 = -28,
	KPARSER_STOP_CNTR3 = -29,
	KPARSER_STOP_CNTR4 = -30,
	KPARSER_STOP_CNTR5 = -31,
	KPARSER_STOP_CNTR6 = -32,
	KPARSER_STOP_CNTR7 = -33,
};

static inline const char *kparser_code_to_text(int code)
{
	switch (code) {
	case KPARSER_OKAY:
		return "okay";
	case KPARSER_RET_OKAY:
		return "okay-ret";
	case KPARSER_OKAY_USE_WILD:
		return "okay-use-wild";
	case KPARSER_OKAY_USE_ALT_WILD:
		return "okay-use-alt-wild";
	case KPARSER_STOP_OKAY:
		return "stop-okay";
	case KPARSER_STOP_NODE_OKAY:
		return "stop-node-okay";
	case KPARSER_STOP_SUB_NODE_OKAY:
		return "stop-sub-node-okay";
	case KPARSER_STOP_FAIL:
		return "stop-fail";
	case KPARSER_STOP_LENGTH:
		return "stop-length";
	case KPARSER_STOP_UNKNOWN_PROTO:
		return "stop-unknown-proto";
	case KPARSER_STOP_ENCAP_DEPTH:
		return "stop-encap-depth";
	case KPARSER_STOP_UNKNOWN_TLV:
		return "stop-unknown-tlv";
	case KPARSER_STOP_TLV_LENGTH:
		return "stop-tlv-length";
	case KPARSER_STOP_BAD_FLAG:
		return "stop-bad-flag";
	case KPARSER_STOP_FAIL_CMP:
		return "stop-fail-cmp";
	case KPARSER_STOP_LOOP_CNT:
		return "stop-loop-cnt";
	case KPARSER_STOP_TLV_PADDING:
		return "stop-tlv-padding";
	case KPARSER_STOP_OPTION_LIMIT:
		return "stop-option-limit";
	case KPARSER_STOP_MAX_NODES:
		return "stop-max-nodes";
	case KPARSER_STOP_COMPARE:
		return "stop-compare";
	case KPARSER_STOP_BAD_EXTRACT:
		return "stop-bad-extract";
	case KPARSER_STOP_BAD_CNTR:
		return "stop-bad-counter";
	default:
		return "unknown-code";
	}
}

/* *********************** HKey utility APIs *********************** */
static inline bool kparser_hkey_id_empty(const struct kparser_hkey *key)
{
	if (!key)
		return true;
	return (key->id == KPARSER_INVALID_ID);
}

static inline bool kparser_hkey_name_empty(const struct kparser_hkey *key)
{
	if (!key)
		return true;
	return ((key->name[0] == '\0') ||
			!strcmp(key->name, KPARSER_DEF_NAME_PREFIX));
}

static inline bool kparser_hkey_empty(const struct kparser_hkey *key)
{
	return (kparser_hkey_id_empty(key) && kparser_hkey_name_empty(key));
}

static inline bool kparser_hkey_user_id_invalid(const struct kparser_hkey *key)
{
	if (!key)
		return true;
	return ((key->id == KPARSER_INVALID_ID) ||
			(key->id > KPARSER_USER_ID_MAX));
}


#endif /* _LINUX_KPARSER_H */
