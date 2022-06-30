/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_H
#define __LINUX_P4TC_H

#include <linux/types.h>
#include <linux/pkt_sched.h>

/* pipeline header */
struct p4tcmsg {
	__u32 pipeid;
	__u32 obj;
};

#define P4TC_MAXPIPELINE_COUNT 32
#define P4TC_MAXRULES_LIMIT 512
#define P4TC_MAXTCLASSES_COUNT 32
#define P4TC_MAXPARSE_KEYS 16
#define P4TC_MAXMETA_SZ 128
#define P4TC_MSGBATCH_SIZE 16

#define TEMPLATENAMSZ 256
#define PIPELINENAMSIZ TEMPLATENAMSZ
#define METANAMSIZ TEMPLATENAMSZ
#define TCLASSNAMSIZ TEMPLATENAMSZ

#define P4TC_TCLASS_FLAGS_KEYSZ 0x01
#define P4TC_TCLASS_FLAGS_COUNT 0x02
#define P4TC_TCLASS_FLAGS_MAX_ENTRIES 0x04
#define P4TC_TCLASS_FLAGS_MAX_MASKS 0x08
#define P4TC_TCLASS_FLAGS_DEFAULT_KEY 0x10

struct p4tc_table_class_parm {
	__u32 tbc_keysz;
	__u32 tbc_count;
	__u32 tbc_max_entries;
	__u32 tbc_max_masks;
	__u32 tbc_default_key;
	__u32 tbc_flags;
};

/* Root attributes */
enum {
	P4TC_ROOT_UNSPEC,
	P4TC_ROOT, /* nested messages */
	P4TC_ROOT_PNAME, /* string */
	__P4TC_ROOT_MAX,
};
#define P4TC_ROOT_MAX __P4TC_ROOT_MAX

/* PIPELINE attributes */
enum {
	P4TC_PIPELINE_UNSPEC,
	P4TC_PIPELINE_MAXRULES, /* u32 */
	P4TC_PIPELINE_NUMTCLASSES, /* u16 */
	P4TC_PIPELINE_STATE, /* u8 */
	P4TC_PIPELINE_PREACTIONS, /* nested preactions */
	P4TC_PIPELINE_POSTACTIONS, /* nested postactions */
	P4TC_PIPELINE_NAME, /* string only used for pipeline dump */
	__P4TC_PIPELINE_MAX
};
#define P4TC_PIPELINE_MAX __P4TC_PIPELINE_MAX

/* P4 Object types */
enum {
	P4TC_OBJ_UNSPEC,
	P4TC_OBJ_PIPELINE,
	P4TC_OBJ_META,
	P4TC_OBJ_TABLE_CLASS,
	__P4TC_OBJ_MAX,
};
#define P4TC_OBJ_MAX __P4TC_OBJ_MAX

/* P4 attributes */
enum {
	P4TC_UNSPEC,
	P4TC_PATH,
	P4TC_PARAMS,
	P4TC_COUNT,
	__P4TC_MAX,
};
#define P4TC_MAX __P4TC_MAX

/* PIPELINE states */
enum {
	P4TC_STATE_NOT_READY,
	P4TC_STATE_READY,
};

enum {
	P4T_UNSPEC,
	P4T_U8 = 1, /* NLA_U8 */
	P4T_U16 = 2, /* NLA_U16 */
	P4T_U32 = 3, /* NLA_U32 */
	P4T_U64 = 4, /* NLA_U64 */
	P4T_STRING = 5, /* NLA_STRING */
	P4T_FLAG = 6, /* NLA_FLAG */
	P4T_MSECS = 7, /* NLA_MSECS */
	P4T_NESTED = 8, /* NLA_NESTED */
	P4T_NESTED_ARRAY = 9, /* NLA_NESTED_ARRAY */
	P4T_NUL_STRING = 10, /* NLA_NUL_STRING */
	P4T_BINARY = 11, /* NLA_BINARY */
	P4T_S8 = 12, /* NLA_S8 */
	P4T_S16 = 13, /* NLA_S16 */
	P4T_S32 = 14, /* NLA_S32 */
	P4T_S64 = 15, /* NLA_S64 */
	P4T_BITFIELD32 = 16, /* NLA_BITFIELD32 */
	P4T_MACADDR = 17, /* NLA_REJECT */
	P4T_IPV4ADDR,
	P4T_BE16,
	P4T_BE32,
	P4T_BE64,
	P4T_U128,
	P4T_S128,
	P4T_PATH,
	__P4T_MAX,
};
#define P4T_MAX (__P4T_MAX - 1)

/* Details all the info needed to find out metadata size and layout inside cb
 * datastructure
 */
struct p4tc_meta_size_params {
	__u16 startbit;
	__u16 endbit;
	__u8 datatype; /* T_XXX */
};

/* Metadata attributes */
enum {
	P4TC_META_UNSPEC,
	P4TC_META_NAME, /* string */
	P4TC_META_SIZE, /* struct p4tc_meta_size_params */
	__P4TC_META_MAX
};
#define P4TC_META_MAX __P4TC_META_MAX

/* Table key attributes */
enum {
	P4TC_KEY_UNSPEC,
	P4TC_KEY_ID, /* u32 */
	P4TC_KEY_ACT, /* nested key actions */
	__P4TC_TKEY_MAX
};
#define P4TC_TKEY_MAX __P4TC_TKEY_MAX

/* Table type attributes */
enum {
	P4TC_TCLASS_UNSPEC,
	P4TC_TCLASS_NAME, /* string */
	P4TC_TCLASS_INFO, /* struct tc_p4_table_type_parm */
	P4TC_TCLASS_PREACTIONS, /* nested table preactions */
	P4TC_TCLASS_KEYS, /* nested table keys */
	P4TC_TCLASS_POSTACTIONS, /* nested table postactions */
	__P4TC_TCLASS_MAX
};
#define P4TC_TCLASS_MAX __P4TC_TCLASS_MAX

#define P4TC_RTA(r)  ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
