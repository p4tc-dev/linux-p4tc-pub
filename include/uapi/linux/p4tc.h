/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_H
#define __LINUX_P4TC_H

#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>

/* pipeline header */
struct p4tcmsg {
	__u32 pipeid;
	__u32 obj;
};

#define P4TC_MAXPIPELINE_COUNT 32
#define P4TC_MAXTABLES_COUNT 32
#define P4TC_MINTABLES_COUNT 0
#define P4TC_MSGBATCH_SIZE 16

#define P4TC_MAX_KEYSZ 512
#define HEADER_MAX_LEN 512
#define P4TC_DEFAULT_NUM_PREALLOC 16

#define TEMPLATENAMSZ 256
#define PIPELINENAMSIZ TEMPLATENAMSZ
#define PARSERNAMSIZ TEMPLATENAMSZ
#define HDRFIELDNAMSIZ TEMPLATENAMSZ
#define ACTPARAMNAMSIZ TEMPLATENAMSZ
#define TABLENAMSIZ TEMPLATENAMSZ

#define P4TC_TABLE_FLAGS_KEYSZ 0x01
#define P4TC_TABLE_FLAGS_MAX_ENTRIES 0x02
#define P4TC_TABLE_FLAGS_MAX_MASKS 0x04
#define P4TC_TABLE_FLAGS_DEFAULT_KEY 0x08
#define P4TC_TABLE_FLAGS_PERMISSIONS 0x10
#define P4TC_TABLE_FLAGS_TYPE 0x20
#define P4TC_TABLE_FLAGS_AGING 0x40

enum {
	P4TC_TABLE_TYPE_EXACT = 1,
	P4TC_TABLE_TYPE_LPM = 2,
	P4TC_TABLE_TYPE_TERNARY = 3,
	__P4TC_TABLE_TYPE_MAX,
};
#define P4TC_TABLE_TYPE_MAX (__P4TC_TABLE_TYPE_MAX - 1)

#define P4TC_CTRL_PERM_C_BIT 9
#define P4TC_CTRL_PERM_R_BIT 8
#define P4TC_CTRL_PERM_U_BIT 7
#define P4TC_CTRL_PERM_D_BIT 6
#define P4TC_CTRL_PERM_X_BIT 5

#define P4TC_DATA_PERM_C_BIT 4
#define P4TC_DATA_PERM_R_BIT 3
#define P4TC_DATA_PERM_U_BIT 2
#define P4TC_DATA_PERM_D_BIT 1
#define P4TC_DATA_PERM_X_BIT 0

#define P4TC_PERM_MAX_BIT P4TC_CTRL_PERM_C_BIT

#define P4TC_CTRL_PERM_C (1 << P4TC_CTRL_PERM_C_BIT)
#define P4TC_CTRL_PERM_R (1 << P4TC_CTRL_PERM_R_BIT)
#define P4TC_CTRL_PERM_U (1 << P4TC_CTRL_PERM_U_BIT)
#define P4TC_CTRL_PERM_D (1 << P4TC_CTRL_PERM_D_BIT)
#define P4TC_CTRL_PERM_X (1 << P4TC_CTRL_PERM_X_BIT)

#define P4TC_DATA_PERM_C (1 << P4TC_DATA_PERM_C_BIT)
#define P4TC_DATA_PERM_R (1 << P4TC_DATA_PERM_R_BIT)
#define P4TC_DATA_PERM_U (1 << P4TC_DATA_PERM_U_BIT)
#define P4TC_DATA_PERM_D (1 << P4TC_DATA_PERM_D_BIT)
#define P4TC_DATA_PERM_X (1 << P4TC_DATA_PERM_X_BIT)

#define p4tc_ctrl_create_ok(perm)   (perm & P4TC_CTRL_PERM_C)
#define p4tc_ctrl_read_ok(perm)     (perm & P4TC_CTRL_PERM_R)
#define p4tc_ctrl_update_ok(perm)   (perm & P4TC_CTRL_PERM_U)
#define p4tc_ctrl_delete_ok(perm)   (perm & P4TC_CTRL_PERM_D)
#define p4tc_ctrl_exec_ok(perm)     (perm & P4TC_CTRL_PERM_X)

#define p4tc_ctrl_perm_rm_create(perm) \
	((perm & ~P4TC_CTRL_PERM_C_BIT))

#define p4tc_data_create_ok(perm)   (perm & P4TC_DATA_PERM_C)
#define p4tc_data_read_ok(perm)     (perm & P4TC_DATA_PERM_R)
#define p4tc_data_update_ok(perm)   (perm & P4TC_DATA_PERM_U)
#define p4tc_data_delete_ok(perm)   (perm & P4TC_DATA_PERM_D)
#define p4tc_data_exec_ok(perm)     (perm & P4TC_DATA_PERM_X)

#define p4tc_data_perm_rm_create(perm) \
	((perm & ~P4TC_DATA_PERM_C_BIT))

struct p4tc_table_parm {
	__u64 tbl_aging;
	__u32 tbl_keysz;
	__u32 tbl_max_entries;
	__u32 tbl_max_masks;
	__u32 tbl_flags;
	__u32 tbl_num_entries;
	__u16 tbl_permissions;
	__u8  tbl_type;
	__u8  PAD0;
};

/* Root attributes */
enum {
	P4TC_ROOT_UNSPEC,
	P4TC_ROOT, /* nested messages */
	P4TC_ROOT_PNAME, /* string */
	__P4TC_ROOT_MAX,
};
#define P4TC_ROOT_MAX __P4TC_ROOT_MAX

/* P4 Object types */
enum {
	P4TC_OBJ_UNSPEC,
	P4TC_OBJ_PIPELINE,
	P4TC_OBJ_HDR_FIELD,
	P4TC_OBJ_ACT,
	P4TC_OBJ_TABLE,
	__P4TC_OBJ_MAX,
};
#define P4TC_OBJ_MAX __P4TC_OBJ_MAX

/* P4 runtime Object types */
enum {
	P4TC_OBJ_RUNTIME_UNSPEC,
	P4TC_OBJ_RUNTIME_TABLE,
	__P4TC_OBJ_RUNTIME_MAX,
};
#define P4TC_OBJ_RUNTIMEMAX __P4TC_OBJ_RUNTIMEMAX

/* P4 attributes */
enum {
	P4TC_UNSPEC,
	P4TC_PATH,
	P4TC_PARAMS,
	P4TC_COUNT,
	__P4TC_MAX,
};
#define P4TC_MAX __P4TC_MAX

/* PIPELINE attributes */
enum {
	P4TC_PIPELINE_UNSPEC,
	P4TC_PIPELINE_NUMTABLES, /* u16 */
	P4TC_PIPELINE_STATE, /* u8 */
	P4TC_PIPELINE_NAME, /* string only used for pipeline dump */
	__P4TC_PIPELINE_MAX
};
#define P4TC_PIPELINE_MAX __P4TC_PIPELINE_MAX

/* PIPELINE states */
enum {
	P4TC_STATE_NOT_READY,
	P4TC_STATE_READY,
};

enum {
	P4T_UNSPEC,
	P4T_U8 = 1,
	P4T_U16 = 2,
	P4T_U32 = 3,
	P4T_U64 = 4,
	P4T_STRING = 5,
	P4T_FLAG = 6,
	P4T_MSECS = 7,
	P4T_NESTED = 8,
	P4T_NESTED_ARRAY = 9,
	P4T_NUL_STRING = 10,
	P4T_BINARY = 11,
	P4T_S8 = 12,
	P4T_S16 = 13,
	P4T_S32 = 14,
	P4T_S64 = 15,
	P4T_BITFIELD32 = 16,
	P4T_MACADDR = 17,
	P4T_IPV4ADDR,
	P4T_BE16,
	P4T_BE32,
	P4T_BE64,
	P4T_U128,
	P4T_S128,
	P4T_PATH,
	P4T_BOOL,
	P4T_DEV,
	P4T_KEY,
	__P4T_MAX,
};
#define P4T_MAX (__P4T_MAX - 1)

enum {
	P4TC_TABLE_DEFAULT_UNSPEC,
	P4TC_TABLE_DEFAULT_ACTION,
	P4TC_TABLE_DEFAULT_PERMISSIONS,
	__P4TC_TABLE_DEFAULT_MAX
};
#define P4TC_TABLE_DEFAULT_MAX (__P4TC_TABLE_DEFAULT_MAX - 1)

enum {
	P4TC_TABLE_ACTS_DEFAULT_ONLY,
	P4TC_TABLE_ACTS_TABLE_ONLY,
	__P4TC_TABLE_ACTS_FLAGS_MAX,
};
#define P4TC_TABLE_ACTS_FLAGS_MAX (__P4TC_TABLE_ACTS_FLAGS_MAX - 1)

enum {
	P4TC_TABLE_ACT_UNSPEC,
	P4TC_TABLE_ACT_FLAGS, /* u8 */
	P4TC_TABLE_ACT_NAME, /* string */
	__P4TC_TABLE_ACT_MAX
};
#define P4TC_TABLE_ACT_MAX (__P4TC_TABLE_ACT_MAX - 1)

/* Table type attributes */
enum {
	P4TC_TABLE_UNSPEC,
	P4TC_TABLE_NAME, /* string */
	P4TC_TABLE_INFO, /* struct p4tc_table_parm */
	P4TC_TABLE_DEFAULT_HIT, /* nested default hit action attributes */
	P4TC_TABLE_DEFAULT_MISS, /* nested default miss action attributes */
	P4TC_TABLE_CONST_ENTRY, /* nested const table entry*/
	P4TC_TABLE_ACTS_LIST, /* nested table actions list */
	__P4TC_TABLE_MAX
};
#define P4TC_TABLE_MAX __P4TC_TABLE_MAX

struct p4tc_hdrfield_type {
	__u16 startbit;
	__u16 endbit;
	__u8  datatype; /* P4T_* */
};

/* Header field attributes */
enum {
	P4TC_HDRFIELD_UNSPEC,
	P4TC_HDRFIELD_DATA,
	P4TC_HDRFIELD_NAME,
	P4TC_HDRFIELD_PARSER_NAME,
	__P4TC_HDRFIELD_MAX
};
#define P4TC_HDRFIELD_MAX (__P4TC_HDRFIELD_MAX - 1)

/* Action attributes */
enum {
	P4TC_ACT_UNSPEC,
	P4TC_ACT_NAME, /* string */
	P4TC_ACT_PARMS, /* nested params */
	P4TC_ACT_OPT, /* action opt */
	P4TC_ACT_TM, /* action tm */
	P4TC_ACT_ACTIVE, /* u8 */
	P4TC_ACT_NUM_PREALLOC, /* u32 num preallocated action instances */
	P4TC_ACT_PAD,
	__P4TC_ACT_MAX
};
#define P4TC_ACT_MAX __P4TC_ACT_MAX

/* Action params attributes */
enum {
	P4TC_ACT_PARAMS_VALUE_UNSPEC,
	P4TC_ACT_PARAMS_VALUE_RAW, /* binary */
	__P4TC_ACT_PARAMS_VALUE_MAX
};
#define P4TC_ACT_VALUE_PARAMS_MAX __P4TC_ACT_PARAMS_VALUE_MAX

enum {
	P4TC_ACT_PARAMS_TYPE_UNSPEC,
	P4TC_ACT_PARAMS_TYPE_BITEND, /* u16 */
	P4TC_ACT_PARAMS_TYPE_CONTAINER_ID, /* u32 */
	__P4TC_ACT_PARAMS_TYPE_MAX
};
#define P4TC_ACT_PARAMS_TYPE_MAX __P4TC_ACT_PARAMS_TYPE_MAX

/* Action params attributes */
enum {
	P4TC_ACT_PARAMS_UNSPEC,
	P4TC_ACT_PARAMS_NAME, /* string */
	P4TC_ACT_PARAMS_ID, /* u32 */
	P4TC_ACT_PARAMS_VALUE, /* bytes */
	P4TC_ACT_PARAMS_MASK, /* bytes */
	P4TC_ACT_PARAMS_TYPE, /* nested type */
	__P4TC_ACT_PARAMS_MAX
};
#define P4TC_ACT_PARAMS_MAX __P4TC_ACT_PARAMS_MAX

struct tc_act_dyna {
	tc_gen;
};

struct p4tc_table_entry_tm {
	__u64 created;
	__u64 lastused;
	__u64 firstused;
	__u16 who_created;
	__u16 who_updated;
	__u16 who_deleted;
	__u16 permissions;
};

enum {
	P4TC_ENTRY_TBL_ATTRS_UNSPEC,
	P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT, /* nested default hit attrs */
	P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS, /* nested default miss attrs */
	P4TC_ENTRY_TBL_ATTRS_PERMISSIONS, /* u16 table permissions */
	__P4TC_ENTRY_TBL_ATTRS,
};
#define P4TC_ENTRY_TBL_ATTRS_MAX (__P4TC_ENTRY_TBL_ATTRS - 1)

/* Table entry attributes */
enum {
	P4TC_ENTRY_UNSPEC,
	P4TC_ENTRY_TBLNAME, /* string */
	P4TC_ENTRY_KEY_BLOB, /* Key blob */
	P4TC_ENTRY_MASK_BLOB, /* Mask blob */
	P4TC_ENTRY_PRIO, /* u32 */
	P4TC_ENTRY_ACT, /* nested actions */
	P4TC_ENTRY_TM, /* entry data path timestamps */
	P4TC_ENTRY_WHODUNNIT, /* tells who's modifying the entry */
	P4TC_ENTRY_CREATE_WHODUNNIT, /* tells who created the entry */
	P4TC_ENTRY_UPDATE_WHODUNNIT, /* tells who updated the entry last */
	P4TC_ENTRY_DELETE_WHODUNNIT, /* tells who deleted the entry */
	P4TC_ENTRY_PERMISSIONS, /* entry CRUDX permissions */
	P4TC_ENTRY_TBL_ATTRS, /* nested table attributes */
	P4TC_ENTRY_DYNAMIC, /* u8 tells if table entry is dynamic */
	P4TC_ENTRY_AGING, /* u64 table entry aging */
	P4TC_ENTRY_PAD,
	__P4TC_ENTRY_MAX
};
#define P4TC_ENTRY_MAX (__P4TC_ENTRY_MAX - 1)

enum {
	P4TC_ENTITY_UNSPEC,
	P4TC_ENTITY_KERNEL,
	P4TC_ENTITY_TC,
	P4TC_ENTITY_TIMER,
	P4TC_ENTITY_MAX
};

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
