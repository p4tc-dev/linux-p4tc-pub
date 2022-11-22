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
#define P4TC_MAXRULES_LIMIT 512
#define P4TC_MAXTABLES_COUNT 32
#define P4TC_MINTABLES_COUNT 0
#define P4TC_MAXPARSE_KEYS 16
#define P4TC_MAXMETA_SZ 128
#define P4TC_MSGBATCH_SIZE 16
#define P4TC_MAX_KEYSZ 512
#define HEADER_MAX_LEN 512
#define META_MAX_LEN 512
#define P4TC_MAX_REGISTER_ELEMS 128

#define P4TC_MAX_KEYSZ 512

#define TEMPLATENAMSZ 256
#define PIPELINENAMSIZ TEMPLATENAMSZ
#define METANAMSIZ TEMPLATENAMSZ
#define PARSERNAMSIZ TEMPLATENAMSZ
#define HDRFIELDNAMSIZ TEMPLATENAMSZ
#define ACTPARAMNAMSIZ TEMPLATENAMSZ
#define TABLENAMSIZ TEMPLATENAMSZ
#define REGISTERNAMSIZ TEMPLATENAMSZ

#define P4TC_TABLE_FLAGS_KEYSZ 0x01
#define P4TC_TABLE_FLAGS_MAX_ENTRIES 0x02
#define P4TC_TABLE_FLAGS_MAX_MASKS 0x04
#define P4TC_TABLE_FLAGS_DEFAULT_KEY 0x08
#define P4TC_TABLE_FLAGS_PERMISSIONS 0x10

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

#define p4tc_data_create_ok(perm)   (perm & P4TC_DATA_PERM_C)
#define p4tc_data_read_ok(perm)     (perm & P4TC_DATA_PERM_R)
#define p4tc_data_update_ok(perm)   (perm & P4TC_DATA_PERM_U)
#define p4tc_data_delete_ok(perm)   (perm & P4TC_DATA_PERM_D)
#define p4tc_data_exec_ok(perm)     (perm & P4TC_DATA_PERM_X)

struct p4tc_table_parm {
	__u32 tbl_keysz;
	__u32 tbl_max_entries;
	__u32 tbl_max_masks;
	__u32 tbl_flags;
	__u32 tbl_num_entries;
	__u16 tbl_permissions;
	__u16 PAD0;
};

#define LABELNAMSIZ 32

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
	P4TC_PIPELINE_NUMTABLES, /* u16 */
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
	P4TC_OBJ_HDR_FIELD,
	P4TC_OBJ_ACT,
	P4TC_OBJ_TABLE,
	P4TC_OBJ_TABLE_ENTRY,
	P4TC_OBJ_REGISTER,
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
	P4T_BOOL,
	P4T_DEV,
	P4T_KEY,
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

/* Linux system metadata */
enum {
	P4TC_KERNEL_META_UNSPEC,
	P4TC_KERNEL_META_PKTLEN,	/* u32 */
	P4TC_KERNEL_META_DATALEN,	/* u32 */
	P4TC_KERNEL_META_SKBMARK,	/* u32 */
	P4TC_KERNEL_META_TCINDEX,	/* u16 */
	P4TC_KERNEL_META_SKBHASH,	/* u32 */
	P4TC_KERNEL_META_SKBPRIO,	/* u32 */
	P4TC_KERNEL_META_IFINDEX,	/* s32 */
	P4TC_KERNEL_META_SKBIIF,	/* s32 */
	P4TC_KERNEL_META_PROTOCOL,	/* be16 */
	P4TC_KERNEL_META_PKTYPE,	/* u8:3 */
	P4TC_KERNEL_META_IDF,		/* u8:1 */
	P4TC_KERNEL_META_IPSUM,		/* u8:2 */
	P4TC_KERNEL_META_OOOK,		/* u8:1 */
	P4TC_KERNEL_META_FCLONE,	/* u8:2 */
	P4TC_KERNEL_META_PEEKED,	/* u8:1 */
	P4TC_KERNEL_META_QMAP,		/* u16 */
	P4TC_KERNEL_META_PTYPEOFF,	/* u8 */
	P4TC_KERNEL_META_CLONEOFF,	/* u8 */
	P4TC_KERNEL_META_PTCLNOFF,	/* u16 */
	P4TC_KERNEL_META_DIRECTION,	/* u8:1 */
	__P4TC_KERNEL_META_MAX
};
#define P4TC_KERNEL_META_MAX (__P4TC_KERNEL_META_MAX - 1)

/* Table key attributes */
enum {
	P4TC_KEY_UNSPEC,
	P4TC_KEY_ACT, /* nested key actions */
	__P4TC_TKEY_MAX
};
#define P4TC_TKEY_MAX __P4TC_TKEY_MAX

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
	P4TC_TABLE_INFO, /* struct tc_p4_table_type_parm */
	P4TC_TABLE_PREACTIONS, /* nested table preactions */
	P4TC_TABLE_KEY, /* nested table key */
	P4TC_TABLE_POSTACTIONS, /* nested table postactions */
	P4TC_TABLE_DEFAULT_HIT, /* nested default hit action attributes */
	P4TC_TABLE_DEFAULT_MISS, /* nested default miss action attributes */
	P4TC_TABLE_OPT_ENTRY, /* nested const table entry*/
	P4TC_TABLE_ACTS_LIST, /* nested table actions list */
	__P4TC_TABLE_MAX
};
#define P4TC_TABLE_MAX __P4TC_TABLE_MAX

struct p4tc_hdrfield_ty {
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
	P4TC_ACT_CMDS_LIST, /* command list */
	P4TC_ACT_ACTIVE, /* u8 */
	P4TC_ACT_PAD,
	__P4TC_ACT_MAX
};
#define P4TC_ACT_MAX __P4TC_ACT_MAX

#define P4TC_CMDS_LIST_MAX 32

/* Action params attributes */
enum {
	P4TC_ACT_PARAMS_VALUE_UNSPEC,
	P4TC_ACT_PARAMS_VALUE_RAW, /* binary */
	P4TC_ACT_PARAMS_VALUE_OPND, /* struct p4tc_u_operand */
	__P4TC_ACT_PARAMS_VALUE_MAX
};
#define P4TC_ACT_VALUE_PARAMS_MAX __P4TC_ACT_PARAMS_VALUE_MAX

/* Action params attributes */
enum {
	P4TC_ACT_PARAMS_UNSPEC,
	P4TC_ACT_PARAMS_NAME, /* string */
	P4TC_ACT_PARAMS_ID, /* u32 */
	P4TC_ACT_PARAMS_VALUE, /* bytes */
	P4TC_ACT_PARAMS_MASK, /* bytes */
	P4TC_ACT_PARAMS_TYPE, /* u32 */
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
};

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
	P4TC_ENTRY_PERMISSIONS, /* entry CRUDX permissions */
	P4TC_ENTRY_PAD,
	__P4TC_ENTRY_MAX
};
#define P4TC_ENTRY_MAX (__P4TC_ENTRY_MAX - 1)

enum {
	P4TC_ENTITY_UNSPEC,
	P4TC_ENTITY_KERNEL,
	P4TC_ENTITY_TC,
	P4TC_ENTITY_MAX
};

#define P4TC_REGISTER_FLAGS_DATATYPE 0x1
#define P4TC_REGISTER_FLAGS_STARTBIT 0x2
#define P4TC_REGISTER_FLAGS_ENDBIT 0x4
#define P4TC_REGISTER_FLAGS_NUMELEMS 0x8
#define P4TC_REGISTER_FLAGS_INDEX 0x10

struct p4tc_u_register {
	__u32 num_elems;
	__u32 datatype;
	__u32 index;
	__u16 startbit;
	__u16 endbit;
	__u16 flags;
};

/* P4 Register attributes */
enum {
	P4TC_REGISTER_UNSPEC,
	P4TC_REGISTER_NAME, /* string */
	P4TC_REGISTER_INFO, /* struct p4tc_u_register */
	P4TC_REGISTER_VALUE, /* value blob */
	__P4TC_REGISTER_MAX
};
#define P4TC_REGISTER_MAX (__P4TC_REGISTER_MAX - 1)

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
