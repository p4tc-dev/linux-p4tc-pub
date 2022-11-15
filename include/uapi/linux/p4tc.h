/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_H
#define __LINUX_P4TC_H

#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <linux/p4tc_entities.h>
#include <linux/pkt_cls.h>

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
#define P4TC_MAX_KEYSZ 128

#define TEMPLATENAMSZ 256
#define PIPELINENAMSIZ TEMPLATENAMSZ
#define METANAMSIZ TEMPLATENAMSZ
#define TCLASSNAMSIZ TEMPLATENAMSZ
#define TINSTNAMSIZ TEMPLATENAMSZ
#define PARSERNAMSIZ TEMPLATENAMSZ
#define HDRFIELDNAMSIZ TEMPLATENAMSZ
#define ACTPARAMNAMSIZ TEMPLATENAMSZ

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
	P4TC_OBJ_TABLE_INST,
	P4TC_OBJ_HDR_FIELD,
	P4TC_OBJ_ACT,
	P4TC_OBJ_TABLE_ENTRY,
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

/* Table instance attributes */
enum {
	P4TC_TINST_UNSPEC,
	P4TC_TINST_CLASS, /* string */
	P4TC_TINST_NAME, /* string */
	P4TC_TINST_CUR_ENTRIES, /* u32 */
	P4TC_TINST_MAX_ENTRIES, /* u32 */
	__P4TC_TINST_MAX
};
#define P4TC_TINST_MAX __P4TC_TINST_MAX

struct p4tc_header_field_ty {
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
	P4TC_ENTRY_TBCNAME, /* string */
	P4TC_ENTRY_TINAME, /* string */
	P4TC_ENTRY_KEY_BLOB, /* Key blob */
	P4TC_ENTRY_MASK_BLOB, /* Mask blob */
	P4TC_ENTRY_PRIO, /* u32 */
	P4TC_ENTRY_ACT, /* nested actions */
	P4TC_ENTRY_TM, /* entry data path timestamps */
	P4TC_ENTRY_WHODUNNIT, /* tells who's modifying the entry */
	P4TC_ENTRY_CREATE_WHODUNNIT, /* tells who created the entry */
	P4TC_ENTRY_UPDATE_WHODUNNIT, /* tells who updated the entry last */
	P4TC_ENTRY_PAD,
	__P4TC_ENTRY_MAX
};
#define P4TC_ENTRY_MAX (__P4TC_ENTRY_MAX - 1)

#define P4TC_RTA(r)  ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

/* P4TC COMMANDS */

/* Operations */
enum {
	P4TC_CMD_OP_UNSPEC,
	P4TC_CMD_OP_SET,
	P4TC_CMD_OP_ACT,
	P4TC_CMD_OP_BEQ,
	P4TC_CMD_OP_BNE,
	P4TC_CMD_OP_BLT,
	P4TC_CMD_OP_BLE,
	P4TC_CMD_OP_BGT,
	P4TC_CMD_OP_BGE,
	P4TC_CMD_OP_PLUS,
	P4TC_CMD_OP_PRINT,
	P4TC_CMD_OP_TBLAPP,
	P4TC_CMD_OP_SNDPORTEGR,
	P4TC_CMD_OP_MIRPORTEGR,
	__P4TC_CMD_OP_MAX
};
#define P4TC_CMD_OP_MAX (__P4TC_CMD_OP_MAX - 1)

/* single operation within P4TC_ACT_CMDS_LIST */
enum {
	P4TC_CMD_UNSPEC,
	P4TC_CMD_OPERATION,	/*struct p4tc_u_operate */
	P4TC_CMD_OPER_A,	/*nested P4TC_CMD_OPER_XXX */
	P4TC_CMD_OPER_B,	/*nested P4TC_CMD_OPER_XXX */
	P4TC_CMD_OPER_C,	/*nested P4TC_CMD_OPER_XXX */
	__P4TC_CMD_OPER_MAX
};
#define P4TC_CMD_OPER_MAX (__P4TC_CMD_OPER_MAX - 1)

#define P4TC_CMDS_RESULTS_HIT 1
#define P4TC_CMDS_RESULTS_MISS 2

/* P4TC_CMD_OPERATION */
struct p4tc_u_operate {
	__u16 op_type;		/* P4TC_CMD_OP_XXX */
	__u8 op_flags;
	__u8 op_UNUSED;
	__u32 op_ctl1;
	__u32 op_ctl2;
};

/* Nested P4TC_CMD_OPER_XXX */
enum {
	P4TC_CMD_OPND_UNSPEC,
	P4TC_CMD_OPND_INFO,
	P4TC_CMD_OPND_PATH,
	__P4TC_CMD_OPND_MAX
};
#define P4TC_CMD_OPND_MAX (__P4TC_CMD_OPND_MAX - 1)

/* operand types */
enum {
	P4TC_OPER_UNSPEC,
	P4TC_OPER_CONST,
	P4TC_OPER_META,
	P4TC_OPER_ACTID,
	P4TC_OPER_TBL,
	P4TC_OPER_KEY,
	P4TC_OPER_RES,
	P4TC_OPER_HDRFIELD,
	P4TC_OPER_PARAM,
	P4TC_OPER_DEV,
	__P4TC_OPER_MAX
};
#define P4TC_OPER_MAX (__P4TC_OPER_MAX - 1)

#define P4TC_CMD_MAX_OPER_PATH_LEN 32

/* P4TC_CMD_OPER_INFO operand*/
struct p4tc_u_operand {
	__u32 immedv;		/* immediate value, otherwise stored in
				 * P4TC_CMD_OPND_PATH
				 */
	__u32 immedv2;
	__u32 pipeid;		/* 0 for kernel-global */
	__u8 oper_type;		/* P4TC_OPER_XXX */
	__u8 oper_datatype;	/* T_XXX */
	__u8 oper_cbitsize;	/* Size of container, u8 = 8, etc
				 * Useful for a type that is not atomic
				 */
	__u8 oper_startbit;
	__u8 oper_endbit;
	__u8 oper_flags;
};

/* operand flags */
#define DATA_IS_IMMEDIATE (BIT(0)) /* data is held as immediate value */
#define DATA_IS_RAW (BIT(1))	 /* bitXX datatype, not intepreted by kernel */
#define DATA_IS_SLICE (BIT(2))	 /* bitslice in a container, not intepreted
				  * by kernel
				  */

#endif
