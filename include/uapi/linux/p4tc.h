/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_H
#define __LINUX_P4TC_H

#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>

#include <linux/tc_act/tc_p4.h>

/* pipeline header */
struct p4tcmsg {
	__u32 pipeid;
	__u32 obj;
};

#define P4TC_MAXPIPELINE_COUNT 32
#define P4TC_MAXTABLES_COUNT 32
#define P4TC_MINTABLES_COUNT 0
#define P4TC_MSGBATCH_SIZE 16

#define P4TC_ACT_MAX_NUM_PARAMS P4TC_MSGBATCH_SIZE
#define EXTPARAMNAMSIZ 256
#define P4TC_MAX_EXTERN_METHODS 32

#define P4TC_MAX_KEYSZ 512
#define P4TC_DEFAULT_NUM_PREALLOC 16

#define P4TC_TMPL_NAMSZ 32
#define P4TC_PIPELINE_NAMSIZ P4TC_TMPL_NAMSZ
#define P4TC_ACT_TMPL_NAMSZ P4TC_TMPL_NAMSZ
#define P4TC_ACT_PARAM_NAMSIZ P4TC_TMPL_NAMSZ
#define P4TC_TABLE_NAMSIZ P4TC_TMPL_NAMSZ
#define P4TC_EXTERN_NAMSIZ P4TC_TMPL_NAMSZ
#define P4TC_EXTERN_INST_NAMSIZ P4TC_TMPL_NAMSZ

enum {
	P4TC_TABLE_TYPE_UNSPEC,
	P4TC_TABLE_TYPE_EXACT = 1,
	P4TC_TABLE_TYPE_LPM = 2,
	P4TC_TABLE_TYPE_TERNARY = 3,
	__P4TC_TABLE_TYPE_MAX,
};

#define P4TC_TABLE_TYPE_MAX (__P4TC_TABLE_TYPE_MAX - 1)

#define P4TC_CTRL_PERM_C_BIT 13
#define P4TC_CTRL_PERM_R_BIT 12
#define P4TC_CTRL_PERM_U_BIT 11
#define P4TC_CTRL_PERM_D_BIT 10
#define P4TC_CTRL_PERM_X_BIT 9
#define P4TC_CTRL_PERM_P_BIT 8
#define P4TC_CTRL_PERM_S_BIT 7

#define P4TC_DATA_PERM_C_BIT 6
#define P4TC_DATA_PERM_R_BIT 5
#define P4TC_DATA_PERM_U_BIT 4
#define P4TC_DATA_PERM_D_BIT 3
#define P4TC_DATA_PERM_X_BIT 2
#define P4TC_DATA_PERM_P_BIT 1
#define P4TC_DATA_PERM_S_BIT 0

#define P4TC_PERM_MAX_BIT P4TC_CTRL_PERM_C_BIT

#define P4TC_CTRL_PERM_C (1 << P4TC_CTRL_PERM_C_BIT)
#define P4TC_CTRL_PERM_R (1 << P4TC_CTRL_PERM_R_BIT)
#define P4TC_CTRL_PERM_U (1 << P4TC_CTRL_PERM_U_BIT)
#define P4TC_CTRL_PERM_D (1 << P4TC_CTRL_PERM_D_BIT)
#define P4TC_CTRL_PERM_X (1 << P4TC_CTRL_PERM_X_BIT)
#define P4TC_CTRL_PERM_P (1 << P4TC_CTRL_PERM_P_BIT)
#define P4TC_CTRL_PERM_S (1 << P4TC_CTRL_PERM_S_BIT)

#define P4TC_DATA_PERM_C (1 << P4TC_DATA_PERM_C_BIT)
#define P4TC_DATA_PERM_R (1 << P4TC_DATA_PERM_R_BIT)
#define P4TC_DATA_PERM_U (1 << P4TC_DATA_PERM_U_BIT)
#define P4TC_DATA_PERM_D (1 << P4TC_DATA_PERM_D_BIT)
#define P4TC_DATA_PERM_X (1 << P4TC_DATA_PERM_X_BIT)
#define P4TC_DATA_PERM_P (1 << P4TC_DATA_PERM_P_BIT)
#define P4TC_DATA_PERM_S (1 << P4TC_DATA_PERM_S_BIT)

#define p4tc_ctrl_create_ok(perm)   ((perm) & P4TC_CTRL_PERM_C)
#define p4tc_ctrl_read_ok(perm)     ((perm) & P4TC_CTRL_PERM_R)
#define p4tc_ctrl_update_ok(perm)   ((perm) & P4TC_CTRL_PERM_U)
#define p4tc_ctrl_delete_ok(perm)   ((perm) & P4TC_CTRL_PERM_D)
#define p4tc_ctrl_exec_ok(perm)     ((perm) & P4TC_CTRL_PERM_X)
#define p4tc_ctrl_pub_ok(perm)      ((perm) & P4TC_CTRL_PERM_P)
#define p4tc_ctrl_sub_ok(perm)      ((perm) & P4TC_CTRL_PERM_S)

#define p4tc_ctrl_perm_rm_create(perm) \
	(((perm) & ~P4TC_CTRL_PERM_C))

#define p4tc_data_create_ok(perm)   ((perm) & P4TC_DATA_PERM_C)
#define p4tc_data_read_ok(perm)     ((perm) & P4TC_DATA_PERM_R)
#define p4tc_data_update_ok(perm)   ((perm) & P4TC_DATA_PERM_U)
#define p4tc_data_delete_ok(perm)   ((perm) & P4TC_DATA_PERM_D)
#define p4tc_data_exec_ok(perm)     ((perm) & P4TC_DATA_PERM_X)
#define p4tc_data_pub_ok(perm)      ((perm) & P4TC_DATA_PERM_P)
#define p4tc_data_sub_ok(perm)      ((perm) & P4TC_DATA_PERM_S)

#define p4tc_data_perm_rm_create(perm) \
	(((perm) & ~P4TC_DATA_PERM_C))

/* Root attributes */
enum {
	P4TC_ROOT_UNSPEC,
	P4TC_ROOT, /* nested messages */
	P4TC_ROOT_PNAME, /* string - mandatory for pipeline create */
	P4TC_ROOT_COUNT,
	P4TC_ROOT_FLAGS,
	__P4TC_ROOT_MAX,
};

#define P4TC_ROOT_MAX (__P4TC_ROOT_MAX - 1)

/* P4 Object types */
enum {
	P4TC_OBJ_UNSPEC,
	P4TC_OBJ_PIPELINE,
	P4TC_OBJ_ACT,
	P4TC_OBJ_TABLE,
	P4TC_OBJ_EXT,
	P4TC_OBJ_EXT_INST,
	__P4TC_OBJ_MAX,
};

#define P4TC_OBJ_MAX (__P4TC_OBJ_MAX - 1)

/* P4 runtime Object types */
enum {
	P4TC_OBJ_RUNTIME_UNSPEC,
	P4TC_OBJ_RUNTIME_TABLE,
	P4TC_OBJ_RUNTIME_EXTERN,
	__P4TC_OBJ_RUNTIME_MAX,
};

#define P4TC_OBJ_RUNTIME_MAX (__P4TC_OBJ_RUNTIME_MAX - 1)

/* P4 attributes */
enum {
	P4TC_UNSPEC,
	P4TC_PATH,
	P4TC_PARAMS,
	P4TC_COUNT,
	__P4TC_MAX,
};

#define P4TC_MAX (__P4TC_MAX - 1)

/* PIPELINE attributes */
enum {
	P4TC_PIPELINE_UNSPEC,
	P4TC_PIPELINE_NUMTABLES, /* u16 */
	P4TC_PIPELINE_STATE, /* u8 */
	P4TC_PIPELINE_NAME, /* string only used for pipeline dump */
	__P4TC_PIPELINE_MAX
};

#define P4TC_PIPELINE_MAX (__P4TC_PIPELINE_MAX - 1)

/* PIPELINE states */
enum {
	P4TC_STATE_NOT_READY,
	P4TC_STATE_READY,
};

enum {
	P4TC_T_UNSPEC,
	P4TC_T_U8,
	P4TC_T_U16,
	P4TC_T_U32,
	P4TC_T_U64,
	P4TC_T_STRING,
	P4TC_T_S8,
	P4TC_T_S16,
	P4TC_T_S32,
	P4TC_T_S64,
	P4TC_T_MACADDR,
	P4TC_T_IPV4ADDR,
	P4TC_T_BE16,
	P4TC_T_BE32,
	P4TC_T_BE64,
	P4TC_T_U128,
	P4TC_T_S128,
	P4TC_T_BOOL,
	P4TC_T_DEV,
	P4TC_T_KEY,
	__P4TC_T_MAX,
};

#define P4TC_T_MAX (__P4TC_T_MAX - 1)

enum {
	P4TC_TABLE_DEFAULT_ACTION_UNSPEC,
	P4TC_TABLE_DEFAULT_ACTION,
	P4TC_TABLE_DEFAULT_ACTION_NOACTION,
	P4TC_TABLE_DEFAULT_ACTION_PERMISSIONS,
	__P4TC_TABLE_DEFAULT_ACTION_MAX
};

#define P4TC_TABLE_DEFAULT_ACTION_MAX (__P4TC_TABLE_DEFAULT_ACTION_MAX - 1)

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
	P4TC_TABLE_NAME, /* string - mandatory for create and update*/
	P4TC_TABLE_KEYSZ, /* u32 - mandatory for create*/
	P4TC_TABLE_MAX_ENTRIES, /* u32 */
	P4TC_TABLE_MAX_MASKS, /* u32 */
	P4TC_TABLE_NUM_ENTRIES, /* u32 */
	P4TC_TABLE_PERMISSIONS, /* u16 */
	P4TC_TABLE_TYPE, /* u8 */
	P4TC_TABLE_DEFAULT_HIT, /* nested default hit action attributes */
	P4TC_TABLE_DEFAULT_MISS, /* nested default miss action attributes */
	P4TC_TABLE_ACTS_LIST, /* nested table actions list */
	P4TC_TABLE_NUM_TIMER_PROFILES, /* u32 - number of timer profiles */
	P4TC_TABLE_TIMER_PROFILES, /* nested timer profiles
				    * kernel -> user space only
				    */
	P4TC_TABLE_ENTRY, /* nested template table entry*/
	P4TC_TABLE_COUNTER, /* string */
	__P4TC_TABLE_MAX
};

#define P4TC_TABLE_MAX (__P4TC_TABLE_MAX - 1)

enum {
	P4TC_TIMER_PROFILE_UNSPEC,
	P4TC_TIMER_PROFILE_ID, /* u32 */
	P4TC_TIMER_PROFILE_AGING, /* u64 */
	__P4TC_TIMER_PROFILE_MAX
};

#define P4TC_TIMER_PROFILE_MAX (__P4TC_TIMER_PROFILE_MAX - 1)

/* Action attributes */
enum {
	P4TC_ACT_UNSPEC,
	P4TC_ACT_NAME, /* string - mandatory for create */
	P4TC_ACT_PARMS, /* nested params */
	P4TC_ACT_OPT, /* action opt */
	P4TC_ACT_TM, /* action tm */
	P4TC_ACT_ACTIVE, /* u8 */
	P4TC_ACT_NUM_PREALLOC, /* u32 num preallocated action instances */
	P4TC_ACT_PAD,
	__P4TC_ACT_MAX
};

#define P4TC_ACT_MAX (__P4TC_ACT_MAX - 1)

/* Action params value attributes */

enum {
	P4TC_ACT_PARAMS_VALUE_UNSPEC,
	P4TC_ACT_PARAMS_VALUE_RAW, /* binary */
	__P4TC_ACT_PARAMS_VALUE_MAX
};

#define P4TC_ACT_VALUE_PARAMS_MAX (__P4TC_ACT_PARAMS_VALUE_MAX - 1)

enum {
	P4TC_ACT_PARAMS_TYPE_UNSPEC,
	P4TC_ACT_PARAMS_TYPE_BITEND, /* u16 */
	P4TC_ACT_PARAMS_TYPE_CONTAINER_ID, /* u32 */
	__P4TC_ACT_PARAMS_TYPE_MAX
};

#define P4TC_ACT_PARAMS_TYPE_MAX (__P4TC_ACT_PARAMS_TYPE_MAX - 1)

enum {
	P4TC_ACT_PARAMS_FLAGS_RUNT,
	__P4TC_ACT_PARAMS_FLAGS_MAX
};

#define P4TC_ACT_PARAMS_FLAGS_MAX (__P4TC_ACT_PARAMS_FLAGS_MAX - 1)

/* Action params attributes */
enum {
	P4TC_ACT_PARAMS_UNSPEC,
	P4TC_ACT_PARAMS_NAME, /* string - mandatory for params create */
	P4TC_ACT_PARAMS_ID, /* u32 */
	P4TC_ACT_PARAMS_TYPE, /* nested type - mandatory for params create */
	P4TC_ACT_PARAMS_FLAGS, /* u8 */
	P4TC_ACT_PARAMS_VALUE, /* bytes - mandatory for runtime params create */
	P4TC_ACT_PARAMS_MASK, /* bytes */
	__P4TC_ACT_PARAMS_MAX
};

#define P4TC_ACT_PARAMS_MAX (__P4TC_ACT_PARAMS_MAX - 1)

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
	P4TC_FILTER_OPND_ENTRY_ACT_UNSPEC,
	P4TC_FILTER_OPND_ENTRY_ACT_NAME, /* string  */
	P4TC_FILTER_OPND_ENTRY_ACT_ID, /* u32 */
	P4TC_FILTER_OPND_ENTRY_ACT_PARAMS, /* nested params */
	__P4TC_FILTER_OPND_ENTRY_ACT_MAX
};

#define P4TC_FILTER_OPND_ENTRY_ACT_MAX (__P4TC_FILTER_OPND_ENTRY_ACT_MAX - 1)

enum {
	P4TC_FILTER_OPND_ENTRY_UNSPEC,
	P4TC_FILTER_OPND_ENTRY_KEY_BLOB, /* Key blob */
	P4TC_FILTER_OPND_ENTRY_MASK_BLOB, /* Mask blob */
	P4TC_FILTER_OPND_ENTRY_ACT, /* nested action -
				     * P4TC_FITLER_OPND_ACT_XXX
				     */
	P4TC_FILTER_OPND_ENTRY_PRIO, /* u32 */
	P4TC_FILTER_OPND_ENTRY_TIME_DELTA, /* in msecs */
	__P4TC_FILTER_OPND_ENTRY_MAX
};

#define P4TC_FILTER_OPND_ENTRY_MAX (__P4TC_FILTER_OPND_ENTRY_MAX - 1)

enum {
	P4TC_FILTER_OPND_UNSPEC,
	P4TC_FILTER_OPND_ENTRY, /* nested entry operands -
				 * P4TC_FILTER_OPND_ENTRY_XXX
				 */
	__P4TC_FILTER_OPND_MAX
};

#define P4TC_FILTER_OPND_MAX (__P4TC_FILTER_OPND_MAX - 1)

enum {
	P4TC_FILTER_OP_KIND_UNSPEC,
	P4TC_FILTER_OP_KIND_REL,
	P4TC_FILTER_OP_KIND_LOGICAL,
	__P4TC_FILTER_OP_KIND_MAX
};

#define P4TC_FILTER_OP_KIND_MAX (__P4TC_FILTER_OP_KIND_MAX - 1)

enum {
	P4TC_FILTER_OP_KIND_REL_UNSPEC,
	P4TC_FILTER_OP_KIND_REL_EQ,
	P4TC_FILTER_OP_KIND_REL_NEQ,
	P4TC_FILTER_OP_KIND_REL_LT,
	P4TC_FILTER_OP_KIND_REL_GT,
	P4TC_FILTER_OP_KIND_REL_LE,
	P4TC_FILTER_OP_KIND_REL_GE,
	__P4TC_FILTER_OP_KIND_REL_MAX
};

#define P4TC_FILTER_OP_KIND_REL_MAX (__P4TC_FILTER_OP_KIND_REL_MAX - 1)

enum {
	P4TC_FILTER_OP_KIND_LOGICAL_UNSPEC,
	P4TC_FILTER_OP_KIND_LOGICAL_AND,
	P4TC_FILTER_OP_KIND_LOGICAL_OR,
	P4TC_FILTER_OP_KIND_LOGICAL_NOT,
	P4TC_FILTER_OP_KIND_LOGICAL_XOR,
	__P4TC_FILTER_OP_KIND_LOGICAL_MAX
};

#define P4TC_FILTER_OP_KIND_LOGICAL_MAX (__P4TC_FILTER_OP_KIND_LOGICAL_MAX - 1)

enum p4tc_filter_ntype {
	P4TC_FILTER_OP_NODE_UNSPEC,
	P4TC_FILTER_OP_NODE_PARENT, /* nested - P4TC_FILTER_XXX */
	P4TC_FILTER_OP_NODE_LEAF, /* nested - P4TC_FILTER_OPND_XXX */
	__P4TC_FILTER_OP_NODE_MAX
};

#define P4TC_FILTER_OP_NODE_MAX (__P4TC_FILTER_OP_NODE_MAX - 1)

enum {
	P4TC_FILTER_OP_UNSPEC,
	P4TC_FILTER_OP_KIND, /* P4TC_FILTER_OP_KIND_REL ||
			      * P4TC_FILTER_OP_KIND_LOGICAL
			      */
	P4TC_FILTER_OP_VALUE, /* P4TC_FILTER_OP_KIND_REL_XXX ||
			       * P4TC_FILTER_OP_KIND_LOGICAL_XXX
			       */
	P4TC_FILTER_OP_NODE1, /* nested - P4TC_FILTER_OP_NODE_XXX */
	P4TC_FILTER_OP_NODE2, /* nested - P4TC_FILTER_OP_NODE_XXX - Present only
			       * for LOGICAL OPS with LOGICAL_NOT being the
			       * exception
			       */
	__P4TC_FILTER_OP_MAX
};

#define P4TC_FILTER_OP_MAX (__P4TC_FILTER_OP_MAX - 1)

enum {
	P4TC_FILTER_UNSPEC,
	P4TC_FILTER_OP,
	__P4TC_FILTER_MAX,
};

#define P4TC_FILTER_MAX (__P4TC_FILTER_MAX - 1)

#define P4TC_FILTER_DEPTH_LIMIT 5

enum {
	P4TC_ENTRY_TBL_ATTRS_UNSPEC,
	P4TC_ENTRY_TBL_ATTRS_DEFAULT_HIT, /* nested default hit attrs */
	P4TC_ENTRY_TBL_ATTRS_DEFAULT_MISS, /* nested default miss attrs */
	P4TC_ENTRY_TBL_ATTRS_PERMISSIONS, /* u16 table permissions */
	P4TC_ENTRY_TBL_ATTRS_TIMER_PROFILE, /* nested timer profile */
	__P4TC_ENTRY_TBL_ATTRS,
};

#define P4TC_ENTRY_TBL_ATTRS_MAX (__P4TC_ENTRY_TBL_ATTRS - 1)

/* Table entry attributes */
enum {
	P4TC_ENTRY_UNSPEC,
	P4TC_ENTRY_TBLNAME, /* string - mandatory for create */
	P4TC_ENTRY_KEY_BLOB, /* Key blob - mandatory for create, update, delete,
			      * and get
			      */
	P4TC_ENTRY_MASK_BLOB, /* Mask blob */
	P4TC_ENTRY_PRIO, /* u32 - mandatory for delete and get for non-exact
			  * table
			  */
	P4TC_ENTRY_ACT, /* nested actions */
	P4TC_ENTRY_TM, /* entry data path timestamps */
	P4TC_ENTRY_WHODUNNIT, /* tells who's modifying the entry */
	P4TC_ENTRY_WHO_CREATED_ENT, /* tells entity who created the entry */
	P4TC_ENTRY_WHO_CREATED, /* tells name of process who created the
				 * entry.
				 */
	P4TC_ENTRY_WHO_CREATED_PID, /* tells pid of process who created the
				     * entry
				     */
	P4TC_ENTRY_WHO_UPDATED_ENT, /* tells entity who created the entry */
	P4TC_ENTRY_WHO_UPDATED, /* tells name of process who updated the
				 * entry.
				 */
	P4TC_ENTRY_WHO_UPDATED_PID, /* tells pid of process who updated the
				     * entry
				     */
	P4TC_ENTRY_WHO_DELETED_ENT, /* tells who deleted the entry */
	P4TC_ENTRY_WHO_DELETED, /* tells name of process who deleted the
				 * entry.
				 */
	P4TC_ENTRY_WHO_DELETED_PID, /* tells pid of process who deleted the
				     * entry
				     */
	P4TC_ENTRY_PERMISSIONS, /* entry CRUDXPS permissions */
	P4TC_ENTRY_TBL_ATTRS, /* nested table attributes */
	P4TC_ENTRY_TMPL_CREATED, /* u8 tells whether entry was create by
				  * template
				  */
	P4TC_ENTRY_DYNAMIC, /* u8 tells if table entry is dynamic */
	P4TC_ENTRY_AGING, /* u64 table entry aging */
	P4TC_ENTRY_PROFILE_ID, /* u32 table entry profile ID */
	P4TC_ENTRY_FILTER, /* nested filter */
	P4TC_ENTRY_COUNTER, /* nested extern associated with entry counter */
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

/* P4 Extern attributes */
enum {
	P4TC_TMPL_EXT_UNSPEC,
	P4TC_TMPL_EXT_NAME, /* string - mandatory for create */
	P4TC_TMPL_EXT_NUM_INSTS, /* u16 */
	P4TC_TMPL_EXT_HAS_EXEC_METHOD, /* u8 */
	__P4TC_TMPL_EXT_MAX
};

#define P4TC_TMPL_EXT_MAX (__P4TC_TMPL_EXT_MAX - 1)

enum {
	P4TC_TMPL_EXT_INST_UNSPEC,
	P4TC_TMPL_EXT_INST_EXT_NAME, /* string */
	P4TC_TMPL_EXT_INST_NAME, /* string - mandatory for create */
	P4TC_TMPL_EXT_INST_NUM_ELEMS, /* u32 */
	P4TC_TMPL_EXT_INST_CONTROL_PARAMS, /* nested control params */
	P4TC_TMPL_EXT_INST_TABLE_BINDABLE, /* bool */
	P4TC_TMPL_EXT_INST_CONSTR_PARAMS, /* nested constructor params */
	__P4TC_TMPL_EXT_INST_MAX
};

#define P4TC_TMPL_EXT_INST_MAX (__P4TC_TMPL_EXT_INST_MAX - 1)

/* Extern params attributes */
enum {
	P4TC_EXT_PARAMS_VALUE_UNSPEC,
	P4TC_EXT_PARAMS_VALUE_RAW, /* binary - mandatory for runtime params create */
	__P4TC_EXT_PARAMS_VALUE_MAX
};

#define P4TC_EXT_VALUE_PARAMS_MAX (__P4TC_EXT_PARAMS_VALUE_MAX - 1)

#define P4TC_EXT_PARAMS_FLAG_ISKEY 0x1
#define P4TC_EXT_PARAMS_FLAG_IS_DATASCALAR 0x2

/* Extern params attributes */
enum {
	P4TC_EXT_PARAMS_UNSPEC,
	P4TC_EXT_PARAMS_NAME, /* string - mandatory for create */
	P4TC_EXT_PARAMS_ID, /* u32 */
	P4TC_EXT_PARAMS_VALUE, /* bytes - mandatory for runtime params create */
	P4TC_EXT_PARAMS_TYPE, /* u32 - mandatory for create */
	P4TC_EXT_PARAMS_BITSZ, /* u16 - mandatory for create */
	P4TC_EXT_PARAMS_FLAGS, /* u8 */
	__P4TC_EXT_PARAMS_MAX
};

#define P4TC_EXT_PARAMS_MAX (__P4TC_EXT_PARAMS_MAX - 1)

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
