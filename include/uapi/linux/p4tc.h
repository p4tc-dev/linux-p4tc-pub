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

#define P4TC_MAX_KEYSZ 512
#define P4TC_DEFAULT_NUM_PREALLOC 16

#define P4TC_TMPL_NAMSZ 32
#define P4TC_PIPELINE_NAMSIZ P4TC_TMPL_NAMSZ
#define P4TC_ACT_TMPL_NAMSZ P4TC_TMPL_NAMSZ
#define P4TC_ACT_PARAM_NAMSIZ P4TC_TMPL_NAMSZ

/* Root attributes */
enum {
	P4TC_ROOT_UNSPEC,
	P4TC_ROOT, /* nested messages */
	P4TC_ROOT_PNAME, /* string - mandatory for pipeline create */
	__P4TC_ROOT_MAX,
};

#define P4TC_ROOT_MAX (__P4TC_ROOT_MAX - 1)

/* P4 Object types */
enum {
	P4TC_OBJ_UNSPEC,
	P4TC_OBJ_PIPELINE,
	P4TC_OBJ_ACT,
	__P4TC_OBJ_MAX,
};

#define P4TC_OBJ_MAX (__P4TC_OBJ_MAX - 1)

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

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
