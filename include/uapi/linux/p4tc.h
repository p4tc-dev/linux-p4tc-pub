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
#define P4TC_MAXTABLES_COUNT 32
#define P4TC_MINTABLES_COUNT 0
#define P4TC_MAXPARSE_KEYS 16
#define P4TC_MAXMETA_SZ 128
#define P4TC_MSGBATCH_SIZE 16

#define P4TC_MAX_KEYSZ 512

#define TEMPLATENAMSZ 256
#define PIPELINENAMSIZ TEMPLATENAMSZ

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
	P4TC_PIPELINE_NUMTABLES, /* u16 */
	P4TC_PIPELINE_STATE, /* u8 */
	P4TC_PIPELINE_NAME, /* string only used for pipeline dump */
	__P4TC_PIPELINE_MAX
};
#define P4TC_PIPELINE_MAX __P4TC_PIPELINE_MAX

/* P4 Object types */
enum {
	P4TC_OBJ_UNSPEC,
	P4TC_OBJ_PIPELINE,
	__P4TC_OBJ_MAX,
};
#define P4TC_OBJ_MAX __P4TC_OBJ_MAX

/* P4 attributes */
enum {
	P4TC_UNSPEC,
	P4TC_PATH,
	P4TC_PARAMS,
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

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
