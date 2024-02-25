/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_H
#define __LINUX_P4TC_H

#include <linux/types.h>
#include <linux/pkt_sched.h>

/* pipeline header */
struct p4tcmsg {
	__u32 obj;
};

#define P4TC_MSGBATCH_SIZE 16

#define P4TC_MAX_KEYSZ 512

#define P4TC_TMPL_NAMSZ 32

/* Root attributes */
enum {
	P4TC_ROOT_UNSPEC,
	P4TC_ROOT, /* nested messages */
	__P4TC_ROOT_MAX,
};

#define P4TC_ROOT_MAX (__P4TC_ROOT_MAX - 1)

/* P4 Object types */
enum {
	P4TC_OBJ_UNSPEC,
	__P4TC_OBJ_MAX,
};

#define P4TC_OBJ_MAX (__P4TC_OBJ_MAX - 1)

/* P4 attributes */
enum {
	P4TC_UNSPEC,
	P4TC_PATH,
	P4TC_PARAMS,
	__P4TC_MAX,
};

#define P4TC_MAX (__P4TC_MAX - 1)

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

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
