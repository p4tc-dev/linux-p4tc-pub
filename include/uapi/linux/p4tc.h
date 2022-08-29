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
#define P4TC_MAXTABLES_COUNT 32
#define P4TC_MINTABLES_COUNT 0
#define P4TC_MAXPARSE_KEYS 16
#define P4TC_MAXMETA_SZ 128
#define P4TC_MSGBATCH_SIZE 16
#define P4TC_MAX_KEYSZ 512
#define HEADER_MAX_LEN 512
#define META_MAX_LEN 512

#define P4TC_MAX_KEYSZ 512

#define TEMPLATENAMSZ 256
#define PIPELINENAMSIZ TEMPLATENAMSZ
#define METANAMSIZ TEMPLATENAMSZ
#define PARSERNAMSIZ TEMPLATENAMSZ
#define HDRFIELDNAMSIZ TEMPLATENAMSZ

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

#define P4TC_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct p4tcmsg))))

#endif
