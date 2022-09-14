/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __UAPI_TC_METACT_H
#define __UAPI_TC_METACT_H

#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/p4tc.h>

/* Operations */
enum {
	METACT_OP_UNSPEC,
	METACT_OP_SET,
	METACT_OP_ACT,
	METACT_OP_BEQ,
	METACT_OP_BNE,
	METACT_OP_BLT,
	METACT_OP_BLE,
	METACT_OP_BGT,
	METACT_OP_BGE,
	METACT_OP_PLUS,
	METACT_OP_PRINT,
	__METACT_OP_MAX
};
#define METACT_OP_MAX (__METACT_OP_MAX - 1)

/* single operation within TCA_METACT_LIST */
enum {
	TCAA_METACT_UNSPEC,
	TCAA_METACT_OPERATION,	/*struct tca_u_meta_operate */
	TCAA_METACT_OPER_A,	/*nested TCAA_METACT_OPER_XXX */
	TCAA_METACT_OPER_B,	/*nested TCAA_METACT_OPER_XXX */
	TCAA_METACT_OPER_C,	/*nested TCAA_METACT_OPER_XXX */
	__TCAA_METACT_OPER_MAX
};
#define TCAA_METACT_OPER_MAX (__TCAA_METACT_OPER_MAX - 1)

/* TCAA_METACT_OPERATION */
struct tca_u_meta_operate {
	__u16 op_type;		/* METACT_OP_XXX */
	__u8 op_flags;
	__u8 op_UNUSED;
	__u32 op_ctl1;
	__u32 op_ctl2;
};

/* Nested TCAA_METACT_OPER_XXX */
enum {
	TCAA_METACT_OPND_UNSPEC,
	TCAA_METACT_OPND_INFO,
	TCAA_METACT_OPND_PATH,
	__TCAA_METACT_OPND_MAX
};
#define TCAA_METACT_OPND_MAX (__TCAA_METACT_OPND_MAX - 1)

/* Maximum path or value size for an operand */
#define METACT_PATH_MAX 4

/* operand types */
enum {
	METACT_OPER_UNSPEC,
	METACT_OPER_CONST,
	METACT_OPER_META,
	METACT_OPER_HDR,
	METACT_OPER_ACTID,
	__METACT_OPER_MAX
};
#define METACT_OPER_MAX (__METACT_OPER_MAX - 1)

#define METACT_MAX_OPER_PATH_LEN 32

/* TCAA_METACT_OPER_INFO operand*/
struct tca_u_meta_operand {
	__u32 immedv;		/* immediate value, otherwise stored in
				 * TCAA_METACT_OPND_PATH
				 */
	__u32 immedv2;
	__u32 pipeid;		/* 0 for kernel-global */
	__u8 oper_type;		/* METACT_OPER_XXX */
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
/* TCA_METACT_PARMS */
struct tc_metact {
	tc_gen;
};

enum {
	TCA_METACT_UNSPEC,
	TCA_METACT_TM,
	TCA_METACT_PARMS,
	TCA_METACT_LIST,
	TCA_METACT_PAD,
	__TCA_METACT_MAX
};
#define TCA_METACT_MAX (__TCA_METACT_MAX - 1)

#define TCA_METACT_LIST_MAX 32

#endif
