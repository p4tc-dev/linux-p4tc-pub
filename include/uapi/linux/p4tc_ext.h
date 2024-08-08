/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_P4TC_EXT_H
#define __LINUX_P4TC_EXT_H

#define P4TC_EXT_NAMSIZ 64

/* Extern attributes */
enum {
	P4TC_EXT_UNSPEC,
	P4TC_EXT_INST_NAME,
	P4TC_EXT_KIND,
	P4TC_EXT_PARAMS,
	P4TC_EXT_KEY,
	P4TC_EXT_PAD,
	P4TC_EXT_FLAGS,
	P4TC_EXT_FILTER,
	__P4TC_EXT_MAX
};

#define P4TC_EXT_ID_DYN 0x01
#define P4TC_EXT_ID_MAX 1023

/* See other P4TC_EXT_FLAGS_ * flags in include/net/act_api.h. */
#define P4TC_EXT_FLAGS_NO_PERCPU_STATS (1 << 0) /* Don't use percpu allocator
						 * for externs stats.
						 */
#define P4TC_EXT_FLAGS_SKIP_HW	(1 << 1) /* don't offload extern to HW */
#define P4TC_EXT_FLAGS_SKIP_SW	(1 << 2) /* don't use extern in SW */

#define P4TC_EXT_FLAG_LARGE_DUMP_ON	(1 << 0)

#define P4TC_EXT_MAX __P4TC_EXT_MAX

#endif
