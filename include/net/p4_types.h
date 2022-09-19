/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TYPES_H
#define __NET_P4TYPES_H

#include <linux/pkt_cls.h>
#include <uapi/linux/p4tc.h>
#include <linux/types.h>

#define P4T_MAX_BITSZ 128

struct p4_type_mask_shift {
	void *mask;
	u8 shift;
};

struct p4_type;
struct p4_type_ops;
struct p4_type_ops {
	int (*validate_p4t)(struct p4_type *container, void *value, u8 startbit,
			    u8 endbit, struct netlink_ext_ack *extack);
	struct p4_type_mask_shift *(*create_bitops)(u8 bitsz,
						    u8 bitstart,
						    u8 bitend,
						    struct netlink_ext_ack *extack);
	int (*host_read)(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval);
	int (*host_write)(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval);
};

#define P4T_MAX_STR_SZ 32
struct p4_type {
	int typeid;
	size_t bitsz;
	struct p4_type_ops *ops;
	char name[P4T_MAX_STR_SZ];
};

int register_p4_types(void);
int unregister_p4_types(void);

struct p4_type *p4type_find_byid(int id);
int p4t_copy(struct p4_type_mask_shift *dst_mask_shift,
	     struct p4_type_ops *dsto, void *dstv,
	     struct p4_type_mask_shift *src_mask_shift,
	     struct p4_type_ops *srco, void *srcv);
int p4t_cmp(struct p4_type_mask_shift *dst_mask_shift,
	     struct p4_type_ops *dsto, void *dstv,
	     struct p4_type_mask_shift *src_mask_shift,
	     struct p4_type_ops *srco, void *srcv);
void p4t_release(struct p4_type_mask_shift *mask_shift);
#endif
