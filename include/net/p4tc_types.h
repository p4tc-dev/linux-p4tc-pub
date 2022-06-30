/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TYPES_H
#define __NET_P4TYPES_H

#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>

#include <uapi/linux/p4tc.h>

#define P4T_MAX_BITSZ P4TC_MAX_KEYSZ

struct p4tc_type_mask_shift {
	void *mask;
	u8 shift;
};

struct p4tc_type;
struct p4tc_type_ops {
	int (*validate_p4t)(struct p4tc_type *container, void *value, u16 startbit,
			    u16 endbit, struct netlink_ext_ack *extack);
	struct p4tc_type_mask_shift *(*create_bitops)(u16 bitsz,
						      u16 bitstart,
						      u16 bitend,
						      struct netlink_ext_ack *extack);
	int (*host_read)(struct p4tc_type *container,
			 struct p4tc_type_mask_shift *mask_shift, void *sval,
			 void *dval);
	int (*host_write)(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval);
	void (*print)(struct net *net, struct p4tc_type *container,
		      const char *prefix, void *val);
};

#define P4T_MAX_STR_SZ 32
struct p4tc_type {
	char name[P4T_MAX_STR_SZ];
	struct p4tc_type_ops *ops;
	size_t container_bitsz;
	size_t bitsz;
	int typeid;
};

struct p4tc_type *p4type_find_byid(int id);
bool p4tc_type_unsigned(int typeid);

int p4t_copy(struct p4tc_type_mask_shift *dst_mask_shift,
	     struct p4tc_type *dst_t, void *dstv,
	     struct p4tc_type_mask_shift *src_mask_shift,
	     struct p4tc_type *src_t, void *srcv);
int p4t_cmp(struct p4tc_type_mask_shift *dst_mask_shift,
	    struct p4tc_type *dst_t, void *dstv,
	    struct p4tc_type_mask_shift *src_mask_shift,
	    struct p4tc_type *src_t, void *srcv);
void p4t_release(struct p4tc_type_mask_shift *mask_shift);

int p4tc_register_types(void);
void p4tc_unregister_types(void);

#endif
