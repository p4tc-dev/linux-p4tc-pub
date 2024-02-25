// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/p4tc_types.c -  P4 datatypes
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/module.h>
#include <linux/init.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/act_api.h>
#include <net/p4tc_types.h>
#include <linux/etherdevice.h>

static DEFINE_IDR(p4tc_types_idr);

static void p4tc_types_put(void)
{
	unsigned long tmp, typeid;
	struct p4tc_type *type;

	idr_for_each_entry_ul(&p4tc_types_idr, type, tmp, typeid) {
		idr_remove(&p4tc_types_idr, typeid);
		kfree(type);
	}
}

struct p4tc_type *p4type_find_byid(int typeid)
{
	return idr_find(&p4tc_types_idr, typeid);
}

static struct p4tc_type *p4type_find_byname(const char *name)
{
	unsigned long tmp, typeid;
	struct p4tc_type *type;

	idr_for_each_entry_ul(&p4tc_types_idr, type, tmp, typeid) {
		if (!strncmp(type->name, name, P4TC_T_MAX_STR_SZ))
			return type;
	}

	return NULL;
}

static bool p4tc_is_type_unsigned_be(int typeid)
{
	switch (typeid) {
	case P4TC_T_BE16:
	case P4TC_T_BE32:
	case P4TC_T_BE64:
		return true;
	default:
		return false;
	}
}

bool p4tc_is_type_unsigned_he(int typeid)
{
	switch (typeid) {
	case P4TC_T_U8:
	case P4TC_T_U16:
	case P4TC_T_U32:
	case P4TC_T_U64:
	case P4TC_T_U128:
	case P4TC_T_BOOL:
		return true;
	default:
		return false;
	}
}

static bool p4tc_is_type_unsigned(int typeid)
{
	return p4tc_is_type_unsigned_he(typeid) ||
		p4tc_is_type_unsigned_be(typeid);
}

static bool p4tc_is_type_signed(int typeid)
{
	switch (typeid) {
	case P4TC_T_S8:
	case P4TC_T_S16:
	case P4TC_T_S32:
	case P4TC_T_S64:
	case P4TC_T_S128:
		return true;
	default:
		return false;
	}
}

bool p4tc_is_type_numeric(int typeid)
{
	return p4tc_is_type_unsigned(typeid) ||
		p4tc_is_type_signed(typeid);
}

void p4t_copy(struct p4tc_type_mask_shift *dst_mask_shift,
	      struct p4tc_type *dst_t, void *dstv,
	      struct p4tc_type_mask_shift *src_mask_shift,
	      struct p4tc_type *src_t, void *srcv)
{
	u64 readval[BITS_TO_U64(P4TC_MAX_KEYSZ)] = {0};
	const struct p4tc_type_ops *srco, *dsto;

	dsto = dst_t->ops;
	srco = src_t->ops;

	__p4tc_type_host_read(srco, src_t, src_mask_shift, srcv,
			      &readval);
	__p4tc_type_host_write(dsto, dst_t, dst_mask_shift, &readval,
			       dstv);
}

int p4t_cmp(struct p4tc_type_mask_shift *dst_mask_shift,
	    struct p4tc_type *dst_t, void *dstv,
	    struct p4tc_type_mask_shift *src_mask_shift,
	    struct p4tc_type *src_t, void *srcv)
{
	u64 a[BITS_TO_U64(P4TC_MAX_KEYSZ)] = {0};
	u64 b[BITS_TO_U64(P4TC_MAX_KEYSZ)] = {0};
	const struct p4tc_type_ops *srco, *dsto;

	dsto = dst_t->ops;
	srco = src_t->ops;

	__p4tc_type_host_read(dsto, dst_t, dst_mask_shift, dstv, a);
	__p4tc_type_host_read(srco, src_t, src_mask_shift, srcv, b);

	return memcmp(a, b, sizeof(a));
}

void p4t_release(struct p4tc_type_mask_shift *mask_shift)
{
	kfree(mask_shift->mask);
	kfree(mask_shift);
}

static int p4t_validate_bitpos(u16 bitstart, u16 bitend, u16 maxbitstart,
			       u16 maxbitend, struct netlink_ext_ack *extack)
{
	if (bitstart > maxbitstart) {
		NL_SET_ERR_MSG_MOD(extack, "bitstart too high");
		return -EINVAL;
	}

	if (bitend > maxbitend) {
		NL_SET_ERR_MSG_MOD(extack, "bitend too high");
		return -EINVAL;
	}

	if (bitstart > bitend) {
		NL_SET_ERR_MSG_MOD(extack, "bitstart > bitend");
		return -EINVAL;
	}

	return 0;
}

static int p4t_u32_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	u32 container_maxsz = U32_MAX;
	u32 *val = value;
	size_t maxval;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 31, 31, extack);
	if (ret < 0)
		return ret;

	maxval = GENMASK(bitend, 0);
	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U32 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4tc_type_mask_shift *
p4t_u32_bitops(u16 bitsiz, u16 bitstart, u16 bitend,
	       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;
	u32 mask = GENMASK(bitend, bitstart);
	u32 *cmask;

	mask_shift = kzalloc(sizeof(*mask_shift), GFP_KERNEL);
	if (!mask_shift)
		return ERR_PTR(-ENOMEM);

	cmask = kzalloc(sizeof(u32), GFP_KERNEL);
	if (!cmask) {
		kfree(mask_shift);
		return ERR_PTR(-ENOMEM);
	}

	*cmask = mask;

	mask_shift->mask = cmask;
	mask_shift->shift = bitstart;

	return mask_shift;
}

static void p4t_u32_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u32 maskedst = 0;
	u32 *dst = dval;
	u32 *src = sval;
	u8 shift = 0;

	if (mask_shift) {
		u32 *dmask = mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);
}

static void p4t_u32_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u32 *dst = dval;
	u32 *src = sval;

	if (mask_shift) {
		u32 *smask = mask_shift->mask;
		u8 shift = mask_shift->shift;

		*dst = (*src & *smask) >> shift;
	} else {
		*dst = *src;
	}
}

static int p4t_s32_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	s32 minsz = S32_MIN, maxsz = S32_MAX;
	s32 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S32 value out of range");
		return -EINVAL;
	}

	return 0;
}

static void p4t_s32_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	s32 *dst = dval;
	s32 *src = sval;

	*dst = *src;
}

static void p4t_s32_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	s32 *dst = dval;
	s32 *src = sval;

	*dst = *src;
}

static int p4t_s64_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	s64 minsz = S64_MIN, maxsz = S64_MAX;
	s64 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S64 value out of range");
		return -EINVAL;
	}

	return 0;
}

static void p4t_s64_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	s64 *dst = dval;
	s64 *src = sval;

	*dst = *src;
}

static void p4t_s64_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	s64 *dst = dval;
	s64 *src = sval;

	*dst = *src;
}

static int p4t_be32_validate(struct p4tc_type *container, void *value,
			     u16 bitstart, u16 bitend,
			     struct netlink_ext_ack *extack)
{
	size_t container_maxsz = U32_MAX;
	__be32 *val_u32 = value;
	__u32 val = 0;
	size_t maxval;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 31, 31, extack);
	if (ret < 0)
		return ret;

	if (value)
		val = be32_to_cpu(*val_u32);

	maxval = GENMASK(bitend, 0);
	if (val && (val > container_maxsz || val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "BE32 value out of range");
		return -EINVAL;
	}

	return 0;
}

static void p4t_be32_hread(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	__be32 *src = sval;
	u32 *dst = dval;

	*dst = be32_to_cpu(*src);
}

static void p4t_be32_write(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	__be32 *dst = dval;
	u32 *src = sval;

	*dst = cpu_to_be32(*src);
}

static void p4t_be64_hread(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	__be64 *src = sval;
	u64 *dst = dval;

	*dst = be64_to_cpu(*src);
}

static void p4t_be64_write(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	__be64 *dst = dval;
	u64 *src = sval;

	*dst = cpu_to_be64(*src);
}

static int p4t_u16_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	u16 container_maxsz = U16_MAX;
	u16 *val = value;
	u16 maxval;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 15, 15, extack);
	if (ret < 0)
		return ret;

	maxval = GENMASK(bitend, 0);
	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U16 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4tc_type_mask_shift *
p4t_u16_bitops(u16 bitsiz, u16 bitstart, u16 bitend,
	       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;
	u16 mask = GENMASK(bitend, bitstart);
	u16 *cmask;

	mask_shift = kzalloc(sizeof(*mask_shift), GFP_KERNEL);
	if (!mask_shift)
		return ERR_PTR(-ENOMEM);

	cmask = kzalloc(sizeof(u16), GFP_KERNEL);
	if (!cmask) {
		kfree(mask_shift);
		return ERR_PTR(-ENOMEM);
	}

	*cmask = mask;

	mask_shift->mask = cmask;
	mask_shift->shift = bitstart;

	return mask_shift;
}

static void p4t_u16_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u16 maskedst = 0;
	u16 *dst = dval;
	u16 *src = sval;
	u8 shift = 0;

	if (mask_shift) {
		u16 *dmask = mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);
}

static void p4t_u16_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u16 *dst = dval;
	u16 *src = sval;

	if (mask_shift) {
		u16 *smask = mask_shift->mask;
		u8 shift = mask_shift->shift;

		*dst = (*src & *smask) >> shift;
	} else {
		*dst = *src;
	}
}

static int p4t_s16_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	s16 minsz = S16_MIN, maxsz = S16_MAX;
	s16 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S16 value out of range");
		return -EINVAL;
	}

	return 0;
}

static void p4t_s16_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	s16 *dst = dval;
	s16 *src = sval;

	*dst = *src;
}

static void p4t_s16_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	s16 *dst = dval;
	s16 *src = sval;

	*src = *dst;
}

static int p4t_be16_validate(struct p4tc_type *container, void *value,
			     u16 bitstart, u16 bitend,
			     struct netlink_ext_ack *extack)
{
	u16 container_maxsz = U16_MAX;
	__be16 *val_u16 = value;
	size_t maxval;
	u16 val = 0;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 15, 15, extack);
	if (ret < 0)
		return ret;

	if (value)
		val = be16_to_cpu(*val_u16);

	maxval = GENMASK(bitend, 0);
	if (val && (val > container_maxsz || val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "BE16 value out of range");
		return -EINVAL;
	}

	return 0;
}

static void p4t_be16_hread(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	__be16 *src = sval;
	u16 *dst = dval;

	*dst = be16_to_cpu(*src);
}

static void p4t_be16_write(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	__be16 *dst = dval;
	u16 *src = sval;

	*dst = cpu_to_be16(*src);
}

static int p4t_u8_validate(struct p4tc_type *container, void *value,
			   u16 bitstart, u16 bitend,
			   struct netlink_ext_ack *extack)
{
	size_t container_maxsz = U8_MAX;
	u8 *val = value;
	u8 maxval;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 7, 7, extack);
	if (ret < 0)
		return ret;

	maxval = GENMASK(bitend, 0);
	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U8 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4tc_type_mask_shift *
p4t_u8_bitops(u16 bitsiz, u16 bitstart, u16 bitend,
	      struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;
	u8 mask = GENMASK(bitend, bitstart);
	u8 *cmask;

	mask_shift = kzalloc(sizeof(*mask_shift), GFP_KERNEL);
	if (!mask_shift)
		return ERR_PTR(-ENOMEM);

	cmask = kzalloc(sizeof(u8), GFP_KERNEL);
	if (!cmask) {
		kfree(mask_shift);
		return ERR_PTR(-ENOMEM);
	}

	*cmask = mask;

	mask_shift->mask = cmask;
	mask_shift->shift = bitstart;

	return mask_shift;
}

static void p4t_u8_write(struct p4tc_type *container,
			 struct p4tc_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	u8 maskedst = 0;
	u8 *dst = dval;
	u8 *src = sval;
	u8 shift = 0;

	if (mask_shift) {
		u8 *dmask = (u8 *)mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);
}

static void p4t_u8_hread(struct p4tc_type *container,
			 struct p4tc_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	u8 *dst = dval;
	u8 *src = sval;

	if (mask_shift) {
		u8 *smask = mask_shift->mask;
		u8 shift = mask_shift->shift;

		*dst = (*src & *smask) >> shift;
	} else {
		*dst = *src;
	}
}

static int p4t_s8_validate(struct p4tc_type *container, void *value,
			   u16 bitstart, u16 bitend,
			   struct netlink_ext_ack *extack)
{
	s8 minsz = S8_MIN, maxsz = S8_MAX;
	s8 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S8 value out of range");
		return -EINVAL;
	}

	return 0;
}

static void p4t_s8_hread(struct p4tc_type *container,
			 struct p4tc_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	s8 *dst = dval;
	s8 *src = sval;

	*dst = *src;
}

static int p4t_u64_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	u64 container_maxsz = U64_MAX;
	u8 *val = value;
	u64 maxval;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 63, 63, extack);
	if (ret < 0)
		return ret;

	maxval = GENMASK_ULL(bitend, 0);
	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U64 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4tc_type_mask_shift *
p4t_u64_bitops(u16 bitsiz, u16 bitstart, u16 bitend,
	       struct netlink_ext_ack *extack)
{
	struct p4tc_type_mask_shift *mask_shift;
	u64 mask = GENMASK(bitend, bitstart);
	u64 *cmask;

	mask_shift = kzalloc(sizeof(*mask_shift), GFP_KERNEL);
	if (!mask_shift)
		return ERR_PTR(-ENOMEM);

	cmask = kzalloc(sizeof(u64), GFP_KERNEL);
	if (!cmask) {
		kfree(mask_shift);
		return ERR_PTR(-ENOMEM);
	}

	*cmask = mask;

	mask_shift->mask = cmask;
	mask_shift->shift = bitstart;

	return mask_shift;
}

static void p4t_u64_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u64 maskedst = 0;
	u64 *dst = dval;
	u64 *src = sval;
	u8 shift = 0;

	if (mask_shift) {
		u64 *dmask = (u64 *)mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);
}

static void p4t_u64_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u64 *dst = dval;
	u64 *src = sval;

	if (mask_shift) {
		u64 *smask = mask_shift->mask;
		u8 shift = mask_shift->shift;

		*dst = (*src & *smask) >> shift;
	} else {
		*dst = *src;
	}
}

/* As of now, we are not allowing bitops for u128 */
static int p4t_u128_validate(struct p4tc_type *container, void *value,
			     u16 bitstart, u16 bitend,
			     struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 127) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only valid bit type larger than bit64 is bit128");
		return -EINVAL;
	}

	return 0;
}

static void p4t_u128_hread(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	memcpy(sval, dval, sizeof(__u64) * 2);
}

static void p4t_u128_write(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	memcpy(sval, dval, sizeof(__u64) * 2);
}

static int p4t_s128_validate(struct p4tc_type *container, void *value,
			     u16 bitstart, u16 bitend,
			     struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 127) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only valid int type larger than int64 is int128");
		return -EINVAL;
	}

	return 0;
}

static void p4t_s128_hread(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	memcpy(sval, dval, sizeof(__u64) * 2);
}

static void p4t_s128_write(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	memcpy(sval, dval, sizeof(__u64) * 2);
}

static int p4t_string_validate(struct p4tc_type *container, void *value,
			       u16 bitstart, u16 bitend,
			       struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend >= P4TC_T_MAX_STR_SZ) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "String size must be at most %u\n",
				       P4TC_T_MAX_STR_SZ);
		return -EINVAL;
	}

	return 0;
}

static void p4t_string_hread(struct p4tc_type *container,
			     struct p4tc_type_mask_shift *mask_shift,
			     void *sval, void *dval)
{
	strscpy(sval, dval, P4TC_T_MAX_STR_SZ);
}

static void p4t_string_write(struct p4tc_type *container,
			     struct p4tc_type_mask_shift *mask_shift,
			     void *sval, void *dval)
{
	strscpy(sval, dval, P4TC_T_MAX_STR_SZ);
}

static int p4t_ipv4_validate(struct p4tc_type *container, void *value,
			     u16 bitstart, u16 bitend,
			     struct netlink_ext_ack *extack)
{
	/* Not allowing bit-slices for now */
	if (bitstart != 0 || bitend != 31) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid bitstart or bitend");
		return -EINVAL;
	}

	return 0;
}

static int p4t_mac_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 47) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid bitstart or bitend");
		return -EINVAL;
	}

	return 0;
}

static int p4t_dev_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 31) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid start or endbit values");
		return -EINVAL;
	}

	return 0;
}

static void p4t_dev_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u32 *src = sval;
	u32 *dst = dval;

	*dst = *src;
}

static void p4t_dev_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u32 *src = sval;
	u32 *dst = dval;

	*dst = *src;
}

static void p4t_key_hread(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	memcpy(dval, sval, BITS_TO_BYTES(container->bitsz));
}

static void p4t_key_write(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	memcpy(dval, sval, BITS_TO_BYTES(container->bitsz));
}

static int p4t_key_validate(struct p4tc_type *container, void *value,
			    u16 bitstart, u16 bitend,
			    struct netlink_ext_ack *extack)
{
	if (p4t_validate_bitpos(bitstart, bitend, 0, P4TC_MAX_KEYSZ, extack))
		return -EINVAL;

	return 0;
}

static int p4t_bool_validate(struct p4tc_type *container, void *value,
			     u16 bitstart, u16 bitend,
			     struct netlink_ext_ack *extack)
{
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 7, 7, extack);
	if (ret < 0)
		return ret;

	return -EINVAL;
}

static void p4t_bool_hread(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	bool *dst = dval;
	bool *src = sval;

	*dst = *src;
}

static void p4t_bool_write(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	bool *dst = dval;
	bool *src = sval;

	*dst = *src;
}

static const struct p4tc_type_ops u8_ops = {
	.validate_p4t = p4t_u8_validate,
	.create_bitops = p4t_u8_bitops,
	.host_read = p4t_u8_hread,
	.host_write = p4t_u8_write,
};

static const struct p4tc_type_ops u16_ops = {
	.validate_p4t = p4t_u16_validate,
	.create_bitops = p4t_u16_bitops,
	.host_read = p4t_u16_hread,
	.host_write = p4t_u16_write,
};

static const struct p4tc_type_ops u32_ops = {
	.validate_p4t = p4t_u32_validate,
	.create_bitops = p4t_u32_bitops,
	.host_read = p4t_u32_hread,
	.host_write = p4t_u32_write,
};

static const struct p4tc_type_ops u64_ops = {
	.validate_p4t = p4t_u64_validate,
	.create_bitops = p4t_u64_bitops,
	.host_read = p4t_u64_hread,
	.host_write = p4t_u64_write,
};

static const struct p4tc_type_ops u128_ops = {
	.validate_p4t = p4t_u128_validate,
	.host_read = p4t_u128_hread,
	.host_write = p4t_u128_write,
};

static const struct p4tc_type_ops s8_ops = {
	.validate_p4t = p4t_s8_validate,
	.host_read = p4t_s8_hread,
};

static const struct p4tc_type_ops s16_ops = {
	.validate_p4t = p4t_s16_validate,
	.host_read = p4t_s16_hread,
	.host_write = p4t_s16_write,
};

static const struct p4tc_type_ops s32_ops = {
	.validate_p4t = p4t_s32_validate,
	.host_read = p4t_s32_hread,
	.host_write = p4t_s32_write,
};

static const struct p4tc_type_ops s64_ops = {
	.validate_p4t = p4t_s64_validate,
	.host_read = p4t_s64_hread,
	.host_write = p4t_s64_write,
};

static const struct p4tc_type_ops s128_ops = {
	.validate_p4t = p4t_s128_validate,
	.host_read = p4t_s128_hread,
	.host_write = p4t_s128_write,
};

static const struct p4tc_type_ops be16_ops = {
	.validate_p4t = p4t_be16_validate,
	.create_bitops = p4t_u16_bitops,
	.host_read = p4t_be16_hread,
	.host_write = p4t_be16_write,
};

static const struct p4tc_type_ops be32_ops = {
	.validate_p4t = p4t_be32_validate,
	.create_bitops = p4t_u32_bitops,
	.host_read = p4t_be32_hread,
	.host_write = p4t_be32_write,
};

static const struct p4tc_type_ops be64_ops = {
	.validate_p4t = p4t_u64_validate,
	.host_read = p4t_be64_hread,
	.host_write = p4t_be64_write,
};

static const struct p4tc_type_ops string_ops = {
	.validate_p4t = p4t_string_validate,
	.host_read = p4t_string_hread,
	.host_write = p4t_string_write,
};

static const struct p4tc_type_ops mac_ops = {
	.validate_p4t = p4t_mac_validate,
	.create_bitops = p4t_u64_bitops,
	.host_read = p4t_u64_hread,
	.host_write = p4t_u64_write,
};

static const struct p4tc_type_ops ipv4_ops = {
	.validate_p4t = p4t_ipv4_validate,
	.host_read = p4t_be32_hread,
	.host_write = p4t_be32_write,
};

static const struct p4tc_type_ops bool_ops = {
	.validate_p4t = p4t_bool_validate,
	.host_read = p4t_bool_hread,
	.host_write = p4t_bool_write,
};

static const struct p4tc_type_ops dev_ops = {
	.validate_p4t = p4t_dev_validate,
	.host_read = p4t_dev_hread,
	.host_write = p4t_dev_write,
};

static const struct p4tc_type_ops key_ops = {
	.validate_p4t = p4t_key_validate,
	.host_read = p4t_key_hread,
	.host_write = p4t_key_write,
};

#ifdef CONFIG_RETPOLINE
void __p4tc_type_host_read(const struct p4tc_type_ops *ops,
			   struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval)
{
	#define HREAD(cops) \
	do { \
		if (ops == &(cops)) \
			return (cops).host_read(container, mask_shift, sval, \
						dval); \
	} while (0)

	HREAD(u8_ops);
	HREAD(u16_ops);
	HREAD(u32_ops);
	HREAD(u64_ops);
	HREAD(u128_ops);
	HREAD(s8_ops);
	HREAD(s16_ops);
	HREAD(s32_ops);
	HREAD(be16_ops);
	HREAD(be32_ops);
	HREAD(mac_ops);
	HREAD(ipv4_ops);
	HREAD(bool_ops);
	HREAD(dev_ops);
	HREAD(key_ops);

	return ops->host_read(container, mask_shift, sval, dval);
}

void __p4tc_type_host_write(const struct p4tc_type_ops *ops,
			    struct p4tc_type *container,
			    struct p4tc_type_mask_shift *mask_shift, void *sval,
			    void *dval)
{
	#define HWRITE(cops) \
	do { \
		if (ops == &(cops)) \
			return (cops).host_write(container, mask_shift, sval, \
						 dval); \
	} while (0)

	HWRITE(u8_ops);
	HWRITE(u16_ops);
	HWRITE(u32_ops);
	HWRITE(u64_ops);
	HWRITE(u128_ops);
	HWRITE(s16_ops);
	HWRITE(s32_ops);
	HWRITE(be16_ops);
	HWRITE(be32_ops);
	HWRITE(mac_ops);
	HWRITE(ipv4_ops);
	HWRITE(bool_ops);
	HWRITE(dev_ops);
	HWRITE(key_ops);

	return ops->host_write(container, mask_shift, sval, dval);
}
#endif

static int ___p4tc_register_type(int typeid, size_t bitsz,
				 size_t container_bitsz,
				 const char *t_name,
				 const struct p4tc_type_ops *ops)
{
	struct p4tc_type *type;
	int err;

	if (typeid > P4TC_T_MAX)
		return -EINVAL;

	if (p4type_find_byid(typeid) || p4type_find_byname(t_name))
		return -EEXIST;

	if (bitsz > P4TC_T_MAX_BITSZ)
		return -E2BIG;

	if (container_bitsz > P4TC_T_MAX_BITSZ)
		return -E2BIG;

	type = kzalloc(sizeof(*type), GFP_ATOMIC);
	if (!type)
		return -ENOMEM;

	err = idr_alloc_u32(&p4tc_types_idr, type, &typeid, typeid, GFP_ATOMIC);
	if (err < 0)
		return err;

	strscpy(type->name, t_name, P4TC_T_MAX_STR_SZ);
	type->typeid = typeid;
	type->bitsz = bitsz;
	type->container_bitsz = container_bitsz;
	type->ops = ops;

	return 0;
}

static int __p4tc_register_type(int typeid, size_t bitsz,
				size_t container_bitsz,
				const char *t_name,
				const struct p4tc_type_ops *ops)
{
	if (___p4tc_register_type(typeid, bitsz, container_bitsz, t_name, ops) <
	    0) {
		pr_err("Unable to allocate p4 type %s\n", t_name);
		p4tc_types_put();
		return -1;
	}

	return 0;
}

#define p4tc_register_type(...)                            \
	do {                                               \
		if (__p4tc_register_type(__VA_ARGS__) < 0) \
			return -1;                         \
	} while (0)

int p4tc_register_types(void)
{
	p4tc_register_type(P4TC_T_U8, 8, 8, "u8", &u8_ops);
	p4tc_register_type(P4TC_T_U16, 16, 16, "u16", &u16_ops);
	p4tc_register_type(P4TC_T_U32, 32, 32, "u32", &u32_ops);
	p4tc_register_type(P4TC_T_U64, 64, 64, "u64", &u64_ops);
	p4tc_register_type(P4TC_T_U128, 128, 128, "u128", &u128_ops);
	p4tc_register_type(P4TC_T_S8, 8, 8, "s8", &s8_ops);
	p4tc_register_type(P4TC_T_BE16, 16, 16, "be16", &be16_ops);
	p4tc_register_type(P4TC_T_BE32, 32, 32, "be32", &be32_ops);
	p4tc_register_type(P4TC_T_BE64, 64, 64, "be64", &be64_ops);
	p4tc_register_type(P4TC_T_S16, 16, 16, "s16", &s16_ops);
	p4tc_register_type(P4TC_T_S32, 32, 32, "s32", &s32_ops);
	p4tc_register_type(P4TC_T_S64, 64, 64, "s64", &s64_ops);
	p4tc_register_type(P4TC_T_S128, 128, 128, "s128", &s128_ops);
	p4tc_register_type(P4TC_T_STRING, P4TC_T_MAX_STR_SZ * 4,
			   P4TC_T_MAX_STR_SZ * 4, "string", &string_ops);
	p4tc_register_type(P4TC_T_MACADDR, 48, 64, "mac", &mac_ops);
	p4tc_register_type(P4TC_T_IPV4ADDR, 32, 32, "ipv4", &ipv4_ops);
	p4tc_register_type(P4TC_T_BOOL, 32, 32, "bool", &bool_ops);
	p4tc_register_type(P4TC_T_DEV, 32, 32, "dev", &dev_ops);
	p4tc_register_type(P4TC_T_KEY, P4TC_MAX_KEYSZ, P4TC_MAX_KEYSZ, "key",
			   &key_ops);

	return 0;
}

void p4tc_unregister_types(void)
{
	p4tc_types_put();
}
