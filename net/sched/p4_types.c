// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4_types.c -  P4 datatypes
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
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
#include <net/p4_types.h>
#include <linux/etherdevice.h>

DEFINE_IDR(p4_types_idr);

struct p4_type *p4type_find_byid(int typeid)
{
	return idr_find(&p4_types_idr, typeid);
}

static struct p4_type *p4type_find_byname(const char *name)
{
	struct p4_type *type;
	unsigned long tmp, typeid;

	idr_for_each_entry_ul(&p4_types_idr, type, tmp, typeid) {
		if (!strncmp(type->name, name, P4T_MAX_STR_SZ))
			return type;
	}

	return NULL;
}

static int p4t_validate_bitpos(u8 bitstart, u8 bitend, u8 maxbitstart,
			       u8 maxbitend, struct netlink_ext_ack *extack)
{
	if (bitstart > maxbitstart) {
		NL_SET_ERR_MSG_MOD(extack, "bitstart too high");
		return -EINVAL;
	}
	if (bitend > maxbitend) {
		NL_SET_ERR_MSG_MOD(extack, "bitend too high");
		return -EINVAL;
	}

	return 0;
}

//XXX: Latter immedv will be 64 bits
static int p4t_u32_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	u32 container_maxsz = U32_MAX;
	u32 *val = value;
	size_t maxval;
	u8 bitsz;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 31, 31, extack);
	if (ret < 0)
		return ret;

	bitsz = bitend - bitstart + 1;
	maxval = (1UL << bitsz) - 1;

	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U32 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4_type_mask_shift *
p4t_u32_bitops(u8 bitsiz, u8 bitstart, u8 bitend,
	       struct netlink_ext_ack *extack)
{
	u32 mask = GENMASK(bitend, bitstart);
	struct p4_type_mask_shift *mask_shift;
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

static int p4t_u32_write(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	u32 *dst = dval;
	u32 *src = sval;
	u32 maskedst = 0;
	u8 shift = 0;

	if (mask_shift) {
		u32 *dmask = mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);

	return 0;
}

static void p4t_u32_print(const char *prefix, void *val)
{
	u32 *v = val;

	pr_info("%s 0x%x\n", prefix, *v);
}

static int p4t_u32_hread(struct p4_type_mask_shift *mask_shift, void *sval,
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

	return 0;
}

/*XXX: future converting immedv to 64 bits */
static int p4t_s32_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	s32 minsz = S32_MIN, maxsz = S32_MAX;
	s32 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S32 value out of range");
		return -EINVAL;
	}

	return 0;
}

static int p4t_s32_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	s32 *dst = dval;
	s32 *src = sval;

	*dst = *src;

	return 0;
}

static int p4t_s32_write(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	s32 *dst = dval;
	s32 *src = sval;

	*dst = *src;

	return 0;
}

static void p4t_s32_print(const char *prefix, void *val)
{
	s32 *v = val;

	pr_info("%s %x\n", prefix, *v);
}

static void p4t_s64_print(const char *prefix, void *val)
{
	s64 *v = val;

	pr_info("%s 0x%llx\n", prefix, *v);
}

static int p4t_be32_validate(struct p4_type *container, void *value, u8 bitstart,
			     u8 bitend, struct netlink_ext_ack *extack)
{
	size_t container_maxsz = U32_MAX;
	__u32 *val_u32 = value;
	__be32 val = 0;
	size_t maxval;
	u8 bitsz;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 31, 31, extack);
	if (ret < 0)
		return ret;

	if (value)
		val = (__be32)(be32_to_cpu(*val_u32));

	bitsz = bitend - bitstart + 1;
	maxval = (1UL << bitsz) - 1;

	if (val && (val > container_maxsz || val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "BE32 value out of range");
		return -EINVAL;
	}

	return 0;
}

static int p4t_be32_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u32 *dst = dval;
	u32 *src = sval;
	u32 readval = be32_to_cpu(*src);

	if (mask_shift) {
		u32 *smask = mask_shift->mask;
		u8 shift = mask_shift->shift;

		readval = (*src & *smask) >> shift;
	}

	*dst = be32_to_cpu(readval);

	return 0;
}

static int p4t_be32_write(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	__be32 *dst = dval;
	u32 maskedst = 0;
	u32 *src = sval;
	u8 shift = 0;

	if (mask_shift) {
		u32 *dmask = (u32 *)mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = cpu_to_be32(maskedst | (*src << shift));

	return 0;
}

static void p4t_be32_print(const char *prefix, void *val)
{
	__be32 *v = val;

	pr_info("%s 0x%x\n", prefix, *v);
}

static int p4t_u16_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	u16 container_maxsz = U16_MAX;
	u16 *val = value;
	u16 maxval;
	u8 bitsz;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 15, 15, extack);
	if (ret < 0)
		return ret;

	bitsz = bitend - bitstart + 1;
	maxval = (1 << bitsz) - 1;

	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U16 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4_type_mask_shift *
p4t_u16_bitops(u8 bitsiz, u8 bitstart, u8 bitend,
	       struct netlink_ext_ack *extack)
{
	u16 mask = GENMASK(bitend, bitstart);
	struct p4_type_mask_shift *mask_shift;
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

static int p4t_u16_write(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	u16 *dst = dval;
	u16 *src = sval;
	u16 maskedst = 0;
	u8 shift = 0;

	if (mask_shift) {
		u16 *dmask = mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);

	return 0;
}

static void p4t_u16_print(const char *prefix, void *val)
{
	u16 *v = val;

	pr_info("%s 0x%x\n", prefix, *v);
}

static int p4t_u16_hread(struct p4_type_mask_shift *mask_shift, void *sval,
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

	return 0;
}

static int p4t_s16_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	s16 minsz = S16_MIN, maxsz = S16_MAX;
	s16 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S16 value out of range");
		return -EINVAL;
	}

	return 0;
}

static int p4t_s16_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	s16 *dst = dval;
	s16 *src = sval;

	*dst = *src;

	return 0;
}

static int p4t_s16_write(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	s16 *dst = dval;
	s16 *src = sval;

	*src = *dst;

	return 0;
}

static void p4t_s16_print(const char *prefix, void *val)
{
	s16 *v = val;

	pr_info("%s %d\n", prefix, *v);
}

static int p4t_be16_validate(struct p4_type *container, void *value, u8 bitstart,
			     u8 bitend, struct netlink_ext_ack *extack)
{
	__be16 container_maxsz = U16_MAX;
	__u16 *val_u16 = value;
	__be16 val = 0;
	size_t maxval;
	u8 bitsz;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 15, 15, extack);
	if (ret < 0)
		return ret;

	if (value)
		val = (__be16)(be16_to_cpu(*val_u16));

	bitsz = bitend - bitstart + 1;
	maxval = (1 << bitsz) - 1;

	if (val && (val > container_maxsz || val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "BE16 value out of range");
		return -EINVAL;
	}

	return 0;
}

static int p4t_be16_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	u16 *dst = dval;
	u16 *src = sval;
	u16 readval = be16_to_cpu(*src);

	if (mask_shift) {
		u16 *smask = mask_shift->mask;
		u8 shift = mask_shift->shift;

		readval = (*src & *smask) >> shift;
	}

	*dst = be16_to_cpu(readval);

	return 0;
}

static int p4t_be16_write(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	__be16 *dst = dval;
	u16 maskedst = 0;
	u16 *src = sval;
	u8 shift = 0;

	if (mask_shift) {
		u16 *dmask = (u16 *)mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = cpu_to_be16(maskedst | (*src << shift));

	return 0;
}

static void p4t_be16_print(const char *prefix, void *val)
{
	__be16 *v = val;

	pr_info("%s 0x%x\n", prefix, *v);
}

static int p4t_u8_validate(struct p4_type *container, void *value, u8 bitstart,
			   u8 bitend, struct netlink_ext_ack *extack)
{
	u8 *val = value;
	size_t container_maxsz = U8_MAX;
	u8 maxval;
	u8 bitsz;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 7, 7, extack);
	if (ret < 0)
		return ret;

	bitsz = bitend - bitstart + 1;
	maxval = (1 << bitsz) - 1;

	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U8 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4_type_mask_shift *
p4t_u8_bitops(u8 bitsiz, u8 bitstart, u8 bitend,
	      struct netlink_ext_ack *extack)
{
	u8 mask = GENMASK(bitend, bitstart);
	struct p4_type_mask_shift *mask_shift;
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

static int p4t_u8_write(struct p4_type_mask_shift *mask_shift, void *sval,
			void *dval)
{
	u8 *dst = dval;
	u8 *src = sval;
	u8 maskedst = 0;
	u8 shift = 0;

	if (mask_shift) {
		u8 *dmask = (u8 *)mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);

	return 0;
}

static void p4t_u8_print(const char *prefix, void *val)
{
	u8 *v = val;

	pr_info("%s 0x%x\n", prefix, *v);
}

static int p4t_u8_hread(struct p4_type_mask_shift *mask_shift, void *sval,
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

	return 0;
}

static int p4t_s8_validate(struct p4_type *container, void *value, u8 bitstart,
			   u8 bitend, struct netlink_ext_ack *extack)
{
	s8 minsz = S8_MIN, maxsz = S8_MAX;
	s8 *val = value;

	if (val && (*val > maxsz || *val < minsz)) {
		NL_SET_ERR_MSG_MOD(extack, "S8 value out of range");
		return -EINVAL;
	}

	return 0;
}

static int p4t_s8_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			void *dval)
{
	s8 *dst = dval;
	s8 *src = sval;

	*dst = *src;

	return 0;
}

static void p4t_s8_print(const char *prefix, void *val)
{
	s8 *v = val;

	pr_info("%s %d\n", prefix, *v);
}

static int p4t_u64_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	u8 *val = value;
	u64 container_maxsz = U64_MAX;
	u64 maxval;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 63, 63, extack);
	if (ret < 0)
		return ret;

	maxval = GENMASK_ULL(bitend, bitstart);
	if (val && (*val > container_maxsz || *val > maxval)) {
		NL_SET_ERR_MSG_MOD(extack, "U64 value out of range");
		return -EINVAL;
	}

	return 0;
}

static struct p4_type_mask_shift *
p4t_u64_bitops(u8 bitsiz, u8 bitstart, u8 bitend,
	       struct netlink_ext_ack *extack)
{
	u64 mask = GENMASK(bitend, bitstart);
	struct p4_type_mask_shift *mask_shift;
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

static int p4t_u64_write(struct p4_type_mask_shift *mask_shift, void *sval,
			 void *dval)
{
	u64 *dst = dval;
	u64 *src = sval;
	u64 maskedst = 0;
	u8 shift = 0;

	if (mask_shift) {
		u64 *dmask = (u64 *)mask_shift->mask;

		maskedst = *dst & ~*dmask;
		shift = mask_shift->shift;
	}

	*dst = maskedst | (*src << shift);

	return 0;
}

static void p4t_u64_print(const char *prefix, void *val)
{
	u64 *v = val;

	pr_info("%s 0x%llx\n", prefix, *v);
}

static int p4t_u64_hread(struct p4_type_mask_shift *mask_shift, void *sval,
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

	return 0;
}

/* As of now, we are not allowing bitops for u128 */
static int p4t_u128_validate(struct p4_type *container, void *value, u8 bitstart,
			     u8 bitend, struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 127)
		return -EINVAL;

	return 0;
}

static int p4t_u128_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	__uint128_t *dst = dval;
	__uint128_t *src = sval;

	memcpy(dst, src, sizeof(__uint128_t));

	return 0;
}

static int p4t_u128_write(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	__uint128_t *dst = dval;
	__uint128_t *src = sval;

	memcpy(dst, src, sizeof(__uint128_t));

	return 0;
}

static void p4t_u128_print(const char *prefix, void *val)
{
	u64 *v = val;

	pr_info("%s[0-63] %16llx", prefix, v[0]);
	pr_info("%s[64-127] %16llx", prefix, v[1]);
}

static int p4t_ipv4_validate(struct p4_type *container, void *value, u8 bitstart,
			     u8 bitend, struct netlink_ext_ack *extack)
{
	/* Not allowing bit-slices for now */
	if (bitstart != 0 || bitend != 31) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid bitstart or bitend");
		return -EINVAL;
	}

	return 0;
}

static void p4t_ipv4_print(const char *prefix, void *val)
{
	u8 *v = val;

	pr_info("%s %u.%u.%u.%u\n", prefix, v[0], v[1], v[2], v[3]);
}

static int p4t_mac_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 47) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid bitstart or bitend");
		return -EINVAL;
	}

	return 0;
}

static void p4t_mac_print(const char *prefix, void *val)
{
	u8 *v = val;

	pr_info("%s %02X:%02x:%02x:%02x:%02x:%02x\n", prefix, v[0], v[1], v[2],
		v[3], v[4], v[5]);
}

static int p4t_dev_validate(struct p4_type *container, void *value, u8 bitstart,
			    u8 bitend, struct netlink_ext_ack *extack)
{
	if (bitstart != 0 || bitend != 31) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid start or endbit values");
		return -EINVAL;
	}

	return 0;
}

static void p4t_dev_print(const char *prefix, void *val)
{
	const struct net_device *dev = val;

	pr_info("%s %s\n", prefix, dev->name);
}

static int p4t_bool_validate(struct p4_type *container, void *value, u8 bitstart,
			     u8 bitend, struct netlink_ext_ack *extack)
{
	bool *val = value;
	int ret;

	ret = p4t_validate_bitpos(bitstart, bitend, 31, 31, extack);
	if (ret < 0)
		return ret;

	if (*val == true || *val == false)
		return 0;

	return -EINVAL;
}

static int p4t_bool_hread(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	bool *dst = dval;
	bool *src = sval;

	*dst = *src;

	return 0;
}

static int p4t_bool_write(struct p4_type_mask_shift *mask_shift, void *sval,
			  void *dval)
{
	bool *dst = dval;
	bool *src = sval;

	*dst = *src;

	return 0;
}

static void p4t_bool_print(const char *prefix, void *val)
{
	bool *v = val;

	pr_info("%s %s", prefix, *v ? "true" : "false");
}

static struct p4_type_ops u8_ops = {
	.validate_p4t = p4t_u8_validate,
	.create_bitops = p4t_u8_bitops,
	.host_read = p4t_u8_hread,
	.host_write = p4t_u8_write,
	.print = p4t_u8_print,
};

static struct p4_type_ops u16_ops = {
	.validate_p4t = p4t_u16_validate,
	.create_bitops = p4t_u16_bitops,
	.host_read = p4t_u16_hread,
	.host_write = p4t_u16_write,
	.print = p4t_u16_print,
};

static struct p4_type_ops u32_ops = {
	.validate_p4t = p4t_u32_validate,
	.create_bitops = p4t_u32_bitops,
	.host_read = p4t_u32_hread,
	.host_write = p4t_u32_write,
	.print = p4t_u32_print,
};

static struct p4_type_ops u64_ops = {
	.validate_p4t = p4t_u64_validate,
	.create_bitops = p4t_u64_bitops,
	.host_read = p4t_u64_hread,
	.host_write = p4t_u64_write,
	.print = p4t_u64_print,
};

static struct p4_type_ops u128_ops = {
	.validate_p4t = p4t_u128_validate,
	.host_read = p4t_u128_hread,
	.host_write = p4t_u128_write,
	.print = p4t_u128_print,
};

static struct p4_type_ops s8_ops = {
	.validate_p4t = p4t_s8_validate,
	.host_read = p4t_s8_hread,
	.print = p4t_s8_print,
};

static struct p4_type_ops s16_ops = {
	.validate_p4t = p4t_s16_validate,
	.host_read = p4t_s16_hread,
	.host_write = p4t_s16_write,
	.print = p4t_s16_print,
};

static struct p4_type_ops s32_ops = {
	.validate_p4t = p4t_s32_validate,
	.host_read = p4t_s32_hread,
	.host_write = p4t_s32_write,
	.print = p4t_s32_print,
};

static struct p4_type_ops s64_ops = {
	.print = p4t_s64_print,
};
static struct p4_type_ops s128_ops = {};

static struct p4_type_ops be16_ops = {
	.validate_p4t = p4t_be16_validate,
	.create_bitops = p4t_u16_bitops,
	.host_read = p4t_be16_hread,
	.host_write = p4t_be16_write,
	.print = p4t_be16_print,
};

static struct p4_type_ops be32_ops = {
	.validate_p4t = p4t_be32_validate,
	.create_bitops = p4t_u32_bitops,
	.host_read = p4t_be32_hread,
	.host_write = p4t_be32_write,
	.print = p4t_be32_print,
};

static struct p4_type_ops string_ops = {};
static struct p4_type_ops nullstring_ops = {};

static struct p4_type_ops flag_ops = {};
static struct p4_type_ops path_ops = {};
static struct p4_type_ops msecs_ops = {};
static struct p4_type_ops mac_ops = {
	.validate_p4t = p4t_mac_validate,
	.create_bitops = p4t_u64_bitops,
	.host_read = p4t_u64_hread,
	.host_write = p4t_u64_write,
	.print = p4t_mac_print,
};
static struct p4_type_ops ipv4_ops = {
	.validate_p4t = p4t_ipv4_validate,
	.host_read = p4t_be32_hread,
	.host_write = p4t_be32_write,
	.print = p4t_ipv4_print,
};
static struct p4_type_ops bool_ops = {
	.validate_p4t = p4t_bool_validate,
	.host_read = p4t_bool_hread,
	.host_write = p4t_bool_write,
	.print = p4t_bool_print,
};

static struct p4_type_ops dev_ops = {
	.validate_p4t = p4t_dev_validate,
	.host_read = p4t_u32_hread,
	.host_write = p4t_u32_write,
	.print = p4t_dev_print,
};

int p4t_copy(struct p4_type_mask_shift *dst_mask_shift,
	     struct p4_type_ops *dsto, void *dstv,
	     struct p4_type_mask_shift *src_mask_shift,
	     struct p4_type_ops *srco, void *srcv)
{
	__uint128_t readval;

	memset(&readval, 0, sizeof(__uint128_t));

	if (src_mask_shift) {
		srco->host_read(src_mask_shift, srcv, &readval);
		dsto->host_write(dst_mask_shift, &readval, dstv);
	} else {
		dsto->host_write(dst_mask_shift, srcv, dstv);
	}

	return 0;
}
EXPORT_SYMBOL(p4t_copy);

int p4t_cmp(struct p4_type_mask_shift *dst_mask_shift,
	    struct p4_type_ops *dsto, void *dstv,
	    struct p4_type_mask_shift *src_mask_shift,
	    struct p4_type_ops *srco, void *srcv)
{
	u64 a[2] = {0}, b[2] = {0};

	dsto->host_read(dst_mask_shift, dstv, a);
	srco->host_read(src_mask_shift, srcv, b);

	return memcmp(a, b, sizeof(a));
}
EXPORT_SYMBOL(p4t_cmp);

void p4t_release(struct p4_type_mask_shift *mask_shift)
{
	kfree(mask_shift->mask);
	kfree(mask_shift);
}
EXPORT_SYMBOL(p4t_release);

static void clean_types_idr(void)
{
	unsigned long tmp, typeid;
	struct p4_type *type;

	idr_for_each_entry_ul(&p4_types_idr, type, tmp, typeid) {
		idr_remove(&p4_types_idr, typeid);
		kfree(type);
	}
}

static int register_p4_type(int typeid, size_t bitsz, size_t container_bitsz,
			    const char *t_name, struct p4_type_ops *ops)
{
	struct p4_type *type;
	int err;

	if (typeid > P4T_MAX)
		return -EINVAL;

	if (p4type_find_byid(typeid) || p4type_find_byname(t_name))
		return -EEXIST;

	if (bitsz > P4T_MAX_BITSZ)
		return -E2BIG;

	if (container_bitsz > P4T_MAX_BITSZ)
		return -E2BIG;

	type = kzalloc(sizeof(*type), GFP_ATOMIC);
	if (!type)
		return -ENOMEM;

	err = idr_alloc_u32(&p4_types_idr, type, &typeid, typeid, GFP_ATOMIC);
	if (err < 0)
		return err;

	type->typeid = typeid;
	type->bitsz = bitsz;
	type->container_bitsz = container_bitsz;
	type->ops = ops;
	strscpy(type->name, t_name, P4T_MAX_STR_SZ);

	return 0;
}

static int unregister_p4_type(int typeid)
{
	struct p4_type *type;

	type = idr_remove(&p4_types_idr, typeid);
	if (!type)
		return -ENOENT;

	kfree(type);

	return 0;
}

static inline int register_or_abort(int typeid, size_t bitsz,
				    size_t container_bitsz,
				    const char *t_name,
				    struct p4_type_ops *ops)
{
	if (register_p4_type(typeid, bitsz, container_bitsz, t_name, ops) < 0) {
		pr_warn("Unable to allocate p4 type %s\n", t_name);
		clean_types_idr();
		return -1;
	}

	return 0;
}

int register_p4_types(void)
{
	if (register_or_abort(P4T_U8, 8, 8, "u8", &u8_ops) < 0)
		return -1;
	if (register_or_abort(P4T_U16, 16, 16, "u16", &u16_ops) < 0)
		return -1;
	if (register_or_abort(P4T_U32, 32, 32, "u32", &u32_ops) < 0)
		return -1;
	if (register_or_abort(P4T_U64, 64, 64, "u64", &u64_ops) < 0)
		return -1;
	if (register_or_abort(P4T_U128, 128, 128, "u128", &u128_ops) < 0)
		return -1;

	if (register_or_abort(P4T_S8, 8, 8, "s8", &s8_ops) < 0)
		return -1;
	if (register_or_abort(P4T_BE16, 16, 16, "be16", &be16_ops) < 0)
		return -1;
	if (register_or_abort(P4T_BE32, 32, 32, "be32", &be32_ops) < 0)
		return -1;
	if (register_or_abort(P4T_S16, 16, 16, "s16", &s16_ops) < 0)
		return -1;
	if (register_or_abort(P4T_S32, 32, 32, "s32", &s32_ops) < 0)
		return -1;
	if (register_or_abort(P4T_S64, 64, 64, "s64", &s64_ops) < 0)
		return -1;
	if (register_or_abort(P4T_S128, 128, 128, "s128", &s128_ops) < 0)
		return -1;

	if (register_or_abort(P4T_STRING, P4T_MAX_STR_SZ * 4,
			      P4T_MAX_STR_SZ * 4, "string",
			      &string_ops) < 0)
		return -1;
	if (register_or_abort(P4T_NUL_STRING, P4T_MAX_STR_SZ * 4,
			      P4T_MAX_STR_SZ * 4, "nullstr",
			      &nullstring_ops) < 0)
		return -1;

	if (register_or_abort(P4T_FLAG, 32, 32, "flag", &flag_ops) < 0)
		return -1;
	if (register_or_abort(P4T_PATH, 0, 0, "path", &path_ops) < 0)
		return -1;
	if (register_or_abort(P4T_MSECS, 0, 0, "msecs", &msecs_ops) < 0)
		return -1;
	if (register_or_abort(P4T_MACADDR, 48, 64, "mac", &mac_ops) < 0)
		return -1;
	if (register_or_abort(P4T_IPV4ADDR, 32, 32, "ipv4", &ipv4_ops) < 0)
		return -1;
	if (register_or_abort(P4T_BOOL, 32, 32, "bool", &bool_ops) < 0)
		return -1;
	if (register_or_abort(P4T_DEV, 32, 32, "dev", &dev_ops) < 0)
		return -1;

	return 0;
}

int unregister_p4_types(void)
{
	unregister_p4_type(P4T_U8);
	unregister_p4_type(P4T_U16);
	unregister_p4_type(P4T_U32);
	unregister_p4_type(P4T_U64);
	unregister_p4_type(P4T_U128);

	unregister_p4_type(P4T_S8);
	unregister_p4_type(P4T_BE16);
	unregister_p4_type(P4T_S16);
	unregister_p4_type(P4T_S32);
	unregister_p4_type(P4T_S64);
	unregister_p4_type(P4T_S128);

	unregister_p4_type(P4T_STRING);
	unregister_p4_type(P4T_NUL_STRING);

	unregister_p4_type(P4T_FLAG);
	unregister_p4_type(P4T_PATH);
	unregister_p4_type(P4T_MSECS);
	unregister_p4_type(P4T_MACADDR);
	unregister_p4_type(P4T_IPV4ADDR);
	unregister_p4_type(P4T_BOOL);
	unregister_p4_type(P4T_DEV);

	return 0;
}

bool is_unsigned(int id)
{
	switch (id) {
	case P4T_U8:
	case P4T_U16:
	case P4T_U32:
	case P4T_U64:
	case P4T_U128:
	case P4T_BOOL:
		return true;
	default:
		return false;
	}
}
