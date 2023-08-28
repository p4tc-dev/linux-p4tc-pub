// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/ext_csum.c	P4TC Checksum e extern
 *
 * Copyright (c) 2023-2024, Mojatatu Networks
 * Copyright (c) 2023-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/tc_wrapper.h>
#include <net/p4tc.h>
#include <net/p4tc_ext_api.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <linux/filter.h>
#include <linux/list.h>
#include <linux/idr.h>
#include <linux/crc32.h>
#include <linux/crc16.h>
#include <net/p4tc_ext/ext_csum.h>

static __wsum p4tc_ext_hash_16bit_complement(const void *data, int len, u16 prev)
{
	return csum_partial(data, len, prev);
}

static u16 p4tc_ext_hash_16bit_complement_get(u16 prev)
{
	return csum_fold(prev);
}

static u16
p4tc_ext_hash_crc16(const void *data, int len, u16 prev)
{
	return crc16(prev, data, len);
}

static u32
p4tc_ext_hash_crc32(const void * data, int len, u32 prev)
{
	return crc32_be(prev, data, len);
}

static void p4tc_ext_csum_params_clear(struct p4tc_ext_csum_params *params)
{
	params->csum = 0;
}

/* Sub will be unoptimised
 * Will only be used in specific scenarios
 */
static u16 ones_complement_sum(u16 x, u16 y) {
	u32 ret = (u32 )x + (u32 )y;

	if ((ret & 0xFFFF0000)) {
		ret = ret + 1;
	}
	return (u16)(ret & 0xFFFF);
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in vmlinux BTF");

__bpf_kfunc __wsum
bpf_p4tc_ext_csum_16bit_complement_add(struct p4tc_ext_csum_params *params,
				       const void *data, const u32 data__sz)
{
	params->csum = p4tc_ext_hash_16bit_complement(data, data__sz,
						      params->csum);
	return params->csum;
}

__bpf_kfunc int
bpf_p4tc_ext_csum_16bit_complement_sub(struct p4tc_ext_csum_params *params,
				       const void *data, const u32 data__sz)
{
	const u16 *data_u16 = data;
	int i;

	if (data__sz < sizeof(u16) || (data__sz % sizeof(u16)))
		return -EINVAL;

	for (i = 0; i < data__sz / sizeof(u16); i++) {
		u16 diff = ~data_u16[i];

		params->csum = ones_complement_sum(params->csum, diff);
	}

	return params->csum;
}

__bpf_kfunc u16
bpf_p4tc_ext_csum_16bit_complement_get(struct p4tc_ext_csum_params *params)
{
	return p4tc_ext_hash_16bit_complement_get(params->csum);
}

__bpf_kfunc void
bpf_p4tc_ext_csum_16bit_complement_clear(struct p4tc_ext_csum_params *params)
{
	p4tc_ext_csum_params_clear(params);
}

__bpf_kfunc void
bpf_p4tc_ext_csum_16bit_complement_set_state(struct p4tc_ext_csum_params *params,
					     u16 csum)
{
	params->csum = csum;
}

__bpf_kfunc u16
bpf_p4tc_ext_csum_crc16_add(struct p4tc_ext_csum_params *params,
			    const void *data, const u32 data__sz)
{
	u16 csum;

	csum = p4tc_ext_hash_crc16(data, data__sz, params->csum);

	params->csum = csum;

	return csum;
}

__bpf_kfunc u16
bpf_p4tc_ext_csum_crc16_get(struct p4tc_ext_csum_params *params)
{
	return (u16) params->csum;
}

__bpf_kfunc void
bpf_p4tc_ext_csum_crc16_clear(struct p4tc_ext_csum_params *params)
{
	p4tc_ext_csum_params_clear(params);
}

__bpf_kfunc u32
bpf_p4tc_ext_csum_crc32_add(struct p4tc_ext_csum_params *params,
			    const void *data, const u32 data__sz)
{
	params->csum = p4tc_ext_hash_crc32(data, data__sz, params->csum);

	return params->csum;
}

__bpf_kfunc u32
bpf_p4tc_ext_csum_crc32_get(struct p4tc_ext_csum_params *params)
{
	return params->csum;
}

__bpf_kfunc void
bpf_p4tc_ext_csum_crc32_clear(struct p4tc_ext_csum_params *params)
{
	p4tc_ext_csum_params_clear(params);
}

__bpf_kfunc u16
bpf_p4tc_ext_hash_16bit_complement(const void *data, const u32 data__sz,
				   u16 seed)
{
	u16 hash = p4tc_ext_hash_16bit_complement(data, data__sz, seed);

	return p4tc_ext_hash_16bit_complement_get(hash);
}

__bpf_kfunc u16
bpf_p4tc_ext_hash_crc16(const void * data, int len, u16 seed)
{
	return p4tc_ext_hash_crc16(data, len, seed);
}

__bpf_kfunc u32
bpf_p4tc_ext_hash_crc32(const void * data, const u32 data__sz, u32 seed)
{
	return p4tc_ext_hash_crc32(data, data__sz, seed);
}

__diag_pop();

#define EXTERN_HASH 1240

BTF_KFUNCS_START(p4tc_kfunc_ext_csum_set)
BTF_ID_FLAGS(func, bpf_p4tc_ext_hash_16bit_complement);
BTF_ID_FLAGS(func, bpf_p4tc_ext_hash_crc16);
BTF_ID_FLAGS(func, bpf_p4tc_ext_hash_crc32);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_16bit_complement_add);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_16bit_complement_sub);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_16bit_complement_get);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_16bit_complement_clear);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_16bit_complement_set_state);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc16_add);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc16_get);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc16_clear);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc32_add);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc32_get);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc32_clear);
BTF_KFUNCS_END(p4tc_kfunc_ext_csum_set)

static const struct btf_kfunc_id_set p4tc_kfunc_ext_set_skb = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_ext_csum_set,
};

static struct p4tc_extern_ops ext_csum_ops = {
	.kind		= "ext_csum",
	.id		= EXTERN_HASH,
	.owner		= THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("P4TC Checksum extern");
MODULE_LICENSE("GPL");

static int __init csum_init_module(void)
{
	int ret = p4tc_register_extern(&ext_csum_ops);
	if (!ret)
		pr_info("Checksum TC extern Loaded\n");

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_set_skb);
	if (ret < 0) {
		p4tc_unregister_extern(&ext_csum_ops);
		pr_info("Failed to register csum TC kfuncs");
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&p4tc_kfunc_ext_set_skb);
	if (ret < 0) {
		pr_info("Failed to register csum XDP kfuncs");
		p4tc_unregister_extern(&ext_csum_ops);
	}

	return ret;
}

static void __exit hash_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_csum_ops);
}

module_init(csum_init_module);
module_exit(hash_cleanup_module);
