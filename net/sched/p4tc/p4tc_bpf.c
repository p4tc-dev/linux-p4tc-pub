// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/btf_ids.h>
#include <linux/net_namespace.h>
#include <net/p4tc.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/filter.h>

BTF_ID_LIST(btf_p4tc_ids)
BTF_ID(struct, p4tc_parser_buffer_act_bpf)

struct p4tc_parser_buffer_act_bpf *bpf_p4tc_get_parser_buffer(void)
{
	struct p4tc_percpu_scratchpad *pad;
	struct p4tc_parser_buffer_act_bpf *parser_buffer;

	pad = this_cpu_ptr(&p4tc_percpu_scratchpad);

	parser_buffer = (struct p4tc_parser_buffer_act_bpf *)&pad->hdrs;

	return parser_buffer;
}

int is_p4tc_kfunc(const struct bpf_reg_state *reg)
{
	const struct btf_type *p4tc_parser_type, *t;

	p4tc_parser_type = btf_type_by_id(reg->btf, btf_p4tc_ids[0]);

	t = btf_type_by_id(reg->btf, reg->btf_id);

	return p4tc_parser_type == t;
}

void bpf_p4tc_set_cookie(u32 cookie)
{
	struct p4tc_percpu_scratchpad *pad;

	pad = this_cpu_ptr(&p4tc_percpu_scratchpad);
	pad->prog_cookie = cookie;
}

BTF_SET8_START(p4tc_tbl_kfunc_set)
BTF_ID_FLAGS(func, bpf_p4tc_get_parser_buffer, 0);
BTF_ID_FLAGS(func, bpf_p4tc_set_cookie, 0);
BTF_SET8_END(p4tc_tbl_kfunc_set)

static const struct btf_kfunc_id_set p4tc_table_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &p4tc_tbl_kfunc_set,
};

int register_p4tc_tbl_bpf(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_table_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					       &p4tc_table_kfunc_set);

	return ret;
}
