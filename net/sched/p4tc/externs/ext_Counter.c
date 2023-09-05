// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/externs/ext_Counter.c Example counter extern implementation
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

#define EXTERN_COUNTER_ID 101
#define EXTERN_COUNTER_TYPE_PKTS 1
#define EXTERN_COUNTER_TYPE_BYTES 2
#define EXTERN_COUNTER_TYPE_PKTSNBYTES 3

#define PKTNBYTES_KEY_PARAM_ID 1
#define PKTNBYTES_PKTS_PARAM_ID 2
#define PKTNBYTES_BYTES_PARAM_ID 3
#define PKTONLY_KEY_PARAM_ID 1
#define PKTONLY_PKTS_PARAM_ID 2
#define BYTEONLY_KEY_PARAM_ID 1
#define BYTEONLY_BYTES_PARAM_ID 2

struct p4tc_extern_count_inst {
	struct p4tc_extern_inst common;
	u8 constr_type;
};

#define to_count_inst(inst) ((struct p4tc_extern_count_inst *)inst)

static int check_byte_param(struct p4tc_extern_param *byte_param,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_type *type;

	if (!byte_param) {
		NL_SET_ERR_MSG(extack, "Packet param must be a specified");
		return -EINVAL;
	}

	type = byte_param->type;
	if (!(type->typeid == P4TC_T_U32 && byte_param->bitsz == 32) &&
	    !(type->typeid == P4TC_T_U64 && byte_param->bitsz == 64)) {
		NL_SET_ERR_MSG(extack, "Byte param must be a bit32 or a bit64");
		return -EINVAL;
	}

	return 0;
}

static int check_pkt_param(struct p4tc_extern_param *pkt_param,
			   struct netlink_ext_ack *extack)
{
	struct p4tc_type *type;

	if (!pkt_param) {
		NL_SET_ERR_MSG(extack, "Packet param must be a specified");
		return -EINVAL;
	}

	type = pkt_param->type;
	if (!(type->typeid == P4TC_T_U32 && pkt_param->bitsz == 32) &&
	    !(type->typeid == P4TC_T_U64 && pkt_param->bitsz == 64)) {
		NL_SET_ERR_MSG(extack,
			       "Packet param must be a bit32 or a bit64");
		return -EINVAL;
	}

	return 0;
}

static int check_params_cnt(struct idr *params_idr,
			    const u32 params_cnt, struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *param;
	unsigned long tmp, id;
	int i = 0;

	idr_for_each_entry_ul(params_idr, param, tmp, id) {
		i++;
	}

	if (params_cnt != i) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Expected %u params received %u params",
				   params_cnt, i);
		return -EINVAL;
	}

	return 0;
}

static int check_key_param(struct p4tc_extern_param *key_param,
			   struct netlink_ext_ack *extack)
{
	if (!key_param || !(key_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY)) {
		NL_SET_ERR_MSG(extack, "First parameter must be key");
		return -EINVAL;
	}

	if (key_param->type->typeid != P4TC_T_U32) {
		NL_SET_ERR_MSG(extack, "First parameter must be of type bit32");
		return -EINVAL;
	}

	return 0;
}

static int check_ext_type_param(struct p4tc_extern_param *ext_type_param,
				struct netlink_ext_ack *extack)
{
	if (!ext_type_param) {
		NL_SET_ERR_MSG(extack,
			       "First constructor parameter must be counter type");
		return -EINVAL;
	}

	if (ext_type_param->type->typeid != P4TC_T_U8 ||
	    ext_type_param->bitsz != 8) {
		NL_SET_ERR_MSG(extack,
			       "Counter type parameter must be of type bit32");
		return -EINVAL;
	}

	return 0;
}

static int
p4tc_extern_counter_validate_pktnbytes(struct p4tc_extern_params *control_params,
				       struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &control_params->params_idr;
	struct p4tc_extern_param *param;
	int err;

	err = check_params_cnt(params_idr, 3, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, PKTNBYTES_KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, PKTNBYTES_PKTS_PARAM_ID);
	err = check_pkt_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, PKTNBYTES_BYTES_PARAM_ID);
	err = check_byte_param(param, extack);
	if (err < 0)
		return err;

	return 0;
}

static int
p4tc_extern_counter_validate_pktonly(struct p4tc_extern_params *control_params,
				     struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &control_params->params_idr;
	struct p4tc_extern_param *param;
	int err;

	err = check_params_cnt(params_idr, 2, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, PKTONLY_KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, PKTONLY_PKTS_PARAM_ID);
	err = check_pkt_param(param, extack);
	if (err < 0)
		return err;

	return 0;
}

static int
p4tc_extern_counter_validate_byteonly(struct p4tc_extern_params *control_params,
				      struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &control_params->params_idr;
	struct p4tc_extern_param *param;
	int err;

	err = check_params_cnt(params_idr, 2, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, BYTEONLY_KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_param_find_byid(params_idr, BYTEONLY_BYTES_PARAM_ID);
	err = check_byte_param(param, extack);
	if (err < 0)
		return err;

	return 0;
}

/* Skip prepended ext_ from counter kind name */
#define skip_prepended_ext(ext_kind) (&((ext_kind)[4]))

static struct p4tc_extern_ops ext_Counter_ops;

static int
p4tc_extern_count_constr(struct p4tc_extern_inst **common,
			 struct p4tc_extern_params *control_params,
			 struct p4tc_extern_params *constr_params,
			 u32 max_num_elems, bool tbl_bindable,
			 struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *constr_type_param;
	struct idr *constr_params_idr = &constr_params->params_idr;
	struct p4tc_extern_params *new_params, *new_constr_params;
	struct p4tc_extern_count_inst *count_inst;
	u8 *constr_type;
	int err = 0;

	constr_type_param = p4tc_ext_param_find_byid(constr_params_idr, 1);
	if (check_ext_type_param(constr_type_param, extack) < 0)
		return -EINVAL;

	constr_type = constr_type_param->value;
	switch (*constr_type) {
	case EXTERN_COUNTER_TYPE_PKTSNBYTES:
		err = p4tc_extern_counter_validate_pktnbytes(control_params,
							     extack);
		break;
	case EXTERN_COUNTER_TYPE_BYTES:
		err = p4tc_extern_counter_validate_byteonly(control_params,
							    extack);
		break;
	case EXTERN_COUNTER_TYPE_PKTS:
		err = p4tc_extern_counter_validate_pktonly(control_params,
							   extack);
		break;
	default:
		NL_SET_ERR_MSG(extack,
			       "Only allowed types are pktsnbytes(1), bytes(2), pkts(3)");
		return -EINVAL;
	}

	if (err < 0)
		return err;

	*common = p4tc_ext_inst_alloc(&ext_Counter_ops,
				      max_num_elems, tbl_bindable,
				      skip_prepended_ext(ext_Counter_ops.kind));
	if (IS_ERR(*common))
		return PTR_ERR(*common);
	count_inst = to_count_inst(*common);

	new_params = p4tc_ext_params_copy(control_params);
	if (IS_ERR(new_params)) {
		err = PTR_ERR(new_params);
		goto free_common;
	}
	count_inst->common.params = new_params;
	count_inst->constr_type = *constr_type;

	new_constr_params = p4tc_ext_params_copy(constr_params);
	if (IS_ERR(new_constr_params)) {
		err = PTR_ERR(new_constr_params);
		goto free_params;
	}
	count_inst->common.constr_params = new_constr_params;

	err = p4tc_extern_inst_init_elems(&count_inst->common, max_num_elems);
	if (err < 0)
		goto free_constr_params;

	return 0;

free_constr_params:
	p4tc_ext_params_free(new_constr_params, true);
free_params:
	p4tc_ext_params_free(new_params, true);
free_common:
	kfree(*common);
	return err;
}

static void
p4tc_extern_count_deconstr(struct p4tc_extern_inst *common)
{
	p4tc_ext_inst_purge(common);
	if (common->params)
		p4tc_ext_params_free(common->params, true);
	if (common->constr_params)
		p4tc_ext_params_free(common->constr_params, true);
	kfree(common);
}

static void p4tc_skb_extern_count_inc(struct p4tc_extern_params *params,
				      const u32 param_id, const u64 cnts_inc)
{
	struct p4tc_extern_param *param = NULL;

	param = idr_find(&params->params_idr, param_id);
	if (param) {
		write_lock_bh(&params->params_lock);
		if (param->type->typeid == P4TC_T_U32) {
			u32 *cnt = param->value;

			(*cnt) += cnts_inc;
		} else {
			u64 *cnt = param->value;

			(*cnt) += cnts_inc;
		}
		write_unlock_bh(&params->params_lock);
	}
}

static int
p4tc_skb_extern_count_pkt_and_byte(struct p4tc_extern_common *common,
				   struct p4tc_table_counters *counters)
{
	p4tc_skb_extern_count_inc(common->params, 2, counters->pkts);
	p4tc_skb_extern_count_inc(common->params, 3, counters->bytes);

	return 0;
}

static int
p4tc_skb_extern_count_pkt(struct p4tc_extern_common *common,
			  struct p4tc_table_counters *counters)
{
	p4tc_skb_extern_count_inc(common->params, 2, counters->pkts);

	return 0;
}

static int
p4tc_skb_extern_count_byte(struct p4tc_extern_common *common,
			   struct p4tc_table_counters *counters)
{
	p4tc_skb_extern_count_inc(common->params, 2, counters->bytes);

	return 0;
}

static int p4tc_extern_count_exec(struct p4tc_extern_common *common,
				  void *priv)
{
	struct p4tc_extern_count_inst *counter_inst;
	struct p4tc_table_counters *counters = priv;
	int ret;

	counter_inst = to_count_inst(common->inst);
	switch (counter_inst->constr_type) {
	case EXTERN_COUNTER_TYPE_PKTSNBYTES:
		ret = p4tc_skb_extern_count_pkt_and_byte(common,
							 counters);
		break;
	case EXTERN_COUNTER_TYPE_BYTES:
		ret = p4tc_skb_extern_count_byte(common, counters);
		break;
	case EXTERN_COUNTER_TYPE_PKTS:
		ret = p4tc_skb_extern_count_pkt(common, counters);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in vmlinux BTF");

__bpf_kfunc int
bpf_p4tc_extern_indirect_count_pktsnbytes(struct __sk_buff *skb_ctx,
					  struct p4tc_ext_bpf_params *params,
					  struct p4tc_ext_bpf_res *res)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct p4tc_table_counters counters = { 0 };
	struct p4tc_extern_count_inst *counter_inst;
	struct p4tc_extern_common *common;
	struct p4tc_pipeline *pipeline;
	int ret = 0;

	common = p4tc_ext_common_elem_get(skb, &pipeline, params);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counter_inst = to_count_inst(common->inst);
	if (counter_inst->constr_type != EXTERN_COUNTER_TYPE_PKTSNBYTES)
		return -EINVAL;

	counters.pkts = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	counters.bytes = qdisc_pkt_len(skb);

	ret = p4tc_skb_extern_count_pkt_and_byte(common, &counters);

	p4tc_ext_common_elem_put(pipeline, common);

	return ret;
}

__bpf_kfunc int
bpf_p4tc_extern_indirect_count_bytesonly(struct __sk_buff *skb_ctx,
					 struct p4tc_ext_bpf_params *params,
					 struct p4tc_ext_bpf_res *res)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct p4tc_table_counters counters = { 0 };
	struct p4tc_extern_count_inst *counter_inst;
	struct p4tc_extern_common *common;
	struct p4tc_pipeline *pipeline;
	int ret = 0;

	common = p4tc_ext_common_elem_get(skb, &pipeline, params);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counter_inst = to_count_inst(common->inst);
	if (counter_inst->constr_type != EXTERN_COUNTER_TYPE_BYTES)
		return -EINVAL;

	counters.bytes = qdisc_pkt_len(skb);

	ret = p4tc_skb_extern_count_byte(common, &counters);

	p4tc_ext_common_elem_put(pipeline, common);

	return ret;
}

__bpf_kfunc int
bpf_p4tc_extern_indirect_count_pktsonly(struct __sk_buff *skb_ctx,
					struct p4tc_ext_bpf_params *params,
					struct p4tc_ext_bpf_res *res)
{
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct p4tc_table_counters counters = { 0 };
	struct p4tc_extern_count_inst *counter_inst;
	struct p4tc_extern_common *common;
	struct p4tc_pipeline *pipeline;
	int ret = 0;

	common = p4tc_ext_common_elem_get(skb, &pipeline, params);

	counter_inst = to_count_inst(common->inst);
	if (counter_inst->constr_type != EXTERN_COUNTER_TYPE_PKTS)
		return -EINVAL;

	counters.pkts = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;

	ret = p4tc_skb_extern_count_pkt(common, &counters);

	p4tc_ext_common_elem_put(pipeline, common);

	return ret;
}

__diag_pop();

BTF_KFUNCS_START(p4tc_kfunc_ext_counters_set)
BTF_ID_FLAGS(func, bpf_p4tc_extern_indirect_count_pktsnbytes);
BTF_ID_FLAGS(func, bpf_p4tc_extern_indirect_count_pktsonly);
BTF_ID_FLAGS(func, bpf_p4tc_extern_indirect_count_bytesonly);
BTF_KFUNCS_END(p4tc_kfunc_ext_counters_set)

static const struct btf_kfunc_id_set p4tc_kfunc_ext_counters_set_skb = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_ext_counters_set,
};

static struct p4tc_extern_ops ext_Counter_ops = {
	.kind		= "ext_Counter",
	.size           = sizeof(struct p4tc_extern_count_inst),
	.id		= EXTERN_COUNTER_ID,
	.construct      = p4tc_extern_count_constr,
	.deconstruct    = p4tc_extern_count_deconstr,
	.exec		= p4tc_extern_count_exec,
	.owner		= THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("Counter extern");
MODULE_LICENSE("GPL");

static int __init counter_init_module(void)
{
	int ret = p4tc_register_extern(&ext_Counter_ops);

	if (ret < 0) {
		pr_info("Failed to register Counter TC extern");
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_counters_set_skb);
	if (ret < 0) {
		pr_info("Failed to register Counter TC kfuncs");
		goto unregister_counters;
	}

	return ret;

unregister_counters:
	p4tc_unregister_extern(&ext_Counter_ops);
	return ret;
}

static void __exit counter_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_Counter_ops);
}

module_init(counter_init_module);
module_exit(counter_cleanup_module);
