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
#include <net/netlink.h>
#include <net/p4tc.h>
#include <net/p4tc_ext_api.h>
#include <net/sock.h>
#include <linux/idr.h>
#include <net/p4tc_ext/ext_counter.h>

#define EXTERN_COUNTER_TYPE_PKTS 0
#define EXTERN_COUNTER_TYPE_BYTES 1
#define EXTERN_COUNTER_TYPE_PKTSNBYTES 2

#define PKTNBYTES_KEY_PARAM_ID 1
#define PKTNBYTES_PKTS_PARAM_ID 2
#define PKTNBYTES_BYTES_PARAM_ID 3
#define PKTONLY_KEY_PARAM_ID 1
#define PKTONLY_PKTS_PARAM_ID 2
#define BYTEONLY_KEY_PARAM_ID 1
#define BYTEONLY_BYTES_PARAM_ID 2

struct p4tc_extern_count_elem {
	struct p4tc_extern_common common;
	spinlock_t count_lock;
};

struct p4tc_extern_count_inst {
	struct p4tc_extern_inst common;
	u8 constr_type;
};

#define to_count_inst(inst) ((struct p4tc_extern_count_inst *)inst)
#define to_count_elem(elem) ((struct p4tc_extern_count_elem *)elem)

static int check_byte_param(struct p4tc_extern_tmpl_param *byte_param,
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

static int check_pkt_param(struct p4tc_extern_tmpl_param *pkt_param,
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

static int check_key_param(struct p4tc_extern_tmpl_param *key_param,
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

static int check_ext_type_param(struct p4tc_extern_tmpl_param *ext_type_param,
				struct netlink_ext_ack *extack)
{
	if (!ext_type_param) {
		NL_SET_ERR_MSG(extack,
			       "First constructor parameter must be counter type");
		return -EINVAL;
	}

	if (ext_type_param->type->typeid != P4TC_T_U32 ||
	    ext_type_param->bitsz != 32) {
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
	struct p4tc_extern_tmpl_param *param;
	int err;

	err = check_params_cnt(params_idr, 3, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr,
					      PKTNBYTES_KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr,
					      PKTNBYTES_PKTS_PARAM_ID);
	err = check_pkt_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr,
					      PKTNBYTES_BYTES_PARAM_ID);
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
	struct p4tc_extern_tmpl_param *param;
	int err;

	err = check_params_cnt(params_idr, 2, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, PKTONLY_KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr,
					      PKTONLY_PKTS_PARAM_ID);
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
	struct p4tc_extern_tmpl_param *param;
	int err;

	err = check_params_cnt(params_idr, 2, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr,
					      BYTEONLY_KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr,
					      BYTEONLY_BYTES_PARAM_ID);
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
			 const struct p4tc_extern_ops *ops,
			 struct p4tc_extern_params *control_params,
			 struct p4tc_extern_params *constr_params,
			 u32 max_num_elems, bool tbl_bindable,
			 struct netlink_ext_ack *extack)
{
	struct idr *constr_params_idr = &constr_params->params_idr;
	struct p4tc_extern_params *new_params, *new_constr_params;
	struct p4tc_extern_tmpl_param *constr_type_param;
	struct p4tc_extern_count_inst *count_inst;
	u8 *constr_type;
	int err = 0;

	constr_type_param = p4tc_ext_tmpl_param_find_byid(constr_params_idr, 1);
	if (check_ext_type_param(constr_type_param, extack) < 0)
		return -EINVAL;

	constr_type = constr_type_param->default_value;
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
			       "Only allowed types are pkts(0), bytes(1), pktsnbytes(2)");
		return -EINVAL;
	}

	if (err < 0)
		return err;

	*common = p4tc_ext_inst_alloc(ops, max_num_elems, tbl_bindable,
				      (char *)skip_prepended_ext(ops->kind));
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
	p4tc_ext_tmpl_params_free(new_constr_params);
free_params:
	p4tc_ext_tmpl_params_free(new_params);
free_common:
	kfree(*common);
	return err;
}

static void
p4tc_extern_count_deconstr(struct p4tc_extern_inst *common)
{
	p4tc_ext_inst_purge(common);
	if (common->params)
		p4tc_ext_tmpl_params_free(common->params);
	if (common->constr_params)
		p4tc_ext_tmpl_params_free(common->constr_params);
	kfree(common);
}

static int
p4tc_extern_count_init(struct p4tc_extern_common *e,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_extern_count_elem *elem = to_count_elem(e);

	spin_lock_init(&elem->count_lock);

	return 0;
}

static void p4tc_skb_extern_count_inc(struct p4tc_extern_params *params,
				      const u32 param_id, const u64 cnts_inc)
{
	struct p4tc_extern_param *param = NULL;

	param = idr_find(&params->params_idr, param_id);
	if (param) {
		spin_lock_bh(&params->params_lock);
		if (param->tmpl_param->type->typeid == P4TC_T_U32) {
			u32 *cnt = param->value;

			(*cnt) += cnts_inc;
		} else {
			u64 *cnt = param->value;

			(*cnt) += cnts_inc;
		}
		spin_unlock_bh(&params->params_lock);
	}
}

static void
p4tc_extern_count_pkt_and_byte(struct p4tc_extern_common *common,
				   struct p4tc_table_counters *counters)
{
	p4tc_skb_extern_count_inc(common->params, 2, counters->pkts);
	p4tc_skb_extern_count_inc(common->params, 3, counters->bytes);
}

static void
p4tc_skb_extern_count_pkt(struct p4tc_extern_common *common,
			  struct p4tc_table_counters *counters)
{
	p4tc_skb_extern_count_inc(common->params, 2, counters->pkts);
}

static void
p4tc_skb_extern_count_byte(struct p4tc_extern_common *common,
			   struct p4tc_table_counters *counters)
{
	p4tc_skb_extern_count_inc(common->params, 2, counters->bytes);
}

static struct p4tc_extern_common *
p4tc_extern_indir_count_get(struct net *net,
			    struct p4tc_pipeline **pipeline,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz, void *key,
			    const u32 key__sz)
{
	if (!params)
		return ERR_PTR(-EINVAL);

	if (params__sz != P4TC_EXT_BPF_PARAMS_SZ)
		return ERR_PTR(-EINVAL);

	return __p4tc_ext_common_elem_get(net, pipeline, params);
}

static struct p4tc_extern_common *
p4tc_extern_entry_get(struct net *net, struct p4tc_pipeline **pipeline,
		      struct p4tc_ext_bpf_params *params,
		      const u32 params__sz, void *key, const u32 key__sz)
{
	struct p4tc_table_entry_key *entry_key = key;
	struct p4tc_table_entry_value *value;
	struct p4tc_table_entry *entry;
	struct p4tc_table *table;
	u32 pipeid, tblid;
	int ret;

	if (!params || !key)
		return ERR_PTR(-EINVAL);

	if (params__sz != P4TC_EXT_BPF_PARAMS_SZ)
		return ERR_PTR(-EINVAL);

	pipeid = params->pipe_id;
	tblid = params->tbl_id;

	if (key__sz != P4TC_ENTRY_KEY_SZ_BYTES(entry_key->keysz))
		return ERR_PTR(-EINVAL);

	*pipeline = p4tc_pipeline_find_get_sealed(net, NULL, pipeid, NULL);
	if (IS_ERR(*pipeline))
		return (struct p4tc_extern_common *)*pipeline;

	table = p4tc_table_find_byid(*pipeline, tblid);
	if (!table) {
		ret = -ENOENT;
		goto pipeline_put;
	}

	entry = p4tc_table_entry_lookup_direct(table, entry_key);
	if (!entry) {
		ret = -ENOENT;
		goto pipeline_put;
	}

	value = p4tc_table_entry_value(entry);
	if (!value->counter) {
		 ret = ENOENT;
		 goto pipeline_put;
	}

	return value->counter;

pipeline_put:
	p4tc_pipeline_put(*pipeline);
	return ERR_PTR(ret);
}

static struct p4tc_extern_common *
p4tc_extern_count_common_get(struct net *net,
			     struct p4tc_pipeline **pipeline,
			     struct p4tc_ext_bpf_params *params,
			     const u32 params__sz, void *key,
			     const u32 key__sz)
{
	struct p4tc_extern_common *common;

	if (params->flags & P4TC_EXT_CNT_DIRECT)
		common = p4tc_extern_entry_get(net, pipeline, params,
					       params__sz, key,
					       key__sz);
	else if (params->flags & P4TC_EXT_CNT_INDIRECT)
		common = p4tc_extern_indir_count_get(net, pipeline,
						     params, params__sz,
						     key, key__sz);
	else
		return ERR_PTR(-EINVAL);

	return common;
}

static struct p4tc_extern_common *
__p4tc_extern_count_common(struct net *net,
			   struct p4tc_ext_bpf_params *params,
			   struct p4tc_pipeline **pipeline,
			   const u32 params__sz, void *key,
			   const u32 key__sz)
{
	struct p4tc_extern_common *common;

	common = p4tc_extern_count_common_get(net, pipeline, params,
					      params__sz, key, key__sz);
	if (IS_ERR(common))
		return common;

	return common;
}

static struct p4tc_extern_common *
p4tc_extern_count_common(struct net *net,
			 struct p4tc_ext_bpf_params *params,
			 struct p4tc_pipeline **pipeline,
			 const u32 params__sz, void *key,
			 const u32 key__sz, const u32 constr_type)
{
	struct p4tc_extern_count_inst *count_inst;
	struct p4tc_extern_common *common;
	int ret = 0;

	common = __p4tc_extern_count_common(net, params, pipeline,
					    params__sz, key, key__sz);
	if (IS_ERR(common))
		return common;

	count_inst = to_count_inst(common->inst);
	if (count_inst->constr_type != constr_type) {
		ret = -EINVAL;
		goto common_put;
	}

	if (!p4tc_data_update_ok(common->p4tc_ext_permissions)) {
		ret = -EPERM;
		goto common_put;
	}

	return common;

common_put:
	p4tc_ext_common_elem_put(*pipeline, common);
	return ERR_PTR(ret);
}

static int p4tc_extern_count_send(struct p4tc_pipeline *pipeline,
				  struct p4tc_extern_common *common)
{
	struct p4tc_ext_nlmsg_attrs nlmsg_attrs = { 0 };

	nlmsg_attrs.pipeid = pipeline->common.p_id;
	nlmsg_attrs.cmd = RTM_P4TC_UPDATE;

	return p4tc_extern_send(pipeline, common, &nlmsg_attrs,
				0, false, NULL);
}

__bpf_kfunc_start_defs();

__bpf_kfunc int
bpf_p4tc_extern_count_pktsnbytes(struct sk_buff *skb,
				 struct p4tc_ext_bpf_params *params,
				 const u32 params__sz, void *key,
				 const u32 key__sz)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	struct p4tc_table_counters counters = { 0 };
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	struct p4tc_extern_count_elem *e;
	int ret = 0;

	common = p4tc_extern_count_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  EXTERN_COUNTER_TYPE_PKTSNBYTES);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counters.pkts = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	counters.bytes = qdisc_pkt_len(skb);

	e = to_count_elem(common);
	spin_lock_bh(&e->count_lock);
	p4tc_extern_count_pkt_and_byte(common, &counters);
	ret = p4tc_extern_count_send(pipeline, common);
	spin_unlock_bh(&e->count_lock);

	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc int
bpf_p4tc_extern_count_bytes(struct sk_buff *skb,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz, void *key,
			    const u32 key__sz)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	struct p4tc_table_counters counters = { 0 };
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	struct p4tc_extern_count_elem *e;
	int ret;

	common = p4tc_extern_count_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  EXTERN_COUNTER_TYPE_BYTES);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counters.pkts = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	counters.bytes = qdisc_pkt_len(skb);

	e = to_count_elem(common);
	spin_lock_bh(&e->count_lock);
	p4tc_skb_extern_count_byte(common, &counters);
	ret = p4tc_extern_count_send(pipeline, common);
	spin_unlock_bh(&e->count_lock);

	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc int
bpf_p4tc_extern_count_pkts(struct sk_buff *skb,
			   struct p4tc_ext_bpf_params *params,
			   const u32 params__sz, void *key,
			   const u32 key__sz)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	struct p4tc_table_counters counters = { 0 };
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	struct p4tc_extern_count_elem *e;
	int ret;

	common = p4tc_extern_count_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  EXTERN_COUNTER_TYPE_PKTS);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counters.pkts = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;

	e = to_count_elem(common);
	spin_lock_bh(&e->count_lock);
	p4tc_skb_extern_count_pkt(common, &counters);
	ret = p4tc_extern_count_send(pipeline, common);
	spin_unlock_bh(&e->count_lock);

	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc int
xdp_p4tc_extern_count_pktsnbytes(struct xdp_buff *xdp,
				 struct p4tc_ext_bpf_params *params,
				 const u32 params__sz, void *key,
				 const u32 key__sz)
{
	struct p4tc_table_counters counters = { 0 };
	struct net *net = dev_net(xdp->rxq->dev);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	struct p4tc_extern_count_elem *e;
	int ret = 0;

	common = p4tc_extern_count_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  EXTERN_COUNTER_TYPE_PKTSNBYTES);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counters.pkts = 1;
	counters.bytes = xdp_get_buff_len(xdp);

	e = to_count_elem(common);
	spin_lock_bh(&e->count_lock);
	p4tc_extern_count_pkt_and_byte(common, &counters);
	ret = p4tc_extern_count_send(pipeline, common);
	spin_unlock_bh(&e->count_lock);

	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc int
xdp_p4tc_extern_count_bytes(struct xdp_buff *xdp,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz, void *key,
			    const u32 key__sz)
{
	struct p4tc_table_counters counters = { 0 };
	struct net *net = dev_net(xdp->rxq->dev);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	struct p4tc_extern_count_elem *e;
	int ret;

	common = p4tc_extern_count_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  EXTERN_COUNTER_TYPE_BYTES);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counters.bytes = xdp_get_buff_len(xdp);

	e = to_count_elem(common);
	spin_lock_bh(&e->count_lock);
	p4tc_skb_extern_count_byte(common, &counters);
	ret = p4tc_extern_count_send(pipeline, common);
	spin_unlock_bh(&e->count_lock);

	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc int
xdp_p4tc_extern_count_pkts(struct xdp_buff *xdp,
			   struct p4tc_ext_bpf_params *params,
			   const u32 params__sz, void *key,
			   const u32 key__sz)
{
	struct p4tc_table_counters counters = { 0 };
	struct net *net = dev_net(xdp->rxq->dev);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	struct p4tc_extern_count_elem *e;
	int ret;

	common = p4tc_extern_count_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  EXTERN_COUNTER_TYPE_PKTS);
	if (IS_ERR(common))
		return PTR_ERR(common);

	counters.pkts = 1;

	e = to_count_elem(common);
	spin_lock_bh(&e->count_lock);
	p4tc_skb_extern_count_pkt(common, &counters);
	ret = p4tc_extern_count_send(pipeline, common);
	spin_unlock_bh(&e->count_lock);

	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(p4tc_kfunc_ext_cnt_set)
BTF_ID_FLAGS(func, bpf_p4tc_extern_count_pktsnbytes);
BTF_ID_FLAGS(func, bpf_p4tc_extern_count_pkts);
BTF_ID_FLAGS(func, bpf_p4tc_extern_count_bytes);
BTF_ID_FLAGS(func, xdp_p4tc_extern_count_pktsnbytes);
BTF_ID_FLAGS(func, xdp_p4tc_extern_count_pkts);
BTF_ID_FLAGS(func, xdp_p4tc_extern_count_bytes);
BTF_KFUNCS_END(p4tc_kfunc_ext_cnt_set)

static const struct btf_kfunc_id_set p4tc_kfunc_ext_counters_set = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_ext_cnt_set,
};

static struct p4tc_extern_ops ext_Counter_ops = {
	.kind = "ext_Counter",
	.size = sizeof(struct p4tc_extern_count_inst),
	.id = P4TC_EXTERN_COUNTER_ID,
	.construct = p4tc_extern_count_constr,
	.deconstruct = p4tc_extern_count_deconstr,
	.init = p4tc_extern_count_init,
	.elem_size = sizeof(struct p4tc_extern_count_elem),
	.owner = THIS_MODULE,
};

static struct p4tc_extern_ops ext_DirectCounter_ops = {
	.kind = "ext_DirectCounter",
	.size = sizeof(struct p4tc_extern_count_inst),
	.id = P4TC_EXTERN_DIRECT_COUNTER_ID,
	.construct = p4tc_extern_count_constr,
	.deconstruct = p4tc_extern_count_deconstr,
	.init = p4tc_extern_count_init,
	.elem_size = sizeof(struct p4tc_extern_count_elem),
	.owner = THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("(Direct)Counter extern");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ext_DirectCounter");

static int __init counter_init_module(void)
{
	int ret = p4tc_register_extern(&ext_Counter_ops);

	if (ret < 0) {
		pr_info("Failed to register Counter TC extern");
		return ret;
	}

	ret = p4tc_register_extern(&ext_DirectCounter_ops);
	if (ret < 0) {
		pr_info("Failed to register DirectCounter TC extern");
		goto unregister_counters;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_counters_set);
	if (ret < 0) {
		pr_info("Failed to register Counter TC kfuncs");
		goto unregister_direct_counters;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&p4tc_kfunc_ext_counters_set);
	if (ret < 0) {
		pr_info("Failed to register Counter XDP kfuncs");
		goto unregister_direct_counters;
	}
	return ret;

unregister_direct_counters:
	p4tc_unregister_extern(&ext_DirectCounter_ops);

unregister_counters:
	p4tc_unregister_extern(&ext_Counter_ops);
	return ret;
}

static void __exit counter_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_Counter_ops);
	p4tc_unregister_extern(&ext_DirectCounter_ops);
}

module_init(counter_init_module);
module_exit(counter_cleanup_module);
