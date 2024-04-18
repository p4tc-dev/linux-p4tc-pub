// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/externs/ext_digest.c Example digest extern implementation
 *
 * Copyright (c) 2024, Mojatatu Networks
 * Copyright (c) 2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <net/p4tc.h>
#include <net/p4tc_ext_api.h>
#include <linux/idr.h>

#define SKB_POOL_SIZE 0x80
#define SKB_MAX_SIZE 0x80

#define EXTERN_DIGEST_ID 0x05000000
#define EXTERN_DIGEST_MAX_SIZE 0x80

struct p4tc_extern_digest_elem {
	struct p4tc_extern_common common;
	spinlock_t digest_lock;
};

struct p4tc_extern_digest_inst {
	struct p4tc_extern_inst common;
	u32 payload_size;
};

#define to_digest_inst(inst) ((struct p4tc_extern_digest_inst *)inst)
#define to_digest_elem(elem) ((struct p4tc_extern_digest_elem *)elem)

static struct p4tc_extern_ops ext_digest_ops;

static struct sk_buff_head skb_pool;

static void alloc_skb_pull(void)
{
	skb_queue_head_init(&skb_pool);

	spin_lock_bh(&skb_pool.lock);
	while (skb_pool.qlen < SKB_POOL_SIZE) {
		struct sk_buff *skb = alloc_skb(NLMSG_GOODSIZE, GFP_ATOMIC);

		if (!skb)
			break;

		__skb_queue_tail(&skb_pool, skb);
	}
	spin_unlock_bh(&skb_pool.lock);
}

static void free_skb_pull(void)
{
	spin_lock_bh(&skb_pool.lock);
	while (skb_pool.qlen) {
		struct sk_buff *skb = __skb_dequeue(&skb_pool);

		consume_skb(skb);
	}
	spin_unlock_bh(&skb_pool.lock);
}

/* Skip prepended ext_ from digest kind name */
#define skip_prepended_ext(ext_kind) (&((ext_kind)[4]))

static int
p4tc_extern_digest_constr(struct p4tc_extern_inst **common,
			  const struct p4tc_extern_ops *ops,
			  struct p4tc_extern_params *control_params,
			  struct p4tc_extern_params *constr_params,
			  u32 max_num_elems, bool tbl_bindable,
			  struct netlink_ext_ack *extack)
{
	struct idr *constr_params_idr = &constr_params->params_idr;
	struct p4tc_extern_digest_inst *digest_inst;
	struct p4tc_extern_params *new_params;
	struct p4tc_extern_tmpl_param *param;
	u32 tot_control_param_bytesz = 0;
	unsigned long param_id, tmp;
	int ret;

	if (max_num_elems) {
		NL_SET_ERR_MSG(extack,
			       "Digest must not have any extern elems");
		return -EINVAL;
	}

	if (!idr_is_empty(constr_params_idr)) {
		NL_SET_ERR_MSG(extack,
			       "Must not have any constructor arguments");
		return -EINVAL;
	}


	idr_for_each_entry_ul(&control_params->params_idr, param, tmp,
			      param_id) {
		tot_control_param_bytesz +=
			BITS_TO_BYTES(param->type->container_bitsz);

	}

	if (tot_control_param_bytesz > EXTERN_DIGEST_MAX_SIZE) {
		NL_SET_ERR_MSG_FMT(extack,
				   "Control parameter byte size exceeds %u",
				   EXTERN_DIGEST_MAX_SIZE);
		return -E2BIG;
	}

	*common = p4tc_ext_inst_alloc(ops, max_num_elems, tbl_bindable,
				      (char *)skip_prepended_ext(ops->kind));
	if (IS_ERR(*common))
		return PTR_ERR(*common);

	new_params = p4tc_ext_params_copy(control_params);
	if (IS_ERR(new_params)) {
		ret = PTR_ERR(new_params);
		goto free_common;
	}

	digest_inst = to_digest_inst(*common);
	digest_inst->common.params = new_params;

	ret = p4tc_extern_inst_init_elems(&digest_inst->common, 0);
	if (ret < 0)
		goto free_params;

	return 0;

free_params:
	p4tc_ext_tmpl_params_free(new_params);
free_common:
	kfree(*common);
	return ret;
}

static void
p4tc_extern_digest_deconstr(struct p4tc_extern_inst *common)
{
	p4tc_ext_inst_purge(common);
	if (common->params)
		p4tc_ext_tmpl_params_free(common->params);
	kfree(common);
}

static int
p4tc_extern_digest_init(struct p4tc_extern_common *e,
			struct netlink_ext_ack *extack)
{
	struct p4tc_extern_digest_elem *elem = to_digest_elem(e);

	spin_lock_init(&elem->digest_lock);

	return 0;
}

static int digest_nlmsg_prepare(struct sk_buff *skb,
				struct p4tc_pipeline *pipeline,
				struct p4tc_extern_common *e)
{
	unsigned char *b = nlmsg_get_pos(skb);
	u32 pipeid = pipeline->common.p_id;
	struct nlmsghdr *nlh;
	struct nlattr *count;
	struct nlattr *nest;
	struct p4tcmsg *t;
	int ret;

	nlh = nlmsg_put(skb, 0, 0, RTM_P4TC_CREATE, sizeof(*t), NLM_F_CREATE);
	if (!nlh)
		return -ENOMEM;
	t = nlmsg_data(nlh);
	t->pipeid = pipeid;
	t->obj = P4TC_OBJ_RUNTIME_EXTERN;

	if (nla_put_string(skb, P4TC_ROOT_PNAME, pipeline->common.name)) {
		ret = -ENOMEM;
		goto out_nlmsg_trim;
	}

	nest = nla_nest_start(skb, P4TC_ROOT);
	if (!nest) {
		ret = -ENOMEM;
		goto out_nlmsg_trim;
	}

	count = nla_nest_start(skb, 1);
	if (p4tc_ext_elem_dump_1(skb, e, false) < 0) {
		ret = -ENOMEM;
		goto out_nlmsg_trim;
	}
	nla_nest_end(skb, count);

	nla_nest_end(skb, nest);

	nlh->nlmsg_len = (unsigned char *)nlmsg_get_pos(skb) - b;

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static void digest_params_write(struct p4tc_extern_common *common,
				struct p4tc_ext_bpf_params *bpf_params)
{
	struct p4tc_extern_params *params = common->params;
	char *in_params_ptr = bpf_params->in_params;
	struct p4tc_extern_param *param;
	unsigned long param_id, tmp;

	idr_for_each_entry_ul(&params->params_idr, param, tmp,
			      param_id) {
		const u16 param_bytesz =
			BITS_TO_BYTES(param->tmpl_param->bitsz);

		memcpy(param->value, in_params_ptr, param_bytesz);
		in_params_ptr += param_bytesz;
	}
}

static bool digest_has_listeneres(struct net *net)
{
	return rtnl_has_listeners(net, RTNLGRP_P4TC_DIGEST);
}

static int
__p4tc_extern_digest_pack(struct p4tc_pipeline *pipeline,
			  struct p4tc_extern_common *common,
			  struct p4tc_ext_bpf_params *params)
{
	struct p4tc_extern_digest_elem *elem = to_digest_elem(common);
	struct p4tc_filter_data filter_data = {};
	struct sk_buff *skb;
	int err = 0;

	if (params->index != P4TC_EXT_ELEM_PRIV_IDX)
		return -EINVAL;

	if (!p4tc_data_pub_ok(common->p4tc_ext_permissions))
		return -EPERM;

	spin_lock_bh(&skb_pool.lock);
	skb = __skb_dequeue(&skb_pool);
	spin_unlock_bh(&skb_pool.lock);
	if (!skb)
		return -ENOENT;

	spin_lock_bh(&elem->digest_lock);
	digest_params_write(common, params);
	digest_nlmsg_prepare(skb, pipeline, common);

	filter_data.common = common;
	filter_data.obj_id = P4TC_FILTER_OBJ_RUNTIME_EXT;
	filter_data.cmd = RTM_P4TC_UPDATE;
	refcount_inc(&skb->users);

	err = p4tc_nlmsg_filtered_notify(pipeline->net, skb, 0,
					 GFP_ATOMIC, RTNLGRP_P4TC_DIGEST,
					 false, p4tc_filter_broadcast_cb,
					 &filter_data);
	spin_unlock_bh(&elem->digest_lock);
	if (err == -ESRCH)
		err = 0;
	else
		goto queue_skb;

	refcount_set(&skb->users, 1);

queue_skb:
	spin_lock_bh(&skb_pool.lock);
	__skb_queue_tail(&skb_pool, skb);
	spin_unlock_bh(&skb_pool.lock);
	return err;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int
bpf_p4tc_extern_digest_pack(struct sk_buff *skb,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	struct p4tc_extern_common *common;
	struct p4tc_pipeline *pipeline;
	int err;

	if (!params)
		return -EINVAL;

	if (params__sz != P4TC_EXT_BPF_PARAMS_SZ)
		return -EINVAL;

	if (!digest_has_listeneres(net))
		return -ESRCH;

	common = p4tc_ext_common_elem_priv_get(skb, &pipeline, params);
	if (IS_ERR(common))
		return PTR_ERR(common);

	err = __p4tc_extern_digest_pack(pipeline, common, params);

	p4tc_ext_common_elem_put(pipeline, common);
	return err;
}

__bpf_kfunc int
xdp_p4tc_extern_digest_pack(struct xdp_buff *ctx,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz)
{
	struct net *net = dev_net(ctx->rxq->dev);
	struct p4tc_extern_common *common;
	struct p4tc_pipeline *pipeline;
	int err;

	if (!params)
		return -EINVAL;

	if (params__sz != P4TC_EXT_BPF_PARAMS_SZ)
		return -EINVAL;

	if (!digest_has_listeneres(net))
		return -ESRCH;

	common = p4tc_xdp_ext_common_elem_priv_get(ctx, &pipeline, params);
	if (IS_ERR(common))
		return PTR_ERR(common);

	err = __p4tc_extern_digest_pack(pipeline, common, params);

	p4tc_ext_common_elem_put(pipeline, common);
	return err;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(p4tc_kfunc_ext_digest_set_defs)
BTF_ID_FLAGS(func, bpf_p4tc_extern_digest_pack);
BTF_ID_FLAGS(func, xdp_p4tc_extern_digest_pack);
BTF_KFUNCS_END(p4tc_kfunc_ext_digest_set_defs)

static const struct btf_kfunc_id_set p4tc_kfunc_ext_digest_set = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_ext_digest_set_defs,
};

static struct p4tc_extern_ops ext_digest_ops = {
	.kind = "ext_Digest",
	.size = sizeof(struct p4tc_extern_digest_inst),
	.id = EXTERN_DIGEST_ID,
	.construct = p4tc_extern_digest_constr,
	.deconstruct = p4tc_extern_digest_deconstr,
	.init = p4tc_extern_digest_init,
	.elem_size = sizeof(struct p4tc_extern_digest_elem),
	.owner = THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("Digest extern");
MODULE_LICENSE("GPL");

static int __init digest_init_module(void)
{
	int ret = p4tc_register_extern(&ext_digest_ops);

	if (ret < 0) {
		pr_info("Failed to register Digest TC extern");
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_digest_set);
	if (ret < 0) {
		pr_info("Failed to register Digest TC kfuncs");
		goto unregister_counters;
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&p4tc_kfunc_ext_digest_set);
	if (ret < 0) {
		pr_info("Failed to register Digest XDP kfuncs");
		goto unregister_counters;
	}
	alloc_skb_pull();

	return ret;

unregister_counters:
	p4tc_unregister_extern(&ext_digest_ops);
	return ret;
}

static void __exit digest_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_digest_ops);
	free_skb_pull();
}

module_init(digest_init_module);
module_exit(digest_cleanup_module);
