// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc/externs/ext_Meter.c Example meter extern implementation
 *
 * Copyright (c) 2023-2024, Mojatatu Networks
 * Copyright (c) 2023-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/gso.h>
#include <net/netlink.h>
#include <net/p4tc_ext_api.h>
#include <net/p4tc_ext/ext_meter.h>

#define EXTERN_METER_TYPE_PKTS 0
#define EXTERN_METER_TYPE_BYTES 1

#define KEY_PARAM_ID 1
#define CIR_PARAM_ID 2
#define CBS_PARAM_ID 3
#define PIR_PARAM_ID 4
#define PBS_PARAM_ID 5

struct p4tc_extern_meter_inst {
	struct p4tc_extern_inst common;
	u32 constr_type;
};

#define to_meter_inst(inst) ((struct p4tc_extern_meter_inst *)inst)

struct p4tc_extern_meter_elem {
	struct p4tc_extern_common common;
	s64 meter_t_c;
	s64 meter_toks;
	s64 meter_ptoks;
	s64 meter_cbs_nsecs;
	u32 meter_cir_mult;
	u8 meter_cir_shift;
	s64 meter_pbs_nsecs;
	u32 meter_pir_mult;
	u8 meter_pir_shift;
	spinlock_t meter_lock;
};

#define to_meter_elem(elem) ((struct p4tc_extern_meter_elem *)elem)

static int check_cir_param(struct p4tc_extern_tmpl_param *cir_param,
			   const u32 constr_type, struct netlink_ext_ack *extack)
{
	u32 cir_type = constr_type == EXTERN_METER_TYPE_PKTS ?
		P4TC_T_U64 : P4TC_T_RATE;
	struct p4tc_type *type;

	if (!cir_param) {
		NL_SET_ERR_MSG(extack, "CIR param must be a specified");
		return -EINVAL;
	}

	type = cir_param->type;
	if (!(type->typeid == cir_type && cir_param->bitsz == 64)) {
		NL_SET_ERR_MSG(extack, "CIR param type is incorrect");
		return -EINVAL;
	}

	return 0;
}

static bool check_burst_value(u64 burst_value, struct netlink_ext_ack *extack)
{
	if (!burst_value) {
		NL_SET_ERR_MSG(extack,
			       "Burst value must be > 0");
		return false;
	}

	return true;
}

static int check_cbs_param(struct p4tc_extern_tmpl_param *cbr_param,
			   const u32 constr_type, struct netlink_ext_ack *extack)
{
	u32 cbr_type = P4TC_T_U64;
	struct p4tc_type *type;

	if (!cbr_param) {
		NL_SET_ERR_MSG(extack, "CBurst param must be a specified");
		return -EINVAL;
	}

	type = cbr_param->type;
	if (!(type->typeid == cbr_type && cbr_param->bitsz == 64)) {
		NL_SET_ERR_MSG(extack,
			       "CBurst param must be a bit64");
		return -EINVAL;
	}

	return 0;
}

static int check_pir_param(struct p4tc_extern_tmpl_param *pir_param,
			   const u32 constr_type, struct netlink_ext_ack *extack)
{
	u32 pir_type = constr_type == EXTERN_METER_TYPE_PKTS ?
		P4TC_T_U64 : P4TC_T_RATE;
	struct p4tc_type *type;

	if (!pir_param) {
		NL_SET_ERR_MSG(extack, "PIR param must be a specified");
		return -EINVAL;
	}

	type = pir_param->type;
	if (!(type->typeid == pir_type && pir_param->bitsz == 64)) {
		NL_SET_ERR_MSG(extack, "PIR param type is incorrect");
		return -EINVAL;
	}

	return 0;
}

static int check_pbs_param(struct p4tc_extern_tmpl_param *pbr_param,
			   const u32 constr_type, struct netlink_ext_ack *extack)
{
	u32 pbr_type = P4TC_T_U64;
	struct p4tc_type *type;

	if (!pbr_param) {
		NL_SET_ERR_MSG(extack, "PBurst param must be a specified");
		return -EINVAL;
	}

	type = pbr_param->type;
	if (!(type->typeid == pbr_type  && pbr_param->bitsz == 64)) {
		NL_SET_ERR_MSG(extack,
			       "PBurst param must be a bit64");
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
			       "First constructor parameter must be meter type");
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

/* Skip prepended ext_ from meter kind name */
#define skip_prepended_ext(ext_kind) (&((ext_kind)[4]))

static int
p4tc_extern_meter_validate_pktonly(struct p4tc_extern_params *control_params,
				   struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &control_params->params_idr;
	struct p4tc_extern_tmpl_param *param;
	int err;

	err = check_params_cnt(params_idr, 5, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, CIR_PARAM_ID);
	err = check_cir_param(param, EXTERN_METER_TYPE_PKTS, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, CBS_PARAM_ID);
	err = check_cbs_param(param, EXTERN_METER_TYPE_PKTS, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, PIR_PARAM_ID);
	err = check_pir_param(param, EXTERN_METER_TYPE_PKTS, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, PBS_PARAM_ID);
	err = check_pbs_param(param, EXTERN_METER_TYPE_PKTS, extack);
	if (err < 0)
		return err;

	return 0;
}

static int
p4tc_extern_meter_validate_byteonly(struct p4tc_extern_params *control_params,
				      struct netlink_ext_ack *extack)
{
	struct idr *params_idr = &control_params->params_idr;
	struct p4tc_extern_tmpl_param *param;
	int err;

	err = check_params_cnt(params_idr, 5, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, KEY_PARAM_ID);
	err = check_key_param(param, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, CIR_PARAM_ID);
	err = check_cir_param(param, EXTERN_METER_TYPE_BYTES, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, CBS_PARAM_ID);
	err = check_cbs_param(param, EXTERN_METER_TYPE_BYTES, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, PIR_PARAM_ID);
	err = check_pir_param(param, EXTERN_METER_TYPE_BYTES, extack);
	if (err < 0)
		return err;

	param = p4tc_ext_tmpl_param_find_byid(params_idr, PBS_PARAM_ID);
	err = check_pbs_param(param, EXTERN_METER_TYPE_BYTES, extack);
	if (err < 0)
		return err;

	return 0;
}

static int
p4tc_extern_meter_constr(struct p4tc_extern_inst **common,
			 const struct p4tc_extern_ops *ops,
			 struct p4tc_extern_params *control_params,
			 struct p4tc_extern_params *constr_params,
			 u32 max_num_elems, bool tbl_bindable,
			 struct netlink_ext_ack *extack)
{
	struct idr *constr_params_idr = &constr_params->params_idr;
	struct p4tc_extern_params *new_params, *new_constr_params;
	struct p4tc_extern_tmpl_param *constr_type_param;
	struct p4tc_extern_meter_inst *meter_inst;
	u8 *constr_type;
	int err = 0;

	constr_type_param = p4tc_ext_tmpl_param_find_byid(constr_params_idr, 1);
	if (check_ext_type_param(constr_type_param, extack) < 0)
		return -EINVAL;

	constr_type = constr_type_param->default_value;
	switch (*constr_type) {
	case EXTERN_METER_TYPE_PKTS:
		err = p4tc_extern_meter_validate_pktonly(control_params,
							 extack);
		break;
	case EXTERN_METER_TYPE_BYTES:
		err = p4tc_extern_meter_validate_byteonly(control_params,
							  extack);
		break;
	default:
		NL_SET_ERR_MSG(extack,
			       "Only allowed types are bytes(0), pkts(1)");
		return -EINVAL;
	}

	if (err < 0)
		return err;

	*common = p4tc_ext_inst_alloc(ops, max_num_elems, tbl_bindable,
				      (char *)skip_prepended_ext(ops->kind));
	if (IS_ERR(*common))
		return PTR_ERR(*common);
	meter_inst = to_meter_inst(*common);

	new_params = p4tc_ext_params_copy(control_params);
	if (IS_ERR(new_params)) {
		err = PTR_ERR(new_params);
		goto free_common;
	}
	meter_inst->common.params = new_params;
	meter_inst->constr_type = *constr_type;

	new_constr_params = p4tc_ext_params_copy(constr_params);
	if (IS_ERR(new_constr_params)) {
		err = PTR_ERR(new_constr_params);
		goto free_params;
	}
	meter_inst->common.constr_params = new_constr_params;

	err = p4tc_extern_inst_init_elems(&meter_inst->common, max_num_elems);
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
p4tc_extern_meter_deconstr(struct p4tc_extern_inst *common)
{
	p4tc_ext_inst_purge(common);
	if (common->params)
		p4tc_ext_tmpl_params_free(common->params);
	if (common->constr_params)
		p4tc_ext_tmpl_params_free(common->constr_params);
	kfree(common);
}

static u64 meter_l2t_ns(u32 mult, u8 shift, unsigned int len)
{
	return ((u64)len * mult) >> shift;
}

static void psched_ratecfg_precompute__(u64 rate, u32 *mult, u8 *shift)
{
	u64 factor = NSEC_PER_SEC;

	*mult = 1;
	*shift = 0;

	if (rate <= 0)
		return;

	for (;;) {
		*mult = div64_u64(factor, rate);
		if (*mult & (1U << 31) || factor & (1ULL << 63))
			break;
		factor <<= 1;
		(*shift)++;
	}
}

/* Called with rtnl_lock before the pipeline is sealed.
 * Which means there can't be a race with the data path and with the control
 * path, since no data path call can happen before the pipelne is sealed and all
 * control path interaction with externs occurs with rtnl_lock
 */
static int
p4tc_extern_meter_init(struct p4tc_extern_common *e,
		       struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *cir_param, *cbr_param, *pir_param, *pbr_param;
	struct idr *params_idr = &e->params->params_idr;
	struct p4tc_extern_meter_elem *meter_elem;
	u64 cir, cbs, pir, pbs;

	cir_param = p4tc_ext_param_find_byid(params_idr, CIR_PARAM_ID);
	cir = *((u64 *)cir_param->value);

	cbr_param = p4tc_ext_param_find_byid(params_idr, CBS_PARAM_ID);
	cbs = *((u64 *)cbr_param->value);

	pir_param = p4tc_ext_param_find_byid(params_idr, PIR_PARAM_ID);
	pir = *((u64 *)pir_param->value);

	pbr_param = p4tc_ext_param_find_byid(params_idr, PBS_PARAM_ID);
	pbs = *((u64 *)pbr_param->value);

	p4tc_ext_hidden_set(e, 1);

	/* No more failures allowed after this point */
	meter_elem = to_meter_elem(e);
	meter_elem->meter_t_c = ktime_get_ns();
	if (cir)
		psched_ratecfg_precompute__(cir, &meter_elem->meter_cir_mult,
					    &meter_elem->meter_cir_shift);

	meter_elem->meter_cbs_nsecs = cir ? meter_l2t_ns(meter_elem->meter_cir_mult,
							 meter_elem->meter_cir_shift,
							 cbs) : 0;
	meter_elem->meter_toks = meter_elem->meter_cbs_nsecs;

	if (pir)
		psched_ratecfg_precompute__(pir, &meter_elem->meter_pir_mult,
					    &meter_elem->meter_pir_shift);

	meter_elem->meter_pbs_nsecs = pir ? meter_l2t_ns(meter_elem->meter_pir_mult,
							 meter_elem->meter_pir_shift,
							 pbs) : 0;
	meter_elem->meter_ptoks = meter_elem->meter_pbs_nsecs;
	spin_lock_init(&meter_elem->meter_lock);

	return 0;
}

static int
__p4tc_extern_meter_rctrl(struct p4tc_extern_inst *inst,
			  struct p4tc_extern_common *elem,
			  struct p4tc_extern_params *params, u32 index,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_extern_param *cir_param, *cbr_param, *pir_param, *pbr_param;
	struct idr *params_idr = &params->params_idr;
	struct p4tc_extern_meter_elem *meter_elem;
	u64 cir, cbs, pir, pbs;
	int err;

	cir_param = p4tc_ext_param_find_byid(params_idr, CIR_PARAM_ID);
	cir = *((u64 *)cir_param->value);

	cbr_param = p4tc_ext_param_find_byid(params_idr, CBS_PARAM_ID);
	cbs = *((u64 *)cbr_param->value);
	if (!check_burst_value(cbs, extack))
		return -EINVAL;

	pbr_param = p4tc_ext_param_find_byid(params_idr, PBS_PARAM_ID);
	pbs = *((u64 *)pbr_param->value);
	if (!check_burst_value(pbs, extack))
		return -EINVAL;

	pir_param = p4tc_ext_param_find_byid(params_idr, PIR_PARAM_ID);
	pir = *((u64 *)pir_param->value);

	err = p4tc_ext_copy_params_values(elem, params_idr);
	if (err < 0)
		return err;

	/* No more failures allowed after this point */
	if (inst->pipe_ext->ext_id == P4TC_EXTERN_METER_ID)
		p4tc_ext_hidden_set(elem, 0);

	meter_elem = to_meter_elem(elem);

	spin_lock_bh(&meter_elem->meter_lock);
	meter_elem->meter_t_c = ktime_get_ns();
	psched_ratecfg_precompute__(cir, &meter_elem->meter_cir_mult,
				    &meter_elem->meter_cir_shift);
	meter_elem->meter_cbs_nsecs = meter_l2t_ns(meter_elem->meter_cir_mult,
						   meter_elem->meter_cir_shift,
						   cbs);
	meter_elem->meter_toks = meter_elem->meter_cbs_nsecs;
	psched_ratecfg_precompute__(pir, &meter_elem->meter_pir_mult,
				    &meter_elem->meter_pir_shift);
	meter_elem->meter_pbs_nsecs = meter_l2t_ns(meter_elem->meter_pir_mult,
						   meter_elem->meter_pir_shift,
						   pbs);
	meter_elem->meter_ptoks = meter_elem->meter_pbs_nsecs;
	spin_unlock_bh(&meter_elem->meter_lock);

	return 0;
}

static int
p4tc_extern_dir_meter_rctrl(int cmd, struct p4tc_extern_inst *inst,
			    struct p4tc_extern_common **e,
			    struct p4tc_extern_params *params, u32 key,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_extern_common *elem;
	int err;

	if (cmd == RTM_P4TC_GET) {
		elem = p4tc_ext_get_common(inst, key, extack);
		if (IS_ERR(elem))
			return PTR_ERR(elem);
		goto assign_elem;
	} else if (cmd == RTM_P4TC_UPDATE) {
		if (key) {
			elem = p4tc_ext_elem_get_bykey(inst, key, extack);
			if (IS_ERR(elem))
				return PTR_ERR(elem);
			if (!params) {
				if (p4tc_ext_is_hidden(elem)) {
					NL_SET_ERR_MSG_FMT(extack,
							   "Must specify parameter for uninit elem key %u",
							   key);
					err = -EINVAL;
					goto common_put;
				}
				goto assign_elem;
			}
		} else {
			elem = p4tc_ext_elem_next_uninit(inst);
			if (!elem) {
				NL_SET_ERR_MSG(extack,
					       "Unable to get meter element");
				return -ENOENT;
			}
		}

		if (!p4tc_ctrl_update_ok(elem->p4tc_ext_permissions)) {
			NL_SET_ERR_MSG(extack, "Update permissions not set");
			err = -EPERM;
			goto common_put;
		}
	} else {
		NL_SET_ERR_MSG(extack,
			       "Only update and get commands are supported");
		return -EOPNOTSUPP;
	}

	err = __p4tc_extern_meter_rctrl(inst, elem, params, key, extack);
	if (err < 0)
		goto common_put;

	if (cmd == RTM_P4TC_UPDATE)
		p4tc_ext_hidden_set(elem, 0);

assign_elem:
	*e = elem;

	return 0;

common_put:
	if (cmd == RTM_P4TC_UPDATE && p4tc_ext_is_hidden(elem))
		__p4tc_ext_elem_put_list(inst, elem);
	else
		p4tc_extern_common_put(elem);
	return err;
}

static int
p4tc_extern_meter_rctrl(int cmd, struct p4tc_extern_inst *inst,
			struct p4tc_extern_common **e,
			struct p4tc_extern_params *params, u32 key,
			struct netlink_ext_ack *extack)
{
	struct p4tc_extern_common *elem;
	int err = 0;

	if (cmd == RTM_P4TC_GET) {
		elem = p4tc_ext_get_common(inst, key, extack);
		if (IS_ERR(elem))
			return PTR_ERR(elem);
		goto assign_elem;
	} else if (cmd == RTM_P4TC_UPDATE) {
		elem = p4tc_ext_idr_common_search(inst, key, extack);
		if (!elem)
			return -ENOENT;

		if (!p4tc_ctrl_update_ok(elem->p4tc_ext_permissions)) {
			NL_SET_ERR_MSG(extack, "Update permissions not set");
			return -EPERM;
		}
	} else {
		NL_SET_ERR_MSG(extack,
			       "Only update and get commands are supported");
		return -EOPNOTSUPP;
	}

	 err = __p4tc_extern_meter_rctrl(inst, elem, params, key, extack);

assign_elem:
	*e = elem;

	return err;
}

static bool p4tc_skb_meter_pbs_check(struct sk_buff *skb, u32 limit)
{
	u32 len;

	if (skb_is_gso(skb))
		return skb_gso_validate_mac_len(skb, limit);

	len = qdisc_pkt_len(skb);
	if (skb_at_tc_ingress(skb))
		len += skb->mac_len;

	return len <= limit;
}

static bool p4tc_xdp_meter_pbs_check(struct xdp_buff *xdp, u32 limit)
{
	return xdp_get_buff_len(xdp) <= limit;
}

static enum meter_colors
p4tc_extern_meter_exec(struct p4tc_extern_common *common,
		       u32 meter_type, int prev_color, u32 pkt_len)
{
	enum meter_colors ret;

	if (prev_color == P4TC_EXTERN_METER_COLOR_RED) {
		ret = P4TC_EXTERN_METER_COLOR_RED;
	} else {
		struct p4tc_extern_meter_elem *meter_elem =
			to_meter_elem(common);
		s64 now, toks, itoks = 0, ptoks = 0;

		spin_lock_bh(&meter_elem->meter_lock);
		now = ktime_get_ns();
		itoks = min_t(s64, now - meter_elem->meter_t_c,
			      meter_elem->meter_cbs_nsecs);
		toks = itoks;

		ptoks = toks + meter_elem->meter_ptoks;
		if (ptoks > meter_elem->meter_pbs_nsecs)
			ptoks = meter_elem->meter_pbs_nsecs;

		if (meter_type == EXTERN_METER_TYPE_PKTS)
			ptoks -= meter_l2t_ns(meter_elem->meter_pir_mult,
					      meter_elem->meter_pir_shift,
					      1);
		else if(meter_type == EXTERN_METER_TYPE_BYTES)
			ptoks -= meter_l2t_ns(meter_elem->meter_pir_mult,
					      meter_elem->meter_pir_shift,
					      pkt_len);

		if (prev_color == P4TC_EXTERN_METER_COLOR_YELLOW)
			goto yellow;

		toks += meter_elem->meter_toks;
		if (toks > meter_elem->meter_cbs_nsecs)
			toks = meter_elem->meter_cbs_nsecs;
		if (meter_type == EXTERN_METER_TYPE_PKTS)
			toks -= (s64)meter_l2t_ns(meter_elem->meter_cir_mult,
						  meter_elem->meter_cir_shift,
						  1);
		else if(meter_type == EXTERN_METER_TYPE_BYTES)
			toks -= (s64)meter_l2t_ns(meter_elem->meter_cir_mult,
						  meter_elem->meter_cir_shift,
						  pkt_len);

		if (toks <= 0) {
			if (ptoks <=0) {
				ret = P4TC_EXTERN_METER_COLOR_RED;
				spin_unlock_bh(&meter_elem->meter_lock);
			} else {
yellow:
				toks = itoks;
				ret = P4TC_EXTERN_METER_COLOR_YELLOW;
				goto save_tokens;
			}
		} else {
			ret = P4TC_EXTERN_METER_COLOR_GREEN;
save_tokens:
			meter_elem->meter_t_c = now;
			meter_elem->meter_toks = toks;
			meter_elem->meter_ptoks = ptoks;
			spin_unlock_bh(&meter_elem->meter_lock);
		}
	}

	return ret;
}

static enum meter_colors
p4tc_skb_extern_meter_exec(struct sk_buff *skb,
			   struct p4tc_extern_common *common, u32 meter_type,
			   int prev_color)
{
	struct idr *params_idr = &common->params->params_idr;
	struct p4tc_extern_param *pbs_param;
	int pkt_len = qdisc_pkt_len(skb);
	u64 pbs;

	pbs_param = p4tc_ext_param_find_byid(params_idr, PBS_PARAM_ID);
	pbs = *((u64 *)pbs_param->value);

	if (prev_color != P4TC_EXTERN_METER_COLOR_RED &&
	    (meter_type == EXTERN_METER_TYPE_PKTS ||
	     p4tc_skb_meter_pbs_check(skb, pbs))) {
		return p4tc_extern_meter_exec(common, meter_type, prev_color,
					      pkt_len);
	}

	return P4TC_EXTERN_METER_COLOR_RED;
}

static enum meter_colors
p4tc_xdp_extern_meter_exec(struct xdp_buff *xdp,
			   struct p4tc_extern_common *common, u32 meter_type,
			   int prev_color)
{
	struct idr *params_idr = &common->params->params_idr;
	struct p4tc_extern_param *pbs_param;
	int pkt_len = xdp_get_buff_len(xdp);
	u64 pbs;

	pbs_param = p4tc_ext_param_find_byid(params_idr, PBS_PARAM_ID);
	pbs = *((u64 *)pbs_param->value);

	if (prev_color != P4TC_EXTERN_METER_COLOR_RED &&
	    (meter_type == EXTERN_METER_TYPE_PKTS ||
	     p4tc_xdp_meter_pbs_check(xdp, pbs))) {
		return p4tc_extern_meter_exec(common, meter_type, prev_color,
					      pkt_len);
	}

	return P4TC_EXTERN_METER_COLOR_RED;
}

static struct p4tc_extern_common *
p4tc_extern_indir_meter_get(struct net *net,
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
	if (!value->meter) {
		 ret = ENOENT;
		 goto pipeline_put;
	}

	return value->meter;

pipeline_put:
	p4tc_pipeline_put(*pipeline);
	return ERR_PTR(ret);
}

static struct p4tc_extern_common *
p4tc_extern_meter_common_get(struct net *net,
			     struct p4tc_pipeline **pipeline,
			     struct p4tc_ext_bpf_params *params,
			     const u32 params__sz, void *key,
			     const u32 key__sz)
{
	struct p4tc_extern_common *common;

	if (params->flags & P4TC_EXT_METER_DIRECT)
		common = p4tc_extern_entry_get(net, pipeline, params,
					       params__sz, key,
					       key__sz);
	else if (params->flags & P4TC_EXT_METER_INDIRECT)
		common = p4tc_extern_indir_meter_get(net, pipeline,
						     params, params__sz,
						     key, key__sz);
	else
		return ERR_PTR(-EINVAL);

	return common;
}

static struct p4tc_extern_common *
p4tc_extern_meter_common(struct net *net,
			 struct p4tc_ext_bpf_params *params,
			 struct p4tc_pipeline **pipeline,
			 const u32 params__sz, void *key,
			 const u32 key__sz, const u32 constr_type)
{
	struct p4tc_extern_meter_inst *meter_inst;
	struct p4tc_extern_common *common;
	int ret = 0;

	common = p4tc_extern_meter_common_get(net, pipeline, params,
					      params__sz, key, key__sz);
	if (IS_ERR(common))
		return common;

	meter_inst = to_meter_inst(common->inst);
	if (meter_inst->constr_type != constr_type) {
		ret = -EINVAL;
		goto common_put;
	}

	return common;

common_put:
	p4tc_pipeline_put(*pipeline);
	return ERR_PTR(ret);
}

static int p4tc_xdp_extern_meter_common(struct xdp_buff *xdp,
					struct p4tc_ext_bpf_params *params,
					const u32 params__sz, void *key,
					const u32 key__sz, u32 constr_type)
{
	struct net *net = dev_net(xdp->rxq->dev);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	int ret = 0;

	common = p4tc_extern_meter_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  constr_type);
	if (IS_ERR(common))
		return PTR_ERR(common);

	ret = p4tc_xdp_extern_meter_exec(xdp, common,
					 constr_type,
					 P4TC_EXTERN_METER_COLOR_UNSPEC);

	p4tc_pipeline_put(pipeline);
	return ret;
}

static int
p4tc_xdp_extern_meter_common_color(struct xdp_buff *xdp,
				   struct p4tc_ext_bpf_params *params,
				   const u32 params__sz, void *key,
				   const u32 key__sz, u32 constr_type)
{
	struct net *net = dev_net(xdp->rxq->dev);
	u32 *color_in = (u32 *)params->in_params;
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	int ret = 0;

	common = p4tc_extern_meter_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  constr_type);
	if (IS_ERR(common))
		return PTR_ERR(common);

	if (*color_in > P4TC_EXTERN_METER_COLOR_YELLOW ||
	    *color_in < P4TC_EXTERN_METER_COLOR_RED) {
		ret = -EINVAL;
		goto common_put;
	}

	ret = p4tc_xdp_extern_meter_exec(xdp, common, constr_type, *color_in);

common_put:
	p4tc_pipeline_put(pipeline);
	return ret;
}


static int p4tc_skb_extern_meter_common(struct sk_buff *skb,
					struct p4tc_ext_bpf_params *params,
					const u32 params__sz, void *key,
					const u32 key__sz, u32 constr_type)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	int ret = 0;

	common = p4tc_extern_meter_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  constr_type);
	if (IS_ERR(common))
		return PTR_ERR(common);

	ret = p4tc_skb_extern_meter_exec(skb, common,
					 constr_type,
					 P4TC_EXTERN_METER_COLOR_UNSPEC);

	p4tc_pipeline_put(pipeline);
	return ret;
}

static int
p4tc_skb_extern_meter_common_color(struct sk_buff *skb,
				   struct p4tc_ext_bpf_params *params,
				   const u32 params__sz, void *key,
				   const u32 key__sz, u32 constr_type)
{
	struct net *net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	u32 *color_in = (u32 *)params->in_params;
	struct p4tc_pipeline *pipeline = NULL;
	struct p4tc_extern_common *common;
	int ret = 0;

	common = p4tc_extern_meter_common(net, params, &pipeline,
					  params__sz, key, key__sz,
					  constr_type);
	if (IS_ERR(common))
		return PTR_ERR(common);

	if (*color_in < P4TC_EXTERN_METER_COLOR_RED ||
	    *color_in > P4TC_EXTERN_METER_COLOR_YELLOW) {
		ret = -EINVAL;
		goto common_put;
	}

	ret = p4tc_skb_extern_meter_exec(skb, common, constr_type, *color_in);

common_put:
	p4tc_pipeline_put(pipeline);
	return ret;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int
bpf_p4tc_extern_meter_bytes(struct sk_buff *skb,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz, void *key,
			    const u32 key__sz)
{
	return p4tc_skb_extern_meter_common(skb, params, params__sz, key,
					    key__sz, EXTERN_METER_TYPE_BYTES);
}

__bpf_kfunc int
bpf_p4tc_extern_meter_pkts(struct sk_buff *skb,
			   struct p4tc_ext_bpf_params *params,
			   const u32 params__sz, void *key,
			   const u32 key__sz)
{
	return p4tc_skb_extern_meter_common(skb, params, params__sz, key,
					    key__sz, EXTERN_METER_TYPE_PKTS);
}

__bpf_kfunc int
bpf_p4tc_extern_meter_bytes_color(struct sk_buff *skb,
				 struct p4tc_ext_bpf_params *params,
				 const u32 params__sz, void *key,
				 const u32 key__sz)
{
	return p4tc_skb_extern_meter_common_color(skb, params, params__sz, key,
						  key__sz,
						  EXTERN_METER_TYPE_BYTES);
}

__bpf_kfunc int
bpf_p4tc_extern_meter_pkts_color(struct sk_buff *skb,
				 struct p4tc_ext_bpf_params *params,
				 const u32 params__sz, void *key,
				 const u32 key__sz)
{
	return p4tc_skb_extern_meter_common_color(skb, params, params__sz, key,
						  key__sz,
						  EXTERN_METER_TYPE_PKTS);
}

__bpf_kfunc int
xdp_p4tc_extern_meter_bytes(struct xdp_buff *xdp,
			    struct p4tc_ext_bpf_params *params,
			    const u32 params__sz, void *key,
			    const u32 key__sz)
{
	return p4tc_xdp_extern_meter_common(xdp, params, params__sz, key,
					    key__sz, EXTERN_METER_TYPE_BYTES);
}

__bpf_kfunc int
xdp_p4tc_extern_meter_pkts(struct xdp_buff *xdp,
			   struct p4tc_ext_bpf_params *params,
			   const u32 params__sz, void *key,
			   const u32 key__sz)
{
	return p4tc_xdp_extern_meter_common(xdp, params, params__sz, key,
					    key__sz, EXTERN_METER_TYPE_PKTS);
}

__bpf_kfunc int
xdp_p4tc_extern_meter_bytes_color(struct xdp_buff *xdp,
				  struct p4tc_ext_bpf_params *params,
				  const u32 params__sz, void *key,
				  const u32 key__sz)
{
	return p4tc_xdp_extern_meter_common_color(xdp, params, params__sz, key,
						  key__sz,
						  EXTERN_METER_TYPE_BYTES);
}

__bpf_kfunc int
xdp_p4tc_extern_meter_pkts_color(struct xdp_buff *xdp,
				 struct p4tc_ext_bpf_params *params,
				 const u32 params__sz, void *key,
				 const u32 key__sz)
{
	return p4tc_xdp_extern_meter_common_color(xdp, params, params__sz, key,
						  key__sz,
						  EXTERN_METER_TYPE_PKTS);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(p4tc_kfunc_ext_meters_set)
BTF_ID_FLAGS(func, bpf_p4tc_extern_meter_pkts);
BTF_ID_FLAGS(func, bpf_p4tc_extern_meter_pkts_color);
BTF_ID_FLAGS(func, bpf_p4tc_extern_meter_bytes);
BTF_ID_FLAGS(func, bpf_p4tc_extern_meter_bytes_color);
BTF_ID_FLAGS(func, xdp_p4tc_extern_meter_pkts);
BTF_ID_FLAGS(func, xdp_p4tc_extern_meter_pkts_color);
BTF_ID_FLAGS(func, xdp_p4tc_extern_meter_bytes);
BTF_ID_FLAGS(func, xdp_p4tc_extern_meter_bytes_color);
BTF_KFUNCS_END(p4tc_kfunc_ext_meters_set)

static const struct btf_kfunc_id_set p4tc_kfunc_ext_meters_set_skb = {
	.owner = THIS_MODULE,
	.set = &p4tc_kfunc_ext_meters_set,
};

static struct p4tc_extern_ops ext_Meter_ops = {
	.kind = "ext_Meter",
	.size = sizeof(struct p4tc_extern_meter_inst),
	.id = P4TC_EXTERN_METER_ID,
	.construct = p4tc_extern_meter_constr,
	.deconstruct = p4tc_extern_meter_deconstr,
	.rctrl = p4tc_extern_meter_rctrl,
	.init = p4tc_extern_meter_init,
	.elem_size = sizeof(struct p4tc_extern_meter_elem),
	.owner = THIS_MODULE,
};

static struct p4tc_extern_ops ext_DirectMeter_ops = {
	.kind= "ext_DirectMeter",
	.size = sizeof(struct p4tc_extern_meter_inst),
	.id = P4TC_EXTERN_DIRECT_METER_ID,
	.construct = p4tc_extern_meter_constr,
	.deconstruct = p4tc_extern_meter_deconstr,
	.rctrl = p4tc_extern_dir_meter_rctrl,
	.init = p4tc_extern_meter_init,
	.elem_size = sizeof(struct p4tc_extern_meter_elem),
	.owner = THIS_MODULE,
};

MODULE_AUTHOR("Mojatatu Networks, Inc");
MODULE_DESCRIPTION("(Direct)Meter extern");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ext_DirectMeter");

static int __init meter_init_module(void)
{
	int ret = p4tc_register_extern(&ext_Meter_ops);

	if (ret < 0) {
		pr_info("Failed to register Meter TC extern %d\n", ret);
		return ret;
	}

	ret = p4tc_register_extern(&ext_DirectMeter_ops);
	if (ret < 0) {
		pr_info("Failed to register DirectMeter TC extern %d\n", ret);
		goto unregister_meters;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					&p4tc_kfunc_ext_meters_set_skb);
	if (ret < 0) {
		pr_info("Failed to register Meter TC kfuncs %d\n", ret);
		goto unregister_direct_meters;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					&p4tc_kfunc_ext_meters_set_skb);
	if (ret < 0) {
		pr_info("Failed to register Meter XDP kfuncs %d\n", ret);
		goto unregister_direct_meters;
	}

	return ret;

unregister_direct_meters:
	p4tc_unregister_extern(&ext_DirectMeter_ops);

unregister_meters:
	p4tc_unregister_extern(&ext_Meter_ops);
	return ret;
}

static void __exit meter_cleanup_module(void)
{
	p4tc_unregister_extern(&ext_Meter_ops);
	p4tc_unregister_extern(&ext_DirectMeter_ops);
}

module_init(meter_init_module);
module_exit(meter_cleanup_module);
