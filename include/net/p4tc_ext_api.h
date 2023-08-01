/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TC_EXT_API_H
#define __NET_P4TC_EXT_API_H

/*
 * Public extern P4TC_EXT API
 */

#include <uapi/linux/p4tc_ext.h>
#include <linux/refcount.h>
#include <net/flow_offload.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/p4tc.h>

struct p4tc_extern_ops;

struct p4tc_extern_params {
	struct idr params_idr;
	rwlock_t params_lock;
	u32 num_params;
};

struct p4tc_extern {
	struct p4tc_extern_params	*params;
	struct idr			*elems_idr;
	const struct p4tc_extern_ops	*ops;
	struct p4tc_extern_inst		*inst;
	struct rcu_head			rcu;
	size_t				attrs_size;
	spinlock_t			p4tc_ext_lock;
	u32				p4tc_ext_key;
	refcount_t			p4tc_ext_refcnt;
	u32				p4tc_ext_flags;
};

/* Reserve 16 bits for user-space. See P4TC_EXT_FLAGS_NO_PERCPU_STATS. */
#define P4TC_EXT_FLAGS_USER_BITS 16
#define P4TC_EXT_FLAGS_USER_MASK 0xffff

struct p4tc_extern_ops {
	struct list_head head;
	char kind[P4TC_EXT_NAMSIZ];
	size_t size;
	struct module *owner;
	struct p4tc_tmpl_extern *tmpl_ext;
	int     (*exec)(struct sk_buff *skb,
			struct p4tc_extern_inst_common *common,
			struct p4tc_extern *e,
			struct p4tc_ext_bpf_params_exec *params,
			struct p4tc_ext_bpf_res *res);
	u32 id; /* identifier should match kind */
};

#define P4TC_EXT_P_CREATED 1
#define P4TC_EXT_P_DELETED 1

int p4tc_register_extern(struct p4tc_extern_ops *ext);
int p4tc_unregister_extern(struct p4tc_extern_ops *ext);

int p4tc_ctl_extern_dump(struct sk_buff *skb, struct netlink_callback *cb,
			 struct nlattr **tb, const char *pname);
void p4tc_ext_purge(struct idr *idr);

int p4tc_ctl_extern(struct sk_buff *skb, struct nlmsghdr *n, int cmd,
		    struct netlink_ext_ack *extack);
struct p4tc_extern_param *
p4tc_extern_param_find_byanyattr(struct idr *params_idr,
				 struct nlattr *name_attr,
				 const u32 param_id,
				 struct netlink_ext_ack *extack);
struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_byany(struct p4tc_pipeline *pipeline,
			 const char *extern_name, u32 ext_id,
			 struct netlink_ext_ack *extack);
struct p4tc_extern_param *
p4tc_extern_param_find_byid(struct idr *params_idr, const u32 param_id);

int
p4tc_extern_exec_bpf(struct sk_buff *skb, struct p4tc_ext_bpf_params *params,
		     struct p4tc_ext_bpf_res *res);

int p4tc_ext_param_value_init(struct net *net,
			      struct p4tc_extern_param *param,
			      struct nlattr **tb, u32 typeid,
			      bool value_required,
			      struct netlink_ext_ack *extack);
void p4tc_ext_param_value_free(struct p4tc_extern_param *param);
int p4tc_ext_param_value_dump(struct sk_buff *skb,
			      struct p4tc_extern_param *param);
int p4tc_extern_inst_init_elems(struct idr *user_ext_idr);

int p4tc_unregister_extern(struct p4tc_extern_ops *ext);

#endif
