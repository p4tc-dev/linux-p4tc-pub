// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/p4tc_pipeline.c	P4 TC PIPELINE
 *
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
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/p4tc.h>
#include <net/netlink.h>
#include <net/flow_offload.h>
#include <net/p4tc_types.h>

static unsigned int pipeline_net_id;
static struct p4tc_pipeline *root_pipeline;

static __net_init int pipeline_init_net(struct net *net)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);

	idr_init(&pipe_net->pipeline_idr);

	return 0;
}

static int tcf_pipeline_put(struct net *net,
			    struct p4tc_template_common *template,
			    bool unconditional_purgeline,
			    struct netlink_ext_ack *extack);

static void __net_exit pipeline_exit_net(struct net *net)
{
	struct p4tc_pipeline_net *pipe_net;
	struct p4tc_pipeline *pipeline;
	unsigned long pipeid, tmp;

	rtnl_lock();
	pipe_net = net_generic(net, pipeline_net_id);
	idr_for_each_entry_ul(&pipe_net->pipeline_idr, pipeline, tmp, pipeid) {
		tcf_pipeline_put(net, &pipeline->common, true, NULL);
	}
	idr_destroy(&pipe_net->pipeline_idr);
	rtnl_unlock();
}

static struct pernet_operations pipeline_net_ops = {
	.init = pipeline_init_net,
	.pre_exit = pipeline_exit_net,
	.id = &pipeline_net_id,
	.size = sizeof(struct p4tc_pipeline_net),
};

static const struct nla_policy tc_pipeline_policy[P4TC_PIPELINE_MAX + 1] = {
	[P4TC_PIPELINE_MAXRULES] =
		NLA_POLICY_RANGE(NLA_U32, 1, P4TC_MAXRULES_LIMIT),
	[P4TC_PIPELINE_NUMTABLES] =
		NLA_POLICY_RANGE(NLA_U16, P4TC_MINTABLES_COUNT, P4TC_MAXTABLES_COUNT),
	[P4TC_PIPELINE_STATE] = { .type = NLA_U8 },
	[P4TC_PIPELINE_PREACTIONS] = { .type = NLA_NESTED },
	[P4TC_PIPELINE_POSTACTIONS] = { .type = NLA_NESTED },
};

static void __act_dep_graph_free(struct list_head *incoming_egde_list)
{
	struct p4tc_act_dep_edge_node *cursor_edge, *tmp_edge;

	list_for_each_entry_safe(cursor_edge, tmp_edge, incoming_egde_list,
				 head) {
		list_del(&cursor_edge->head);
		kfree(cursor_edge);
	}
}

static void act_dep_graph_free(struct list_head *graph)
{
	struct p4tc_act_dep_node *cursor, *tmp;

	list_for_each_entry_safe(cursor, tmp, graph, head) {
		__act_dep_graph_free(&cursor->incoming_egde_list);

		list_del(&cursor->head);
		kfree(cursor);
	}
}

void tcf_pipeline_delete_from_dep_graph(struct p4tc_pipeline *pipeline,
					struct p4tc_act *act)
{
	struct p4tc_act_dep_node *act_node, *node_tmp;

	list_for_each_entry_safe(act_node, node_tmp, &pipeline->act_dep_graph,
				 head) {
		if (act_node->act_id == act->a_id) {
			__act_dep_graph_free(&act_node->incoming_egde_list);
			list_del(&act_node->head);
			kfree(act_node);
		}
	}

	list_for_each_entry_safe(act_node, node_tmp,
				 &pipeline->act_topological_order, head) {
		if (act_node->act_id == act->a_id) {
			list_del(&act_node->head);
			kfree(act_node);
		}
	}
}

/* Node id indicates the callee's act id.
 * edge_node->act_id indicates the caller's act id.
 */
void tcf_pipeline_add_dep_edge(struct p4tc_pipeline *pipeline,
			       struct p4tc_act_dep_edge_node *edge_node,
			       u32 node_id)
{
	struct p4tc_act_dep_node *cursor;

	list_for_each_entry(cursor, &pipeline->act_dep_graph, head) {
		if (cursor->act_id == node_id)
			break;
	}

	list_add_tail(&edge_node->head, &cursor->incoming_egde_list);
}

/* Find root node, that is, the node in our graph that has no incoming edges.
 */
struct p4tc_act_dep_node *find_root_node(struct list_head *act_dep_graph)
{
	struct p4tc_act_dep_node *cursor, *root_node;

	list_for_each_entry(cursor, act_dep_graph, head) {
		if (list_empty(&cursor->incoming_egde_list)) {
			root_node = cursor;
			return root_node;
		}
	}

	return NULL;
}

/* node_id indicates where the edge is directed to
 * edge_node->act_id indicates where the edge comes from.
 */
bool tcf_pipeline_check_act_backedge(struct p4tc_pipeline *pipeline,
				     struct p4tc_act_dep_edge_node *edge_node,
				     u32 node_id)
{
	struct p4tc_act_dep_node *root_node = NULL;

	/* make sure we dont call ourselves */
	if (edge_node->act_id == node_id)
		return true;

	/* add to the list temporarily so we can run our algorithm to
	 * find edgeless node and detect a cycle
	 */
	tcf_pipeline_add_dep_edge(pipeline, edge_node, node_id);

	/* Now lets try to find a node which has no incoming edges (root node).
	 * If we find a root node it means there is no cycle;
	 * OTOH, if we dont find one, it means we have circular depency.
	 */
	root_node = find_root_node(&pipeline->act_dep_graph);

	if (!root_node)
		return true;

	list_del(&edge_node->head);

	return false;
}

static struct p4tc_act_dep_node *
find_and_del_root_node(struct list_head *act_dep_graph)
{
	struct p4tc_act_dep_node *cursor, *tmp, *root_node;

	root_node = find_root_node(act_dep_graph);
	list_del(&root_node->head);

	list_for_each_entry_safe(cursor, tmp, act_dep_graph, head) {
		struct p4tc_act_dep_edge_node *cursor_edge, *tmp_edge;

		list_for_each_entry_safe(cursor_edge, tmp_edge,
					 &cursor->incoming_egde_list, head) {
			if (cursor_edge->act_id == root_node->act_id) {
				list_del(&cursor_edge->head);
				kfree(cursor_edge);
			}
		}
	}

	return root_node;
}

static int act_dep_graph_copy(struct list_head *new_graph,
			      struct list_head *old_graph)
{
	int err = -ENOMEM;
	struct p4tc_act_dep_node *cursor, *tmp;

	list_for_each_entry_safe(cursor, tmp, old_graph, head) {
		struct p4tc_act_dep_edge_node *cursor_edge, *tmp_edge;
		struct p4tc_act_dep_node *new_dep_node;

		new_dep_node = kzalloc(sizeof(*new_dep_node), GFP_KERNEL);
		if (!new_dep_node)
			goto free_graph;

		INIT_LIST_HEAD(&new_dep_node->incoming_egde_list);
		list_add_tail(&new_dep_node->head, new_graph);
		new_dep_node->act_id = cursor->act_id;

		list_for_each_entry_safe(cursor_edge, tmp_edge,
					 &cursor->incoming_egde_list, head) {
			struct p4tc_act_dep_edge_node *new_dep_edge_node;

			new_dep_edge_node =
				kzalloc(sizeof(*new_dep_edge_node), GFP_KERNEL);
			if (!new_dep_edge_node)
				goto free_graph;

			list_add_tail(&new_dep_edge_node->head,
				      &new_dep_node->incoming_egde_list);
			new_dep_edge_node->act_id = cursor_edge->act_id;
		}
	}

	return 0;

free_graph:
	act_dep_graph_free(new_graph);
	return err;
}

int determine_act_topological_order(struct p4tc_pipeline *pipeline,
				    bool copy_dep_graph)
{
	int i = pipeline->num_created_acts;
	struct p4tc_act_dep_node *act_node, *node_tmp;
	struct p4tc_act_dep_node *node;
	struct list_head *dep_graph;

	if (copy_dep_graph) {
		int err;

		dep_graph = kzalloc(sizeof(*dep_graph), GFP_KERNEL);
		if (!dep_graph)
			return -ENOMEM;

		INIT_LIST_HEAD(dep_graph);
		err = act_dep_graph_copy(dep_graph, &pipeline->act_dep_graph);
		if (err < 0)
			return err;
	} else {
		dep_graph = &pipeline->act_dep_graph;
	}

	/* Clear from previous calls */
	list_for_each_entry_safe(act_node, node_tmp,
				 &pipeline->act_topological_order, head) {
		list_del(&act_node->head);
		kfree(act_node);
	}

	while (i--) {
		node = find_and_del_root_node(dep_graph);
		list_add_tail(&node->head, &pipeline->act_topological_order);
	}

	if (copy_dep_graph)
		kfree(dep_graph);

	return 0;
}

static void tcf_pipeline_destroy(struct p4tc_pipeline *pipeline,
				 bool free_pipeline)
{
	idr_destroy(&pipeline->p_meta_idr);
	idr_destroy(&pipeline->p_act_idr);
	idr_destroy(&pipeline->p_tbl_idr);

	if (free_pipeline)
		kfree(pipeline);
}

static void tcf_pipeline_destroy_rcu(struct rcu_head *head)
{
	struct p4tc_pipeline *pipeline;
	struct net *net;

	pipeline = container_of(head, struct p4tc_pipeline, rcu);

	net = pipeline->net;
	tcf_pipeline_destroy(pipeline, true);
	put_net(net);
}

static int tcf_pipeline_put(struct net *net,
			    struct p4tc_template_common *template,
			    bool unconditional_purgeline,
			    struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);
	struct p4tc_pipeline *pipeline = to_pipeline(template);
	struct net *pipeline_net = maybe_get_net(net);
	struct p4tc_act_dep_node *act_node, *node_tmp;
	unsigned long tbl_id, m_id, tmp;
	struct p4tc_metadata *meta;
	struct p4tc_table *table;

	if (pipeline_net && !refcount_dec_if_one(&pipeline->p_ref)) {
		NL_SET_ERR_MSG(extack, "Can't delete referenced pipeline");
		return -EBUSY;
        }

	/* XXX: The action fields are only accessed in the control path
	 * since they will be copied to the filter, where the data path
	 * will use them. So there is no need to free them in the rcu
	 * callback. We can just free them here
	 */
	p4tc_action_destroy(pipeline->preacts);
	p4tc_action_destroy(pipeline->postacts);

	idr_for_each_entry_ul(&pipeline->p_tbl_idr, table, tmp, tbl_id)
		table->common.ops->put(net, &table->common, true, extack);

	act_dep_graph_free(&pipeline->act_dep_graph);

	list_for_each_entry_safe(act_node, node_tmp,
				 &pipeline->act_topological_order, head) {
		struct p4tc_act *act;

		act = tcf_action_find_byid(pipeline, act_node->act_id);
		act->common.ops->put(net, &act->common, true, extack);
		list_del(&act_node->head);
		kfree(act_node);
	}

	idr_for_each_entry_ul(&pipeline->p_meta_idr, meta, tmp, m_id)
		meta->common.ops->put(net, &meta->common, true, extack);

	if (pipeline->parser)
		tcf_parser_del(net, pipeline, pipeline->parser, extack);

	idr_remove(&pipe_net->pipeline_idr, pipeline->common.p_id);

	if (pipeline_net)
		call_rcu(&pipeline->rcu, tcf_pipeline_destroy_rcu);
	else
		tcf_pipeline_destroy(pipeline,
				     refcount_read(&pipeline->p_ref) == 1);

	return 0;
}

static inline int pipeline_try_set_state_ready(struct p4tc_pipeline *pipeline,
					       struct netlink_ext_ack *extack)
{
	int ret;

	if (pipeline->curr_tables != pipeline->num_tables) {
		NL_SET_ERR_MSG(extack,
			       "Must have all table defined to update state to ready");
		return -EINVAL;
	}

	if (!pipeline->preacts) {
		NL_SET_ERR_MSG(extack,
			       "Must specify pipeline preactions before sealing");
		return -EINVAL;
	}

	if (!pipeline->postacts) {
		NL_SET_ERR_MSG(extack,
			       "Must specify pipeline postactions before sealing");
		return -EINVAL;
	}
	ret = tcf_table_try_set_state_ready(pipeline, extack);
	if (ret < 0)
		return ret;

	/* Will never fail in this case */
	determine_act_topological_order(pipeline, false);

	pipeline->p_state = P4TC_STATE_READY;
	return true;
}

struct p4tc_pipeline *tcf_pipeline_find_byid(struct net *net, const u32 pipeid)
{
	struct p4tc_pipeline_net *pipe_net;

	if (pipeid == P4TC_KERNEL_PIPEID)
		return root_pipeline;

	pipe_net = net_generic(net, pipeline_net_id);

	return idr_find(&pipe_net->pipeline_idr, pipeid);
}

static struct p4tc_pipeline *tcf_pipeline_find_byname(struct net *net,
						      const char *name)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);
	struct p4tc_pipeline *pipeline;
	unsigned long tmp, id;

	idr_for_each_entry_ul(&pipe_net->pipeline_idr, pipeline, tmp, id) {
		/* Don't show kernel pipeline */
		if (id == P4TC_KERNEL_PIPEID)
			continue;
		if (strncmp(pipeline->common.name, name, PIPELINENAMSIZ) == 0)
			return pipeline;
	}

	return NULL;
}

static struct p4tc_pipeline *tcf_pipeline_create(struct net *net,
						 struct nlmsghdr *n,
						 struct nlattr *nla,
						 const char *p_name, u32 pipeid,
						 struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);
	int ret = 0;
	struct nlattr *tb[P4TC_PIPELINE_MAX + 1];
	struct p4tc_pipeline *pipeline;

	ret = nla_parse_nested(tb, P4TC_PIPELINE_MAX, nla, tc_pipeline_policy,
			       extack);

	if (ret < 0)
		return ERR_PTR(ret);

	pipeline = kmalloc(sizeof(*pipeline), GFP_KERNEL);
	if (!pipeline)
		return ERR_PTR(-ENOMEM);

	if (!p_name || p_name[0] == '\0') {
		NL_SET_ERR_MSG(extack, "Must specify pipeline name");
		ret = -EINVAL;
		goto err;
	}

	if (pipeid != P4TC_KERNEL_PIPEID &&
	    tcf_pipeline_find_byid(net, pipeid)) {
		NL_SET_ERR_MSG(extack, "Pipeline was already created");
		ret = -EEXIST;
		goto err;
	}

	if (tcf_pipeline_find_byname(net, p_name)) {
		NL_SET_ERR_MSG(extack, "Pipeline was already created");
		ret = -EEXIST;
		goto err;
	}

	strscpy(pipeline->common.name, p_name, PIPELINENAMSIZ);

	if (pipeid) {
		ret = idr_alloc_u32(&pipe_net->pipeline_idr, pipeline, &pipeid,
				    pipeid, GFP_KERNEL);
	} else {
		pipeid = 1;
		ret = idr_alloc_u32(&pipe_net->pipeline_idr, pipeline, &pipeid,
				    UINT_MAX, GFP_KERNEL);
	}

	if (ret < 0) {
		NL_SET_ERR_MSG(extack, "Unable to allocate pipeline id");
		goto err;
	}

	pipeline->common.p_id = pipeid;

	if (tb[P4TC_PIPELINE_MAXRULES])
		pipeline->max_rules =
			*((u32 *)nla_data(tb[P4TC_PIPELINE_MAXRULES]));
	else
		pipeline->max_rules = P4TC_DEFAULT_MAX_RULES;

	if (tb[P4TC_PIPELINE_NUMTABLES])
		pipeline->num_tables =
			*((u16 *)nla_data(tb[P4TC_PIPELINE_NUMTABLES]));
	else
		pipeline->num_tables = P4TC_DEFAULT_NUM_TABLES;

	if (tb[P4TC_PIPELINE_PREACTIONS]) {
		pipeline->preacts = kcalloc(TCA_ACT_MAX_PRIO,
					    sizeof(struct tc_action *),
					    GFP_KERNEL);
		if (!pipeline->preacts) {
			ret = -ENOMEM;
			goto idr_rm;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_PREACTIONS],
				       pipeline->preacts, pipeid, 0, extack);
		if (ret < 0) {
			kfree(pipeline->preacts);
			goto idr_rm;
		}
		pipeline->num_preacts = ret;
	} else {
		pipeline->preacts = NULL;
		pipeline->num_preacts = 0;
	}

	if (tb[P4TC_PIPELINE_POSTACTIONS]) {
		pipeline->postacts = kcalloc(TCA_ACT_MAX_PRIO,
					     sizeof(struct tc_action *),
					     GFP_KERNEL);
		if (!pipeline->postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_POSTACTIONS],
				       pipeline->postacts, pipeid, 0, extack);
		if (ret < 0) {
			kfree(pipeline->postacts);
			goto preactions_destroy;
		}
		pipeline->num_postacts = ret;
	} else {
		pipeline->postacts = NULL;
		pipeline->num_postacts = 0;
	}

	pipeline->parser = NULL;

	idr_init(&pipeline->p_act_idr);

	idr_init(&pipeline->p_tbl_idr);
	pipeline->curr_tables = 0;

	idr_init(&pipeline->p_meta_idr);
	pipeline->p_meta_offset = 0;

	INIT_LIST_HEAD(&pipeline->act_dep_graph);
	INIT_LIST_HEAD(&pipeline->act_topological_order);
	pipeline->num_created_acts = 0;

	pipeline->p_state = P4TC_STATE_NOT_READY;

	pipeline->net = net;

	refcount_set(&pipeline->p_ref, 1);

	pipeline->common.ops = (struct p4tc_template_ops *)&p4tc_pipeline_ops;

	return pipeline;

preactions_destroy:
	p4tc_action_destroy(pipeline->preacts);

idr_rm:
	idr_remove(&pipe_net->pipeline_idr, pipeid);

err:
	kfree(pipeline);
	return ERR_PTR(ret);
}

static struct p4tc_pipeline *
__tcf_pipeline_find_byany(struct net *net, const char *p_name, const u32 pipeid,
			  struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline = NULL;
	int err;

	if (pipeid) {
		pipeline = tcf_pipeline_find_byid(net, pipeid);
		if (!pipeline) {
			NL_SET_ERR_MSG(extack, "Unable to find pipeline by id");
			err = -EINVAL;
			goto out;
		}
	} else {
		if (p_name) {
			pipeline = tcf_pipeline_find_byname(net, p_name);
			if (!pipeline) {
				NL_SET_ERR_MSG(extack,
					       "Pipeline name not found");
				err = -EINVAL;
				goto out;
			}
		}
	}

	return pipeline;

out:
	return ERR_PTR(err);
}

struct p4tc_pipeline *tcf_pipeline_find_byany(struct net *net,
					      const char *p_name,
					      const u32 pipeid,
					      struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		__tcf_pipeline_find_byany(net, p_name, pipeid, extack);
	if (!pipeline) {
		NL_SET_ERR_MSG(extack, "Must specify pipeline name or id");
		return ERR_PTR(-EINVAL);
	}

	return pipeline;
}

struct p4tc_pipeline *tcf_pipeline_get(struct net *net, const char *p_name,
				       const u32 pipeid,
				       struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		__tcf_pipeline_find_byany(net, p_name, pipeid, extack);
	if (!pipeline) {
		NL_SET_ERR_MSG(extack, "Must specify pipeline name or id");
		return ERR_PTR(-EINVAL);
	} else if (IS_ERR(pipeline)) {
		return pipeline;
	}

	/* Should never happen */
	WARN_ON(!refcount_inc_not_zero(&pipeline->p_ref));

	return pipeline;
}

void __tcf_pipeline_put(struct p4tc_pipeline *pipeline)
{
	struct net *net = maybe_get_net(pipeline->net);

	if (net) {
		refcount_dec(&pipeline->p_ref);
		put_net(net);
	/* If netns is going down, we already deleted the pipeline objects in
	 * the pre_exit net op
	 */
	} else {
		kfree(pipeline);
	}
}

struct p4tc_pipeline *
tcf_pipeline_find_byany_unsealed(struct net *net, const char *p_name,
				 const u32 pipeid,
				 struct netlink_ext_ack *extack)
{
	struct p4tc_pipeline *pipeline =
		tcf_pipeline_find_byany(net, p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return pipeline;

	if (pipeline_sealed(pipeline)) {
		NL_SET_ERR_MSG(extack, "Pipeline is sealed");
		return ERR_PTR(-EINVAL);
	}

	return pipeline;
}

static struct p4tc_pipeline *
tcf_pipeline_update(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		    const char *p_name, const u32 pipeid,
		    struct netlink_ext_ack *extack)
{
	struct tc_action **preacts = NULL;
	struct tc_action **postacts = NULL;
	u16 num_tables = 0;
	u16 max_rules = 0;
	int ret = 0;
	struct nlattr *tb[P4TC_PIPELINE_MAX + 1];
	struct p4tc_pipeline *pipeline;
	int num_preacts, num_postacts;

	ret = nla_parse_nested(tb, P4TC_PIPELINE_MAX, nla, tc_pipeline_policy,
			       extack);

	if (ret < 0)
		goto out;

	pipeline =
		tcf_pipeline_find_byany_unsealed(net, p_name, pipeid, extack);
	if (IS_ERR(pipeline))
		return pipeline;

	if (tb[P4TC_PIPELINE_NUMTABLES])
		num_tables = *((u16 *)nla_data(tb[P4TC_PIPELINE_NUMTABLES]));

	if (tb[P4TC_PIPELINE_MAXRULES])
		max_rules = *((u32 *)nla_data(tb[P4TC_PIPELINE_MAXRULES]));

	if (tb[P4TC_PIPELINE_PREACTIONS]) {
		preacts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				  GFP_KERNEL);
		if (!preacts) {
			ret = -ENOMEM;
			goto out;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_PREACTIONS],
				       preacts, pipeline->common.p_id, 0,
				       extack);
		if (ret < 0) {
			kfree(preacts);
			goto out;
		}
		num_preacts = ret;
	}

	if (tb[P4TC_PIPELINE_POSTACTIONS]) {
		postacts = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				   GFP_KERNEL);
		if (!postacts) {
			ret = -ENOMEM;
			goto preactions_destroy;
		}

		ret = p4tc_action_init(net, tb[P4TC_PIPELINE_POSTACTIONS],
				       postacts, pipeline->common.p_id, 0,
				       extack);
		if (ret < 0) {
			kfree(postacts);
			goto preactions_destroy;
		}
		num_postacts = ret;
	}

	if (tb[P4TC_PIPELINE_STATE]) {
		ret = pipeline_try_set_state_ready(pipeline, extack);
		if (ret < 0)
			goto postactions_destroy;
		tcf_meta_fill_user_offsets(pipeline);
	}

	if (max_rules)
		pipeline->max_rules = max_rules;
	if (num_tables)
		pipeline->num_tables = num_tables;
	if (preacts) {
		p4tc_action_destroy(pipeline->preacts);
		pipeline->preacts = preacts;
		pipeline->num_preacts = num_preacts;
	}
	if (postacts) {
		p4tc_action_destroy(pipeline->postacts);
		pipeline->postacts = postacts;
		pipeline->num_postacts = num_postacts;
	}

	return pipeline;

postactions_destroy:
	p4tc_action_destroy(postacts);

preactions_destroy:
	p4tc_action_destroy(preacts);
out:
	return ERR_PTR(ret);
}

static struct p4tc_template_common *
tcf_pipeline_cu(struct net *net, struct nlmsghdr *n, struct nlattr *nla,
		struct p4tc_nl_pname *nl_pname, u32 *ids,
		struct netlink_ext_ack *extack)
{
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_pipeline *pipeline;

	if (n->nlmsg_flags & NLM_F_REPLACE)
		pipeline = tcf_pipeline_update(net, n, nla, nl_pname->data,
					       pipeid, extack);
	else
		pipeline = tcf_pipeline_create(net, n, nla, nl_pname->data,
					       pipeid, extack);

	if (IS_ERR(pipeline))
		goto out;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

out:
	return (struct p4tc_template_common *)pipeline;
}

static int _tcf_pipeline_fill_nlmsg(struct sk_buff *skb,
				    const struct p4tc_pipeline *pipeline)
{
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *nest, *preacts, *postacts;

	nest = nla_nest_start(skb, P4TC_PARAMS);
	if (!nest)
		goto out_nlmsg_trim;
	if (nla_put_u32(skb, P4TC_PIPELINE_MAXRULES, pipeline->max_rules))
		goto out_nlmsg_trim;

	if (nla_put_u16(skb, P4TC_PIPELINE_NUMTABLES, pipeline->num_tables))
		goto out_nlmsg_trim;
	if (nla_put_u8(skb, P4TC_PIPELINE_STATE, pipeline->p_state))
		goto out_nlmsg_trim;

	if (pipeline->preacts) {
		preacts = nla_nest_start(skb, P4TC_PIPELINE_PREACTIONS);
		if (tcf_action_dump(skb, pipeline->preacts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, preacts);
	}

	if (pipeline->postacts) {
		postacts = nla_nest_start(skb, P4TC_PIPELINE_POSTACTIONS);
		if (tcf_action_dump(skb, pipeline->postacts, 0, 0, false) < 0)
			goto out_nlmsg_trim;
		nla_nest_end(skb, postacts);
	}

	nla_nest_end(skb, nest);

	return skb->len;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_pipeline_fill_nlmsg(struct net *net, struct sk_buff *skb,
				   struct p4tc_template_common *template,
				   struct netlink_ext_ack *extack)
{
	const struct p4tc_pipeline *pipeline = to_pipeline(template);

	if (_tcf_pipeline_fill_nlmsg(skb, pipeline) <= 0) {
		NL_SET_ERR_MSG(extack,
			       "Failed to fill notification attributes for pipeline");
		return -EINVAL;
	}

	return 0;
}

static int tcf_pipeline_del_one(struct net *net,
				struct p4tc_template_common *tmpl,
				struct netlink_ext_ack *extack)
{
	return tcf_pipeline_put(net, tmpl, false, extack);
}

static int tcf_pipeline_gd(struct net *net, struct sk_buff *skb,
			   struct nlmsghdr *n, struct nlattr *nla,
			   struct p4tc_nl_pname *nl_pname, u32 *ids,
			   struct netlink_ext_ack *extack)
{
	unsigned char *b = nlmsg_get_pos(skb);
	u32 pipeid = ids[P4TC_PID_IDX];
	struct p4tc_template_common *tmpl;
	struct p4tc_pipeline *pipeline;
	int ret = 0;

	if (n->nlmsg_type == RTM_DELP4TEMPLATE &&
	    (n->nlmsg_flags & NLM_F_ROOT)) {
		NL_SET_ERR_MSG(extack, "Pipeline flush not supported");
		return -EOPNOTSUPP;
	}

	pipeline = tcf_pipeline_find_byany(net, nl_pname->data, pipeid, extack);
	if (IS_ERR(pipeline))
		return PTR_ERR(pipeline);

	tmpl = (struct p4tc_template_common *)pipeline;
	ret = tcf_pipeline_fill_nlmsg(net, skb, tmpl, extack);
	if (ret < 0)
		return -1;

	if (!ids[P4TC_PID_IDX])
		ids[P4TC_PID_IDX] = pipeline->common.p_id;

	if (!nl_pname->passed)
		strscpy(nl_pname->data, pipeline->common.name, PIPELINENAMSIZ);

	if (n->nlmsg_type == RTM_DELP4TEMPLATE) {
		ret = tcf_pipeline_del_one(net, tmpl, extack);
		if (ret < 0)
			goto out_nlmsg_trim;
	}

	return ret;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return ret;
}

static int tcf_pipeline_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			     struct nlattr *nla, char **p_name, u32 *ids,
			     struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct p4tc_pipeline_net *pipe_net = net_generic(net, pipeline_net_id);

	return tcf_p4_tmpl_generic_dump(skb, ctx, &pipe_net->pipeline_idr,
					P4TC_PID_IDX, extack);
}

static int tcf_pipeline_dump_1(struct sk_buff *skb,
			       struct p4tc_template_common *common)
{
	struct p4tc_pipeline *pipeline = to_pipeline(common);
	unsigned char *b = nlmsg_get_pos(skb);
	struct nlattr *param;

	/* Don't show kernel pipeline in dump */
	if (pipeline->common.p_id == P4TC_KERNEL_PIPEID)
		return 1;

	param = nla_nest_start(skb, P4TC_PARAMS);
	if (!param)
		goto out_nlmsg_trim;
	if (nla_put_string(skb, P4TC_PIPELINE_NAME, pipeline->common.name))
		goto out_nlmsg_trim;

	nla_nest_end(skb, param);

	return 0;

out_nlmsg_trim:
	nlmsg_trim(skb, b);
	return -ENOMEM;
}

static int register_pipeline_pernet(void)
{
	return register_pernet_subsys(&pipeline_net_ops);
}

static void __tcf_pipeline_init(void)
{
	int pipeid = P4TC_KERNEL_PIPEID;

	root_pipeline = kzalloc(sizeof(*root_pipeline), GFP_ATOMIC);
	if (!root_pipeline) {
		pr_err("Unable to register kernel pipeline\n");
		return;
	}

	strscpy(root_pipeline->common.name, "kernel", PIPELINENAMSIZ);

	idr_init(&root_pipeline->p_meta_idr);

	root_pipeline->common.ops =
		(struct p4tc_template_ops *)&p4tc_pipeline_ops;

	root_pipeline->common.p_id = pipeid;

	root_pipeline->p_state = P4TC_STATE_READY;

	tcf_meta_init(root_pipeline);
}

static void tcf_pipeline_init(void)
{
	if (register_pipeline_pernet() < 0)
		pr_err("Failed to register per net pipeline IDR");

	if (p4tc_register_types() < 0)
		pr_err("Failed to register P4 types");

	__tcf_pipeline_init();
}

const struct p4tc_template_ops p4tc_pipeline_ops = {
	.init = tcf_pipeline_init,
	.cu = tcf_pipeline_cu,
	.fill_nlmsg = tcf_pipeline_fill_nlmsg,
	.gd = tcf_pipeline_gd,
	.put = tcf_pipeline_put,
	.dump = tcf_pipeline_dump,
	.dump_1 = tcf_pipeline_dump_1,
};
