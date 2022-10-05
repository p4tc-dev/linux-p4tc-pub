/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM p4tc

#if !defined(__P4TC_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define __P4TC_TRACE_H

#include <linux/tracepoint.h>

struct p4tc_pipeline;

TRACE_EVENT(p4_classify,

	    TP_PROTO(struct sk_buff *skb, struct p4tc_pipeline *pipeline),

	    TP_ARGS(skb, pipeline),

	    TP_STRUCT__entry(__string(pname, pipeline->common.name)
			     __field(u32,  p_id)
			     __field(u32,  ifindex)
			     __field(u32,  ingress)
			    ),

	    TP_fast_assign(__assign_str(pname, pipeline->common.name);
			   __entry->p_id = pipeline->common.p_id;
			   __entry->ifindex = skb->dev->ifindex;
			   __entry->ingress = skb_at_tc_ingress(skb);
			  ),

	    TP_printk("dev=%u dir=%s pipeline=%s p_id=%u",
		      __entry->ifindex,
		      __entry->ingress ? "ingress" : "egress",
		      __get_str(pname),
		      __entry->p_id
		     )
);

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
