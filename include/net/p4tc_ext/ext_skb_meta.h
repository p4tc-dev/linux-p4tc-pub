/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TC_EXT_SKB_META_H
#define __NET_P4TC_EXT_SKB_META_H

#include <linux/types.h>

enum {
	P4TC_SKB_META_SET_SZ = 24,
	P4TC_SKB_META_SZ = 2,
};

#define P4TC_SKB_META_SET_TSTAMP BIT(0)
#define P4TC_SKB_META_SET_MARK BIT(1)
#define P4TC_SKB_META_SET_CLASSID BIT(2)
#define P4TC_SKB_META_SET_TC_INDEX BIT(3)
#define P4TC_SKB_META_SET_QMAP BIT(4)
#define P4TC_SKB_META_SET_PROTO BIT(5)

struct p4tc_skb_meta_set {
	s64 tstamp;
	u32 mark;
	__u16 tc_classid;
	u16 tc_index;
	u16 queue_mapping;
	__be16 protocol;
	u32 bitmask;
};

#define P4TC_SKB_META_GET_AT_INGRESS_BIT BIT(0)
#define P4TC_SKB_META_GET_FROM_INGRESS_BIT BIT(1)

struct p4tc_skb_meta_get {
	u8 tc_at_ingress:1,
	   from_ingress:1;
	u8 bitmask;
};

#endif /* __NET_P4TC_EXT_SKB_META_H */
