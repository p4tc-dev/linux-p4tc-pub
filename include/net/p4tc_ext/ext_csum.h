/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TC_EXT_CSUM_H
#define __NET_P4TC_EXT_CSUM_H

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

struct p4tc_ext_csum_params {
	__wsum csum;
};

BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc16_add);
BTF_ID_FLAGS(func, bpf_p4tc_ext_csum_crc16_get);
#endif
