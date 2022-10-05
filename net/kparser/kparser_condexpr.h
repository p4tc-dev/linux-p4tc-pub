/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_condexpr.h - kParser conditionals helper and structures header file
 *
 * Authors:     Tom Herbert <tom@sipanda.io>
 *              Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef __KPARSER_CONDEXPR_H__
#define __KPARSER_CONDEXPR_H__

/* Definitions for parameterized conditional expressions */

#include "kparser_types.h"
#include "kparser_metaextract.h"

/* Evaluate one conditional expression */
static inline bool kparser_expr_evaluate(const struct kparser_condexpr_expr *expr, void *hdr)
{
	__u64 val;

	pr_debug("{%s:%d}: soff:%u len:%u mask:%x type:%d\n",
		 __func__, __LINE__, expr->src_off, expr->length, expr->mask, expr->type);

	__kparser_metadata_bytes_extract(hdr + expr->src_off, (__u8 *)&val, expr->length, false);

	val &= expr->mask;

	pr_debug("{%s:%d}: type:%d val:%llx expr->value:%u\n",
		 __func__, __LINE__, expr->type, val, expr->value);

	switch (expr->type) {
	case KPARSER_CONDEXPR_TYPE_EQUAL:
		return (val == expr->value);
	case KPARSER_CONDEXPR_TYPE_NOTEQUAL:
		return (val != expr->value);
	case KPARSER_CONDEXPR_TYPE_LT:
		return (val < expr->value);
	case KPARSER_CONDEXPR_TYPE_LTE:
		return (val <= expr->value);
	case KPARSER_CONDEXPR_TYPE_GT:
		return (val > expr->value);
	case KPARSER_CONDEXPR_TYPE_GTE:
		return (val >= expr->value);
	default:
		break;
	}

	return false;
}
#endif /* __KPARSER_CONDEXPR_H__ */
