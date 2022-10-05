/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_condexpr.h - kParser conditionals helper and structures header file
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Authors:     Tom Herbert <tom@sipanda.io>
 *              Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef __KPARSER_CONDEXPR_H__
#define __KPARSER_CONDEXPR_H__

/* Definitions for parameterized conditional expressions */

#include <net/kparser/kparser_types.h>
#include <net/kparser/kparser_metaextract.h>

/* Evaluate one conditional expression */
static inline bool kparser_expr_evaluate(
		const struct kparser_condexpr_expr *expr,
		void *hdr)
{
	__u64 val;

	pr_debug("{%s:%d}: soff:%u len:%u mask:%x type:%d\n",
			__FUNCTION__, __LINE__, expr->src_off,
			expr->length, expr->mask, expr->type);
	__kparser_metadata_bytes_extract(hdr + expr->src_off, (__u8 *)&val,
					expr->length, false);

	val &= expr->mask;

	pr_debug("{%s:%d}: type:%d val:%llx expr->value:%u\n",
			__FUNCTION__, __LINE__,
			expr->type, val, expr->value);

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
		return false;
	}
}

#endif /* __KPARSER_CONDEXPR_H__ */
