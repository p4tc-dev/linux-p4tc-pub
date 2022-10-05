/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser.h - kParser global net header file
 *
 * Authors:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef _NET_KPARSER_H
#define _NET_KPARSER_H

#include <linux/kparser.h>
#include <linux/skbuff.h>

/* The kParser data path API can consume max 512 bytes */
#define KPARSER_MAX_SKB_PACKET_LEN	512

/* kparser_parse(): Function to parse a skb using a parser instance key.
 *
 * skb: input packet skb
 * kparser_key: key of the associated kParser parser object which must be
 *              already created via CLI.
 * _metadata: User provided metadata buffer. It must be same as configured
 *            metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 * avoid_ref: Set this flag in case caller wants to avoid holding the reference
 *            of the active parser object to save performance on the data path.
 *            But please be advised, caller should hold the reference of the
 *            parser object while using this data path. In this case, the CLI
 *            can be used in advance to get the reference, and caller will also
 *            need to release the reference via CLI once it is done with the
 *            data path.
 *
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 */
extern int kparser_parse(struct sk_buff *skb,
			 const struct kparser_hkey *kparser_key,
			 void *_metadata, size_t metadata_len,
			 bool avoid_ref);

/* __kparser_parse(): Function to parse a void * packet buffer using a parser instance key.
 *
 * parser: Non NULL kparser_get_parser() returned and cached opaque pointer
 * referencing a valid parser instance.
 * _hdr: input packet buffer
 * parse_len: length of input packet buffer
 * _metadata: User provided metadata buffer. It must be same as configured
 * metadata objects in CLI.
 * metadata_len: Total length of the user provided metadata buffer.
 *
 * return: kParser error code as defined in include/uapi/linux/kparser.h
 */
extern int __kparser_parse(const void *parser, void *_hdr,
			   size_t parse_len, void *_metadata, size_t metadata_len);

/* kparser_get_parser(): Function to get an opaque reference of a parser instance and mark it
 * immutable so that while actively using, it can not be deleted. The parser is identified by a key.
 * It marks the associated parser and whole parse tree immutable so that when it is locked, it can
 * not be deleted.
 *
 * kparser_key: key of the associated kParser parser object which must be
 * already created via CLI.
 * avoid_ref: Set this flag in case caller wants to avoid holding the reference
 *            of the active parser object to save performance on the data path.
 *            But please be advised, caller should hold the reference of the
 *            parser object while using this data path. In this case, the CLI
 *            can be used in advance to get the reference, and caller will also
 *            need to release the reference via CLI once it is done with the
 *            data path.
 *
 * return: NULL if key not found, else an opaque parser instance pointer which
 * can be used in the following APIs 3 and 4.
 *
 * NOTE: This call makes the whole parser tree immutable. If caller calls this
 * more than once, later caller will need to release the same parser exactly that
 * many times using the API kparser_put_parser().
 */
extern const void *kparser_get_parser(const struct kparser_hkey *kparser_key,
				      bool avoid_ref);

/* kparser_put_parser(): Function to return and undo the read only operation done previously by
 * kparser_get_parser(). The parser instance is identified by using a previously obtained opaque
 * parser pointer via API kparser_get_parser(). This undo the immutable change so that any component
 * of the whole parse tree can be deleted again.
 *
 * parser: void *, Non NULL opaque pointer which was previously returned by kparser_get_parser().
 * Caller can use cached opaque pointer as long as system does not restart and kparser.ko is not
 * reloaded.
 * avoid_ref: Set this flag only when this was used in the prio call to
 *            kparser_get_parser(). Incorrect usage of this flag might cause
 *            error and make the parser state unstable.
 *
 * return: boolean, true if put operation is success, else false.
 *
 * NOTE: This call makes the whole parser tree deletable for the very last call.
 */
extern bool kparser_put_parser(const void *parser, bool avoid_ref);

/* net/core/filter.c's callback hook structure to use kParser APIs if kParser enabled */
struct get_kparser_funchooks {
	const void * (*kparser_get_parser_hook)(const struct kparser_hkey
						*kparser_key, bool avoid_ref);
	int (*__kparser_parse_hook)(const void *parser, void *_hdr,
				    size_t parse_len, void *_metadata, size_t metadata_len);
	bool (*kparser_put_parser_hook)(const void *parser, bool avoid_ref);
};

extern struct get_kparser_funchooks kparser_funchooks;

#endif /* _NET_KPARSER_H */
