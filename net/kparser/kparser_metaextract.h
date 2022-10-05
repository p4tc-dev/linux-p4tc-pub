/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * kparser_metaextract.h - kParser metadata helper and structures header file
 *
 * Authors:     Tom Herbert <tom@sipanda.io>
 *              Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#ifndef __KPARSER_METAEXTRACT_H__
#define __KPARSER_METAEXTRACT_H__

#include "kparser_types.h"

#include <asm/byteorder.h>

#ifdef __LITTLE_ENDIAN
#define kparser_htonll(X)						\
	(((__u64)htonl((X) & 0xffffffff) << 32) | htonl((X) >> 32))
#define kparser_ntohll(X)						\
	(((__u64)ntohl((X) & 0xffffffff) << 32) | ntohl((X) >> 32))
#else
#error "Cannot determine endianness"
#define kparser_htonll(X) (X)
#define kparser_ntohll(X) (X)
#endif

/* Metadata extraction pseudo instructions
 *
 * These instructions extract header data and set control data into metadata.
 * Common fields are:
 *    - code: Describes the data being written to the metadata. See descriptions
 *	      below
 *    - frame: Boolean value. If true then the data is a written to the current
 *	      metadata frame (frame + dst_off), else the data is written
 *	      to the metadata base (metadata + dst_off)
 *    - cntr: Counter. If nonzero the data is written to an array defined
 *	      by the specified counter. Note that dst_off in this case could
 *	      be the base off set of an array plus the offset within an
 *	      element of the array
 *    - dst_off: Destination offset into the metadata to write the extracted
 *	      data. This is a nine bits to allow an offset of 0 to 511
 *	      bytes. In the case of writing a sixteen bit constant,
 *	      dst_off is an eight byte field that is multiplied by two
 *	      to derive the target destination offset
 *
 * Metadata extraction codes:
 *    - KPARSER_METADATA_BYTES_EXTRACT: bytes field
 *	    Extract some number of bytes of header data. The src_off field
 *	    indicates the source offset in bytes from the current header being
 *	    processed, and length indicates the number of bytes to be extracted.
 *	    One is added to the length to get the target length. For example,
 *	    to extract the IPv4 source address into metadata, src_off would be
 *	    set to twelve and length would be set to three (that indicates
 *	    to extract four bytes). If e_bit is true then the bytes are endian
 *	    swapped before being stored
 *    - KPARSER_METADATA_NIBBS_EXTRACT: nibbs field
 *	    Extract some number of nibbles of header data. The src_off field
 *	    indicates the source offset in nibbles from the current header being
 *	    processed, and length indicates the number of nibbles to be
 *	    extracted. Note that nibbles are counted such that the high order
 *	    nibble of the first byte is nibble zero, and the low order is
 *	    nibble one. When nibbles are written to be aligned to the
 *	    destination bytes (e.g. the high order nibble to the first
 *	    destination byte contains nibble zero). If an off number of nibbles
 *	    are written, then the last nibble is written to the high order
 *	    nibble of the last byte, and the low order nibble of the last
 *	    byte is zero. If e_bit is true then the resultant bytes are endian
 *	    swapped before being stored
 *    - KPARSER_METADATA_CONSTANT_BYTE_SET: constant_byte field
 *	    Set a byte constant in the metadata. The data field contains the
 *	    value of the byte to be written
 *    - KPARSER_METADATA_CONSTANT_HWORD_SET: constant_hword field
 *	    Set a half word (16 bits) constant in the metadata. The data field
 *	    contains the value of the halfword to be written. Note that dst_off
 *	    is multiplied by two to derive the target offset
 *    - KPARSER_METADATA_OFFSET_SET: offset field
 *	    Set the current absolute offset of a field in a packet. This
 *	    is the offset in two bytes of the current header being processed
 *	    plus the value in add_off which is the offset of the field of
 *	    interest in the current header. For instance, to get the offset of
 *	    the source IP address add_off would be set to twelve; and for a
 *	    plain IPv4 Ethernet packet the value written to metadata would
 *	    be twenty-six (offset of the IPv4 header is fourteen plus twelve
 *	    which is value of add_off and the offset of the source address
 *	    in the IPv4 header). If bit_offset is set then the bit offset of
 *	    the field is written. This is derived as eight times the current
 *	    header byte offset plus add_off. For example, to extract the
 *	    bit offset of the fragment offset of IPv4 header, add_off would
 *	    have the value fifty-one. For a plain IPv4 Ethernet packet, the
 *	    extract bit offset would then be 163
 *    - KPARSER_METADATA_CTRL_HDR_LENGTH: control field
 *	    Write the length of the current header to metadata. The length is
 *	    written in two bytes. A counter operation may be specified as
 *	    described below
 *    - KPARSER_METADATA_CTRL_NUM_NODES: control field
 *	    Write the current number of parse nodes that have been visited to
 *	    metadata. The number of nodes is written in two bytes. A counter
 *	    operation may be specified as described below
 *    - KPARSER_METADATA_CTRL_NUM_ENCAPS: control field
 *	    Write the current number of encapsulation levels to metadata. The
 *	    number of nodes is written in two bytes. A counter operation may be
 *	    specified as described below
 *    - KPARSER_METADATA_CTRL_TIMESTAMP: control field
 *	    Write the receive timestamp of a packet to metadata. The timestamp
 *	    number of nodes is written in eight bytes. A counter operation may
 *	    be specified as described below
 *    - KPARSER_METADATA_CTRL_COUNTER: control_counter field
 *	    Write the current value of a counter to metadata. The counter is
 *	    specified in counter_for_data. The counter is written in two bytes.
 *	    A counter operation may be specified as described below
 *    - KPARSER_METADATA_CTRL_NOOP: control_noop field
 *	    "No operation". This pseudo instruction does not write any data.
 *	    It's primary purpose is to allow counter operations after performing
 *	    non-control pseudo instructions (note that the non-control variants
 *	    don't have a cntr_op field)
 *
 * There are two operations that may be performed on a counter and that are
 * expressed in control type pseudo instructions: increment and reset. A
 * counter operation is set in the cntr_op field of control pseudo instructions.
 * The defined counter operations are:
 *    - KPARSER_METADATA_CNTROP_NULL: No counter operation
 *    - KPARSER_METADATA_CNTROP_INCREMENT: Increment the counter specified
 *	    in cntr by one. The configuration for the counter is check and
 *	    if the limit for the counter is exceeded the appropriate behavior
 *	    is done
 *    - KPARSER_METADATA_CNTROP_RESET: Reset the counter specified
 *          in cntr to zero
 */

/* Metatdata extract codes */
#define KPARSER_METADATA_BYTES_EXTRACT		0 /* Var bytes */
#define KPARSER_METADATA_NIBBS_EXTRACT		1 /* Var bytes */
#define KPARSER_METADATA_CONSTANT_BYTE_SET	2 /* One byte */
#define KPARSER_METADATA_CONSTANT_HWORD_SET	3 /* Two bytes */
#define KPARSER_METADATA_OFFSET_SET		4 /* Two bytes */
#define KPARSER_METADATA_CTRL_HDR_LENGTH	5 /* Two bytes */
#define KPARSER_METADATA_CTRL_NUM_NODES		6 /* Two bytes */
#define KPARSER_METADATA_CTRL_NUM_ENCAPS	7 /* Two bytes */
#define KPARSER_METADATA_CTRL_TIMESTAMP		8 /* Eight bytes */
#define KPARSER_METADATA_CTRL_RET_CODE		9 /* Four bytes */
#define KPARSER_METADATA_CTRL_COUNTER		10 /* Two bytes */
#define KPARSER_METADATA_CTRL_NOOP		11 /* Zero bytes */

#define KPARSER_METADATA_CNTROP_NULL		0
#define KPARSER_METADATA_CNTROP_INCREMENT	1
#define KPARSER_METADATA_CNTROP_RESET		2

/* Metadata extraction pseudo instructions
 * This emulates the custom SiPANDA riscv instructions for metadata extractions,
 * hence these are called pseudo instructions
 */
struct kparser_metadata_extract {
	union {
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 9; // Target offset in frame or meta
			__u32 rsvd: 24;
		} gen;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 9; // Target offset in frame or meta
			__u32 e_bit: 1;	// Swap endianness (true)
			__u32 src_off: 9; // Src offset in header
			__u32 length: 5; // Byte length to read/write
		} bytes;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 9; // Target offset in frame or meta
			__u32 e_bit: 1;	// Swap endianness (true)
			__u32 src_off: 10; // Src offset in header
			__u32 length: 4; // Nibble length to read/write
		} nibbs;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 9; // Target offset / 2 in frame or meta
			__u32 rsvd: 7;
			__u32 data: 8;	// Byte constant
		} constant_byte;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 8; // Target offset / 2 in frame or meta
			__u32 data: 16;	// Byte constant
		} constant_hword;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 9; // Target offset in frame or meta
			__u32 bit_offset: 1;
			__u32 rsvd: 2;
			__u32 add_off: 12; // 3 bits for bit offset
		} offset;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 dst_off: 9; // Target offset in frame or meta
			__u32 cntr_op: 3; // Counter operation
			__u32 cntr_for_data: 3;
			__u32 rsvd: 9;
		} control;
		struct {
			__u32 code: 4;	// One of KPARSER_METADATA_* ops
			__u32 frame: 1;	// Write to frame (true) else to meta
			__u32 cntr: 3;	// Counter number
			__u32 cntr_op: 3; // Counter operation
			__u32 rsvd: 21;
		} control_noop;
		__u32 val;
	};
};

/* Helper macros to make various pseudo instructions */

#define __KPARSER_METADATA_MAKE_BYTES_EXTRACT(FRAME, SRC_OFF, DST_OFF, LEN, E_BIT, CNTR)	\
{												\
	.bytes.code = KPARSER_METADATA_BYTES_EXTRACT,						\
	.bytes.frame = FRAME,									\
	.bytes.src_off = SRC_OFF,								\
	.bytes.dst_off = DST_OFF,								\
	.bytes.length = (LEN) - 1, /* Minimum one byte */					\
	.bytes.e_bit = E_BIT,									\
	.bytes.cntr = CNTR,									\
}

static inline struct kparser_metadata_extract
__kparser_metadata_make_bytes_extract(bool frame, size_t src_off,
				      size_t dst_off, size_t len,
				      bool e_bit,
				      unsigned int cntr)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_BYTES_EXTRACT(frame, src_off,
						      dst_off, len,
						      e_bit, cntr);
	return mde;
}

#define __KPARSER_METADATA_MAKE_NIBBS_EXTRACT(FRAME, NIBB_SRC_OFF,				\
		DST_OFF, NIBB_LEN, E_BIT, CNTR)							\
{												\
	.nibbs.code = KPARSER_METADATA_NIBBS_EXTRACT,						\
	.nibbs.frame = FRAME,									\
	.nibbs.src_off = NIBB_SRC_OFF,								\
	.nibbs.dst_off = DST_OFF,								\
	.nibbs.length = (NIBB_LEN) - 1, /* Minimum one nibble */				\
	.nibbs.e_bit = E_BIT,									\
	.nibbs.cntr = CNTR,									\
}

static inline struct kparser_metadata_extract
__kparser_make_make_nibbs_extract(bool frame, size_t nibb_src_off,
				  size_t dst_off, size_t nibb_len,
				  bool e_bit, unsigned int cntr)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_NIBBS_EXTRACT(frame, nibb_src_off,
						      dst_off, nibb_len,
						      e_bit, cntr);

	return mde;
}

#define __KPARSER_METADATA_MAKE_SET_CONST_BYTE(FRAME, DST_OFF, DATA, CNTR)			\
{												\
	.constant_byte.code = KPARSER_METADATA_CONSTANT_BYTE_SET,				\
	.constant_byte.frame = FRAME,								\
	.constant_byte.dst_off = DST_OFF,							\
	.constant_byte.data = DATA,								\
	.constant_byte.cntr = CNTR,								\
}

static inline struct kparser_metadata_extract
__kparser_metadata_set_const_byte(bool frame, size_t dst_off,
				  __u8 data, unsigned int cntr)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONST_BYTE(frame, dst_off,
						       data, cntr);

	return mde;
}

#define __KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(FRAME, DST_OFF, DATA, CNTR)			\
{												\
	.constant_hword.code =									\
	KPARSER_METADATA_CONSTANT_HWORD_SET,							\
	.constant_hword.frame = FRAME,								\
	.constant_hword.dst_off = DST_OFF,							\
	.constant_hword.data = DATA,								\
	.constant_hword.cntr = CNTR,								\
}

static inline struct kparser_metadata_extract
__kparser_metadata_set_const_halfword(bool frame, size_t dst_off,
				      __u16 data,
				      unsigned int cntr)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONST_HALFWORD(frame, dst_off,
							   data, cntr);

	return mde;
}

#define __KPARSER_METADATA_MAKE_OFFSET_SET(FRAME, DST_OFF, BIT_OFFSET, ADD_OFF, CNTR)		\
{												\
	.offset.code = KPARSER_METADATA_OFFSET_SET,						\
	.offset.frame = FRAME,									\
	.offset.dst_off = DST_OFF,								\
	.offset.bit_offset = BIT_OFFSET,							\
	.offset.add_off = ADD_OFF,								\
	.offset.cntr = CNTR,									\
}

static inline struct kparser_metadata_extract
__kparser_metadata_offset_set(bool frame, size_t dst_off,
			      bool bit_offset, size_t add_off, unsigned int cntr)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_OFFSET_SET(frame, dst_off,
						   bit_offset, add_off, cntr);
	return mde;
}

#define __KPARSER_METADATA_MAKE_SET_CONTROL_COUNTER(FRAME, DST_OFF, CNTR_DATA, CNTR, CNTR_OP)	\
{												\
	.control.code = KPARSER_METADATA_CTRL_COUNTER,						\
	.control.frame = FRAME,									\
	.control.dst_off = DST_OFF,								\
	.control.cntr = CNTR,									\
	.control.cntr_op = CNTR_OP,								\
	.control.cntr_for_data = CNTR_DATA,							\
}

static inline struct kparser_metadata_extract
__kparser_metadata_set_control_counter(bool frame, size_t dst_off,
				       unsigned int cntr_data,
		unsigned int cntr,
		unsigned int cntr_op)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONTROL_COUNTER(frame,
							    dst_off, cntr_data, cntr,
							    cntr_op);
	return mde;
}

#define __KPARSER_METADATA_MAKE_SET_CONTROL(FRAME, CODE, DST_OFF, CNTR, CNTR_OP)		\
{												\
	.control.code = CODE,									\
	.control.frame = FRAME,									\
	.control.dst_off = DST_OFF,								\
	.control.cntr = CNTR,									\
	.control.cntr_op = CNTR_OP,								\
}

static inline struct kparser_metadata_extract
__kparser_metadata_set_control(bool frame, unsigned int code,
			       size_t dst_off, unsigned int cntr,
			       unsigned int cntr_op)
{
	const struct kparser_metadata_extract mde =
		__KPARSER_METADATA_MAKE_SET_CONTROL(frame, code, dst_off,
						    cntr, cntr_op);
	return mde;
}

struct kparser_metadata_table {
	int num_ents;
	struct kparser_metadata_extract *entries;
};

/* Extract functions */
static inline int __kparser_metadata_bytes_extract(const __u8 *sptr,
						   __u8 *dptr, size_t length, bool e_bit)
{
	__u16 v16;
	__u32 v32;
	__u64 v64;
	int i;

	if (!dptr)
		return KPARSER_OKAY;

	switch (length) {
	case sizeof(__u8):
		*dptr = *sptr;
		break;
	case sizeof(__u16):
		v16 = *(__u16 *)sptr;
		*((__u16 *)dptr) = e_bit ? ntohs(v16) : v16;
		break;
	case sizeof(__u32):
		v32 = *(__u32 *)sptr;
		*((__u32 *)dptr) = e_bit ? ntohl(v32) : v32;
		break;
	case sizeof(__u64):
		v64 = *(__u64 *)sptr;
		*((__u64 *)dptr) = e_bit ? kparser_ntohll(v64) : v64;
		break;
	default:
		if (e_bit) {
			for (i = 0; i < length; i++)
				dptr[i] = sptr[length - 1 - i];
		} else {
			memcpy(dptr, sptr, length);
		}
	}

	return KPARSER_OKAY;
}

static inline void *metadata_get_dst(size_t dst_off, void *mdata)
{
	return &((__u8 *)mdata)[dst_off];
}

static inline bool __metatdata_validate_counter(const struct kparser_parser *parser,
						unsigned int cntr)
{
	if (!parser) {
		pr_warn("Metadata counter is set for extraction but no parser is set");
		return false;
	}

	if (!parser->cntrs) {
		pr_warn("Metadata counter is set but no counters are configured for parser");
		return false;
	}

	if (cntr >= KPARSER_CNTR_NUM_CNTRS) {
		pr_warn("Metadata counter %u is greater than maximum %u",
			cntr, KPARSER_CNTR_NUM_CNTRS);
		return false;
	}

	return true;
}

static inline void *metadata_get_dst_cntr(const struct kparser_parser *parser,
					  size_t dst_off, void *mdata,
		unsigned int cntr, int code)
{
	const struct kparser_cntr_conf *cntr_conf;
	__u8 *dptr = &((__u8 *)mdata)[dst_off];
	size_t step;

	if (!cntr)
		return dptr;

	cntr--; // Make zero based to access array

	if (!__metatdata_validate_counter(parser, cntr))
		return dptr;

	cntr_conf = &parser->cntrs_conf.cntrs[cntr];

	if (code != KPARSER_METADATA_CTRL_COUNTER) {
		if (parser->cntrs->cntr[cntr] >= cntr_conf->array_limit) {
			if (!cntr_conf->array_limit ||
			    !cntr_conf->overwrite_last)
				return NULL;
			step = cntr_conf->array_limit - 1;
		} else {
			step = parser->cntrs->cntr[cntr];
		}

		dptr += cntr_conf->el_size * step;
	}

	return dptr;
}

static inline int __metadata_cntr_operation(const struct kparser_parser *parser,
					    unsigned int operation, unsigned int cntr)
{
	/* cntr 0 means no counter attached, the index starts from 1 in this case
	 */
	if (!cntr)
		return KPARSER_OKAY;

	cntr--; /* Make zero based to access array */

	if (!__metatdata_validate_counter(parser, cntr))
		return KPARSER_STOP_BAD_CNTR;

	switch (operation) {
	default:
	case KPARSER_METADATA_CNTROP_NULL:
		break;
	case KPARSER_METADATA_CNTROP_INCREMENT:
		/* Note: parser is const but
		 * parser->cntrs->cntr is writable
		 */
		if (parser->cntrs->cntr[cntr] <
		    parser->cntrs_conf.cntrs[cntr].max_value)
			parser->cntrs->cntr[cntr]++;
		else if (parser->cntrs_conf.cntrs[cntr].error_on_exceeded)
			return KPARSER_STOP_CNTR1 - cntr;
		break;
	case KPARSER_METADATA_CNTROP_RESET:
		parser->cntrs->cntr[cntr] = 0;
		break;
	}

	return KPARSER_OKAY;
}

static inline int kparser_metadata_bytes_extract(const struct kparser_parser *parser,
						 struct kparser_metadata_extract mde,
						 const void *hdr, void *mdata)
{
	__u8 *dptr = metadata_get_dst_cntr(parser, mde.bytes.dst_off, mdata,
					   mde.bytes.cntr, 0);
	const __u8 *sptr = &((__u8 *)hdr)[mde.bytes.src_off];

	if (!dptr)
		return KPARSER_OKAY;

	return __kparser_metadata_bytes_extract(sptr, dptr,
						mde.bytes.length + 1,
						mde.bytes.e_bit);
}

static inline int kparser_metadata_nibbs_extract(const struct kparser_parser *parser,
						 struct kparser_metadata_extract mde,
						 const void *hdr, void *mdata)
{
	__u8 *dptr = metadata_get_dst_cntr(parser, mde.nibbs.dst_off, mdata,
					   mde.nibbs.cntr, 0);
	const __u8 *sptr = &((__u8 *)hdr)[mde.nibbs.src_off / 2];
	size_t nibb_len = mde.nibbs.length + 1;
	__u8 data;
	int i;

	if (!dptr)
		return KPARSER_OKAY;

	if (mde.nibbs.src_off % 2 == 0 && nibb_len % 2 == 0) {
		/* This is effectively a byte transfer case */

		return __kparser_metadata_bytes_extract(sptr, dptr,
							mde.nibbs.length / 2,
							mde.nibbs.e_bit);
	}

	if (mde.nibbs.e_bit) {
		/* Endianness bit is set. dlen is the number of bytes
		 * set for output
		 */
		size_t dlen = (nibb_len + 1) / 2;

		if (mde.nibbs.src_off % 2) {
			/* Starting from the odd nibble */
			if (nibb_len % 2) {
				/* Odd length and odd start nibble offset. Set
				 * the reverse of all the bytes after the first
				 * nibble, and * construct the last byte from
				 * the low order nibble of the first input byte
				 */
				for (i = 0; i < dlen - 1; i++)
					dptr[i] = sptr[dlen - 1 - i];
				dptr[i] = sptr[0] & 0xf;
			} else {
				/* Even length and n-bit is set. Logically
				 * shift all the nibbles in the string left and
				 * then set the reversed bytes.
				 */

				/* High order nibble of last byte becomes
				 * low order nibble of first output byte
				 */
				data = sptr[dlen] >> 4;

				for (i = 0; i < dlen - 1; i++) {
					/* Construct intermediate bytes. data
					 * contains the input high order nibble
					 * of the next input byte shifted right.
					 * That value is or'ed with the shifted
					 * left low order nibble of the current
					 * byte. The result is set in the
					 * reversed position in the output
					 */
					dptr[i] = data | sptr[dlen - 1 - i] << 4;

					/* Get the next data value */
					data = sptr[dlen - 1 - i] >> 4;
				}
				/* Set the last byte as the or of the last
				 * data value and the low order nibble of the
				 * zeroth byte of the input shifted left
				 */
				dptr[i] = data | sptr[0] << 4;
			}
		} else {
			/* Odd length (per check above) and n-bit is not
			 * set. Logically shift all the nibbles in the
			 * string right and then set the reversed bytes
			 */

			/* High order nibble of last byte becomes
			 * low order nibble of first output byte
			 */
			data = sptr[dlen - 1] >> 4;

			for (i = 0; i < dlen - 1; i++) {
				/* Construct intermediate bytes. data contains
				 * the input high order nibble of the next
				 * input byte shifted right. That value is
				 * or'ed with the shifted left low order nibble
				 * of the current byte. The result is set in the
				 * reversed position in the output
				 */
				dptr[i] = data | sptr[dlen - 2 - i] << 4;

				/* Get next data value */
				data = sptr[dlen - 2 - i] >> 4;
			}

			/* Last output byte is set to high oder nibble of first
			 * input byte shifted right
			 */
			dptr[i] = data;
		}
	} else {
		/* No e-bit (no endiannes) */

		size_t byte_len;
		int ind = 0;

		if (mde.nibbs.src_off % 2) {
			/* Starting from the odd nibble. Set first output byte
			 * to masked low order nibble of first input byte
			 */
			dptr[0] = sptr[0] & 0xf;
			ind = 1;
			nibb_len--;
		}

		/* Copy all the whole intermediate bytes */
		byte_len = nibb_len / 2;
		memcpy(&dptr[ind], &sptr[ind], byte_len);

		if (nibb_len % 2) {
			/* Have an odd nibble at the endian. Set the last
			 * output byte to the mask high order nibble of the
			 * last input byte
			 */
			dptr[ind + byte_len] = sptr[ind + byte_len] & 0xf0;
		}
	}

	return KPARSER_OKAY;
}

static inline int kparser_metadata_const_set_byte(const struct kparser_parser *parser,
						  struct kparser_metadata_extract mde,
						  void *mdata)
{
	__u8 *dptr = metadata_get_dst_cntr(parser, mde.constant_byte.dst_off,
					   mdata, mde.constant_byte.cntr, 0);

	if (dptr)
		*dptr = mde.constant_byte.data;

	return KPARSER_OKAY;
}

static inline int kparser_metadata_const_set_hword(const struct kparser_parser *parser,
						   struct kparser_metadata_extract mde,
						   void *mdata)
{
	__u16 *dptr = metadata_get_dst_cntr(parser, mde.constant_hword.dst_off,
					    mdata, mde.constant_hword.cntr, 0);

	if (dptr)
		*dptr = mde.constant_hword.data;

	return KPARSER_OKAY;
}

static inline int kparser_metadata_set_offset(const struct kparser_parser *parser,
					      struct kparser_metadata_extract mde,
					      void *mdata, size_t hdr_offset)
{
	__u16 *dptr = metadata_get_dst_cntr(parser, mde.offset.dst_off, mdata,
					    mde.offset.cntr, 0);

	if (dptr) {
		*dptr = mde.offset.bit_offset ?
			8 * hdr_offset + mde.offset.add_off :
			hdr_offset + mde.offset.add_off;
	}

	return KPARSER_OKAY;
}

static inline int __kparser_metadata_control_extract(const struct kparser_parser *parser,
						     const struct kparser_metadata_extract mde,
						     const void *_hdr, size_t hdr_len,
						     size_t hdr_offset, void *mdata,
						     const struct kparser_ctrl_data *ctrl)
{
	__u16 *dptr = metadata_get_dst_cntr(parser, mde.control.dst_off, mdata,
					    mde.control.cntr, mde.control.code);

	switch (mde.control.code) {
	case KPARSER_METADATA_CTRL_HDR_LENGTH:
		if (dptr)
			*((__u16 *)dptr) = hdr_len;
		break;
	case KPARSER_METADATA_CTRL_NUM_NODES:
		if (dptr)
			*((__u16 *)dptr) = ctrl->node_cnt;
		break;
	case KPARSER_METADATA_CTRL_NUM_ENCAPS:
		if (dptr)
			*((__u16 *)dptr) = ctrl->encap_levels;
		break;
	case KPARSER_METADATA_CTRL_TIMESTAMP:
		/* TODO */
		break;
	case KPARSER_METADATA_CTRL_COUNTER:
		if (!__metatdata_validate_counter(parser,
						  mde.control.cntr_for_data))
			return KPARSER_STOP_BAD_CNTR;
		if (dptr)
			*(__u16 *)dptr = parser->cntrs->cntr[mde.control.cntr_for_data - 1];
		break;
	case KPARSER_METADATA_CTRL_RET_CODE:
		if (dptr)
			*((int *)dptr) = ctrl->ret;
		break;
	case KPARSER_METADATA_CTRL_NOOP:
		break;
	default:
		pr_debug("Unknown extract\n");
		return KPARSER_STOP_BAD_EXTRACT;
	}

	return __metadata_cntr_operation(parser, mde.control.cntr_op, mde.control.cntr);
}

/* Front end functions to process one metadata extraction pseudo instruction
 * in the context of parsing a packet
 */
static inline int kparser_metadata_extract(const struct kparser_parser *parser,
					   const struct kparser_metadata_extract mde,
					   const void *_hdr, size_t hdr_len,
					   size_t hdr_offset, void *_metadata,
					   void *_frame,
					   const struct kparser_ctrl_data *ctrl)
{
	void *mdata = mde.gen.frame ? _frame : _metadata;
	int ret;

	switch (mde.gen.code) {
	case KPARSER_METADATA_BYTES_EXTRACT:
		ret = kparser_metadata_bytes_extract(parser, mde,
						     _hdr, mdata);
		break;
	case KPARSER_METADATA_NIBBS_EXTRACT:
		ret = kparser_metadata_nibbs_extract(parser, mde,
						     _hdr, mdata);
		break;
	case KPARSER_METADATA_CONSTANT_BYTE_SET:
		ret = kparser_metadata_const_set_byte(parser, mde,
						      mdata);
		break;
	case KPARSER_METADATA_CONSTANT_HWORD_SET:
		ret = kparser_metadata_const_set_hword(parser, mde,
						       mdata);
		break;
	case KPARSER_METADATA_OFFSET_SET:
		ret = kparser_metadata_set_offset(parser, mde, mdata,
						  hdr_offset);
		break;
	default: /* Should be a control metadata extraction */
		ret = __kparser_metadata_control_extract(parser, mde,
							 _hdr,
							 hdr_len,
							 hdr_offset,
							 mdata, ctrl);
	}

	return ret;
}

static inline bool kparser_metadata_convert(const struct kparser_conf_metadata *conf,
					    struct kparser_metadata_extract *mde,
					    int cntridx, int cntr_arr_idx)
{
	__u32 encoding_type;

	switch (conf->type) {
	case KPARSER_METADATA_HDRDATA:
		*mde = __kparser_metadata_make_bytes_extract(conf->frame,
							     conf->soff, conf->doff, conf->len,
							     conf->e_bit, cntridx);
		return true;

	case KPARSER_METADATA_HDRDATA_NIBBS_EXTRACT:
		*mde = __kparser_make_make_nibbs_extract(conf->frame,
							 conf->soff,
							 conf->doff,
							 conf->len,
							 conf->e_bit,
							 cntridx);
		return true;

	case KPARSER_METADATA_BIT_OFFSET:
		*mde =	__kparser_metadata_offset_set(conf->frame,
						      conf->doff,
						      true,
						      conf->add_off,
						      cntridx);
		return true;

	case KPARSER_METADATA_OFFSET:
		*mde =	__kparser_metadata_offset_set(conf->frame,
						      conf->doff,
						      false,
						      conf->add_off,
						      cntridx);
		return true;

	case KPARSER_METADATA_CONSTANT_BYTE:
		*mde =	__kparser_metadata_set_const_byte(conf->frame,
							  conf->doff, conf->constant_value,
				cntridx);
		return true;

	case KPARSER_METADATA_CONSTANT_HALFWORD:
		*mde =	__kparser_metadata_set_const_halfword(conf->frame,
							      conf->doff, conf->constant_value,
				cntridx);
		return true;

	case KPARSER_METADATA_COUNTER:
		*mde = __kparser_metadata_set_control_counter(conf->frame, conf->doff,
							      cntridx, cntr_arr_idx,
							      conf->cntr_op);
		return true;

	case KPARSER_METADATA_HDRLEN:
		encoding_type = KPARSER_METADATA_CTRL_HDR_LENGTH;
		break;

	case KPARSER_METADATA_NUMENCAPS:
		encoding_type = KPARSER_METADATA_CTRL_NUM_ENCAPS;
		break;

	case KPARSER_METADATA_NUMNODES:
		encoding_type = KPARSER_METADATA_CTRL_NUM_NODES;
		break;

	case KPARSER_METADATA_TIMESTAMP:
		encoding_type = KPARSER_METADATA_CTRL_TIMESTAMP;
		break;

	case KPARSER_METADATA_RETURN_CODE:
		encoding_type = KPARSER_METADATA_CTRL_RET_CODE;
		break;

	case KPARSER_METADATA_COUNTEROP_NOOP:
		encoding_type = KPARSER_METADATA_CTRL_NOOP;
		break;

	default:
		return false;
	}

	*mde = __kparser_metadata_set_control(conf->frame, encoding_type, conf->doff,
					      cntridx, conf->cntr_op);

	return true;
}

#endif /* __KPARSER_METAEXTRACT_H__ */
