/*
 * HPACK decompressor
 *
 * Copyright 2021 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/h2.h>
#include <haproxy/hpack-dec.h>
#include <haproxy/hpack-huff.h>
#include <haproxy/hpack-tbl.h>
#include <haproxy/tools.h>

#define DEBUG_HPACK

#if defined(DEBUG_HPACK)
#define qpack_debug_printf printf
#define qpack_debug_hexdump debug_hexdump
#else
#define qpack_debug_printf(...) do { } while (0)
#define qpack_debug_hexdump(...) do { } while (0)
#endif


/* reads a varint from <raw>'s lowest <b> bits and <len> bytes max (raw included).
 * returns the 64-bit value on success after updating buf and len_in. Forces
 * len_in to (uint64_t)-1 on truncated input.
 * Note that this function is similar to the one used for HPACK (except that is supports
 * up to 62-bits integers).
 */
static uint64_t qpack_get_varint(const unsigned char **buf, uint64_t *len_in, int b)
{
	uint64_t ret = 0;
	int len = *len_in;
	const uint8_t *raw = *buf;
	uint8_t shift = 0;

	len--;
	ret = *raw++ & ((1 << b) - 1);
	if (ret != (uint64_t)((1 << b) - 1))
		goto end;

	while (len && (*raw & 128)) {
		ret += ((uint64_t)*raw++ & 127) << shift;
		shift += 7;
		len--;
	}

	/* last 7 bits */
	if (!len)
		goto too_short;

	len--;
	ret += ((uint64_t)*raw++ & 127) << shift;

 end:
	*buf = raw;
	*len_in = len;
	return ret;

 too_short:
	*len_in = (uint64_t)-1;
	return 0;
}

int qpack_decode(struct buffer *buf)
{
	size_t len;

	len = b_data(buf);
	qpack_debug_hexdump(stderr, "[QPACK-DEC] ", b_head(buf), 0, len);

	if (!len)
		return 0;

#if 0
	pos = *buf;
	switch (*pos) {
	case QPACK_DEC_INST_INSERT_COUNT_INC:
		break;
	case QPACK_DEC_INST_STREAM_CANCEL:
		break;
	case QPACK_DEC_INST_SECT_ACK:
		break;
	}
#endif
}
