/*
 * include/haproxy/quic_stream-t.h
 * This file contains types for QUIC streams.
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_STREAM_T_H
#define _HAPROXY_QUIC_STREAM_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <stdint.h>

#include <haproxy/pool.h>
#include <haproxy/xprt_quic-t.h>

#include <import/eb64tree.h>

/* Bit shift to get the stream sub ID for internal use which is obtained
 * shifting the stream IDs by this value, knowing that the
 * QUIC_STREAM_ID_TYPE_SHIFT less significant bits identify the stream ID
 * types (client initiated bidirectional, server initiated bidirectional,
 * client initiated unidirectional, server initiated bidirectional).
 * Note that there is no reference to such stream sub IDs in the RFC.
 */
#define QUIC_STREAM_ID_TYPE_SHIFT 2
#define QUIC_STREAM_ID_TYPE_MASK  0x3

/* Stream ID types */
enum quic_strm_id_types {
	CLT_BIDI = 0,
	SRV_BIDI = 1,
	CLT_UNI  = 2,
	SRV_UNI  = 3,
	/* Must be the last one */
	MAX_STRM_ID_TYPES = 4,
};

/* Structure to store information about RX STREAM frames. */
struct quic_rx_strm_frm {
	struct eb64_node offset_node;
	uint64_t len;
	const unsigned char *data;
	struct quic_rx_packet *pkt;
};

/* QUIC stream identified by its sub ID node. */
struct quic_strm {
	struct eb64_node sub_id_node;
	struct eb_root frms;
};

/* Store all the QUIC streams for a connection. */
struct quic_strms {
	uint64_t largest_sub_id;
	struct eb_root root;
};

extern struct pool_head *pool_head_quic_rx_strm_frm;
extern struct pool_head *pool_head_quic_strm;

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_T_H */
