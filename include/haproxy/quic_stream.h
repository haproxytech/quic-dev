/*
 * include/haproxy/quic_stream.h
 * This file defines anything related to QUIC streams.
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

#ifndef _HAPROXY_QUIC_STREAM_H
#define _HAPROXY_QUIC_STREAM_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/pool.h>
#include <haproxy/quic_stream-t.h>

#include  <import/eb64tree.h>

/* Allocate a new QUIC stream with <sub_id> as sub ID.
 * Return it if succeeded, NULL if not.
 */
struct quic_strm *new_quic_strm(uint64_t sub_id)
{
	struct quic_strm *strm;

	strm = pool_alloc(pool_head_quic_strm);
	if (strm) {
		strm->sub_id_node.key = sub_id;
		strm->frms = EB_ROOT_UNIQUE;
	}

	return strm;
}

/* Allocate a new STREAM RX frame from <stream_fm> STREAM frame attached to
 * <pkt> RX packet.
 * Return it if succeeded, NULL if not.
 */
struct quic_rx_strm_frm *new_quic_rx_strm_frm(struct quic_stream *stream_frm,
                                              struct quic_rx_packet *pkt)
{
	struct quic_rx_strm_frm *frm;

	frm = pool_alloc(pool_head_quic_rx_strm_frm);
	if (frm) {
		frm->offset_node.key = stream_frm->offset;
		frm->len = stream_frm->len;
		frm->data = stream_frm->data;
		frm->pkt = pkt;
	}

	return frm;
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STREAM_H */
