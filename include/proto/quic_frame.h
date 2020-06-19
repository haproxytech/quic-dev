/*
 * include/proto/quic_conn.h
 * This file contains definitions for QUIC connections.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _PROTO_QUIC_FRAME_H
#define _PROTO_QUIC_FRAME_H

#include <types/quic_frame.h>
#include <types/xprt_quic.h>

const char *quic_frame_type_string(enum quic_frame_type ft);

int qc_build_frm(unsigned char **buf, const unsigned char *end,
                 struct quic_frame *frm, struct quic_conn *conn);

int qc_parse_frm(struct quic_frame *frm, struct quic_rx_packet *pkt,
                 const unsigned char **buf, const unsigned char *end,
                 struct quic_conn *conn);

#endif /* _PROTO_QUIC_FRAME_H */
