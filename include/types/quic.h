/*
 * include/types/quic.h
 * This file contains QUIC socket protocol definitions.
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

#ifndef _TYPES_QUIC_H
#define _TYPES_QUIC_H

#define QUIC_PROTOCOL_VERSION_DRAFT_28   0xff00001c /* draft-28 */

#define QUIC_INITIAL_IPV4_MTU      1252 /* (bytes) */
#define QUIC_INITIAL_IPV6_MTU      1232
/* XXX TO DO XXX */
/* Maximum packet length during handshake */
#define QUIC_PACKET_MAXLEN     QUIC_INITIAL_IPV4_MTU

/* The minimum length of Initial packets. */
#define QUIC_INITIAL_PACKET_MINLEN 1200

/*
 * QUIC CID lengths. This the length of the connection IDs for this QUIC
 * implementation.
 */
#define QUIC_CID_LEN               8

/* Common definitions for short and long QUIC packet headers. */
/* QUIC connection ID maximum length for version 1. */
#define QUIC_CID_MAXLEN               20 /* bytes */
/*
 * All QUIC packets with long headers are made of at least (in bytes):
 * flags(1), version(4), DCID length(1), DCID(0..20), SCID length(1), SCID(0..20)
 */
#define QUIC_LONG_PACKET_MINLEN            7
/*
 * All QUIC packets with short headers are made of at least (in bytes):
 * flags(1), DCID length(1), DCID(0..20)
 */
#define QUIC_SHORT_PACKET_MINLEN           2
/* Byte 0 of QUIC packets. */
#define QUIC_PACKET_LONG_HEADER_BIT  0x80 /* Long header format if set, short if not. */
#define QUIC_PACKET_FIXED_BIT        0x40 /* Must always be set for all the headers. */

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |1|1|T|T|X|X|X|X|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                      Long Header Packet Format
 */

/* Two bits (T) for QUIC packet types. */
#define QUIC_PACKET_TYPE_BITMASK     0x03
#define QUIC_PACKET_TYPE_SHIFT       4

enum quic_pkt_type {
	QUIC_PACKET_TYPE_INITIAL,
	QUIC_PACKET_TYPE_0RTT,
	QUIC_PACKET_TYPE_HANDSHAKE,
	QUIC_PACKET_TYPE_RETRY,
	/*
	 * The following one is not defined by the RFC but we define it for our
	 * own convenience.
	 */
	QUIC_PACKET_TYPE_SHORT,
};

/* Packet number field length. */
#define QUIC_PACKET_PNL_BITMASK      0x03
#define QUIC_PACKET_PN_MAXLEN        4

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |0|1|S|R|R|K|P|P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Destination Connection ID (0..160)           ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Packet Number (8/16/24/32)              ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Protected Payload (*)                   ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                      Short Header Packet Format
 */

/* Bit (S) of short header. */
#define QUIC_PACKET_SPIN_BIT         0x20

/* Reserved Bits (R):  The next two bits of byte 0 are reserved.
 * These bits are protected using header protection
 * (see Section 5.4 of [QUIC-TLS]). The value included
 * prior to protection MUST be set to 0. An endpoint MUST treat
 * receipt of a packet that has a non-zero value for these bits,
 * after removing both packet and header protection, as a connection
 * error of type PROTOCOL_VIOLATION. Discarding such a packet after
 * only removing header protection can expose the endpoint to attacks
 * (see Section 9.3 of [QUIC-TLS]).
 */
#define QUIC_PACKET_RESERVED_BITS    0x18 /* (protected) */

#define QUIC_PACKET_KEY_PHASE_BIT    0x04 /* (protected) */

/*
 * Tranport level error codes.
 */
#define NO_ERROR                     0x00
#define INTERNAL_ERROR               0x01
#define CONNECTION_REFUSED_ERROR     0x02
#define FLOW_CONTROL_ERROR           0x03
#define STREAM_LIMIT_ERROR           0x04
#define STREAM_STATE_ERROR           0x05
#define FINAL_SIZE_ERROR             0x06
#define FRAME_ENCODING_ERROR         0x07
#define TRANSPORT_PARAMETER_ERROR    0x08
#define CONNECTION_ID_LIMIT_ERROR    0x09
#define PROTOCOL_VIOLATION           0x0a
#define INVALID_TOKEN                0x0b
#define APPLICATION_ERROR            0x0c
#define CRYPTO_BUFFER_EXCEEDED       0x0d

/* XXX TODO: check/complete this remaining part (256 crypto reserved errors). */
#define CRYPTO_ERROR                0x100

/* Similar to kernel min()/max() definitions. */
#define min(a, b) ({      \
    typeof(a) _a = (a);   \
    typeof(b) _b = (b);   \
    (void) (&_a == &_b);  \
    _a < _b ? _a : _b; })

#define max(a, b) ({      \
    typeof(a) _a = (a);   \
    typeof(b) _b = (b);   \
    (void) (&_a == &_b);  \
    _a > _b ? _a : _b; })

#endif /* _TYPES_QUIC_H */
