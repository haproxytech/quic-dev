/*
 * include/haproxy/qpack-t.h
 * This file containts types for QPACK
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

#ifndef _HAPROXY_QPACK_T_H
#define _HAPROXY_QPACK_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

/* Encoder */
/* Instruction bitmask */
#define QPACK_ENC_INST_BITMASK 0xe0
/* Instructions */
#define QPACK_ENC_INST_DUPLICATE            0x00 // Duplicate
#define QPACK_ENC_INST_SET_DT_CAPACITY      0x20 // Set Dynamic Table Capacity
#define QPACK_ENC_INST_INSERT_WITH_LIT_NAME 0x40 // Insert With Literal Name
#define QPACK_ENC_INST_INSERT_WITH_NAME_REF 0x80 // Insert With Name Reference

/* Decoder */
/* Instructions bitmask */
#define QPACK_DEC_INST_BITMASK 0xc0
/* Instructions */
#define QPACK_DEC_INST_INSERT_COUNT_INC     0x00 // Insert Count Increment
#define QPACK_DEC_INST_STREAM_CANCEL        0x40 // Stream Cancellation
#define QPACK_DEC_INST_SECT_ACK             0x80 // Section Acknowledgment

#endif /* USE_QUIC */
#endif /* _HAPROXY_QPACK_T_H */
