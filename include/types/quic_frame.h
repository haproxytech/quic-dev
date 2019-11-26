/*
 * include/types/quic_frame.h
 * This file contains QUIC frame definitions.
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

#ifndef _TYPES_QUIC_FRAME_H
#define _TYPES_QUIC_FRAME_H

/* QUIC frame types. */
#define QUIC_FT_PADDING              0x00
#define QUIC_FT_PING                 0x01
#define QUIC_FT_ACK                  0x02
#define QUIC_FT_ACK_ECN              0x03
#define QUIC_FT_RESET_STREAM         0x04
#define QUIC_FT_STOP_SENDING         0x05
#define QUIC_FT_CRYPTO               0x06
#define QUIC_FT_NEW_TOKEN            0x07

#define QUIC_FT_STREAM_8             0x08
#define QUIC_FT_STREAM_9             0x09
#define QUIC_FT_STREAM_A             0x0a
#define QUIC_FT_STREAM_B             0x0b
#define QUIC_FT_STREAM_C             0x0c
#define QUIC_FT_STREAM_D             0x0d
#define QUIC_FT_STREAM_E             0x0e
#define QUIC_FT_STREAM_F             0x0f

#define QUIC_FT_MAX_DATA             0x10
#define QUIC_FT_MAX_STREAM_DATA      0x11
#define QUIC_FT_MAX_STREAMS_BIDI     0x12
#define QUIC_FT_MAX_STREAMS_UNI      0x13
#define QUIC_FT_DATA_BLOCKED         0x14
#define QUIC_FT_STREAM_DATA_BLOCKED  0x15
#define QUIC_FT_STREAMS_BLOCKED_BIDI 0x16
#define QUIC_FT_STREAMS_BLOCKED_UNI  0x17
#define QUIC_FT_NEW_CONNECTION_ID    0x18
#define QUIC_FT_RETIRE_CONNECTION_ID 0x19
#define QUIC_FT_PATH_CHALLENGE       0x1a
#define QUIC_FT_PATH_RESPONSE        0x1b
#define QUIC_FT_CONNECTION_CLOSE_TPT 0x1c
#define QUIC_FT_CONNECTION_CLOSE_APP 0x1d

#endif /* _TYPES_QUIC_FRAME_H */
