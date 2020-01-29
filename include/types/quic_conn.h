/*
 * include/types/quic_conn.h
 * This file contains QUIC connection definitions.
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

#ifndef _TYPES_QUIC_CONN_H
#define _TYPES_QUIC_CONN_H

#include <sys/socket.h>

#include <types/quic.h>
#include <types/quic_tls.h>

#include <eb64tree.h>
#include <ebmbtree.h>


/* The maximum number of QUIC packets stored by the fd I/O handler by QUIC
 * connection. Must be a power of two.
 */
#define QUIC_CONN_MAX_PACKET  64

/*
 * This struct is used by ebmb_node structs as last member of flexible array.
 * So do not change the order of the member of quic_cid struct.
 * <data> member must be the first one.
 */
struct quic_cid {
	unsigned char data[QUIC_CID_MAXLEN + sizeof(struct sockaddr_storage)];
	unsigned char len;
};

#define QUIC_STATELESS_RESET_TOKEN_LEN 16

struct preferred_address {
	uint16_t ipv4_port;
	uint16_t ipv6_port;
	uint8_t ipv4_addr[4];
	uint8_t ipv6_addr[16];
	struct quic_cid cid;
	uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
};

/* Default values for some of transport parameters */
#define QUIC_DFLT_MAX_PACKET_SIZE     65527
#define QUIC_DFLT_ACK_DELAY_COMPONENT     3 /* milliseconds */
#define QUIC_DFLT_MAX_ACK_DELAY          25 /* milliseconds */

/* Types of QUIC transport parameters */
#define QUIC_TP_ORIGINAL_CONNECTION_ID               0
#define QUIC_TP_IDLE_TIMEOUT                         1
#define QUIC_TP_STATELESS_RESET_TOKEN                2
#define QUIC_TP_MAX_PACKET_SIZE                      3
#define QUIC_TP_INITIAL_MAX_DATA                     4
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL   5
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE  6
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI          7
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI             8
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI              9
#define QUIC_TP_ACK_DELAY_EXPONENT                  10
#define QUIC_TP_MAX_ACK_DELAY                       11
#define QUIC_TP_DISABLE_ACTIVE_MIGRATION            12
#define QUIC_TP_PREFERRED_ADDRESS                   13
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT          14

/*
 * These defines are not for transport parameter type, but the maximum accepted value for
 * transport parameter types.
 */
#define QUIC_TP_ACK_DELAY_EXPONENT_LIMIT 20
#define QUIC_TP_MAX_ACK_DELAY_LIMIT      (1UL << 14)

/*
 * QUIC transport parameters.
 * Note that forbidden parameters sent by clients MUST generate TRANSPORT_PARAMETER_ERROR errors.
 */
struct quic_transport_params {
	uint64_t idle_timeout;
	uint64_t max_packet_size;                                      /* Default: 65527 (max of UDP payload for IPv6) */
	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;
	uint64_t ack_delay_exponent;                                   /* Default: 3, max: 20 */
	uint64_t max_ack_delay;                                        /* Default: 3ms, max: 2^14ms*/
	uint64_t active_connection_id_limit;

	/* Booleans */
	uint8_t disable_active_migration;
	uint8_t with_stateless_reset_token;
	uint8_t with_preferred_address;
	uint8_t with_original_connection_id;

	uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN]; /* Forbidden for clients */
	struct quic_cid original_connection_id;                        /* Forbidden for clients */
	struct preferred_address preferred_address;                    /* Forbidden for clients */
};

/* The QUIC packet numbers are 62-bits integers */
#define QUIC_MAX_PACKET_NUM      ((1ULL << 62) - 1)

/* Default QUIC connection transport parameters */
extern struct quic_transport_params quid_dflt_transport_params;

struct quic_packet {
	int from_server;
	int long_header;
	unsigned char type;
	uint32_t version;
	/* Initial desctination connection ID. */
	struct quic_cid dcid;
	struct quic_cid scid;
	/* Packet number */
	uint64_t pn;
	/* Packet number length */
	uint32_t pnl;
	uint64_t token_len;
	/* Packet length */
	uint64_t len;
	size_t aad_len;
	unsigned char data[QUIC_PACKET_MAXLEN];
	struct eb64_node pn_node;
};

struct crypto_frame {
	unsigned char data[QUIC_PACKET_MAXLEN];
	size_t datalen;
	size_t offset;
};

struct quic_conn {
	uint32_t version;

	/* Initial DCID (comming with first Initial packets) */
	struct ebmb_node idcid_node;
	struct quic_cid idcid;

	struct quic_cid dcid;
	struct ebmb_node scid_node;
	struct quic_cid scid;

	struct quic_tls_ctx tls_ctx[QUIC_TLS_ENC_LEVEL_MAX];
	struct eb_root iqpkts[QUIC_TLS_ENC_LEVEL_MAX];
	struct quic_pktns tx_ns[QUIC_TLS_PKTNS_MAX];
	struct quic_pktns rx_ns[QUIC_TLS_PKTNS_MAX];
	/* One largest packet number by client/server by number space */
	uint64_t client_max_pn[3];
	uint64_t server_max_pn[3];
	/* Last QUIC_CONN_MAX_PACKET QUIC received packets */
	struct quic_packet pkts[QUIC_CONN_MAX_PACKET];
	/* The packet used among ->pkts to store the current QUIC received packet */
	int curr_pkt;

	struct crypto_frame icfs[QUIC_CONN_MAX_PACKET];
	int curr_icf;
	int pend_icf;
};

#endif /* _TYPES_QUIC_CONN_H */
