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

#include <types/quic.h>

/* The maximum number of QUIC packets stored by the fd I/O handler by QUIC
 * connection. Must be a power of two.
 */
#define QUIC_CONN_MAX_PACKET  64

struct quic_cid {
	unsigned char len;
	unsigned char data[QUIC_CID_MAXLEN];
};

struct quic_packet {
	int from_server;
	int long_header;
	unsigned char type;
	uint32_t version;
	struct quic_cid dcid;
	struct quic_cid scid;
	/* Packet number */
	uint64_t pn;
	/* Packet number length */
	uint32_t pnl;
	uint64_t token_len;
	/* Packet length */
	uint64_t len;
	unsigned char data[QUIC_PACKET_MAXLEN];
};


struct crypto_frame {
	const unsigned char *data;
	size_t datalen;
	size_t offset;
};

struct quic_conn {
	size_t cid_len;
	int aead_algo;
	struct ctx {
		unsigned char initial_secret[32];
		unsigned char client_initial_secret[32];
		unsigned char key[16];
		unsigned char iv[12];
		unsigned char aead_iv[16];
		/* Header protection key.
		 * Note: the header protection is applied after packet protection.
		 * As the header belong to the data, its protection must be removed before removing
		 * the packet protection.
		 */
		unsigned char hp[16];
		const EVP_CIPHER *aead;
	} ctx;
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

	/* XXX Do not insert anything after <cid> which contains a flexible array member!!! XXX */
	struct ebmb_node cid;
};

#endif /* _TYPES_QUIC_CONN_H */
