/*
 * include/types/xprt_quic.h
 * This file contains applet function prototypes
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

#ifndef _TYPES_XPRT_QUIC_H
#define _TYPES_XPRT_QUIC_H

#include <sys/socket.h>
#include <openssl/ssl.h>

#include <common/mini-clist.h>

#include <types/quic.h>
#include <types/quic_cc.h>
#include <types/quic_frame.h>
#include <types/quic_tls.h>
#include <types/quic_loss.h>
#include <types/task.h>

#include <eb64tree.h>
#include <ebmbtree.h>

/* The maximum number of QUIC packets stored by the fd I/O handler by QUIC
 * connection. Must be a power of two.
 */
#define QUIC_CONN_MAX_PACKET  64

#define QUIC_STATELESS_RESET_TOKEN_LEN 16

#define           QUIC_EV_CONN_NEW       (1ULL << 0)
#define           QUIC_EV_CONN_INIT      (1ULL << 1)
#define           QUIC_EV_CONN_ISEC      (1ULL << 2)
#define           QUIC_EV_CONN_RSEC      (1ULL << 3)
#define           QUIC_EV_CONN_WSEC      (1ULL << 4)
#define           QUIC_EV_CONN_RWSEC     (1ULL << 5)
#define           QUIC_EV_CONN_LPKT      (1ULL << 6)
#define           QUIC_EV_CONN_SPKT      (1ULL << 7)
#define           QUIC_EV_CONN_CHPKT     (1ULL << 8)
#define           QUIC_EV_CONN_HPKT      (1ULL << 9)
#define           QUIC_EV_CONN_PAPKT     (1ULL << 10)
#define           QUIC_EV_CONN_PAPKTS    (1ULL << 11)
#define           QUIC_EV_CONN_HDSHK     (1ULL << 12)
#define           QUIC_EV_CONN_RMHP      (1ULL << 13)
#define           QUIC_EV_CONN_PRSHPKT   (1ULL << 14)
#define           QUIC_EV_CONN_PRSAPKT   (1ULL << 15)
#define           QUIC_EV_CONN_PRSFRM    (1ULL << 16)
#define           QUIC_EV_CONN_PRSAFRM   (1ULL << 17)
#define           QUIC_EV_CONN_BFRM      (1ULL << 18)
#define           QUIC_EV_CONN_PHPKTS    (1ULL << 19)
#define           QUIC_EV_CONN_TRMHP     (1ULL << 20)
#define           QUIC_EV_CONN_ELRMHP    (1ULL << 21)
#define           QUIC_EV_CONN_ELRXPKTS  (1ULL << 22)
#define           QUIC_EV_CONN_SSLDATA   (1ULL << 23)
#define           QUIC_EV_CONN_RXCDATA   (1ULL << 24)
#define           QUIC_EV_CONN_ADDDATA   (1ULL << 25)
#define           QUIC_EV_CONN_FFLIGHT   (1ULL << 26)
#define           QUIC_EV_CONN_SSLALERT  (1ULL << 27)
#define           QUIC_EV_CONN_CPAPKT    (1ULL << 28)
#define           QUIC_EV_CONN_RTTUPDT   (1ULL << 29)
#define           QUIC_EV_CONN_CC        (1ULL << 30)
#define           QUIC_EV_CONN_SPPKTS    (1ULL << 31)
#define           QUIC_EV_CONN_PKTLOSS   (1ULL << 32)
#define           QUIC_EV_CONN_STIMER    (1ULL << 33)
#define           QUIC_EV_CONN_PTIMER    (1ULL << 34)
#define           QUIC_EV_CONN_SPTO      (1ULL << 35)

#define           QUIC_EV_CONN_ENEW      (1ULL << 32)
#define           QUIC_EV_CONN_EISEC     (1ULL << 33)
#define           QUIC_EV_CONN_ERSEC     (1ULL << 34)
#define           QUIC_EV_CONN_EWSEC     (1ULL << 35)
#define           QUIC_EV_CONN_ELPKT     (1ULL << 36)
#define           QUIC_EV_CONN_ESPKT     (1ULL << 37)
#define           QUIC_EV_CONN_ECHPKT    (1ULL << 38)
#define           QUIC_EV_CONN_EHPKT     (1ULL << 39)
#define           QUIC_EV_CONN_EPAPKT    (1ULL << 40)

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

extern struct trace_source trace_quic;
extern struct pool_head *pool_head_quic_rx_packet;
extern struct pool_head *pool_head_quic_tx_packet;
extern struct pool_head *pool_head_quic_tx_frm;

/*
 * This struct is used by ebmb_node structs as last member of flexible arrays.
 * So do not change the order of the member of quic_cid struct.
 * <data> member must be the first one.
 */
struct quic_cid {
	unsigned char data[QUIC_CID_MAXLEN + sizeof(in_port_t) + sizeof(struct in6_addr)];
	unsigned char len;
};

/* The data structure used to build a set of connection IDs for each connection. */
struct quic_connection_id {
	struct eb64_node seq_num;
	uint64_t retire_prior_to;
	struct quic_cid cid;
	unsigned char stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
};

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
#define QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID   0
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
#define QUIC_TP_INITIAL_SOURCE_CONNECTION_ID        15

/*
 * These defines are not for transport parameter type, but the maximum accepted value for
 * transport parameter types.
 */
#define QUIC_TP_ACK_DELAY_EXPONENT_LIMIT 20
#define QUIC_TP_MAX_ACK_DELAY_LIMIT      (1UL << 14)

/* The maximum length of encoded transport parameters for any QUIC peer. */
#define QUIC_TP_MAX_ENCLEN    128
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
	uint8_t original_destination_connection_id_present;
	uint8_t initial_source_connection_id_present;

	uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN]; /* Forbidden for clients */
	/*
	 * MUST be sent by servers.
	 * When received by clients, must be set to 1 if present.
	 */
	struct quic_cid original_destination_connection_id;            /* Forbidden for clients */
	/* MUST be present both for servers and clients. */
	struct quic_cid initial_source_connection_id;
	struct preferred_address preferred_address;                    /* Forbidden for clients */
};

/* Structure for ACK ranges sent in ACK frames. */
struct quic_ack_range {
	struct list list;
	int64_t first;
	int64_t last;
};

struct quic_ack_ranges {
	/* list of ACK ranges. */
	struct list list;
	/* The number of ACK ranges is this lists */
	size_t sz;
	/* The number of bytes required to encode this ACK ranges lists. */
	size_t enc_sz;
};

/* Flag the packet number space as requiring an ACK frame to be sent. */
#define QUIC_FL_PKTNS_ACK_REQUIRED  (1UL << 0)
#define QUIC_FL_PKTNS_ACK_RECEIVED  (1UL << 1)

/* The maximum number of dgrams which may be sent upon PTO expirations. */
#define QUIC_MAX_NB_PTO_DGRAMS         2

/* QUIC packet number space */
struct quic_pktns {
	struct {
		/* List of frames to send. */
		struct list frms;
		/* Next packet number to use for transmissions. */
		int64_t next_pn;
		/* Largest acked sent packet. */
		int64_t largest_acked_pn;
		/* The packet which has been sent. */
		struct eb_root pkts;
		/* The time the most recent ack-eliciting packer was sent. */
		unsigned int time_of_last_eliciting;
		/* The time this packet number space has experienced packet loss. */
		unsigned int loss_time;
		/* Boolean to denote if we must send probe packet. */
		unsigned int pto_probe;
		/* In flight bytes for this packet number space. */
		size_t in_flight;
	} tx;
	struct {
		/* Largest packet number */
		int64_t largest_pn;
		/* Number of ack-eliciting packets. */
		size_t nb_ack_eliciting;
		struct quic_ack_ranges ack_ranges;
	} rx;
	unsigned int flags;
};

/* The QUIC packet numbers are 62-bits integers */
#define QUIC_MAX_PACKET_NUM      ((1ULL << 62) - 1)

/* Default QUIC connection transport parameters */
extern struct quic_transport_params quid_dflt_transport_params;

/* Flag a received packet as being an ack-eliciting packet. */
#define QUIC_FL_RX_PACKET_ACK_ELICITING (1UL << 0)

struct quic_rx_packet {
	struct list list;
	unsigned char type;
	uint32_t version;
	/* Initial desctination connection ID. */
	struct quic_cid dcid;
	struct quic_cid scid;
	size_t pn_offset;
	/* Packet number */
	int64_t pn;
	/* Packet number length */
	uint32_t pnl;
	uint64_t token_len;
	/* Packet length */
	uint64_t len;
	/* Additional authenticated data length */
	size_t aad_len;
	unsigned char data[QUIC_PACKET_MAXLEN];
	struct eb64_node pn_node;
	volatile unsigned int refcnt;
	unsigned int flags;
};

/* Structure to store enough information about the RX CRYPTO frames. */
struct quic_rx_crypto_frm {
	struct eb64_node offset_node;
	uint64_t len;
	const unsigned char *data;
	struct quic_rx_packet *pkt;
};

/* Flag a sent packet as being an ack-eliciting packet. */
#define QUIC_FL_TX_PACKET_ACK_ELICITING (1UL << 0)
/* Flag a sent packet as containing a PADDING frame. */
#define QUIC_FL_TX_PACKET_PADDING       (1UL << 1)
/* Flag a sent packet as being in flight. */
#define QUIC_FL_TX_PACKET_IN_FLIGHT     (QUIC_FL_TX_PACKET_ACK_ELICITING | QUIC_FL_TX_PACKET_PADDING)

/* Structure to store enough information about TX QUIC packets. */
struct quic_tx_packet {
	/* List entry point. */
	struct list list;
	/* This is not the packet length but the length of outstanding data
	 * for in flight TX packet.
	 */
	size_t in_flight_len;
	struct eb64_node pn_node;
	/* The number of bytes of CRYPTO data in this packet. */
	size_t cdata_len;
	/* The list of frames of this packet. */
	struct list frms;
	/* The time this packet was sent (usec). */
	unsigned int time_sent;
	/* Packet number spakce. */
	struct quic_pktns *pktns;
	/* Flags. */
	unsigned int flags;
};

/* Structure to stora enough information about the TX frames. */
struct quic_tx_frm {
	struct list list;
	unsigned char type;
	union {
		struct quic_crypto crypto;
		struct quic_new_connection_id new_connection_id;
	};
};


#define QUIC_CRYPTO_BUF_SHIFT  10
#define QUIC_CRYPTO_BUF_MASK   ((1UL << QUIC_CRYPTO_BUF_SHIFT) - 1)
/* The maximum allowed size of CRYPTO data buffer provided by the TLS stack. */
#define QUIC_CRYPTO_BUF_SZ    (1UL << QUIC_CRYPTO_BUF_SHIFT) /* 1 KB */

/* The maximum number of bytes of CRYPTO data in flight during handshakes. */
#define QUIC_CRYPTO_IN_FLIGHT_MAX 4096

/*
 * CRYPTO buffer struct.
 * Such buffers are used to send CRYPTO data.
 */
struct quic_crypto_buf {
	unsigned char data[QUIC_CRYPTO_BUF_SZ];
	size_t sz;
};

/* QUIC buffer structure used to build outgoing packets. */
struct q_buf {
	/* Points to the data in this buffer. */
	unsigned char *area;
	/* Points to the current position to write into this buffer. */
	unsigned char *pos;
	/* Point to the end of this buffer past one. */
	const unsigned char *end;
	/* The number of data bytes in this buffer. */
	size_t data;
	/* The list of packets attached to this buffer which have not been already sent. */
	struct list pkts;
};

struct quic_enc_level {
	enum ssl_encryption_level_t level;
	struct quic_tls_ctx tls_ctx;
	struct {
		/* The packets received by the listener I/O handler
		   with header protection removed. */
		struct eb_root pkts;
		/* Liste of QUIC packets with protected header. */
		struct list pqpkts;
		/* Crypto frames */
		struct {
			uint64_t offset;
			struct eb_root frms; /* XXX TO CHECK XXX */
		} crypto;
	} rx;
	struct {
		struct {
			struct quic_crypto_buf **bufs;
			/* The number of element in use in the previous array. */
			size_t nb_buf;
			/* The total size of the CRYPTO data stored in the CRYPTO buffers. */
			size_t sz;
			/* The offset of the CRYPT0 data stream. */
			uint64_t offset;
		} crypto;
	} tx;
	struct quic_pktns *pktns;
};

struct quic_path {
	/* Control congestion. */
	struct quic_cc cc;
	/* Packet loss detection information. */
	struct quic_loss loss;

	/* MTU. */
	size_t mtu;
	/* Congestion window. */
	size_t cwnd;
	/* Minimum congestion window. */
	size_t min_cwnd;
	/* Outstanding data (in bytes). */
	uint64_t in_flight;
	/* Number of in flight ack-eliciting packets. */
	uint64_t in_flight_ae_pkts;
};

/* The number of buffers for outgoing packets (must be a power of two). */
#define QUIC_CONN_TX_BUFS_NB 8
#define QUIC_CONN_TX_BUF_SZ  QUIC_PACKET_MAXLEN

struct quic_conn {
	uint32_t version;

	/* Transport parameters. */
	struct quic_transport_params params;
	unsigned char enc_params[QUIC_TP_MAX_ENCLEN]; /* encoded QUIC transport parameters */
	size_t enc_params_len;

	/*
	 * Original Destination Connection ID  (comming with first client Initial packets).
	 * Used only by servers.
	 */
	struct ebmb_node odcid_node;
	struct quic_cid odcid;

	struct quic_cid dcid;
	struct ebmb_node scid_node;
	struct quic_cid scid;
	struct eb_root cids;

	struct quic_enc_level els[QUIC_TLS_ENC_LEVEL_MAX];

	struct quic_transport_params rx_tps;

	struct quic_pktns pktns[QUIC_TLS_PKTNS_MAX];

	/* Used only to reach the tasklet for the I/O handler from this quic_conn object. */
	struct connection *conn;
	/* Output buffer used during the handshakes. */
	struct {
		unsigned char data[QUIC_PACKET_MAXLEN];
		unsigned char *pos;
	} obuf;

	struct {
		/* The remaining frames to send. */
		struct list frms_to_send;

		/* Array of buffers. */
		struct q_buf **bufs;
		/* The size of the previous array. */
		size_t nb_buf;
		/* Writer index. */
		int wbuf;
		/* Reader index. */
		int rbuf;
		/* Number of sent bytes. */
		uint64_t bytes;
		/* The number of datagrams which may be sent
		 * when sending probe packets.
		 */
		size_t nb_pto_dgrams;
	} tx;
	struct {
		/* Number of received bytes. */
		uint64_t bytes;
	} rx;
	/* In flight CRYPTO data counter. */
	size_t ifcdata;
	unsigned int max_ack_delay;
	struct quic_path paths[1];
	struct quic_path *path;

	struct task *timer_task;
	unsigned int timer;
};

#endif /* _TYPES_XPRT_QUIC_H */
