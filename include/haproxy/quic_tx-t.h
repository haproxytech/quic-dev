#ifndef _HAPROXY_TX_T_H
#define _HAPROXY_TX_T_H

#define QUIC_MIN_CC_PKTSIZE  128
#define QUIC_DGRAM_HEADLEN  (sizeof(uint16_t) + sizeof(void *))
#define QUIC_MAX_CC_BUFSIZE (2 * (QUIC_MIN_CC_PKTSIZE + QUIC_DGRAM_HEADLEN))

#include <import/eb64tree.h>
#include <haproxy/list-t.h>

extern struct pool_head *pool_head_quic_tx_packet;
extern struct pool_head *pool_head_quic_cc_buf;

/* Flag a sent packet as being an ack-eliciting packet. */
#define QUIC_FL_TX_PACKET_ACK_ELICITING (1UL << 0)
/* Flag a sent packet as containing a PADDING frame. */
#define QUIC_FL_TX_PACKET_PADDING       (1UL << 1)
/* Flag a sent packet as being in flight. */
#define QUIC_FL_TX_PACKET_IN_FLIGHT     (QUIC_FL_TX_PACKET_ACK_ELICITING | QUIC_FL_TX_PACKET_PADDING)
/* Flag a sent packet as containing a CONNECTION_CLOSE frame */
#define QUIC_FL_TX_PACKET_CC            (1UL << 2)
/* Flag a sent packet as containing an ACK frame */
#define QUIC_FL_TX_PACKET_ACK           (1UL << 3)
/* Flag a sent packet as being coalesced to another one in the same datagram */
#define QUIC_FL_TX_PACKET_COALESCED     (1UL << 4)
/* Flag a sent packet as being probing with old data */
#define QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA (1UL << 5)

/* Structure to store enough information about TX QUIC packets. */
struct quic_tx_packet {
	/* List entry point. */
	struct list list;
	/* Packet length */
	size_t len;
	/* This is not the packet length but the length of outstanding data
	 * for in flight TX packet.
	 */
	size_t in_flight_len;
	struct eb64_node pn_node;
	/* The list of frames of this packet. */
	struct list frms;
	/* The time this packet was sent (ms). */
	unsigned int time_sent;
	/* Packet number spakce. */
	struct quic_pktns *pktns;
	/* Flags. */
	unsigned int flags;
	/* Reference counter */
	int refcnt;
	/* Next packet in the same datagram */
	struct quic_tx_packet *next;
	/* Previous packet in the same datagram */
	struct quic_tx_packet *prev;
	/* Largest acknowledged packet number if this packet contains an ACK frame */
	int64_t largest_acked_pn;
	/* Delivery rate sampling information */
	struct {
		uint64_t delivered;
		uint64_t tx_in_flight;
		uint64_t lost;
		int64_t end_seq;
		uint32_t delivered_time;
		uint32_t first_sent_time;
		int is_app_limited;
	} rs;
	unsigned char type;
};

/* Return value for qc_build_pkt(). */
enum qc_build_pkt_err {
	QC_BUILD_PKT_ERR_NONE  = 0,
	QC_BUILD_PKT_ERR_ALLOC,    /* memory allocation failure */
	QC_BUILD_PKT_ERR_ENCRYPT,  /* error during encryption operation */
	QC_BUILD_PKT_ERR_BUFROOM,  /* no more room in input buf or congestion window */
};

#endif /* _HAPROXY_TX_T_H */
