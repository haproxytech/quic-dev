/*
 * include/proto/quic_loss.h
 * This file provides interface definition for QUIC loss detection.
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

#ifndef _PROTO_QUIC_LOSS_H
#define _PROTO_QUIC_LOSS_H

#include <stdint.h>

#include <common/time.h>

#include <types/xprt_quic.h>

#include <proto/trace.h>

#define TRACE_SOURCE &trace_quic

static inline void quic_loss_init(struct quic_loss *ql)
{
	ql->srtt = 0;
	ql->rtt_var = 0;
	ql->rtt_min = 0;
	ql->pto_count = 0;
}

/* Update <ql> QUIC loss information with new <rtt> measurement and <ack_delay>
 * on ACK frame receipt which MUST be min(ack->ack_delay, max_ack_delay) for
 * non handshake packets.
 */
static inline void quic_loss_srtt_update(struct quic_loss *ql,
                                         unsigned long rtt, unsigned long ack_delay,
                                         struct quic_conn *conn)
{
	TRACE_PROTO("Loss info update", QUIC_EV_CONN_RTTUPDT, conn->conn, &rtt, &ack_delay);
	ql->latest_rtt = rtt;
	if (!ql->srtt) {
		/* No previous measurement. */
		ql->srtt = rtt << 3;
		/* rttval <- rtt / 2 or 4*rttval <- 2*rtt. */
		ql->rtt_var = rtt << 1;
		ql->rtt_min = rtt;
	}
	else {
		long diff;

		ql->rtt_min = min(rtt, ql->rtt_min);
		/* Specific to QUIC (RTT adjustment). */
		if (ack_delay && rtt > ql->rtt_min + ack_delay)
			rtt -= ack_delay;
		diff = ql->srtt - rtt;
		if (diff < 0)
			diff = -diff;
		/* 4*rttvar = 3*rttvar + |diff| */
		ql->rtt_var += diff - (ql->rtt_var >> 2);
		/* 8*srtt = 7*srtt + rtt */
		ql->srtt += rtt - (ql->srtt >> 3);
	}
	TRACE_PROTO("Loss info update", QUIC_EV_CONN_RTTUPDT, conn->conn,,, ql);
}

/*
 * Return 1 if a persitent congestion is observed for a list of
 * lost packets sent during <period> period depending on <ql> loss information,
 * <now_us> the current time and <max_ack_delay_us> the maximum ACK delay of the connection
 * experiencing a packet loss. Return 0 on the contrary.
 */
static inline int quic_loss_persistent_congestion(struct quic_loss *ql,
                                                  uint64_t period,
                                                  uint64_t now_us,
                                                  uint64_t max_ack_delay_us)
{
	uint64_t congestion_period;

	if (!period)
		return 0;

	congestion_period = (ql->srtt >> 3) +
		max(ql->rtt_var, QUIC_TIMER_GRANULARITY_US) + max_ack_delay_us;
	congestion_period *= QUIC_LOSS_PACKET_THRESHOLD;

	return period >= congestion_period;
}

#endif /* _PROTO_QUIC_LOSS_H */
