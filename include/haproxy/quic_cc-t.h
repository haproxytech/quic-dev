/*
 * include/haproxy/quic_cc-t.h
 * This file contains definitions for QUIC congestion control.
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_CC_H
#define _HAPROXY_QUIC_CC_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>
#include <stddef.h> /* size_t */

#include <haproxy/buf-t.h>
#include <haproxy/quic_loss-t.h>

#define QUIC_CC_INFINITE_SSTHESH ((uint32_t)-1)

extern struct quic_cc_algo quic_cc_algo_nr;
extern struct quic_cc_algo quic_cc_algo_cubic;
extern struct quic_cc_algo *default_quic_cc_algo;

/* Fake algorithm with its fixed window */
extern struct quic_cc_algo quic_cc_algo_nocc;

extern unsigned long long last_ts;

enum quic_cc_algo_state_type {
	/* Slow start. */
	QUIC_CC_ST_SS,
	/* Conservative slow start (HyStart++ only) */
	QUIC_CC_ST_CS,
	/* Congestion avoidance. */
	QUIC_CC_ST_CA,
	/* Recovery period. */
	QUIC_CC_ST_RP,
};

enum quic_cc_event_type {
	/* ACK receipt. */
	QUIC_CC_EVT_ACK,
	/* Packet loss. */
	QUIC_CC_EVT_LOSS,
	/* ECN-CE. */
	QUIC_CC_EVT_ECN_CE,
};

struct quic_cc_event {
	enum quic_cc_event_type type;
	union {
		struct ack {
			uint64_t acked;
			uint64_t pn;
			unsigned int time_sent;
		} ack;
		struct loss {
			unsigned int time_sent;
		} loss;
	};
};

enum quic_cc_algo_type {
	QUIC_CC_ALGO_TP_NEWRENO,
	QUIC_CC_ALGO_TP_CUBIC,
	QUIC_CC_ALGO_TP_NOCC,
};

struct quic_cc {
	/* <conn> is there only for debugging purpose. */
	struct quic_conn *qc;
	struct quic_cc_algo *algo;
	uint32_t priv[18];
};

struct quic_cc_path {
	/* Control congestion. */
	struct quic_cc cc;
	/* Packet loss detection information. */
	struct quic_loss loss;

	/* MTU. */
	size_t mtu;
	/* Congestion window. */
	uint64_t cwnd;
	/* The current maximum congestion window value reached. */
	uint64_t mcwnd;
	/* The maximum congestion window value which can be reached. */
	uint64_t max_cwnd;
	/* Minimum congestion window. */
	uint64_t min_cwnd;
	/* Prepared data to be sent (in bytes). */
	uint64_t prep_in_flight;
	/* Outstanding data (in bytes). */
	uint64_t in_flight;
	/* Number of in flight ack-eliciting packets. */
	uint64_t ifae_pkts;
};

struct quic_cc_algo {
	enum quic_cc_algo_type type;
	int (*init)(struct quic_cc *cc);
	void (*event)(struct quic_cc *cc, struct quic_cc_event *ev);
	void (*slow_start)(struct quic_cc *cc);
	void (*state_trace)(struct buffer *buf, const struct quic_cc *cc);
	void (*hystart_start_round)(struct quic_cc *cc, uint64_t pn);
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CC_H */
