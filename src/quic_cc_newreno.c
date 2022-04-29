/*
 * NewReno congestion control algorithm.
 *
 * This file contains definitions for QUIC congestion control.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#include <haproxy/quic_cc.h>
#include <haproxy/trace.h>
#include <haproxy/xprt_quic.h>

#define TRACE_SOURCE    &trace_quic

static int quic_cc_nr_init(struct quic_cc *cc)
{
	cc->algo_state.nr.state = QUIC_CC_ST_SS;
	cc->algo_state.nr.ssthresh = QUIC_CC_INFINITE_SSTHESH;
	cc->algo_state.nr.recovery_start_time = 0;
	cc->algo_state.nr.remain_acked = 0;

	return 1;
}

/* Re-enter slow start state. */
static void quic_cc_nr_slow_start(struct quic_cc *cc)
{
	struct quic_path *path;

	path = container_of(cc, struct quic_path, cc);
	path->cwnd = path->min_cwnd;
	/* Re-entering slow start state. */
	cc->algo_state.nr.state = QUIC_CC_ST_SS;
	/* Recovery start time reset */
	cc->algo_state.nr.recovery_start_time = 0;
}

/* Slow start callback. */
static void quic_cc_nr_ss_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct quic_path *path;

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc, ev);
	path = container_of(cc, struct quic_path, cc);
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		/* Do not increase the congestion window in recovery period. */
		if (ev->ack.time_sent <= cc->algo_state.nr.recovery_start_time)
			return;

		path->cwnd += ev->ack.acked;
		/* Exit to congestion avoidance if slow start threshold is reached. */
		if (path->cwnd > cc->algo_state.nr.ssthresh)
			cc->algo_state.nr.state = QUIC_CC_ST_CA;
		break;

	case QUIC_CC_EVT_LOSS:
		cc->algo_state.nr.recovery_start_time = now_ms;
		path->cwnd = QUIC_MAX(path->cwnd >> 1, path->min_cwnd);
		cc->algo_state.nr.ssthresh = path->cwnd;
		/* Exit to congestion avoidance. */
		cc->algo_state.nr.state = QUIC_CC_ST_CA;
		break;

	case QUIC_CC_EVT_ECN_CE:
		/* XXX TO DO XXX */
		break;
	}
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc,, cc);
}

/* Congestion avoidance callback. */
static void quic_cc_nr_ca_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct quic_path *path;

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc, ev);
	path = container_of(cc, struct quic_path, cc);
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
	{
		uint64_t acked;
		/* Do not increase the congestion window in recovery period. */
		if (ev->ack.time_sent <= cc->algo_state.nr.recovery_start_time)
			goto out;

		/* Increasing the congestion window by (acked / cwnd)
		 */
		acked = ev->ack.acked * path->mtu + cc->algo_state.nr.remain_acked;
		cc->algo_state.nr.remain_acked = acked % path->cwnd;
		path->cwnd += acked / path->cwnd;
		break;
	}

	case QUIC_CC_EVT_LOSS:
		/* Do not decrease the congestion window when already in recovery period. */
		if (ev->loss.time_sent <= cc->algo_state.nr.recovery_start_time)
			goto out;

		cc->algo_state.nr.recovery_start_time = now_ms;
		cc->algo_state.nr.ssthresh = path->cwnd;
		path->cwnd = QUIC_MAX(path->cwnd >> 1, path->min_cwnd);
		break;

	case QUIC_CC_EVT_ECN_CE:
		/* XXX TO DO XXX */
		break;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc, NULL, cc);
}

static void quic_cc_nr_state_trace(struct buffer *buf, const struct quic_cc *cc)
{
	struct quic_path *path;

	path = container_of(cc, struct quic_path, cc);
	chunk_appendf(buf, " state=%s cwnd=%llu ssthresh=%ld recovery_start_time=%llu",
	              quic_cc_state_str(cc->algo_state.nr.state),
	              (unsigned long long)path->cwnd,
	              (long)cc->algo_state.nr.ssthresh,
	              (unsigned long long)cc->algo_state.nr.recovery_start_time);
}

static void (*quic_cc_nr_state_cbs[])(struct quic_cc *cc,
                                      struct quic_cc_event *ev) = {
	[QUIC_CC_ST_SS] = quic_cc_nr_ss_cb,
	[QUIC_CC_ST_CA] = quic_cc_nr_ca_cb,
};

static void quic_cc_nr_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	return quic_cc_nr_state_cbs[cc->algo_state.nr.state](cc, ev);
}

struct quic_cc_algo quic_cc_algo_nr = {
	.type        = QUIC_CC_ALGO_TP_NEWRENO,
	.init        = quic_cc_nr_init,
	.event       = quic_cc_nr_event,
	.slow_start  = quic_cc_nr_slow_start,
	.state_trace = quic_cc_nr_state_trace,
};

