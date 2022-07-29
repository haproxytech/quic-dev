/*
 * Congestion controller handling.
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

#include <haproxy/buf.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/xprt_quic-t.h>


struct quic_cc_algo *default_quic_cc_algo = &quic_cc_algo_cubic;

/*
 * Initialize <cc> congestion control with <algo> as algorithm depending on <ipv4>
 * a boolean which is true for an IPv4 path.
 */
void quic_cc_init(struct quic_cc *cc,
                  struct quic_cc_algo *algo, struct quic_conn *qc)
{
	cc->qc = qc;
	cc->algo = algo;
	if (cc->algo->init)
		(cc->algo->init(cc));
}

/* Send <ev> event to <cc> congestion controller. */
void quic_cc_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	cc->algo->event(cc, ev);
}

void quic_cc_state_trace(struct buffer *buf, const struct quic_cc *cc)
{
	cc->algo->state_trace(buf, cc);
}

void quic_cc_hystart_reset(struct quic_cc *cc)
{
	struct quic_path *path = container_of(cc, struct quic_path, cc);

	fprintf(stderr, "%s\n", __func__);
	path->hs.curr_rnd_min_rtt = UINT32_MAX;
	path->hs.last_rnd_min_rtt = UINT32_MAX;
	path->hs.css_min_rtt      = UINT32_MAX;
	path->hs.rtt_sample_count = 0;
	path->hs.wnd_end = (uint64_t)-1;
}

void quic_cc_hystart_sent_pkt(struct quic_cc *cc, uint64_t pn)
{
	struct quic_path *path = container_of(cc, struct quic_path, cc);

	if (path->hs.wnd_end != -1)
		return;

	fprintf(stderr, "%s\n", __func__);
	path->hs.wnd_end = pn;
	path->hs.last_rnd_min_rtt = path->hs.curr_rnd_min_rtt;
	path->hs.rtt_sample_count = 0;
}

void quic_cc_hystart_rtt_sample(struct quic_cc *cc)
{
	struct quic_path *path = container_of(cc, struct quic_path, cc);

	fprintf(stderr, "%s\n", __func__);
	if (path->hs.wnd_end == -1)
		return;

	path->hs.curr_rnd_min_rtt =
		QUIC_MIN(path->hs.curr_rnd_min_rtt, path->loss.latest_rtt);
	path->hs.rtt_sample_count++;
}
