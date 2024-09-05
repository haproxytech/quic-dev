/* Delivery Rate Sampling */

#include <haproxy/pool.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/quic_cc_drs.h>
#include <haproxy/quic_tx-t.h>
#include <haproxy/ticks.h>
#include <haproxy/window_filter.h>

DECLARE_POOL(pool_head_quic_cc_drs, "quic_cc_drs", sizeof(struct quic_cc_drs));

static void quic_cc_rs_init(struct quic_cc_rs *rs)
{
	rs->interval = UINT32_MAX;
	rs->delivered = 0;
	rs->prior_delivered = 0;
	rs->prior_time = TICK_ETERNITY;
	rs->tx_in_flight = 0;
	rs->lost = 0;
	rs->prior_lost = 0;
	rs->send_elapsed = 0;
	rs->ack_elapsed = 0;
	rs->is_app_limited = 0;
}

void quic_cc_drs_init(struct quic_cc_drs *drs)
{
	quic_cc_rs_init(&drs->rs);
	wf_init(&drs->wf, 12);
	drs->round_count = 0;
	drs->next_round_delivered = 0;
	drs->delivered = 0;
	drs->lost = 0;
	drs->last_seq = -1;
	drs->delivered_time = TICK_ETERNITY;
	drs->first_sent_time = TICK_ETERNITY;
	drs->app_limited = false;
	drs->is_cwnd_limited = false;
}

/* Update <pkt> TX packet rate sampling information.
 * Must be called after <pkt> has just been sent.
 */
void quic_cc_drs_on_pkt_sent(struct quic_cc_path *path,
                             struct quic_tx_packet *pkt, struct quic_cc_drs *drs)
{
	if (!path->in_flight)
		drs->first_sent_time  = drs->delivered_time = pkt->time_sent;

	pkt->rs.first_sent_time = drs->first_sent_time;
	pkt->rs.delivered_time  = drs->delivered_time;
	pkt->rs.delivered       = drs->delivered;
	pkt->rs.is_app_limited  = drs->app_limited != 0;

	pkt->rs.tx_in_flight = path->in_flight + pkt->len;
	pkt->rs.lost = drs->lost;
	pkt->rs.end_seq = ++drs->last_seq;
}

/* Return 1 if <pkt> TX packet is the most recently sent packet
 * that has been delivered, 0 if not.
 */
static inline int quic_cc_drs_is_newest_packet(struct quic_cc_drs *drs,
                                               struct quic_tx_packet *pkt)
{
	return pkt->time_sent > drs->first_sent_time ||
		(pkt->time_sent == drs->first_sent_time &&
		 pkt->rs.end_seq > drs->rs.last_end_seq);
}

void quic_cc_drs_on_ack_recv(struct quic_cc_drs *drs, struct quic_cc_path *path,
                            uint64_t pkt_delivered)
{
	struct quic_cc_rs *rs = &drs->rs;
	uint64_t rate;

	if (drs->app_limited && drs->delivered > drs->app_limited)
		drs->app_limited = 0;

	if (pkt_delivered >= drs->next_round_delivered) {
		drs->next_round_delivered = pkt_delivered;
		++drs->round_count;
	}

	if (tick_isset(rs->prior_time))
		return;

	rs->interval = MAX(rs->send_elapsed, rs->ack_elapsed);

	rs->delivered = drs->delivered - rs->prior_delivered;
	rs->lost = drs->lost - rs->prior_lost;

	if (rs->interval < path->loss.rtt_min) {
		rs->interval = UINT32_MAX;
		return;
	}

	if (!rs->interval)
		return;

	rate = rs->delivered * 1000 / rs->interval;
	if (rate >= wf_get_best(&drs->wf) || !drs->app_limited) {
		wf_update(&drs->wf, rate, drs->round_count);
		path->delivery_rate = wf_get_best(&drs->wf);
	}
}

void quic_cc_update_rate_sample(struct quic_cc_drs *drs,
                                struct quic_tx_packet *pkt)
{
	struct quic_cc_rs *rs = &drs->rs;

	drs->delivered += pkt->len;
	drs->delivered_time = now_ms;
	/* Update info using the newest packet. */
	if (tick_isset(rs->prior_time) && !quic_cc_drs_is_newest_packet(drs, pkt))
		return;

	rs->prior_delivered  = pkt->rs.delivered;
	rs->prior_time       = pkt->rs.delivered_time;
	rs->is_app_limited   = pkt->rs.is_app_limited;
	rs->send_elapsed     = pkt->time_sent - pkt->rs.first_sent_time;
	rs->ack_elapsed      = drs->delivered_time - pkt->rs.delivered_time;
	rs->last_end_seq     = pkt->rs.end_seq;
	drs->first_sent_time = pkt->time_sent;
}
