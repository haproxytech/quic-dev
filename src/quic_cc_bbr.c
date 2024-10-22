#include <inttypes.h>

#include <haproxy/compat.h>
#include <haproxy/quic_tx-t.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_cc_drs.h>
#include <haproxy/ticks.h>
#include <haproxy/window_filter.h>

/* TODO: check ->delivery_rate usage here vs RFC */
/* XXX TO BE REMOVED */
#define true  1
#define false 0

/* BBRStartupPacingGain: A constant specifying the minimum gain value for
 * calculating the pacing rate that will allow the sending rate to double
 * each round (4 * ln(2) ~= 2.77); used in Startup mode for BBR.pacing_gain.
 */
#define BBR_STARTUP_PACING_GAIN_MULT 277 /* percents, (4 * ln(2)=2.77) */
#define BBR_STARTUP_CWND_GAIN_MULT   200 /* percents */
#define BBR_DRAIN_PACING_GAIN_MULT    35 /* percents */
/* BBRDefaultCwndGain: A constant specifying the minimum gain value that
 * allows the sending rate to double each round (2). Used by default in most
 * phases for BBR.cwnd_gain.
 */
#define BBR_DEFAULT_CWND_GAIN_MULT BBR_STARTUP_CWND_GAIN_MULT
#define BBR_PACING_MARGIN_PERCENT 1

/* BBRLossThresh (2%) */
#define BBR_LOSS_THRESH_MULT   2
#define BBR_LOSS_THRESH_DIVI 100
/* BBRBeta (0.7) */
#define BBR_BETA_MULT  7
#define BBR_BETA_DIVI 10
/* BBRHeadroom (0.15) */
#define BBR_HEADROOM_MULT  15
#define BBR_HEADROOM_DIVI 100

#define BBR_MAX_BW_FILTERLEN       2
#define BBR_EXTRA_ACKED_FILTERLEN 10

#define BBR_MIN_RTT_FILTERLEN      10000 /* ms */
#define BBR_PROBE_RTT_CWND_GAIN_MULT  50 /* percents */
#define BBR_PROBE_RTT_DURATION       200 /* ms */
#define BBR_PROBE_RTT_INTERVAL      5000 /* ms */
/* The divisor to apply to the gain multiplicandes above (BBR.*_GAIN_MULT)
 * whose the unit is the percent.
 */
#define BBR_GAIN_DIVI                100

/* 4.1.1: State Transition Diagram */
/* BBR state */
enum bbr_state {
	BBR_ST_STARTUP,
	BBR_ST_DRAIN,
	BBR_ST_PROBE_BW_DOWN,
	BBR_ST_PROBE_BW_CRUISE,
	BBR_ST_PROBE_BW_REFILL,
	BBR_ST_PROBE_BW_UP,
	BBR_ST_PROBE_RTT,
};

enum bbr_ack_phase {
	BBR_ACK_PHASE_ACKS_PROBE_STARTING,
	BBR_ACK_PHASE_ACKS_PROBE_STOPPING,
	BBR_ACK_PHASE_ACKS_PROBE_FEEDBACK,
	BBR_ACK_PHASE_ACKS_REFILLING,
};

struct bbr {
	struct quic_cc_drs *drs;
	/* 2.4 Output Control Parameters */
	uint64_t pacing_rate;
	uint64_t send_quantum;
	/* 2.5 Pacing State and Parameters */
	/* BBR.pacing_gain: The dynamic gain factor used to scale BBR.bw to
	 * produce BBR.pacing_rate.
	 */
	uint64_t pacing_gain; // percents
	//uint32_t next_departure_time; /* XXX check this XXX */
	/* 2.6. cwnd State and Parameters */
	/* BBR.cwnd_gain: The dynamic gain factor used to scale the estimated BDP
	 * to produce a congestion window (cwnd).
	 */
	uint64_t cwnd_gain; // percents
	/* 2.7 General Algorithm State */
	enum bbr_state state;
	uint64_t round_count;
	int round_start; /* boolean */
	uint64_t next_round_delivered;
	int idle_restart; /* boolean */
	/* 2.9.1 Data Rate Network Path Model Parameters */
	uint64_t max_bw;
	uint64_t bw_lo;
	uint64_t bw;
	uint64_t prior_cwnd;
	/* 2.9.2 Data Volume Network Path Model Parameters */
	uint32_t min_rtt;
	uint64_t extra_acked;
	uint64_t bytes_lost_in_round;
	uint64_t loss_events_in_round;
	uint64_t offload_budget;
	uint64_t probe_up_cnt;
	uint32_t cycle_stamp;
	enum bbr_ack_phase ack_phase;
	int bw_probe_wait; /* XXX TODO: check this type. */
	int bw_probe_samples;
	int bw_probe_up_rounds;
	uint64_t bw_probe_up_acks;
	uint64_t max_inflight;
	uint64_t inflight_hi;
	uint64_t bw_hi;
	uint64_t inflight_lo;
	/* 2.10 State for Responding to Congestion */
	int loss_round_start; /* boolean */
	uint64_t bw_latest;
	int loss_in_round; /* boolean */
	uint64_t loss_round_delivered;
	uint64_t rounds_since_bw_probe;
	uint64_t inflight_latest;
	/* 2.11 Estimating BBR.max_bw */
	struct wf max_bw_filter;
	uint64_t cycle_count;
	/* 2.12 Estimating BBR.extra_acked */
	uint32_t extra_acked_interval_start;
	uint64_t extra_acked_delivered;
	struct wf extra_acked_filter;
	/* 2.13 Startup Parameters and State */
	int full_bw_reached; /* boolean */
	int full_bw_now; /* boolean */
	uint64_t full_bw;
	int full_bw_count;
	int filled_pipe; /* boolean */
	/* 2.14 ProbeRTT and min_rtt Parameters and State */
	/* 2.14.1 Parameters for Estimating BBR.min_rtt */
	uint32_t min_rtt_stamp;
	/* 2.14.2  Parameters for Scheduling ProbeRTT */
	uint32_t probe_rtt_min_delay; /* ms */
	uint32_t probe_rtt_min_stamp; /* ms */
	uint32_t probe_rtt_done_stamp;
	int probe_rtt_round_done; /* boolean */
	int probe_rtt_expired; /* boolean */
	int in_loss_recovery; /* boolean */
	int packet_conservation; /* boolean */
};

static inline uint64_t bbr_min_pipe_cwnd(struct quic_cc_path *p)
{
	return 4 * p->mtu;
}

static inline int is_inflight_too_high(struct quic_cc_rs *rs)
{
	return rs->lost * BBR_LOSS_THRESH_DIVI >
		rs->tx_in_flight * BBR_LOSS_THRESH_MULT;
}

static inline int bbr_is_probing_bw(struct bbr *bbr)
{
	switch (bbr->state) {
	case BBR_ST_PROBE_BW_DOWN:
	case BBR_ST_PROBE_BW_CRUISE:
	case BBR_ST_PROBE_BW_REFILL:
	case BBR_ST_PROBE_BW_UP:
		return 1;
	default:
		return 0;
	}
}

static void bbr_reset_congestion_signals(struct bbr *bbr)
{
	bbr->loss_in_round = false;
	bbr->bw_latest = 0;
	bbr->inflight_latest = 0;
}

static void bbr_reset_lower_bounds(struct bbr *bbr)
{
	bbr->bw_lo = UINT64_MAX;
	bbr->inflight_lo = UINT64_MAX;
}

static void bbr_init_round_counting(struct bbr *bbr)
{
	bbr->next_round_delivered = 0;
	bbr->round_start = false;
	bbr->round_count = 0;
}

static void bbr_reset_full_bw(struct bbr *bbr)
{
	bbr->filled_pipe = 0;
	bbr->full_bw = 0;
	bbr->full_bw_count = 0;
	bbr->full_bw_now = false;
}

static void bbr_init_pacing_rate(struct bbr *bbr)
{
	/* XXX Not clear at this time XXX */
}

static void bbr_enter_startup(struct bbr *bbr)
{
	bbr->state = BBR_ST_STARTUP;
	bbr->pacing_gain = BBR_STARTUP_PACING_GAIN_MULT;
	bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
}

static void bbr_enter_drain(struct bbr *bbr)
{
    bbr->state = BBR_ST_DRAIN;
    bbr->pacing_gain = BBR_DRAIN_PACING_GAIN_MULT;    /* pace slowly */
    bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
}

static void bbr_enter_probe_rtt(struct bbr *bbr)
{
	bbr->state = BBR_ST_PROBE_RTT;
	bbr->pacing_gain = 100;
	bbr->cwnd_gain = BBR_PROBE_RTT_CWND_GAIN_MULT;
}

static void bbr_save_cwnd(struct bbr *bbr, struct quic_cc_path *p)
{
	if (!bbr->in_loss_recovery && bbr->state != BBR_ST_PROBE_RTT) {
		bbr->prior_cwnd = p->cwnd;
	}
	else {
		bbr->prior_cwnd = MAX(bbr->prior_cwnd, p->cwnd);
	}
}

static void bbr_restore_cwnd(struct bbr *bbr, struct quic_cc_path *p)
{
	//BUG_ON(p->cwnd == 5008);
	p->cwnd = MAX(p->cwnd, bbr->prior_cwnd);
	//BUG_ON(p->cwnd == 5008);
}

/* <gain> must be provided in percents. */
static uint64_t bbr_bdp_multiple(struct bbr *bbr, struct quic_cc_path *p,
                                 uint64_t bw, uint64_t gain)
{
	uint64_t bdp;

	fprintf(stderr, "%s min_rtt=%u bw=%llu\n", __func__, bbr->min_rtt, (ullong)bbr->bw);
	if (bbr->min_rtt == UINT32_MAX)
		return p->initial_wnd; /* no valid RTT samples yet */

	bdp = bw * bbr->min_rtt / 1000;

	/* Note that <gain> unit is the percent. */
	return gain * bdp / BBR_GAIN_DIVI;
}

static void bbr_update_offload_budget(struct bbr *bbr, struct quic_cc_path *p)
{
	bbr->offload_budget = 3 * p->send_quantum;
}

static uint64_t bbr_quantization_budget(struct bbr *bbr, struct quic_cc_path *p,
                                        uint64_t inflight)
{
	bbr_update_offload_budget(bbr, p);
	inflight = MAX(inflight, bbr->offload_budget);
	inflight = MAX(inflight, bbr_min_pipe_cwnd(p));
	if (bbr->state == BBR_ST_PROBE_BW_UP)
		inflight += 2 * p->mtu;

	return inflight;
}

static uint64_t bbr_inflight(struct bbr *bbr, struct quic_cc_path *p,
                             uint64_t bw, uint64_t gain)
{
	uint64_t inflight = bbr_bdp_multiple(bbr, p, bw, gain);
	return bbr_quantization_budget(bbr, p, inflight);
}

static void bbr_update_max_inflight(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t inflight;

	/* Not defined by RFC */
	//BBRUpdateAggregationBudget();
	inflight = bbr_bdp_multiple(bbr, p, bbr->bw, bbr->cwnd_gain);
	inflight += bbr->extra_acked;
	bbr->max_inflight = bbr_quantization_budget(bbr, p, inflight);
}

static void bbr_set_pacing_rate_with_gain(struct bbr *bbr,
                                          struct quic_cc_path *p,
                                          uint64_t pacing_gain)
{
	uint64_t rate;

	rate = pacing_gain * bbr->bw * (100 - BBR_PACING_MARGIN_PERCENT) / 100;
	if (bbr->full_bw_reached || rate > bbr->pacing_rate)
		bbr->pacing_rate = rate;
}

static void bbr_set_pacing_rate(struct bbr *bbr, struct quic_cc_path *p)
{
	bbr_set_pacing_rate_with_gain(bbr, p, bbr->pacing_gain);
}

static uint64_t bbr_probe_rtt_cwnd(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t probe_rtt_cwnd =
		bbr_bdp_multiple(bbr, p, bbr->bw, BBR_PROBE_RTT_CWND_GAIN_MULT);

	fprintf(stderr, "%s probe_rtt_cwnd=%llu bbr_min_pipe_cwnd()=%llu\n",
	        __func__, (ull)probe_rtt_cwnd, (ull)bbr_min_pipe_cwnd(p));

    return MAX(probe_rtt_cwnd, bbr_min_pipe_cwnd(p));
}

static void bbr_bound_cwnd_for_probe_rtt(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->state == BBR_ST_PROBE_RTT) {
		//BUG_ON(p->cwnd == 5008);
		p->cwnd = MIN(p->cwnd, bbr_probe_rtt_cwnd(bbr, p));
		//BUG_ON(p->cwnd == 5008);
	}
}

/* Return a volume of data that tries to leave free headroom in the bottleneck
 * buffer or link for other flows, for fairness convergence and lower RTTs and
 * loss.
 */
static uint64_t bbr_inflight_with_headroom(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t headroom;

	if (bbr->inflight_hi == UINT64_MAX)
		return UINT64_MAX;

	headroom =
		MAX(p->mtu, bbr->inflight_hi * BBR_HEADROOM_MULT / BBR_HEADROOM_DIVI);
	return MAX(bbr->inflight_hi - headroom, bbr_min_pipe_cwnd(p));
}

static void bbr_set_send_quantum(struct bbr *bbr, struct quic_cc_path *p)
{
	/* XXX Check this XXX */
	bbr->send_quantum = bbr->pacing_rate;
    bbr->send_quantum = MIN(bbr->send_quantum, 64 * 1024);
    bbr->send_quantum = MAX(bbr->send_quantum, 2 * p->mtu);
}

static void bbr_bound_cwnd_for_model(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t cap = UINT64_MAX;

    if (bbr_is_probing_bw(bbr) &&  bbr->state != BBR_ST_PROBE_BW_CRUISE)
      cap = bbr->inflight_hi;
    else if (bbr->state == BBR_ST_PROBE_RTT || bbr->state == BBR_ST_PROBE_BW_CRUISE)
      cap = bbr_inflight_with_headroom(bbr, p);

    /* apply inflight_lo (possibly infinite): */
    cap = MIN(cap, bbr->inflight_lo);
    cap = MAX(cap, bbr_min_pipe_cwnd(p));
    p->cwnd = MIN(p->cwnd, cap);
	//BUG_ON(p->cwnd == 5008);
}

static void bbr_set_cwnd(struct bbr *bbr, struct quic_cc_path *p, uint32_t acked)
{
	bbr_update_max_inflight(bbr, p);
	// bbr_modulate_cwnd_for_recovery() ??? (see ngtcp2).
	if (bbr->full_bw_reached) {
		p->cwnd += acked;
		p->cwnd = MIN(p->cwnd + acked, bbr->max_inflight);
	//BUG_ON(p->cwnd == 5008);
	}
	else if (p->cwnd < bbr->max_inflight || bbr->drs->delivered < p->initial_wnd) {
		p->cwnd = p->cwnd + acked;
	//BUG_ON(p->cwnd == 5008);
	}
	p->cwnd = MAX(p->cwnd, bbr_min_pipe_cwnd(p));
	bbr_bound_cwnd_for_probe_rtt(bbr, p);
	bbr_bound_cwnd_for_model(bbr, p);
}

static int bbr_init(struct quic_cc *cc)
{
	struct bbr *bbr = quic_cc_priv(cc);

	bbr->drs = pool_alloc(pool_head_quic_cc_drs);
	if (!bbr->drs)
		return 0;

	quic_cc_drs_init(bbr->drs);
	wf_init(&bbr->max_bw_filter, BBR_MAX_BW_FILTERLEN);
	wf_init(&bbr->extra_acked_filter, BBR_EXTRA_ACKED_FILTERLEN);
	/* InitWindowedMaxFilter() */
	bbr->min_rtt = UINT32_MAX; /* ms */ /* XXX check this XXX */
	bbr->min_rtt_stamp = now_ms;
	bbr->probe_rtt_done_stamp = TICK_ETERNITY; /* XXX check this XXX */
	bbr->probe_rtt_round_done = false;
	bbr->prior_cwnd = 0;
	bbr->idle_restart = false;
	bbr->extra_acked_interval_start = now_ms;
	bbr->extra_acked_delivered = 0;
	bbr->full_bw_reached = false;

	bbr_reset_congestion_signals(bbr);
	bbr_reset_lower_bounds(bbr);
	bbr_init_round_counting(bbr);
	bbr_reset_full_bw(bbr);
	bbr_init_pacing_rate(bbr);
	bbr_enter_startup(bbr);

	/* Not in RFC */
	bbr->loss_round_start = false;
	bbr->loss_round_delivered = UINT64_MAX;
	bbr->send_quantum = 0; /* XXX check this */
	bbr->max_bw = 0;
	bbr->bw = 0;
	bbr->extra_acked = 0;
	bbr->bytes_lost_in_round = 0;
	bbr->loss_events_in_round = 0;
	bbr->offload_budget = 0;
	bbr->probe_up_cnt = UINT64_MAX;
	bbr->cycle_stamp = TICK_ETERNITY;
	bbr->ack_phase = 0;
	bbr->bw_probe_wait = 0;
	bbr->bw_probe_samples = 0;
	bbr->bw_probe_up_rounds = 0;
	bbr->bw_probe_up_acks = 0;
	bbr->max_inflight = 0;
	bbr->inflight_hi = UINT64_MAX;
	bbr->bw_hi = UINT64_MAX;
	bbr->cycle_count = 0;
	bbr->probe_rtt_min_delay = UINT32_MAX;
	bbr->probe_rtt_min_stamp = now_ms;
	bbr->probe_rtt_expired = false;
	bbr->in_loss_recovery = false;
	bbr->packet_conservation = false;

	return 1;
}

static void bbr_check_startup_high_loss()
{
}

static void bbr_check_startup_done(struct bbr *bbr)
{
	bbr_check_startup_high_loss();
	if (bbr->state == BBR_ST_STARTUP && bbr->full_bw_reached)
		bbr_enter_drain(bbr);
}

static void bbr_start_round(struct bbr *bbr)
{
	bbr->next_round_delivered = bbr->drs->delivered;
}

static void bbr_update_round(struct bbr *bbr, uint64_t ack_packet_delivered)
{
	if (ack_packet_delivered >= bbr->next_round_delivered) {
		bbr_start_round(bbr);
		bbr->round_count++;
		bbr->rounds_since_bw_probe++;
		bbr->round_start = 1;
		bbr->bytes_lost_in_round = 0;
	}
	else {
		bbr->round_start = 0;
	}
}

static void bbr_pick_probe_wait(struct bbr *bbr)
{
	/* TODO */
#if 0
	BBR.rounds_since_bw_probe =
		random_int_between(0, 1); /* 0 or 1 */
	/* Decide the random wall clock bound for wait: */
	BBR.bw_probe_wait =
		2 + random_float_between(0.0, 1.0); /* 0..1 sec */
#endif
}

static void bbr_raise_inflight_hi_slope(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t growth_this_round = p->mtu << bbr->bw_probe_up_rounds;

	bbr->bw_probe_up_rounds = MIN(bbr->bw_probe_up_rounds + 1, 30);
	bbr->probe_up_cnt = MAX(p->cwnd / growth_this_round, 1) * p->mtu;
}

static void bbr_start_probe_bw_down(struct bbr *bbr, uint32_t ts)
{
	bbr_reset_congestion_signals(bbr);
	bbr->probe_up_cnt = UINT64_MAX;
	bbr_pick_probe_wait(bbr);
	bbr->cycle_stamp = ts;
	bbr->ack_phase = BBR_ACK_PHASE_ACKS_PROBE_STOPPING;
	bbr_start_round(bbr);
	bbr->state = BBR_ST_PROBE_BW_DOWN;
	bbr->pacing_gain = 90;
	bbr->cwnd_gain = 200;
}

static void bbr_start_probe_bw_cruise(struct bbr *bbr)
{
	bbr->state = BBR_ST_PROBE_BW_CRUISE;
	bbr->pacing_gain = 100;
	bbr->cwnd_gain = 200;
}

static void bbr_start_probe_bw_refill(struct bbr *bbr)
{
	bbr_reset_lower_bounds(bbr);
	bbr->bw_probe_up_rounds = 0;
	bbr->bw_probe_up_acks = 0;
	bbr->ack_phase = BBR_ACK_PHASE_ACKS_REFILLING;
	bbr_start_round(bbr);
	bbr->state = BBR_ST_PROBE_BW_REFILL;
	bbr->pacing_gain = 100;
	bbr->cwnd_gain = 200;
}

static void bbr_start_probe_bw_up(struct bbr *bbr, struct quic_cc_path *p,
                                  uint32_t ts)
{
	bbr->ack_phase = BBR_ACK_PHASE_ACKS_PROBE_STARTING;
	bbr_start_round(bbr);
	bbr->cycle_stamp = ts;
	bbr->state = BBR_ST_PROBE_BW_UP;
	bbr->pacing_gain = 125;
	bbr->cwnd_gain = 225;
	bbr_raise_inflight_hi_slope(bbr, p);
}

static void bbr_exit_probe_rtt(struct bbr *bbr, uint32_t ts)
{
	bbr_reset_lower_bounds(bbr);
	if (bbr->filled_pipe) {
		bbr_start_probe_bw_down(bbr, ts);
		bbr_start_probe_bw_cruise(bbr);
	} else {
		bbr_enter_startup(bbr);
	}
}

static void bbr_check_drain_done(struct bbr *bbr,
                                 struct quic_cc_path *p, uint32_t ts)
{
	if (bbr->state == BBR_ST_DRAIN &&
	    p->in_flight <= bbr_inflight(bbr, p, bbr->bw, 100))
		bbr_start_probe_bw_down(bbr, ts);
}

static void bbr_update_latest_delivery_signals(struct bbr *bbr,
                                               struct quic_cc_path *p)
{
	struct quic_cc_drs *drs = bbr->drs;

	bbr->loss_round_start = 0;
	bbr->bw_latest = MAX(bbr->bw_latest, p->delivery_rate);
	bbr->inflight_latest = MAX(bbr->inflight_latest, drs->rs.delivered);
	if (drs->rs.prior_delivered >= bbr->loss_round_delivered) {
		bbr->loss_round_delivered = drs->delivered;
		bbr->loss_round_start = 1;
	}
}

static void bbr_advance_max_bw_filter(struct bbr *bbr)
{
	bbr->cycle_count++;
}

static uint64_t bbr_target_inflight(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t bdp = bbr_inflight(bbr, p, bbr->bw, 100);
	return MIN(bdp, p->cwnd);
}

static void bbr_handle_inflight_too_high(struct bbr *bbr,
                                         struct quic_cc_path *p,
                                         struct quic_cc_rs *rs, uint32_t ts)
{
	bbr->bw_probe_samples = 0;
	if (!rs->is_app_limited)
		bbr->inflight_hi =
			MAX(rs->tx_in_flight, bbr_target_inflight(bbr, p) * BBR_BETA_MULT / BBR_BETA_DIVI);

	if (bbr->state == BBR_ST_PROBE_BW_UP)
		bbr_start_probe_bw_down(bbr, ts);
}

static inline int bbr_rs_is_inflight_too_high(struct quic_cc_rs *rs)
{
	return rs->lost * BBR_LOSS_THRESH_DIVI > rs->tx_in_flight * BBR_LOSS_THRESH_MULT;
}

static int bbr_is_inflight_too_high(struct bbr *bbr, struct quic_cc_path *p,
                                    uint32_t ts)
{
	if (!bbr_rs_is_inflight_too_high(&bbr->drs->rs))
		return 0;

	if (bbr->bw_probe_samples)
		bbr_handle_inflight_too_high(bbr, p, &bbr->drs->rs, ts);

	return 1;
}

static void bbr_probe_inflight_hi_upward(struct bbr *bbr, struct quic_cc_path *p, uint32_t acked)
{
	if (!bbr->drs->is_cwnd_limited || p->cwnd < bbr->inflight_hi)
		return; /* not fully using inflight_hi, so don't grow it */

	bbr->bw_probe_up_acks += acked;
	if (bbr->bw_probe_up_acks >= bbr->probe_up_cnt) {
		uint64_t delta;

		delta = bbr->bw_probe_up_acks / bbr->probe_up_cnt;
		bbr->bw_probe_up_acks -= delta * bbr->probe_up_cnt;
		bbr->inflight_hi += delta * p->mtu;
	}

	if (bbr->round_start)
		bbr_raise_inflight_hi_slope(bbr, p);
}

/* Track ACK state and update BBR.max_bw window and
 * BBR.inflight_hi.
 */
static void bbr_adapt_upper_bounds(struct bbr *bbr, struct quic_cc_path *p,
                                   uint32_t acked, uint32_t ts)
{
	if (bbr->ack_phase == BBR_ACK_PHASE_ACKS_PROBE_STARTING && bbr->round_start)
		/* starting to get bw probing samples */
		bbr->ack_phase = BBR_ACK_PHASE_ACKS_PROBE_FEEDBACK;

	if (bbr->ack_phase == BBR_ACK_PHASE_ACKS_PROBE_STOPPING && bbr->round_start) {
		/* end of samples from bw probing phase */
		if (bbr_is_probing_bw(bbr) && !bbr->drs->rs.is_app_limited)
			bbr_advance_max_bw_filter(bbr);
	}

	if (bbr_is_inflight_too_high(bbr, p, ts))
		return;

	/* bbr->bw_hi never be updated */
	if (bbr->inflight_hi == UINT64_MAX /* || bbr->bw_hi == UINT64_MAX */)
		return;

	if (bbr->drs->rs.tx_in_flight > bbr->inflight_hi)
		bbr->inflight_hi = bbr->drs->rs.tx_in_flight;

	if (p->delivery_rate > bbr->bw_hi)
		bbr->bw_hi = p->delivery_rate;

	if (bbr->state == BBR_ST_PROBE_BW_UP)
		bbr_probe_inflight_hi_upward(bbr, p, acked);
}


static inline int bbr_has_elapsed_in_phase(struct bbr *bbr,
                                           uint32_t interval, uint32_t ts)
{
	//return ts > bbr->cycle_stamp + interval;
	/* Note that <ts> should be set to <now_ms> */
	return tick_is_lt(tick_add(bbr->cycle_stamp, interval), ts);
}

static int bbr_is_reno_coexistence_probe_time(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t reno_rounds;

	reno_rounds = bbr_target_inflight(bbr, p) / p->mtu;
	return bbr->rounds_since_bw_probe >= MIN(reno_rounds, 63);
}

/* Is it time to transition from DOWN or CRUISE to REFILL? */
static int bbr_is_time_to_probe_bw(struct bbr *bbr, struct quic_cc_path *p,
                                   uint32_t ts)
{
	if (bbr_has_elapsed_in_phase(bbr, bbr->bw_probe_wait, ts) ||
	    bbr_is_reno_coexistence_probe_time(bbr, p)) {
		bbr_start_probe_bw_refill(bbr);
		return 1;
	}

	return 0;
}

/* Time to transition from DOWN to CRUISE? */
static int bbr_is_time_to_cruise(struct bbr *bbr, struct quic_cc_path *p)
{
	if (p->in_flight > bbr_inflight_with_headroom(bbr, p))
		return 0; /* not enough headroom */

	if (p->in_flight <= bbr_inflight(bbr, p, bbr->max_bw, 1))
		return 1; /* inflight <= estimated BDP */

	return 0;
}

/* Time to transition from UP to DOWN? */
static int bbr_is_time_to_go_down(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->drs->is_cwnd_limited && p->cwnd >= bbr->inflight_hi) {
		bbr_reset_full_bw(bbr); /* bw is limited by inflight_hi */
		bbr->full_bw = p->delivery_rate;
	}
	else if (bbr->full_bw_now) {
		return 1;  /* we estimate we've fully used path bw */
	}

	return 0;
}

/* The core state machine logic for ProbeBW: */
static void bbr_update_probe_bw_cycle_phase(struct bbr *bbr, struct quic_cc_path *p,
                                            uint32_t acked, uint32_t ts)
{
	if (!bbr->full_bw_reached)
		return; /* only handling steady-state behavior here */

	bbr_adapt_upper_bounds(bbr, p, acked, ts);
	if (!bbr_is_probing_bw(bbr))
		return; /* only handling ProbeBW states here: */

	switch (bbr->state) {
	case BBR_ST_PROBE_BW_DOWN:
		if (bbr_is_time_to_probe_bw(bbr, p, ts))
			return;/* already decided state transition */

		if (bbr_is_time_to_cruise(bbr, p))
			bbr_start_probe_bw_cruise(bbr);
		break;

	case BBR_ST_PROBE_BW_CRUISE:
		if (bbr_is_time_to_probe_bw(bbr, p, ts))
			return; /* already decided state transition */
		break;

	case BBR_ST_PROBE_BW_REFILL:
		/* After one round of REFILL, start UP */
		if (bbr->round_start) {
			bbr->bw_probe_samples = 1;
			bbr_start_probe_bw_up(bbr, p, ts);
		}
		break;

	case BBR_ST_PROBE_BW_UP:
		if (bbr_is_time_to_go_down(bbr, p))
			bbr_start_probe_bw_down(bbr, ts);
		break;

	default:
		break;
	}
}

static void bbr_update_min_rtt(struct bbr *bbr, uint32_t ack_rtt, uint32_t ts)
{
	int min_rtt_expired;

	fprintf(stderr, "%s ack_rtt=%u ts=%u\n", __func__, ack_rtt, ts);
	bbr->probe_rtt_expired =
		tick_is_lt(tick_add(bbr->probe_rtt_min_stamp, BBR_PROBE_RTT_INTERVAL), ts);
	if (ack_rtt != UINT32_MAX && (ack_rtt < bbr->probe_rtt_min_delay ||
	                              bbr->probe_rtt_expired)) {
		bbr->probe_rtt_min_delay = ack_rtt;
		bbr->probe_rtt_min_stamp = ts;
	}

	min_rtt_expired =
		tick_is_lt(tick_add(bbr->min_rtt_stamp, BBR_MIN_RTT_FILTERLEN), ts);
	if (bbr->probe_rtt_min_delay < bbr->min_rtt || min_rtt_expired) {
		bbr->min_rtt       = bbr->probe_rtt_min_delay;
		bbr->min_rtt_stamp = bbr->probe_rtt_min_stamp;
	}
}

static void bbr_check_probe_rtt_done(struct bbr *bbr, struct quic_cc_path *p,
                                     uint32_t ts)
{
	if (tick_isset(bbr->probe_rtt_done_stamp) && tick_is_lt(bbr->probe_rtt_done_stamp, ts)) {
		/* schedule next ProbeRTT: */
		bbr->probe_rtt_min_stamp = ts;
		bbr_restore_cwnd(bbr, p);
		bbr_exit_probe_rtt(bbr, ts);
	}
}

static void bbr_mark_connection_app_limited(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t app_limited = bbr->drs->delivered + p->in_flight;

	bbr->drs->app_limited = app_limited ? app_limited : p->mtu;
}

static void bbr_handle_probe_rtt(struct bbr *bbr, struct quic_cc_path *p, uint32_t ts)
{
	/* Ignore low rate samples during ProbeRTT: */
	bbr_mark_connection_app_limited(bbr, p);
	if (!tick_isset(bbr->probe_rtt_done_stamp) &&
		p->in_flight <= bbr_probe_rtt_cwnd(bbr, p)) {
		/* Wait for at least ProbeRTTDuration to elapse: */
		bbr->probe_rtt_done_stamp = tick_add(ts, BBR_PROBE_RTT_DURATION);
		/* Wait for at least one round to elapse: */
		bbr->probe_rtt_round_done = false;
		bbr_start_round(bbr);
	}
	else if (tick_isset(bbr->probe_rtt_done_stamp)) {
		if (bbr->round_start)
			bbr->probe_rtt_round_done = true;
		if (bbr->probe_rtt_round_done)
			bbr_check_probe_rtt_done(bbr, p, ts);
	}
}

static void bbr_check_probe_rtt(struct bbr *bbr, struct quic_cc_path *p, uint32_t ts)
{
	fprintf(stderr, "%s %d %d %d\n", __func__, bbr->state != BBR_ST_PROBE_RTT,
	        bbr->probe_rtt_expired, !bbr->idle_restart);
	if (bbr->state != BBR_ST_PROBE_RTT &&
	    bbr->probe_rtt_expired && !bbr->idle_restart) {
		bbr_enter_probe_rtt(bbr);
		bbr_save_cwnd(bbr, p);
		bbr->probe_rtt_done_stamp = TICK_ETERNITY;
		bbr->ack_phase = BBR_ACK_PHASE_ACKS_PROBE_STOPPING;
		bbr_start_round(bbr);
	}

	if (bbr->state == BBR_ST_PROBE_RTT)
		bbr_handle_probe_rtt(bbr, p, ts);
	if (bbr->drs->rs.delivered > 0)
		bbr->idle_restart = false;
}

static void bbr_update_max_bw(struct bbr *bbr, struct quic_cc_path *p,
                              uint64_t ack_packet_delivered)
{
	struct quic_cc_rs *rs = &bbr->drs->rs;

	fprintf(stderr, "%s\n", __func__);
	bbr_update_round(bbr, ack_packet_delivered);
	if (p->delivery_rate >= bbr->max_bw || !rs->is_app_limited) {
		wf_update(&bbr->max_bw_filter, p->delivery_rate, bbr->cycle_count);
		bbr->max_bw = wf_get_best(&bbr->max_bw_filter);
	}
}

static void bbr_init_lower_bounds(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->bw_lo == UINT64_MAX)
		bbr->bw_lo = bbr->max_bw;
	if (bbr->inflight_lo == UINT64_MAX)
		bbr->inflight_lo = p->cwnd;
}

static void bbr_loss_lower_bounds(struct bbr *bbr)
{
	bbr->bw_lo = MAX(bbr->bw_latest, bbr->bw_lo * BBR_BETA_MULT / BBR_BETA_DIVI);
	bbr->inflight_lo = MAX(bbr->inflight_latest,
	                       bbr->inflight_lo * BBR_BETA_MULT / BBR_BETA_DIVI);
}

static void bbr_adapt_lower_bounds_from_congestion(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr_is_probing_bw(bbr))
		return;

	if (bbr->loss_in_round) {
		bbr_init_lower_bounds(bbr, p);
		bbr_loss_lower_bounds(bbr);
	}
}

static void bbr_update_congestion_signals(struct bbr *bbr, struct quic_cc_path *p,
                                          uint64_t bytes_lost, uint64_t ack_packet_delivered)
{
	bbr_update_max_bw(bbr, p, ack_packet_delivered);
	if (bytes_lost) {
		bbr->bytes_lost_in_round += bytes_lost;
		++bbr->loss_events_in_round;

		if (!bbr->loss_in_round) {
			bbr->loss_in_round = 1;
			bbr->loss_round_delivered = bbr->drs->delivered;
		}
	}

	if (!bbr->loss_round_start)
		return;  /* wait until end of round trip */

	bbr_adapt_lower_bounds_from_congestion(bbr, p);  /* once per round, adapt */
	bbr->loss_in_round = 0;
}

static void bbr_update_ack_aggregation(struct bbr *bbr,
                                       struct quic_cc_path *p,
                                       uint32_t acked)
{
	uint32_t interval = now_ms - bbr->extra_acked_interval_start;
	uint64_t expected_delivered = bbr->bw * interval;
	uint64_t extra;

	if (bbr->extra_acked_delivered <= expected_delivered) {
		bbr->extra_acked_delivered = 0;
		bbr->extra_acked_interval_start = now_ms;
		expected_delivered = 0;
	}

	bbr->extra_acked_delivered += acked;
	extra = bbr->extra_acked_delivered - expected_delivered;
	extra = MIN(extra, p->cwnd);

	/* XXX CHECK THIS XXX: the RFC make use of a <window_length> parameter
	 * to be passed to wf_update().
	 */
	wf_update(&bbr->extra_acked_filter, extra, bbr->round_count);
	bbr->extra_acked = wf_get_best(&bbr->extra_acked_filter);
}

static void bbr_advance_latest_delivery_signals(struct bbr *bbr,
                                                struct quic_cc_path *p)
{
	if (bbr->loss_round_start) {
		bbr->bw_latest = p->delivery_rate;
		bbr->inflight_latest = bbr->drs->rs.delivered;
	}
}

static void bbr_check_full_bw_reached(struct bbr *bbr, struct quic_cc_path *p)
{
	struct quic_cc_rs *rs = &bbr->drs->rs;

	if (bbr->full_bw_now || rs->is_app_limited)
		return; /* no need to check for a full pipe now */

	if (p->delivery_rate * 100 >= bbr->full_bw * 125) {
		bbr_reset_full_bw(bbr);       /* bw is still growing, so reset */
		bbr->full_bw = p->delivery_rate; /* record new baseline bw */
		return;
	}

	if (!bbr->round_start)
		return;

	bbr->full_bw_count++;   /* another round w/o much growth */
	bbr->full_bw_now = bbr->full_bw_count >= 3;
	if (bbr->full_bw_now)
		bbr->full_bw_reached = true;
}

static void bbr_bound_bw_for_model(struct bbr *bbr)
{
	fprintf(stderr, "%s max_bw=%llu bw_lo=%llu\n", __func__, (ull)bbr->max_bw, (ull)bbr->bw_lo);
	bbr->bw = MIN(bbr->max_bw, bbr->bw_lo);
}

static void bbr_update_model_and_state(struct bbr *bbr,
                                       struct quic_cc_path *p,
                                       uint32_t acked,
                                       uint32_t ack_rtt,
                                       uint32_t bytes_lost,
                                       uint32_t ts)
{
	bbr_update_latest_delivery_signals(bbr, p);
	bbr_update_congestion_signals(bbr, p, bytes_lost, acked);
	bbr_update_ack_aggregation(bbr, p, acked);
	bbr_check_full_bw_reached(bbr, p);
	bbr_check_startup_done(bbr);
	bbr_check_drain_done(bbr, p, ts);
	bbr_update_probe_bw_cycle_phase(bbr, p, acked, ts);
	bbr_update_min_rtt(bbr, ack_rtt, ts);
	bbr_check_probe_rtt(bbr, p, ts);
	bbr_advance_latest_delivery_signals(bbr, p);
	bbr_bound_bw_for_model(bbr);
}

static void bbr_update_control_parameters(struct bbr *bbr,
                                          struct quic_cc_path *p,
                                          uint32_t acked)
{
	bbr_set_pacing_rate(bbr, p);
	bbr_set_send_quantum(bbr, p);
	bbr_set_cwnd(bbr, p, acked);
}

__attribute__((unused))
static void bbr_handle_recovery(struct quic_cc *cc)
{
	/* XXX TODO XXX */
}

__attribute__((unused))
static void bbr_update_on_ack(struct quic_cc *cc,
                              uint32_t acked, uint32_t ack_rtt,
                              uint32_t bytes_lost, uint32_t ts)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	bbr_update_model_and_state(bbr, p, acked, ack_rtt, bytes_lost, ts);
	bbr_update_control_parameters(bbr, p, acked);
}

static void bbr_note_loss(struct bbr *bbr, uint64_t C_delivered)
{
	if (!bbr->loss_in_round)   /* first loss in this round trip? */
		bbr->loss_round_delivered = C_delivered;
	bbr->loss_in_round = 1;
}

/* At what prefix of packet did losses exceed BBRLossThresh? */
static uint64_t bbr_inflight_hi_from_lost_packet(struct quic_cc_rs *rs, struct quic_tx_packet *pkt)
{
	uint64_t inflight_prev, lost_prev, lost_prefix;
	uint64_t size = pkt->len;

	/* What was in flight before this packet? */
	inflight_prev = rs->tx_in_flight - size;
	/* What was lost before this packet? */
	lost_prev = rs->lost - size;
	lost_prefix =
		(BBR_LOSS_THRESH_MULT * inflight_prev - lost_prev * BBR_LOSS_THRESH_DIVI) /
		(BBR_LOSS_THRESH_DIVI - BBR_LOSS_THRESH_MULT);
	return inflight_prev + lost_prefix;
}

/* XXX TODO: check this function, not clear at all! XXX */
static void bbr_handle_lost_packet(struct bbr *bbr, struct quic_cc_path *p,
                                   struct quic_tx_packet *pkt,
                                   uint32_t lost, uint32_t ts)
{
	struct quic_cc_rs rs = {0};

	/* C.delivered = bbr->drs->delivered */
	bbr_note_loss(bbr, bbr->drs->delivered);
	if (!bbr->bw_probe_samples)
		return; /* not a packet sent while probing bandwidth */

	rs.tx_in_flight = pkt->in_flight_len; /* inflight at transmit */
	/* here bbr->rst->lost is not yet incremented */
	rs.lost = bbr->drs->lost + pkt->len - lost; /* data lost since transmit */
	/* XXX TODO: check when must be set this QUIC_FL_TX_PACKET_IS_APP_LIMITED flag */
	rs.is_app_limited = pkt->rs.is_app_limited;
	if (is_inflight_too_high(&rs)) {
		rs.tx_in_flight = bbr_inflight_hi_from_lost_packet(&rs, pkt);
		bbr_handle_inflight_too_high(bbr, p, &rs, ts);
	}
}

__attribute__((unused))
static void bbr_update_on_loss(struct quic_cc *cc, struct quic_tx_packet *pkt,
                               uint32_t ts, uint32_t lost)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	bbr_handle_lost_packet(bbr, p, pkt, lost, ts);
}

static void bbr_handle_restart_from_idle(struct bbr *bbr, struct quic_cc_path *p)
{
	if (p->in_flight != 0 || !bbr->drs->app_limited)
		return;

	bbr->idle_restart = true;
	bbr->extra_acked_interval_start = now_ms;

	if (bbr_is_probing_bw(bbr)) {
		bbr_set_pacing_rate_with_gain(bbr, p, 100);
	} else if (bbr->state == BBR_ST_PROBE_RTT) {
		bbr_check_probe_rtt_done(bbr, p, now_ms);
	}
}

static void bbr_on_transmit(struct quic_cc *cc)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	bbr_handle_restart_from_idle(bbr, p);
}

#if 0
static void bbr_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	switch (ev->type) {
	case QUIC_CC_EVT_TX:
		bbr_on_transmit(cc);
		break;
	case QUIC_CC_EVT_ACK:
		bbr_handle_recovery(cc); /* XXX TODO XXX */
		bbr_update_on_ack(cc, ev->ack.acked, ev->ack.rtt, ev->ack.bytes_lost, now_ms);
		break;
	case QUIC_CC_EVT_LOSS:
		break;
	default:
		break;
	}
}
#endif

static void bbr_drs_on_transmit(struct quic_cc *cc, struct quic_tx_packet *pkt)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	quic_cc_drs_on_pkt_sent(p, pkt, bbr->drs);
}

struct quic_cc_drs *bbr_get_drs(struct quic_cc *cc)
{
	struct bbr *bbr = quic_cc_priv(cc);
	return bbr->drs;
}

struct quic_cc_algo quic_cc_algo_bbr = {
	.type        = QUIC_CC_ALGO_TP_BBR,
	.init        = bbr_init,
	//.event       = bbr_event,
	.get_drs     = bbr_get_drs,
	.on_transmit = bbr_on_transmit,
	.drs_on_transmit = bbr_drs_on_transmit,
};

void bbr_check(void)
{
	struct quic_cc *cc;
	BUG_ON(sizeof(struct bbr) > sizeof(cc->priv));
}

INITCALL0(STG_REGISTER, bbr_check);
