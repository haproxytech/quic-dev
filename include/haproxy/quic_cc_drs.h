#include <inttypes.h>

#include <haproxy/window_filter.h>

#define false 0
#define true  1

/* Rate sample */
struct quic_cc_rs {
	uint64_t delivered;
	uint64_t prior_delivered;
	uint64_t tx_in_flight;
	uint64_t lost;
	uint64_t prior_lost;
	int64_t last_end_seq;
	uint32_t interval;
	uint32_t prior_time;
	uint32_t send_elapsed;
	uint32_t ack_elapsed;
	uint32_t is_app_limited;
};

/* Delivery rate sampling */
struct quic_cc_drs {
	struct quic_cc_rs rs;
	struct wf wf;
	uint64_t round_count;
	uint64_t next_round_delivered;
	uint64_t delivered;
	uint64_t lost;
	int64_t last_seq;
	uint32_t delivered_time;
	uint32_t first_sent_time;
	int is_cwnd_limited; /* boolean */
	int app_limited; /* boolean */
};

extern struct pool_head *pool_head_quic_cc_drs;

void quic_cc_drs_init(struct quic_cc_drs *drs);
void quic_cc_drs_on_pkt_sent(struct quic_cc_path *path,
                             struct quic_tx_packet *pkt, struct quic_cc_drs *drs);
void quic_cc_drs_update_rate_sample(struct quic_cc_drs *drs,
                                    struct quic_tx_packet *pkt);
void quic_cc_drs_on_ack_recv(struct quic_cc_drs *drs, struct quic_cc_path *path,
                             uint64_t pkt_delivered);
