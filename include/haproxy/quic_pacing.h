#ifndef _HAPROXY_QUIC_PACING_H
#define _HAPROXY_QUIC_PACING_H

#include <haproxy/quic_pacing-t.h>

#include <haproxy/list.h>
#include <haproxy/quic_frame-t.h>

static inline void quic_pacing_init(struct quic_pacer *pacer,
                                    const struct quic_cc_path *path)
{
	pacer->path = path;
}

static inline ullong quic_pacing_ns_pkt(const struct quic_pacer *pacer)
{
	return pacer->path->loss.srtt * 1000000 / (pacer->path->cwnd / pacer->path->mtu + 1);
}

enum quic_tx_err quic_pacing_send(struct quic_pacer *pacer, struct quic_conn *qc);

void quic_pacing_set_frm_list(struct quic_pacer *pacer, struct list *frms, int sent);

#endif /* _HAPROXY_QUIC_PACING_H */
