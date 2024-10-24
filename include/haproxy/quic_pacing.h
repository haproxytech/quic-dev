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

static inline void quic_pacing_set_frm_list(struct quic_pacer *pacer,
                                            struct list *frms)
{
	struct quic_frame *frm, *frm_back;

	LIST_INIT(&pacer->frms);

	list_for_each_entry_safe(frm, frm_back, frms, list) {
		LIST_DEL_INIT(&frm->list);
		LIST_APPEND(&pacer->frms, &frm->list);
	}
}

static inline ullong quic_pacing_ns_pkt(const struct quic_pacer *pacer)
{
	return pacer->path->loss.srtt * 1000000 / (pacer->path->cwnd / pacer->path->mtu + 1);
}

#endif /* _HAPROXY_QUIC_PACING_H */
