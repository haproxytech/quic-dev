#include <haproxy/quic_pacing.h>

#include <haproxy/quic_trace.h>
#include <haproxy/quic_tx.h>
#include <haproxy/trace.h>

struct quic_conn;

enum quic_tx_err quic_pacing_send(struct quic_pacer *pacer, struct quic_conn *qc)
{
	enum quic_tx_err ret;

	if (pacer->next > now_mono_time())
		return QUIC_TX_ERR_AGAIN;

	BUG_ON(LIST_ISEMPTY(&pacer->frms));
	ret = qc_send_mux(qc, &pacer->frms, 1);
	TRACE_POINT(QUIC_EV_CONN_TXPKT);

	/* TODO handle QUIC_TX_ERR_FATAL */
	return ret;
}

void quic_pacing_set_frm_list(struct quic_pacer *pacer, struct list *frms, int sent)
{
	struct quic_frame *frm, *frm_back;

	TRACE_POINT(QUIC_EV_CONN_TXPKT);
	if (frms != &pacer->frms) {
		LIST_INIT(&pacer->frms);

		list_for_each_entry_safe(frm, frm_back, frms, list) {
			LIST_DEL_INIT(&frm->list);
			LIST_APPEND(&pacer->frms, &frm->list);
		}
	}

	pacer->next = now_mono_time() + quic_pacing_ns_pkt(pacer) * sent;
}
