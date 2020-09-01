/*
 * QUIC transport layer over SOCK_DGRAM sockets.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/proxy.h>
#include <proto/quic_cc.h>
#include <proto/quic_frame.h>
#include <proto/quic_loss.h>
#include <proto/quic_tls.h>
#include <proto/ssl_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/trace.h>
#include <proto/xprt_quic.h>

#include <types/global.h>

struct quic_conn_ctx {
	struct connection *conn;
	SSL *ssl;
	BIO *bio;
	int state;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *subs;
};

struct quic_transport_params quid_dflt_transport_params = {
	.max_packet_size    = QUIC_DFLT_MAX_PACKET_SIZE,
	.ack_delay_exponent = QUIC_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay      = QUIC_DFLT_MAX_ACK_DELAY,
};

/* trace source and events */
static void quic_trace(enum trace_level level, uint64_t mask, \
                       const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event quic_trace_events[] = {
	{ .mask = QUIC_EV_CONN_NEW,      .name = "new_conn",         .desc = "new QUIC connection" },
	{ .mask = QUIC_EV_CONN_INIT,     .name = "new_conn_init",    .desc = "new QUIC connection initialization" },
	{ .mask = QUIC_EV_CONN_ISEC,     .name = "init_secs",        .desc = "initial secrets derivation" },
	{ .mask = QUIC_EV_CONN_RSEC,     .name = "read_secs",        .desc = "read secrets derivation" },
	{ .mask = QUIC_EV_CONN_WSEC,     .name = "write_secs",       .desc = "write secrets derivation" },
	{ .mask = QUIC_EV_CONN_LPKT,     .name = "lstnr_packet",     .desc = "new listener received packet" },
	{ .mask = QUIC_EV_CONN_SPKT,     .name = "srv_packet",       .desc = "new server received packet" },
	{ .mask = QUIC_EV_CONN_CHPKT,    .name = "chdshk_pkt",       .desc = "clear handhshake packet building" },
	{ .mask = QUIC_EV_CONN_HPKT,     .name = "hdshk_pkt",        .desc = "handhshake packet building" },
	{ .mask = QUIC_EV_CONN_PAPKT,    .name = "phdshk_apkt",      .desc = "post handhshake application packet preparation" },
	{ .mask = QUIC_EV_CONN_PAPKTS,   .name = "phdshk_apkts",     .desc = "post handhshake application packets preparation" },
	{ .mask = QUIC_EV_CONN_HDSHK,    .name = "hdshk",            .desc = "SSL handhshake processing" },
	{ .mask = QUIC_EV_CONN_RMHP,     .name = "rm_hp",            .desc = "Remove header protection" },
	{ .mask = QUIC_EV_CONN_PRSHPKT,  .name = "parse_hpkt",       .desc = "parse handshake packet" },
	{ .mask = QUIC_EV_CONN_PRSAPKT,  .name = "parse_apkt",       .desc = "parse application packet" },
	{ .mask = QUIC_EV_CONN_PRSFRM,   .name = "parse_frm",        .desc = "parse frame" },
	{ .mask = QUIC_EV_CONN_PRSAFRM,  .name = "parse_ack_frm",    .desc = "parse ACK frame" },
	{ .mask = QUIC_EV_CONN_BFRM,     .name = "build_frm",        .desc = "build frame" },
	{ .mask = QUIC_EV_CONN_PHPKTS,   .name = "phdshk_pkts",      .desc = "handhshake packets preparation" },
	{ .mask = QUIC_EV_CONN_TRMHP,    .name = "rm_hp_try",        .desc = "header protection removing try" },
	{ .mask = QUIC_EV_CONN_ELRMHP,   .name = "el_rm_hp",         .desc = "handshake enc. level header protection removing" },
	{ .mask = QUIC_EV_CONN_ELRXPKTS, .name = "el_treat_rx_pkts", .desc = "handshake enc. level rx packets treatment" },
	{ .mask = QUIC_EV_CONN_SSLDATA,  .name = "ssl_provide_data", .desc = "CRYPTO data provision to TLS stack" },
	{ .mask = QUIC_EV_CONN_RXCDATA,  .name = "el_treat_rx_cfrms",.desc = "enc. level RX CRYPTO frames processing"},
	{ .mask = QUIC_EV_CONN_ADDDATA,  .name = "add_hdshk_data",   .desc = "TLS stack ->add_handshake_data() call"},
	{ .mask = QUIC_EV_CONN_FFLIGHT,  .name = "flush_flight",     .desc = "TLS stack ->flush_flight() call"},
	{ .mask = QUIC_EV_CONN_SSLALERT, .name = "send_alert",       .desc = "TLS stack ->send_alert() call"},
	{ .mask = QUIC_EV_CONN_CPAPKT,   .name = "phdshk_cpakt",     .desc = "clear post handhshake app. packet preparation" },
	{ .mask = QUIC_EV_CONN_RTTUPDT,  .name = "rtt_updt",         .desc = "RTT sampling" },
	{ .mask = QUIC_EV_CONN_SPPKTS,   .name = "sppkts",           .desc = "send prepared packets" },
	{ .mask = QUIC_EV_CONN_PKTLOSS,  .name = "pktloss",          .desc = "detect packet loss" },
	{ .mask = QUIC_EV_CONN_STIMER,   .name = "stimer",           .desc = "set timer" },
	{ .mask = QUIC_EV_CONN_PTIMER,   .name = "ptimer",           .desc = "process timer" },
	{ .mask = QUIC_EV_CONN_SPTO,     .name = "spto",             .desc = "set PTO" },

	{ .mask = QUIC_EV_CONN_ENEW,     .name = "new_conn_err",     .desc = "error on new QUIC connection" },
	{ .mask = QUIC_EV_CONN_EISEC,    .name = "init_secs_err",    .desc = "error on initial secrets derivation" },
	{ .mask = QUIC_EV_CONN_ERSEC,    .name = "read_secs_err",    .desc = "error on read secrets derivation" },
	{ .mask = QUIC_EV_CONN_EWSEC,    .name = "write_secs_err",   .desc = "error on write secrets derivation" },
	{ .mask = QUIC_EV_CONN_ELPKT,    .name = "lstnr_packet_err", .desc = "error on new listener received packet" },
	{ .mask = QUIC_EV_CONN_ESPKT,    .name = "srv_packet_err",   .desc = "error on new server received packet" },
	{ .mask = QUIC_EV_CONN_ECHPKT,   .name = "chdshk_pkt_err",   .desc = "error on clear handhshake packet building" },
	{ .mask = QUIC_EV_CONN_EHPKT,    .name = "hdshk_pkt_err",    .desc = "error on handhshake packet building" },
	{ .mask = QUIC_EV_CONN_EPAPKT,   .name = "phdshk_apkt_err",  .desc = "error on post handhshake application packet building" },
	{ /* end */ }
};

static const struct name_desc quic_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="quic", .desc="QUIC transport" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc quic_trace_decoding[] = {
#define QUIC_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
	{ /* end */ }
};


struct trace_source trace_quic = {
	.name = IST("quic"),
	.desc = "QUIC xprt",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a connection */
	.default_cb = quic_trace,
	.known_events = quic_trace_events,
	.lockon_args = quic_trace_lockon_args,
	.decoding = quic_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

#define TRACE_SOURCE    &trace_quic
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

#if 1
__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...)
{
	int i;
	va_list ap;
	const unsigned char *p;
	char str_buf[2 + 1 + 16 + 1 + 1];

	va_start(ap, title_fmt);
	vfprintf(stderr, title_fmt, ap);
	va_end(ap);

	p = buf;
	str_buf[0] = str_buf[1] = ' ';
	str_buf[2] = '|';

	for (i = 0; i < buflen; i++) {
		if (!(i & 0xf))
			fprintf(stderr, "%08X: ", i);
		fprintf(stderr, " %02x", *p);
		if (isalnum(*p))
			str_buf[(i & 0xf) + 3] = *p;
		else
			str_buf[(i & 0xf) + 3] = '.';
		if ((i & 0xf) == 0xf || i == buflen -1) {
			int k;

			for (k = 0; k < (0x10 - (i & 0xf) - 1); k++)
				fprintf(stderr, "   ");
			str_buf[(i & 0xf) + 4] = '|';
			str_buf[(i & 0xf) + 5 ] = '\0';
			fprintf(stderr, "%s\n", str_buf);
		}
		p++;
	}
}
#else
__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...) {}
#endif

DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));

DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connnection_id_pool", sizeof(struct quic_connection_id));

DECLARE_POOL(pool_head_quic_rx_packet, "quic_rx_packet_pool", sizeof(struct quic_rx_packet));

DECLARE_STATIC_POOL(pool_head_quic_tx_packet, "quic_tx_packet_pool", sizeof(struct quic_tx_packet));

DECLARE_STATIC_POOL(pool_head_quic_conn_ctx, "quic_conn_ctx_pool", sizeof(struct quic_conn_ctx));

DECLARE_STATIC_POOL(pool_head_quic_rx_crypto_frm, "quic_rx_crypto_frm_pool", sizeof(struct quic_rx_crypto_frm));

DECLARE_STATIC_POOL(pool_head_quic_tx_frm, "quic_tx_frm_pool", sizeof(struct quic_tx_frm));

DECLARE_STATIC_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf_pool", sizeof(struct quic_crypto_buf));

DECLARE_STATIC_POOL(pool_head_quic_frame, "quic_frame_pool", sizeof(struct quic_frame));

DECLARE_STATIC_POOL(pool_head_quic_ack_range, "quic_ack_range_pool", sizeof(struct quic_ack_range));

static BIO_METHOD *ha_quic_meth;


static ssize_t qc_build_hdshk_pkt(struct q_buf *buf, struct quic_conn *qc, int pkt_type,
                                  struct quic_enc_level *qel);

static int qc_prep_phdshk_pkts(struct quic_conn *qc);

/* Add traces to <buf> depending on <frm> TX frame type. */
static inline void chunk_tx_frm_appendf(struct buffer *buf,
                                        const struct quic_tx_frm *frm)
{
	switch (frm->type) {
	case QUIC_FT_CRYPTO:
		chunk_appendf(buf, " cfoff=%lu cflen=%lu",
		              frm->crypto.offset, frm->crypto.len);
		break;
	default:
		chunk_appendf(buf, " %s", quic_frame_type_string(frm->type));
	}
}

/*
 * the QUIC traces always expect that arg1, if non-null, is of type connection.
 */
static void quic_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;

	if (conn) {
		struct quic_tls_secrets *secs;
		struct quic_conn *qc;

		qc = conn->quic_conn;
		chunk_appendf(&trace_buf, " : conn@%p", conn);
		if ((mask & QUIC_EV_CONN_INIT) && qc) {
			chunk_appendf(&trace_buf, "\n  odcid");
			quic_cid_dump(&trace_buf, &qc->odcid);
			chunk_appendf(&trace_buf, " dcid");
			quic_cid_dump(&trace_buf, &qc->dcid);
			chunk_appendf(&trace_buf, " scid");
			quic_cid_dump(&trace_buf, &qc->scid);
		}

		if (mask & QUIC_EV_CONN_ADDDATA) {
			const enum ssl_encryption_level_t *level = a2;
			const size_t *len = a3;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, " el=%c(%d)", quic_enc_level_char(lvl), lvl);
			}
			if (len)
				chunk_appendf(&trace_buf, " len=%zu", *len);
		}
		if ((mask & QUIC_EV_CONN_ISEC) && qc) {
			/* Initial read & write secrets. */
			enum quic_tls_enc_level level = QUIC_TLS_ENC_LEVEL_INITIAL;
			const unsigned char *rx_sec = a2;
			const unsigned char *tx_sec = a3;

			secs = &qc->els[level].tls_ctx.rx;
			if (secs->flags & QUIC_FL_TLS_SECRETS_SET) {
				chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(level));
				if (rx_sec)
					quic_tls_secret_hexdump(&trace_buf, rx_sec, 32);
				quic_tls_keys_hexdump(&trace_buf, secs);
			}
			secs = &qc->els[level].tls_ctx.tx;
			if (secs->flags & QUIC_FL_TLS_SECRETS_SET) {
				chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(level));
				if (tx_sec)
					quic_tls_secret_hexdump(&trace_buf, tx_sec, 32);
				quic_tls_keys_hexdump(&trace_buf, secs);
			}
		}
		if (mask & (QUIC_EV_CONN_RSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;
			const unsigned char *secret = a3;
			const size_t *secret_len = a4;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, "\n  RX el=%c", quic_enc_level_char(lvl));
				if (secret && secret_len)
					quic_tls_secret_hexdump(&trace_buf, secret, *secret_len);
				secs = &qc->els[lvl].tls_ctx.rx;
				if (secs->flags & QUIC_FL_TLS_SECRETS_SET)
					quic_tls_keys_hexdump(&trace_buf, secs);
			}
		}

		if (mask & (QUIC_EV_CONN_WSEC|QUIC_EV_CONN_RWSEC)) {
			const enum ssl_encryption_level_t *level = a2;
			const unsigned char *secret = a3;
			const size_t *secret_len = a4;

			if (level) {
				enum quic_tls_enc_level lvl = ssl_to_quic_enc_level(*level);

				chunk_appendf(&trace_buf, "\n  TX el=%c", quic_enc_level_char(lvl));
				if (secret && secret_len)
					quic_tls_secret_hexdump(&trace_buf, secret, *secret_len);
				secs = &qc->els[lvl].tls_ctx.tx;
				if (secs->flags & QUIC_FL_TLS_SECRETS_SET)
					quic_tls_keys_hexdump(&trace_buf, secs);
			}

		}
		if (mask & QUIC_EV_CONN_CHPKT) {
			const long int len = (long int)a2;

			if (qc->ifcdata != QUIC_CRYPTO_IN_FLIGHT_MAX)
				chunk_appendf(&trace_buf, "\n  ifcdata=%lu", qc->ifcdata);
			if (len)
				chunk_appendf(&trace_buf, " pktlen=%ld", len);
		}

		if (mask & QUIC_EV_CONN_HPKT) {
			const struct quic_tx_packet *pkt = a2;

			if (pkt) {
				const struct quic_tx_frm *frm;
				chunk_appendf(&trace_buf, "\n  pn=%lu cdata_len=%lu",
				              (unsigned long)pkt->pn_node.key, pkt->cdata_len);
				list_for_each_entry(frm, &pkt->frms, list)
					chunk_tx_frm_appendf(&trace_buf, frm);
				chunk_appendf(&trace_buf, " ifcdata=%zu", qc->ifcdata);
			}
		}

		if (mask & QUIC_EV_CONN_HDSHK) {
			const enum quic_handshake_state *state = a2;
			const int *err = a3;

			if (state)
				chunk_appendf(&trace_buf, " state=%s", quic_hdshk_state_str(*state));
			if (err)
				chunk_appendf(&trace_buf, " err=%s", ssl_error_str(*err));
		}

		if (mask & (QUIC_EV_CONN_TRMHP|QUIC_EV_CONN_ELRMHP)) {
			const struct quic_rx_packet *pkt = a2;
			const unsigned long *pktlen = a3;
			const SSL *ssl = a4;

			if (pkt) {
				chunk_appendf(&trace_buf, "\n  pkt@%p el=%c",
				              pkt, quic_packet_type_enc_level_char(pkt->type));
				if (pkt->pnl)
					chunk_appendf(&trace_buf, " pnl=%u pn=%lu", pkt->pnl, pkt->pn);
				if (pkt->token_len)
					chunk_appendf(&trace_buf, " toklen=%lu", pkt->token_len);
				if (pkt->aad_len)
					chunk_appendf(&trace_buf, " aadlen=%lu", pkt->aad_len);
				chunk_appendf(&trace_buf, " flags:0x%x len=%lu", pkt->flags, pkt->len);
			}
			if (pktlen)
				chunk_appendf(&trace_buf, " (%ld)", *pktlen);
			if (ssl) {
				enum ssl_encryption_level_t level = SSL_quic_read_level(ssl);
				chunk_appendf(&trace_buf, " el=%c",
				              quic_enc_level_char(ssl_to_quic_enc_level(level)));
			}
		}

		if (mask & (QUIC_EV_CONN_ELRXPKTS|QUIC_EV_CONN_PRSHPKT|QUIC_EV_CONN_SSLDATA)) {
			const struct quic_rx_packet *pkt = a2;
			const struct quic_rx_crypto_frm *cf = a3;
			const SSL *ssl = a4;

			if (pkt)
				chunk_appendf(&trace_buf, "\n  pkt@%p el=%c pn=%lu", pkt,
							  quic_packet_type_enc_level_char(pkt->type), pkt->pn);
			if (cf)
				chunk_appendf(&trace_buf, " cfoff=%lu cflen=%lu",
							  (unsigned long)cf->offset_node.key, cf->len);
			if (ssl) {
				enum ssl_encryption_level_t level = SSL_quic_read_level(ssl);
				chunk_appendf(&trace_buf, " el=%c",
							  quic_enc_level_char(ssl_to_quic_enc_level(level)));
			}
		}

		if (mask & (QUIC_EV_CONN_PRSFRM|QUIC_EV_CONN_BFRM)) {
			const struct quic_frame *frm = a2;

			if (a2)
				chunk_appendf(&trace_buf, " %s", quic_frame_type_string(frm->type));
		}

		if (mask & QUIC_EV_CONN_RMHP) {
			const struct quic_rx_packet *pkt;

			pkt = a2;
			if (pkt) {
				const int *ret = a3;

				chunk_appendf(&trace_buf, " pkt@%p", pkt);
				if (ret && *ret)
					chunk_appendf(&trace_buf, "\n  pnl=%u pn=%lu", pkt->pnl, pkt->pn);
			}
		}

		if (mask & QUIC_EV_CONN_PRSAFRM) {
			const struct quic_tx_frm *frm = a2;
			const unsigned long *val1 = a3;
			const unsigned long *val2 = a4;

			if (frm)
				chunk_tx_frm_appendf(&trace_buf, frm);
			if (val1)
				chunk_appendf(&trace_buf, " %lu", *val1);
			if (val2)
				chunk_appendf(&trace_buf, "..%lu", *val2);
		}

		if (mask & QUIC_EV_CONN_RTTUPDT) {
			const unsigned int *rtt_sample = a2;
			const unsigned int *ack_delay = a3;
			const struct quic_loss *ql = a4;

			if (rtt_sample)
				chunk_appendf(&trace_buf, " rtt_sample=%ums", *rtt_sample);
			if (ack_delay)
				chunk_appendf(&trace_buf, " ack_delay=%ums", *ack_delay);
			if (ql)
				chunk_appendf(&trace_buf,
				              " srtt=%ums rttvar=%ums min_rtt=%ums",
				              ql->srtt >> 3, ql->rtt_var >> 2, ql->rtt_min);
		}
		if (mask & QUIC_EV_CONN_CC) {
			const struct quic_cc_event *ev = a2;
			const struct quic_cc *cc = a3;

			if (a2)
				quic_cc_event_trace(&trace_buf, ev);
			if (a3)
				quic_cc_state_trace(&trace_buf, cc);
		}

		if (mask & QUIC_EV_CONN_PKTLOSS) {
			const struct quic_pktns *pktns = a2;
			const struct list *lost_pkts = a3;
			struct quic_conn *qc = conn->quic_conn;

			if (pktns) {
				chunk_appendf(&trace_buf, " pktns=%s",
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H");
				if (pktns->tx.loss_time)
				              chunk_appendf(&trace_buf, " loss_time=%dms",
				                            TICKS_TO_MS(qc->timer - now_ms));
			}
			if (lost_pkts && !LIST_ISEMPTY(lost_pkts)) {
				struct quic_tx_packet *pkt;

				chunk_appendf(&trace_buf, " lost_pkts:");
				list_for_each_entry(pkt, lost_pkts, list)
					chunk_appendf(&trace_buf, " %lu", (unsigned long)pkt->pn_node.key);
			}
		}

		if (mask & (QUIC_EV_CONN_STIMER|QUIC_EV_CONN_SPTO)) {
			struct quic_conn *qc = conn->quic_conn;
			const struct quic_pktns *pktns = a2;
			const int *duration = a3;

			if (pktns) {
				chunk_appendf(&trace_buf, " pktns=%s",
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H");
				if (mask & QUIC_EV_CONN_STIMER) {
					if (pktns->tx.loss_time)
						chunk_appendf(&trace_buf, " loss_time=%dms",
						              TICKS_TO_MS(pktns->tx.loss_time - now_ms));
				}
				if (mask & QUIC_EV_CONN_SPTO) {
					if (pktns->tx.time_of_last_eliciting)
						chunk_appendf(&trace_buf, " tole=%dms",
									  TICKS_TO_MS(pktns->tx.time_of_last_eliciting - now_ms));
					if (duration)
						chunk_appendf(&trace_buf, " duration=%dms", *duration);
					if (pktns->tx.pto)
						chunk_appendf(&trace_buf, " pto=%dms", TICKS_TO_MS(pktns->tx.pto - now_ms));
				}
			}

			if (!(mask & QUIC_EV_CONN_SPTO) && qc->timer_task) {
				chunk_appendf(&trace_buf,
				              " expire=%dms", TICKS_TO_MS(qc->timer - now_ms));
			}
		}

		if (mask & QUIC_EV_CONN_SPPKTS) {
			const struct quic_tx_packet *pkt = a2;

			if (pkt) {
				chunk_appendf(&trace_buf, " #%lu(%s)",
				              (unsigned long)pkt->pn_node.key,
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_INITIAL] ? "I" :
				              pkt->pktns == &qc->pktns[QUIC_TLS_PKTNS_01RTT] ? "01RTT": "H");
			}
		}
	}
	if (mask & QUIC_EV_CONN_LPKT) {
		const struct quic_rx_packet *pkt = a2;

		if (pkt)
			chunk_appendf(&trace_buf, " type=0x%02x long? %d", pkt->type, qc_pkt_long(pkt));
	}

}

/* Returns 1 if the peer has validated <qc> QUIC connection address, 0 if not. */
static inline int quic_peer_validated_addr(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;

	qc = ctx->conn->quic_conn;
	if (objt_server(qc->conn->target))
		return 1;

	if ((qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE].pktns->flags & QUIC_FL_PKTNS_ACK_RECEIVED) ||
	    (qc->els[QUIC_TLS_ENC_LEVEL_APP].pktns->flags & QUIC_FL_PKTNS_ACK_RECEIVED) ||
	    (ctx->state & QUIC_HS_ST_COMPLETE))
		return 1;

	return 0;
}

/* Set the timer attached to the QUIC connection with <ctx> as I/O handler and used for
 * both loss detection and PTO and schedule the task assiated to this timer if needed.
 */
static inline void qc_set_timer(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;
	struct quic_pktns *pktns;

	TRACE_ENTER(QUIC_EV_CONN_STIMER, ctx->conn);
	qc = ctx->conn->quic_conn;
	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		qc->timer = pktns->tx.loss_time;
		goto out;
	}

	/* XXX TODO: anti-amplification: the timer must be
	 * cancelled for a server which reached the anti-amplification limit.
	 */

	if (!qc->path->in_flight_ae_pkts && quic_peer_validated_addr(ctx)) {
		/* Timer cancellation. */
		qc->timer = TICK_ETERNITY;
		goto out;
	}

	pktns = quic_pto_pktns(qc, ctx->state & QUIC_HS_ST_COMPLETE);
	if (tick_isset(pktns->tx.pto))
		qc->timer = pktns->tx.pto;
 out:
	task_schedule(qc->timer_task, qc->timer);
	TRACE_LEAVE(QUIC_EV_CONN_STIMER, ctx->conn, pktns);
}

#ifndef OPENSSL_IS_BORINGSSL
int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *read_secret,
                                   const uint8_t *write_secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->quic_conn->els[ssl_to_quic_enc_level(level)].tls_ctx;
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, conn);
	tls_ctx->rx.aead = tls_ctx->tx.aead = tls_aead(cipher);
	tls_ctx->rx.md   = tls_ctx->tx.md   = tls_md(cipher);
	tls_ctx->rx.hp   = tls_ctx->tx.hp   = tls_hp(cipher);

	HEXDUMP(read_secret, secret_len, "read_secret (level %d):\n", level);
	HEXDUMP(write_secret, secret_len, "write_secret:\n");

	if (!quic_tls_derive_keys(tls_ctx->rx.aead, tls_ctx->rx.hp, tls_ctx->rx.md,
	                          tls_ctx->rx.key, sizeof tls_ctx->rx.key,
	                          tls_ctx->rx.iv, sizeof tls_ctx->rx.iv,
	                          tls_ctx->rx.hp_key, sizeof tls_ctx->rx.hp_key,
	                          read_secret, secret_len)) {
		TRACE_DEVEL("RX key derivation failed", QUIC_EV_CONN_RWSEC, conn);
		return 0;
	}

	tls_ctx->rx.flags |= QUIC_FL_TLS_SECRETS_SET;
	if (!quic_tls_derive_keys(tls_ctx->tx.aead, tls_ctx->tx.hp, tls_ctx->tx.md,
	                          tls_ctx->tx.key, sizeof tls_ctx->tx.key,
	                          tls_ctx->tx.iv, sizeof tls_ctx->tx.iv,
	                          tls_ctx->tx.hp_key, sizeof tls_ctx->tx.hp_key,
	                          write_secret, secret_len)) {
		TRACE_DEVEL("TX key derivation failed", QUIC_EV_CONN_RWSEC, conn);
		return 0;
	}

	tls_ctx->tx.flags |= QUIC_FL_TLS_SECRETS_SET;
	if (objt_server(conn->target) && level == ssl_encryption_application) {
		const unsigned char *buf;
		size_t buflen;

		SSL_get_peer_quic_transport_params(ssl, &buf, &buflen);
		if (!buflen)
			return 0;

		if (!quic_transport_params_store(conn->quic_conn, 1, buf, buf + buflen))
			return 0;
	}
	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, conn, &level);

	return 1;
}
#else
/*
 * ->set_read_secret callback to derive the RX secrets at <level>
 * encryption level.
 * Returns 1 if succedded, 0 if not.
 */
int ha_set_rsec(SSL *ssl, enum ssl_encryption_level_t level,
                const SSL_CIPHER *cipher,
                const uint8_t *secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->quic_conn->els[ssl_to_quic_enc_level(level)].tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_RSEC, conn);
	tls_ctx->rx.aead = tls_aead(cipher);
	tls_ctx->rx.md = tls_md(cipher);
	tls_ctx->rx.hp = tls_hp(cipher);

	HEXDUMP(secret, secret_len, "RX secret (level %d):\n", level);
	if (!quic_tls_derive_keys(tls_ctx->rx.aead, tls_ctx->rx.hp, tls_ctx->rx.md,
	                          tls_ctx->rx.key, sizeof tls_ctx->rx.key,
	                          tls_ctx->rx.iv, sizeof tls_ctx->rx.iv,
	                          tls_ctx->rx.hp_key, sizeof tls_ctx->rx.hp_key,
	                          secret, secret_len)) {
		TRACE_DEVEL("RX key derivation failed", QUIC_EV_CONN_RSEC, conn);
		goto err;
	}

	if (objt_server(conn->target) && level == ssl_encryption_application) {
		const unsigned char *buf;
		size_t buflen;

		SSL_get_peer_quic_transport_params(ssl, &buf, &buflen);
		if (!buflen)
			goto err;

		if (!quic_transport_params_store(conn->quic_conn, 1, buf, buf + buflen))
			goto err;
	}

	tls_ctx->rx.flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_RSEC, conn, &level, secret, &secret_len);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ERSEC, conn);
	return 0;
}
/*
 * ->set_write_secret callback to derive the TX secrets at <level>
 * encryption level.
 * Returns 1 if succedded, 0 if not.
 */
int ha_set_wsec(SSL *ssl, enum ssl_encryption_level_t level,
                const SSL_CIPHER *cipher,
                const uint8_t *secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->quic_conn->els[ssl_to_quic_enc_level(level)].tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_WSEC, conn);
	tls_ctx->tx.aead = tls_aead(cipher);
	tls_ctx->tx.md = tls_md(cipher);
	tls_ctx->tx.hp = tls_hp(cipher);

	HEXDUMP(secret, secret_len, "TX secret (level %d):\n", level);
	if (!quic_tls_derive_keys(tls_ctx->tx.aead, tls_ctx->tx.hp, tls_ctx->tx.md,
	                          tls_ctx->tx.key, sizeof tls_ctx->tx.key,
	                          tls_ctx->tx.iv, sizeof tls_ctx->tx.iv,
	                          tls_ctx->tx.hp_key, sizeof tls_ctx->tx.hp_key,
	                          secret, secret_len)) {
		TRACE_DEVEL("TX key derivation failed", QUIC_EV_CONN_WSEC, conn);
		goto err;
	}

	tls_ctx->tx.flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_WSEC, conn, &level, secret, &secret_len);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_EWSEC, conn);
	return 0;
}
#endif

/*
 * This function copies the CRYPTO data provided by the TLS stack found at <data>
 * with <len> as size in CRYPTO buffers dedicated to store the information about
 * outgoing CRYPTO frames so that to be able to replay the CRYPTO data streams.
 * It fails only if it could not managed to allocate enough CRYPTO buffers to
 * store all the data.
 * Note that CRYPTO data may exist at any encryption level except at 0-RTT.
 */
static int quic_crypto_data_cpy(struct quic_enc_level *qel,
                                const unsigned char *data, size_t len)
{
	struct quic_crypto_buf **qcb;
	/* The remaining byte to store in CRYPTO buffers. */
	size_t cf_offset, cf_len, *nb_buf;
	unsigned char *pos;

	nb_buf = &qel->tx.crypto.nb_buf;
	qcb = &qel->tx.crypto.bufs[*nb_buf - 1];
	cf_offset = (*nb_buf - 1) * QUIC_CRYPTO_BUF_SZ + (*qcb)->sz;
	cf_len = len;

	while (len) {
		size_t to_copy, room;

		pos = (*qcb)->data + (*qcb)->sz;
		room = QUIC_CRYPTO_BUF_SZ  - (*qcb)->sz;
		to_copy = len > room ? room : len;
		if (to_copy) {
			memcpy(pos, data, to_copy);
			/* Increment the total size of this CRYPTO buffers by <to_copy>. */
			qel->tx.crypto.sz += to_copy;
			(*qcb)->sz += to_copy;
			pos += to_copy;
			len -= to_copy;
			data += to_copy;
		}
		else {
			struct quic_crypto_buf **tmp;

			tmp = realloc(qel->tx.crypto.bufs,
			              (*nb_buf + 1) * sizeof *qel->tx.crypto.bufs);
			if (tmp) {
				qel->tx.crypto.bufs = tmp;
				qcb = &qel->tx.crypto.bufs[*nb_buf];
				*qcb = pool_alloc(pool_head_quic_crypto_buf);
				if (!*qcb) {
					QDPRINTF("%s: crypto allocation failed\n", __func__);
					return 0;
				}
				(*qcb)->sz = 0;
				++*nb_buf;
			}
			else {
				break;
			}
		}
	}

	/*
	 * Allocate a TX CRYPTO frame only if all the CRYPTO data
	 * have been buffered.
	 */
	if (!len) {
		struct quic_tx_frm *frm;

		frm = pool_alloc(pool_head_quic_tx_frm);
		if (!frm)
			return 0;

		frm->type = QUIC_FT_CRYPTO;
		frm->crypto.offset = cf_offset;
		frm->crypto.len = cf_len;
		LIST_ADDQ(&qel->tx.frms, &frm->list);
	}

	return len == 0;
}


/*
 * ->add_handshake_data QUIC TLS callback used by the QUIC TLS stack when it
 * wants to provide the QUIC layer with CRYPTO data.
 * Returns 1 if succeeded, 0 if not.
 */
int ha_quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len)
{
	struct connection *conn;
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;

	conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, conn);
	tel = ssl_to_quic_enc_level(level);
	qel = &conn->quic_conn->els[tel];

	if (tel == -1) {
		TRACE_PROTO("Wrong encryption level", QUIC_EV_CONN_ADDDATA, conn);
		goto err;
	}

	if (!quic_crypto_data_cpy(qel, data, len)) {
		TRACE_PROTO("Could not bufferize", QUIC_EV_CONN_ADDDATA, conn);
		goto err;
	}

	TRACE_PROTO("CRYPTO data buffered", QUIC_EV_CONN_ADDDATA,
	            conn, &level, &len);

	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ADDDATA, conn);
	return 0;
}

int ha_quic_flush_flight(SSL *ssl)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_FFLIGHT, conn);
	TRACE_LEAVE(QUIC_EV_CONN_FFLIGHT, conn);

	return 1;
}

int ha_quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSLALERT, conn);
	TRACE_LEAVE(QUIC_EV_CONN_SSLALERT, conn);
	return 1;
}

/* QUIC TLS methods */
static SSL_QUIC_METHOD ha_quic_method = {
#ifdef OPENSSL_IS_BORINGSSL
	.set_read_secret        = ha_set_rsec,
	.set_write_secret       = ha_set_wsec,
#else
	.set_encryption_secrets = ha_quic_set_encryption_secrets,
#endif
	.add_handshake_data     = ha_quic_add_handshake_data,
	.flush_flight           = ha_quic_flush_flight,
	.send_alert             = ha_quic_send_alert,
};

/*
 * Initialize the TLS context of a listener with <bind_conf> as configuration.
 * Returns an error count.
 */
int ssl_quic_initial_ctx(struct bind_conf *bind_conf)
{
	struct proxy *curproxy = bind_conf->frontend;
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	int cfgerr = 0;

#if 0
	/* XXX Did not manage to use this. */
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:"
		"TLS_AES_256_GCM_SHA384:"
		"TLS_CHACHA20_POLY1305_SHA256:"
		"TLS_AES_128_CCM_SHA256";
#endif
	const char *groups = "P-256:X25519:P-384:P-521";
	long options =
		(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	bind_conf->initial_ctx = ctx;

	SSL_CTX_set_options(ctx, options);
#if 0
	if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 cipher list to '%s' "
		         "for bind '%s' at [%s:%d].\n",
		         curproxy->id, ciphers,
		         bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}
#endif

	if (SSL_CTX_set1_curves_list(ctx, groups) != 1) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 curves list to '%s' "
		         "for bind '%s' at [%s:%d].\n",
		         curproxy->id, groups,
		         bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_default_verify_paths(ctx);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef OPENSSL_IS_BORINGSSL
	SSL_CTX_set_select_certificate_cb(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#elif (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (bind_conf->ssl_conf.early_data) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_max_early_data(ctx, global.tune.bufsize - global.tune.maxrewrite);
	}
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#else
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
#endif
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif
	SSL_CTX_set_quic_method(ctx, &ha_quic_method);

	return cfgerr;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 * errno is cleared before starting so that the caller knows that if it spots an
 * error without errno, it's pending and can be retrieved via getsockopt(SO_ERROR).
 */
static size_t quic_conn_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	errno = 0;

	if (unlikely(!(fdtab[conn->handle.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			goto leave;
		}
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = recvfrom(conn->handle.fd, b_tail(buf), try, 0, NULL, 0);

		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			if (ret < try) {
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, unless the poller supports POLL_RDHUP. If
				 * we know this is the case, we don't try to read more
				 * as we know there's no more available. Similarly, if
				 * there's no problem with lingering we don't even try
				 * to read an unlikely close from the client since we'll
				 * close first anyway.
				 */
				if (fdtab[conn->handle.fd].ev & FD_POLL_HUP)
					goto read0;

				if ((!fdtab[conn->handle.fd].linger_risk) ||
				    (cur_poller.flags & HAP_POLL_F_RDHUP)) {
					fd_done_recv(conn->handle.fd);
					break;
				}
			}
			count -= ret;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN || errno == ENOTCONN) {
			fd_cant_recv(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	return done;

 read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Now a final check for a possible asynchronous low-level error
	 * report. This can happen when a connection receives a reset
	 * after a shutdown, both POLL_HUP and POLL_ERR are queued, and
	 * we might have come from there by just checking POLL_HUP instead
	 * of recv()'s return value 0, so we have no way to tell there was
	 * an error without checking.
	 */
	if (unlikely(fdtab[conn->handle.fd].ev & FD_POLL_ERR))
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto leave;
}


/* Send up to <count> pending bytes from buffer <buf> to connection <conn>'s
 * socket. <flags> may contain some CO_SFL_* flags to hint the system about
 * other pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this. It's up to the caller to update the buffer's contents
 * based on the return value.
 */
static size_t quic_conn_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < count || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = sendto(conn->handle.fd, b_peek(buf, done), try, send_flag,
		             (struct sockaddr *)conn->dst, get_addr_len(conn->dst));
		if (ret > 0) {
			count -= ret;
			done += ret;

			/* A send succeeded, so we can consier ourself connected */
			conn->flags |= CO_FL_WAIT_L4L6;
			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN || errno == EINPROGRESS) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (done > 0) {
		/* we count the total bytes sent, and the send rate for 32-byte
		 * blocks. The reason for the latter is that freq_ctr are
		 * limited to 4GB and that it's not enough per second.
		 */
		_HA_ATOMIC_ADD(&global.out_bytes, done);
		update_freq_ctr(&global.out_32bps, (done + 16) / 32);
	}
	return done;
}

static int quic_conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_subscribe(conn, xprt_ctx, event_type, es);
}

static int quic_conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_unsubscribe(conn, xprt_ctx, event_type, es);
}

/*
 * Decode an expected packet number from <truncated_on> its truncated value,
 * depending on <largest_pn> the largest received packet number, and <pn_nbits>
 * the number of bits used to encode this packet number (its length in bytes * 8).
 * See https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-encoding
 */
static uint64_t decode_packet_number(uint64_t largest_pn,
                                     uint32_t truncated_pn, unsigned int pn_nbits)
{
	uint64_t expected_pn = largest_pn + 1;
	uint64_t pn_win = (uint64_t)1 << pn_nbits;
	uint64_t pn_hwin = pn_win / 2;
	uint64_t pn_mask = pn_win - 1;
	uint64_t candidate_pn;


	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
	/* Note that <pn_win> > <pn_hwin>. */
	if (candidate_pn < QUIC_MAX_PACKET_NUM - pn_win &&
	    candidate_pn + pn_hwin <= expected_pn)
	  return candidate_pn + pn_win;

	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
	  return candidate_pn - pn_win;

	return candidate_pn;
}

/*
 * Remove the header protection of <pkt> QUIC packet using <tls_ctx> as QUIC TLS
 * cryptographic context.
 * <largest_pn> is the largest received packet number and <pn> the address of
 * the packet number field for this packet with <byte0> address of its first byte.
 * <end> points to one byte past the end of this packet.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_do_rm_hp(struct quic_rx_packet *pkt, struct quic_tls_ctx *tls_ctx,
                       int64_t largest_pn, unsigned char *pn,
                       unsigned char *byte0, const unsigned char *end,
                       struct quic_conn_ctx *ctx)
{
	int ret, outlen, i, pnlen;
	uint64_t packet_number;
	uint32_t truncated_pn = 0;
	unsigned char mask[5] = {0};
	unsigned char *sample;
	EVP_CIPHER_CTX *cctx;
	unsigned char *hp_key;

	TRACE_ENTER(QUIC_EV_CONN_RMHP, ctx->conn, pkt);
	/* Check there is enough data in this packet. */
	if (end - pn < QUIC_PACKET_PN_MAXLEN + sizeof mask) {
		TRACE_DEVEL("too short packet", QUIC_EV_CONN_RMHP, ctx->conn, pkt);
		return 0;
	}

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx) {
		TRACE_DEVEL("memory allocation failed", QUIC_EV_CONN_RMHP, ctx->conn, pkt);
		return 0;
	}

	ret = 0;
	sample = pn + QUIC_PACKET_PN_MAXLEN;

	hp_key = tls_ctx->rx.hp_key;
	if (!EVP_DecryptInit_ex(cctx, tls_ctx->rx.hp, NULL, hp_key, sample) ||
	    !EVP_DecryptUpdate(cctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_DecryptFinal_ex(cctx, mask, &outlen)) {
		TRACE_DEVEL("decryption failed", QUIC_EV_CONN_RMHP, ctx->conn, pkt);
	    goto out;
	}

	*byte0 ^= mask[0] & (*byte0 & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	pnlen = (*byte0 & QUIC_PACKET_PNL_BITMASK) + 1;
	for (i = 0; i < pnlen; i++) {
		pn[i] ^= mask[i + 1];
		truncated_pn = (truncated_pn << 8) | pn[i];
	}

	packet_number = decode_packet_number(largest_pn, truncated_pn, pnlen * 8);
	/* Store remaining information for this unprotected header */
	pkt->pn = packet_number;
	pkt->pnl = pnlen;

	ret = 1;

 out:
	EVP_CIPHER_CTX_free(cctx);
	TRACE_LEAVE(QUIC_EV_CONN_RMHP, ctx->conn, pkt, &ret);

	return ret;
}

/*
 * Encrypt the payload of a QUIC packet with <pn> as number found at <payload>
 * address, with <payload_len> as payload length, <aad> as address of
 * the ADD and <aad_len> as AAD length depending on the <tls_ctx> QUIC TLS
 * context.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_packet_encrypt(unsigned char *payload, size_t payload_len,
                               unsigned char *aad, size_t aad_len, uint64_t pn,
                               struct quic_tls_ctx *tls_ctx, struct connection *conn)
{
	unsigned char iv[12];
	unsigned char *tx_iv = tls_ctx->tx.iv;
	size_t tx_iv_sz = sizeof tls_ctx->tx.iv;

	if (!quic_aead_iv_build(iv, sizeof iv, tx_iv, tx_iv_sz, pn)) {
		TRACE_DEVEL("AEAD IV building for encryption failed", QUIC_EV_CONN_HPKT, conn);
		return 0;
	}

	if (!quic_tls_encrypt(payload, payload_len, aad, aad_len,
	                      tls_ctx->tx.aead, tls_ctx->tx.key, iv)) {
		TRACE_DEVEL("QUIC packet encryption failed", QUIC_EV_CONN_HPKT, conn);
		return 0;
	}

	return 1;
}

/*
 * Decrypt <qpkt> QUIC packet with <tls_ctx> as QUIC TLS cryptographic context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_pkt_decrypt(struct quic_rx_packet *qpkt, struct quic_tls_ctx *tls_ctx)
{
	int ret;
	unsigned char iv[12];
	unsigned char *rx_iv = tls_ctx->rx.iv;
	size_t rx_iv_sz = sizeof tls_ctx->rx.iv;

	if (!quic_aead_iv_build(iv, sizeof iv, rx_iv, rx_iv_sz, qpkt->pn)) {
		QDPRINTF("%s AEAD IV building failed\n", __func__);
		return 0;
	}

	ret = quic_tls_decrypt(qpkt->data + qpkt->aad_len, qpkt->len - qpkt->aad_len,
	                       qpkt->data, qpkt->aad_len,
	                       tls_ctx->rx.aead, tls_ctx->rx.key, iv);
	if (!ret) {
		QDPRINTF("%s: qpkt #%lu long %d decryption failed\n",
		         __func__, qpkt->pn, qc_pkt_long(qpkt));
		return 0;
	}

	/* Update the packet length (required to parse the frames). */
	qpkt->len = qpkt->aad_len + ret;
	QDPRINTF("QUIC packet #%lu long header? %d decryption done\n",
	         qpkt->pn, qc_pkt_long(qpkt));

	return 1;
}

/* Treat <frm> frame whose packet it is attached to has just been acknowledged. */
static inline void qc_treat_acked_tx_frm(struct quic_tx_frm *frm,
                                         struct quic_conn_ctx *ctx)
{
	TRACE_PROTO("Removing frame", QUIC_EV_CONN_PRSAFRM, ctx->conn, frm);
	switch (frm->type) {
	case QUIC_FT_CRYPTO:
		ctx->conn->quic_conn->ifcdata -= frm->crypto.len;
		break;
	}
	LIST_DEL(&frm->list);
	pool_free(pool_head_quic_tx_frm, frm);
}

/*
 * Remove <largest> down to <smallest> node entries from <pkts> tree of TX packet,
 * deallocating them, and their TX frames.
 * Returns the last node reached to be used for the next range.
 * May be NULL if <largest> node could not be found.
 */
static inline struct eb64_node *qc_ackrng_pkts(struct eb_root *pkts, unsigned int *pkt_flags,
                                               struct list *newly_acked_pkts,
                                               struct eb64_node *largest_node,
                                               uint64_t largest, uint64_t smallest,
                                               struct quic_conn_ctx *ctx)
{
	struct eb64_node *node;
	struct quic_tx_packet *pkt;

	if (largest_node)
		node = largest_node;
	else {
		node = eb64_lookup(pkts, largest);
		while (!node && largest > smallest) {
			node = eb64_lookup(pkts, --largest);
		}
	}

	while (node && node->key >= smallest) {
		struct quic_tx_frm *frm, *frmbak;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		*pkt_flags |= pkt->flags;
		LIST_ADD(newly_acked_pkts, &pkt->list);
		QDPRINTF("Removing packet #%llu\n", pkt->pn_node.key);
		TRACE_PROTO("Removing packet #", QUIC_EV_CONN_PRSAFRM, ctx->conn,, &pkt->pn_node.key);
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
			qc_treat_acked_tx_frm(frm, ctx);
		node = eb64_prev(node);
		eb64_delete(&pkt->pn_node);
	}

	return node;
}

/*
 * Treat <frm> frame whose packet it is attached to has just been detected as non
 * acknowledged.
 */
static inline void qc_treat_nacked_tx_frm(struct quic_tx_frm *frm,
                                          struct quic_enc_level *qel,
                                          struct quic_conn_ctx *ctx)
{
	TRACE_PROTO("to resend frame", QUIC_EV_CONN_PRSAFRM, ctx->conn, frm);
	switch (frm->type) {
	case QUIC_FT_CRYPTO:
		ctx->conn->quic_conn->ifcdata -= frm->crypto.len;
		break;
	}
	LIST_DEL(&frm->list);
	LIST_ADD(&qel->tx.frms, &frm->list);
}


/* Free the TX packets of <pkts> list */
static inline void free_quic_tx_pkts(struct list *pkts)
{
	struct quic_tx_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, pkts, list)
		pool_free(pool_head_quic_tx_packet, pkt);
}

/* Send a packet loss event nofification to the congestion controller
 * attached to <qc> connection with <lost_bytes> the number of lost bytes,
 * <oldest_lost>, <newest_lost> the oldest lost packet and newest lost packet
 * at <now_us> current time.
 * Always succeeds.
 */
static inline void qc_cc_loss_event(struct quic_conn *qc,
                                    unsigned int lost_bytes,
                                    unsigned int newest_time_sent,
                                    unsigned int period,
                                    unsigned int now_us)
{
	struct quic_cc_event ev = {
		.type = QUIC_CC_EVT_LOSS,
		.loss.now_ms           = now_ms,
		.loss.max_ack_delay    = qc->max_ack_delay,
		.loss.lost_bytes       = lost_bytes,
		.loss.newest_time_sent = newest_time_sent,
		.loss.period           = period,
	};

	quic_cc_event(&qc->path->cc, &ev);
}

/* Send a packet ack event nofication for each newly acked packet of
 * <newly_acked_pkts> list and free them.
 * Always succeeds.
 */
static inline void qc_treat_newly_acked_pkts(struct quic_conn_ctx *ctx,
                                             struct list *newly_acked_pkts)
{
	struct quic_conn *qc = ctx->conn->quic_conn;
	struct quic_tx_packet *pkt, *tmp;
	struct quic_cc_event ev = { .type = QUIC_CC_EVT_ACK, };

	list_for_each_entry_safe(pkt, tmp, newly_acked_pkts, list) {
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->in_flight_ae_pkts--;
		ev.ack.acked = pkt->in_flight_len;
		ev.ack.time_sent = pkt->time_sent;
		quic_cc_event(&qc->path->cc, &ev);
		pool_free(pool_head_quic_tx_packet, pkt);
	}

}

/* Handle <pkts> list of lost packets detected at <now_us> handling
 * their TX frames.
 * Send a packet loss event to the congestion controller if
 * in flight packet have been lost.
 * Also frees the packet in <pkts> list.
 * Never fails.
 */
static inline void qc_release_lost_pkts(struct quic_enc_level *qel,
                                        struct quic_conn_ctx *ctx,
                                        struct list *pkts,
                                        uint64_t now_us)
{
	struct quic_conn *qc = ctx->conn->quic_conn;
	struct quic_tx_packet *pkt, *oldest_lost, *newest_lost;
	struct quic_tx_frm *frm, *frmbak;
	uint64_t lost_bytes;

	lost_bytes = 0;
	oldest_lost = newest_lost = NULL;
	list_for_each_entry(pkt, pkts, list) {
		lost_bytes += pkt->in_flight_len;
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->in_flight_ae_pkts--;
		/* Treat the frames of this lost packet. */
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list)
			qc_treat_nacked_tx_frm(frm, qel, ctx);
		if (!oldest_lost) {
			oldest_lost = newest_lost = pkt;
		}
		else {
			if (newest_lost != oldest_lost)
				pool_free(pool_head_quic_tx_packet, newest_lost);
			newest_lost = pkt;
		}
	}

	if (lost_bytes) {
		/* Sent a packet loss event to the congestion controller. */
		qc_cc_loss_event(ctx->conn->quic_conn, lost_bytes, newest_lost->time_sent,
		                 newest_lost->time_sent - oldest_lost->time_sent, now_us);
		pool_free(pool_head_quic_tx_packet, oldest_lost);
		if (newest_lost != oldest_lost)
			pool_free(pool_head_quic_tx_packet, newest_lost);
	}
}

/* Treat <pkts> list of lost packets without freeing them so that
 * to send a packet loss event to the congestion controller.
 * Never fails.
 */
static inline void qc_treat_lost_pkts(struct quic_conn_ctx *ctx,
                                      struct list *pkts,
                                      uint64_t now_us)
{
	struct quic_conn *qc = ctx->conn->quic_conn;
	struct quic_tx_packet *pkt, *oldest_lost, *newest_lost;
	uint64_t lost_bytes;

	lost_bytes = 0;
	oldest_lost = newest_lost = NULL;
	list_for_each_entry(pkt, pkts, list) {
		lost_bytes += pkt->in_flight_len;
		pkt->pktns->tx.in_flight -= pkt->in_flight_len;
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->in_flight_ae_pkts--;
		if (!oldest_lost) {
			oldest_lost = newest_lost = pkt;
		}
		else {
			newest_lost = pkt;
		}
	}

	if (lost_bytes) {
		/* Send a packet loss event to the congestion controller. */
		qc_cc_loss_event(ctx->conn->quic_conn, lost_bytes, newest_lost->time_sent,
		                 newest_lost->time_sent - oldest_lost->time_sent, now_us);
	}
}

/* Look for packet loss from sent packets for <qel> encryption level of a
 * connection with <ctx> as I/O handler context. If remove is true, remove them from
 * their tree if deemed as lost or set the <loss_time> value the packet number
 * space if any not deemed lost.
 * Should be called after having received an ACK frame with newly acknowledged
 * packets or when the the loss detection timer has expired.
 * Always succeeds.
 */
static void qc_packet_loss_lookup(struct quic_pktns *pktns,
                                  struct quic_conn *qc,
                                  struct list *lost_pkts, int remove)
{
	struct eb_root *pkts;
	struct eb64_node *node;
	struct quic_loss *ql;
	unsigned int loss_delay, loss_send_time;

	TRACE_ENTER(QUIC_EV_CONN_PKTLOSS, qc->conn, pktns);
	pkts = &pktns->tx.pkts;
	pktns->tx.loss_time = TICK_ETERNITY;
	if (eb_is_empty(pkts))
		goto out;

	ql = &qc->path->loss;
	loss_delay = max(ql->latest_rtt, ql->srtt >> 3);
	loss_delay += loss_delay >> 3;
	loss_delay = max(loss_delay, MS_TO_TICKS(QUIC_TIMER_GRANULARITY));
	loss_send_time = now_ms - loss_delay;

	node = eb64_first(pkts);
	while (node) {
		struct quic_tx_packet *pkt;
		int64_t largest_acked_pn;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		largest_acked_pn = pktns->tx.largest_acked_pn;
		node = eb64_next(node);
		if ((int64_t)pkt->pn_node.key > largest_acked_pn)
			break;

		if (tick_is_le(pkt->time_sent, loss_send_time) ||
			(int64_t)largest_acked_pn >= pkt->pn_node.key + QUIC_LOSS_PACKET_THRESHOLD) {
			if (remove)
				eb64_delete(&pkt->pn_node);
			LIST_ADDQ(lost_pkts, &pkt->list);
		}
		else {
			pktns->tx.loss_time = tick_first(pktns->tx.loss_time, pkt->time_sent + loss_delay);
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PKTLOSS, qc->conn, pktns, lost_pkts);
}

/*
 * Parse ACK frame into <frm> from a buffer at <buf> address with <end> being at
 * one byte past the end of this buffer. Also update <rtt_sample> if needed, i.e.
 * if the largest acked packet was newly acked and if there was at leas one newly
 * acked ack-eliciting packet.
 * Return 1, if succeeded, 0 if not.
 */
static inline int qc_parse_ack_frm(struct quic_frame *frm, struct quic_conn_ctx *ctx,
                                   struct quic_enc_level *qel,
                                   unsigned int *rtt_sample,
                                   const unsigned char **pos, const unsigned char *end)
{
	struct quic_ack *ack = &frm->ack;
	uint64_t smallest, largest;
	struct eb_root *pkts;
	struct eb64_node *largest_node;
	unsigned int time_sent, pkt_flags;
	struct list newly_acked_pkts = LIST_HEAD_INIT(newly_acked_pkts);
	struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

	if (ack->largest_ack > qel->pktns->tx.next_pn) {
		TRACE_DEVEL("ACK for not sent packet", QUIC_EV_CONN_PRSAFRM,
		            ctx->conn,, &ack->largest_ack);
		goto err;
	}

	if (ack->first_ack_range > ack->largest_ack) {
		TRACE_DEVEL("too big first ACK range", QUIC_EV_CONN_PRSAFRM,
		            ctx->conn,, &ack->first_ack_range);
		goto err;
	}

	largest = ack->largest_ack;
	smallest = largest - ack->first_ack_range;
	pkts = &qel->pktns->tx.pkts;
	pkt_flags = 0;
	largest_node = NULL;
	time_sent = 0;

	if ((int64_t)ack->largest_ack > qel->pktns->tx.largest_acked_pn) {
		largest_node = eb64_lookup(pkts, largest);
		if (!largest_node) {
			TRACE_DEVEL("Largest acked packet not found",
			            QUIC_EV_CONN_PRSAFRM, ctx->conn);
			goto err;
		}

		time_sent = eb64_entry(&largest_node->node,
		                       struct quic_tx_packet, pn_node)->time_sent;
	}

	TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
	            ctx->conn,, &largest, &smallest);
	do {
		uint64_t gap, ack_range;

		if (!ack->ack_range_num--) {
			qc_ackrng_pkts(pkts, &pkt_flags, &newly_acked_pkts,
			               largest_node, largest, smallest, ctx);
			break;
		}

		if (!quic_dec_int(&gap, pos, end))
			goto err;

		if (smallest < gap + 2) {
			TRACE_DEVEL("wrong gap value", QUIC_EV_CONN_PRSAFRM,
						ctx->conn,, &gap, &smallest);
			goto err;
		}

		largest = smallest - gap - 2;
		if (!quic_dec_int(&ack_range, pos, end))
			goto err;

		if (largest < ack_range) {
			TRACE_DEVEL("wrong ack range value", QUIC_EV_CONN_PRSAFRM,
						ctx->conn,, &largest, &ack_range);
			goto err;
		}

		/* Do not use this node anymore. */
		largest_node = NULL;
		/* Next range */
		smallest = largest - ack_range;

		TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,
		            ctx->conn,, &largest, &smallest);
	} while (1);

	if (time_sent && (pkt_flags & QUIC_FL_TX_PACKET_ACK_ELICITING)) {
		*rtt_sample = now_ms - time_sent;
		qel->pktns->tx.largest_acked_pn = ack->largest_ack;
	}

	/* Flag this packet number space as having received an ACK. */
	qel->pktns->flags |= QUIC_FL_PKTNS_ACK_RECEIVED;
	if (!LIST_ISEMPTY(&newly_acked_pkts) && !eb_is_empty(&qel->pktns->tx.pkts)) {
		qc_packet_loss_lookup(qel->pktns, ctx->conn->quic_conn, &lost_pkts, 1);
		if (!LIST_ISEMPTY(&lost_pkts))
			qc_release_lost_pkts(qel, ctx, &lost_pkts, now_ms);
	}

	qc_treat_newly_acked_pkts(ctx, &newly_acked_pkts);

	return 1;

 err:
	free_quic_tx_pkts(&newly_acked_pkts);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PRSAFRM, ctx->conn);
	return 0;
}

/*
 * Provide CRYPTO data to the TLS stack found at <data> with <len> as length
 * from <qel> encryption level with <ctx> as QUIC connection context.
 * Remaining parameter are there for debuging purposes.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_provide_cdata(struct quic_enc_level *el,
                                   struct quic_conn_ctx *ctx,
                                   const unsigned char *data, size_t len,
                                   struct quic_rx_packet *pkt,
                                   struct quic_rx_crypto_frm *cf)
{
	int ssl_err;

	TRACE_ENTER(QUIC_EV_CONN_SSLDATA, ctx->conn);
	ssl_err = SSL_ERROR_NONE;
	if (SSL_provide_quic_data(ctx->ssl, el->level, data, len) != 1) {
		TRACE_PROTO("SSL_provide_quic_data() error",
					QUIC_EV_CONN_SSLDATA, ctx->conn, pkt, cf, ctx->ssl);
		goto err;
	}

	el->rx.crypto.offset += len;
	TRACE_PROTO("in order CRYPTO data",
	            QUIC_EV_CONN_SSLDATA, ctx->conn,, cf, ctx->ssl);

	if (ctx->state < QUIC_HS_ST_COMPLETE) {
		ssl_err = SSL_do_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
				goto out;
			}

			TRACE_DEVEL("SSL handshake error",
						QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
			goto err;
		}

		TRACE_PROTO("SSL handshake OK", QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);
		if (objt_listener(ctx->conn->target))
			ctx->state = QUIC_HS_ST_CONFIRMED;
		else
			ctx->state = QUIC_HS_ST_COMPLETE;
	} else {
		ssl_err = SSL_process_quic_post_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_DEVEL("SSL post handshake",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
				goto out;
			}

			TRACE_DEVEL("SSL post handshake error",
						QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
			goto err;
		}

		TRACE_PROTO("SSL post handshake succeeded",
		            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_SSLDATA, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_SSLDATA, ctx->conn);
	return 0;
}

/*
 * Parse all the frames of <qpkt> QUIC packet for QUIC connection with <ctx>
 * as I/O handler context and <qel> as encryption level.
 * Returns 1 if succeeded, 0 if failed.
 */
static int qc_parse_pkt_frms(struct quic_rx_packet *pkt, struct quic_conn_ctx *ctx,
                             struct quic_enc_level *qel)
{
	struct quic_frame frm;
	const unsigned char *pos, *end;
	struct quic_conn *conn = ctx->conn->quic_conn;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, ctx->conn);
	/* Skip the AAD */
	pos = pkt->data + pkt->aad_len;
	end = pkt->data + pkt->len;

	while (pos < end) {
		if (!qc_parse_frm(&frm, pkt, &pos, end, conn))
			goto err;

		switch (frm.type) {
		case QUIC_FT_CRYPTO:
			if (frm.crypto.offset != qel->rx.crypto.offset) {
				struct quic_rx_crypto_frm *cf;

				cf = pool_alloc(pool_head_quic_rx_crypto_frm);
				if (!cf) {
					TRACE_DEVEL("CRYPTO frame allocation failed",
					            QUIC_EV_CONN_PRSHPKT, ctx->conn);
					goto err;
				}

				cf->offset_node.key = frm.crypto.offset;
				cf->len = frm.crypto.len;
				cf->data = frm.crypto.data;
				cf->pkt = pkt;
				eb64_insert(&qel->rx.crypto.frms, &cf->offset_node);
				quic_rx_packet_refinc(pkt);
			}
			else {
				/* XXX TO DO: <cf> is used only for the traces. */
				struct quic_rx_crypto_frm cf = {0};

				cf.offset_node.key = frm.crypto.offset;
				cf.len = frm.crypto.len;
				if (!qc_provide_cdata(qel, ctx,
				                      frm.crypto.data, frm.crypto.len,
				                      pkt, &cf))
					goto err;
			}
			/* ack-eliciting frame. */
			pkt->flags |= QUIC_FL_RX_PACKET_ACK_ELICITING;
			break;
		case QUIC_FT_PADDING:
			if (pos != end) {
				TRACE_DEVEL("wrong frame", QUIC_EV_CONN_PRSHPKT, ctx->conn, pkt);
				goto err;
			}
			break;
		case QUIC_FT_ACK:
		{
			unsigned int rtt_sample;

			rtt_sample = 0;
			if (!qc_parse_ack_frm(&frm, ctx, qel, &rtt_sample, &pos, end))
				goto err;

			if (rtt_sample) {
				unsigned int ack_delay;

				ack_delay = !quic_application_pktns(qel->pktns, conn) ? 0 :
					MS_TO_TICKS(min(quic_ack_delay_ms(&frm.ack, conn), conn->max_ack_delay));
				quic_loss_srtt_update(&conn->path->loss, rtt_sample, ack_delay, conn);
			}
			tasklet_wakeup(ctx->wait_event.tasklet);
			break;
		}
		case QUIC_FT_PING:
			pkt->flags |= QUIC_FL_RX_PACKET_ACK_ELICITING;
			break;
		case QUIC_FT_CONNECTION_CLOSE:
		case QUIC_FT_CONNECTION_CLOSE_APP:
			break;
		case QUIC_FT_NEW_CONNECTION_ID:
		case QUIC_FT_STREAM_A:
		case QUIC_FT_STREAM_B:
			pkt->flags |= QUIC_FL_RX_PACKET_ACK_ELICITING;
			break;
		case QUIC_FT_HANDSHAKE_DONE:
			if (objt_listener(ctx->conn->target))
				goto err;

			ctx->state = QUIC_HS_ST_CONFIRMED;
			break;
		default:
			goto err;
		}
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PRSHPKT, ctx->conn);
	return 0;
}

/*
 * Prepare as much as possible handshake packets for the QUIC connection
 * with <ctx> as I/O handler context.
 * Returns 1 if succeeded, or 0 if something wrong happened.
 */
static int qc_prep_hdshk_pkts(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;
	enum quic_tls_enc_level tel, next_tel;
	struct quic_enc_level *qel;
	struct q_buf *wbuf;
	/* A boolean to flag <wbuf> as reusable, even if not empty. */
	int reuse_wbuf;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, ctx->conn);
	qc = ctx->conn->quic_conn;
	if (!quic_get_tls_enc_levels(&tel, &next_tel, ctx->state)) {
		TRACE_DEVEL("unknown enc. levels",
		            QUIC_EV_CONN_PHPKTS, ctx->conn);
		goto err;
	}

	reuse_wbuf = 0;
	wbuf = q_wbuf(qc);
	qel = &qc->els[tel];
	/*
	 * When entering this function, the writter buffer must be empty.
	 * Most of the time it points to the reader buffer.
	 */
	while ((q_buf_empty(wbuf) || reuse_wbuf)) {
		ssize_t ret;

		/* Do not build any more packet if no ACK are required
		 * and if there is not more CRYPTO data available or in flight
		 * CRYPTO data limit reached.
		 */
		if (!(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		    (LIST_ISEMPTY(&qel->tx.frms) ||
		     qc->ifcdata >= QUIC_CRYPTO_IN_FLIGHT_MAX)) {
			TRACE_DEVEL("nothing more to do",
			            QUIC_EV_CONN_PHPKTS, ctx->conn);
			/* Consume the buffer if we were supposed to reuse it. */
			if (reuse_wbuf)
					wbuf = q_next_wbuf(qc);
			break;
		}

		reuse_wbuf = 0;
		ret = qc_build_hdshk_pkt(wbuf, qc,
		                         quic_tls_level_pkt_type(tel), qel);
		switch (ret) {
		case -2:
			goto err;
		case -1:
			/* Not enough room in <wbuf>. */
			wbuf = q_next_wbuf(qc);
			continue;
		case 0:
			goto out;
		default:
			/* Special case for Initial packets: when they have all
			 * been sent, select the next level.
			 */
			if (LIST_ISEMPTY(&qel->tx.frms) &&
			    tel == QUIC_TLS_ENC_LEVEL_INITIAL) {
				tel = next_tel;
				qel = &qc->els[tel];
				if (LIST_ISEMPTY(&qel->tx.frms)) {
					/* If there is no more data for the next level, let's
					 * consume a buffer. This is the case for a client
					 * which sends only one Initial packet, then wait
					 * for additional CRYPTO data from the server to enter the
					 * next level.
					 */
					wbuf = q_next_wbuf(qc);
				}
				else {
					/* Let's try to reuse this buffer. */
					reuse_wbuf = 1;
				}
			}
			else {
				wbuf = q_next_wbuf(qc);
			}
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_PHPKTS, ctx->conn);
	return 0;
}

/*
 * Send the QUIC packets which have been prepared for QUIC connections
 * with <ctx> as I/O handler context.
 */
static int qc_send_ppkts(struct quic_conn_ctx *ctx)
{
	struct quic_conn *qc;
	struct buffer tmpbuf = { };
	struct q_buf *rbuf;

	TRACE_ENTER(QUIC_EV_CONN_SPPKTS, ctx->conn);
	qc = ctx->conn->quic_conn;
	for (rbuf = q_rbuf(qc); !q_buf_empty(rbuf) ; rbuf = q_next_rbuf(qc)) {
		struct quic_tx_packet *p, *q;
		unsigned int time_sent;

		tmpbuf.area = (char *)rbuf->area;
		tmpbuf.size = tmpbuf.data = rbuf->data;

	    if (ctx->xprt->snd_buf(qc->conn, qc->conn->xprt_ctx,
	                           &tmpbuf, tmpbuf.data, 0) <= 0)
		    break;

	    time_sent = now_ms;
	    /* Reset this buffer to make it available for the next packet to prepare. */
	    q_buf_reset(rbuf);
		/* Remove from <rbuf> the packets which have just been sent. */
		list_for_each_entry_safe(p, q, &rbuf->pkts, list) {
			p->time_sent = time_sent;
			if (p->flags & QUIC_FL_TX_PACKET_ACK_ELICITING) {
				p->pktns->tx.time_of_last_eliciting = time_sent;
				qc->path->in_flight_ae_pkts++;
			}
			TRACE_PROTO("sent pkt", QUIC_EV_CONN_SPPKTS, ctx->conn, p);
			if (p->in_flight_len)
				qc_set_timer(ctx);
			qc->path->in_flight += p->in_flight_len;
			p->pktns->tx.in_flight += p->in_flight_len;
			LIST_DEL(&p->list);
		}
	}
	TRACE_LEAVE(QUIC_EV_CONN_SPPKTS, ctx->conn);

	return 1;
}

/*
 * Build all the frames which must be sent just after the handshake have succeeded.
 * This is essentially NEW_CONNECTION_ID frames. A QUIC server must also send
 * a HANDSHAKE_DONE frame.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_build_post_handshake_frames(struct quic_conn *conn)
{
	int i;
	struct quic_frame *frm;

	/* Only servers must send a HANDSHAKE_DONE frame. */
	if (!objt_server(conn->conn->target)) {
		frm = pool_alloc(pool_head_quic_frame);
		frm->type = QUIC_FT_HANDSHAKE_DONE;
		LIST_ADDQ(&conn->tx.frms_to_send, &frm->list);
	}

	for (i = 1; i < conn->rx_tps.active_connection_id_limit; i++) {
		struct quic_connection_id *cid;

		frm = pool_alloc(pool_head_quic_frame);
		memset(frm, 0, sizeof *frm);
		cid = new_quic_connection_id(&conn->cids, i);
		if (!frm || !cid)
			goto err;

		quic_connection_id_to_frm_cpy(frm, cid);
		LIST_ADDQ(&conn->tx.frms_to_send, &frm->list);
	}

    return 1;

 err:
	free_quic_conn_cids(conn);
	return 0;
}

/* Deallocate <l> list of ACK ranges. */
void free_ack_range_list(struct list *l)
{
	struct quic_ack_range *curr, *next;

	list_for_each_entry_safe(curr, next, l, list) {
		LIST_DEL(&curr->list);
		free(curr);
	}
}

/* Return the gap value between <p> and <q> ACK ranges. */
static inline size_t sack_gap(struct quic_ack_range *p,
                              struct quic_ack_range *q)
{
	return p->first - q->last - 2;
}


/*
 * Remove the last elements of <ack_ranges> list of ack range updating its
 * encoded size until it goes below <limit>.
 * Returns 1 if succeded, 0 if not (no more element to remove).
 */
static int quic_rm_last_ack_ranges(struct quic_ack_ranges *qars, size_t limit)
{
	struct list *l = &qars->list;
	struct quic_ack_range *last, *prev_last;

	last = LIST_PREV(l, struct quic_ack_range *, list);
	while (qars->enc_sz > limit) {
		if (l->n == l)
			return 0;

		prev_last = LIST_PREV(&last->list, struct quic_ack_range *, list);
		if (prev_last == last)
			return 0;

		qars->enc_sz -= quic_int_getsize(last->last - last->first);
		qars->enc_sz -= quic_int_getsize(sack_gap(prev_last, last));
		qars->enc_sz -= quic_decint_size_diff(qars->sz);
		--qars->sz;
		LIST_DEL(&last->list);
		pool_free(pool_head_quic_ack_range, last);
		last = prev_last;
	}

	return 1;
}

/*
 * Update <l> list of ACK ranges with <pn> new packet number.
 * Note that this function computes the number of bytes required to encode
 * this list without taking into an account ->ack_delay member field.
 *
 *    Descending order
 *    ------------->
 *                range1                  range2
 *    ..........|--------|..............|--------|
 *              ^        ^              ^        ^
 *              |        |              |        |
 *            last1     first1        last2    first2
 *    ..........+--------+--------------+--------+......
 *                 diff1       gap12       diff2
 *
 * To encode the previous list of ranges we must encode integers as follows:
 *          enc(last1),enc(diff1),enc(gap12),enc(diff2)
 *  with diff1 = last1 - first1
 *       diff2 = last2 - first2
 *       gap12 = first1 - last2 - 2
 *
 * To update this encoded list, we must considered 4 cases:
 *    ->last is incremented by 1, the previous gap, if any, must be decremented by one,
 *    ->first is decremented by 1, the next gap, if any, must be decremented by one,
 *    in both previous cases <diff> value is increment by 1.
 *    -> a new range is inserted between two others, <diff>=0 (1 byte),
 *    and a gap is splitted in two other gaps, and the size of the list is incremented
 *    by 1.
 *    -> two ranges are merged.
 */
int quic_update_ack_ranges_list(struct quic_ack_ranges *ack_ranges, int64_t pn)
{
	struct list *l = &ack_ranges->list;
	size_t *sz = &ack_ranges->sz;
	size_t *enc_sz = &ack_ranges->enc_sz;

	struct quic_ack_range *curr, *prev, *next;
	struct quic_ack_range *new_sack;

	prev = NULL;

	if (LIST_ISEMPTY(l)) {
		/* Range insertion. */
		new_sack = pool_alloc(pool_head_quic_ack_range);
		if (!new_sack)
			return 0;

		new_sack->first = new_sack->last = pn;
		LIST_ADD(l, &new_sack->list);
		/* Add the size of this new encoded range and the
		 * encoded number of ranges in this list after the first one
		 * which is 0 (1 byte).
		 */
		*enc_sz += quic_int_getsize(pn) + 2;
		++*sz;
		return 1;
	}

	list_for_each_entry_safe(curr, next, l, list) {
		/* Already existing packet number */
		if (pn >= curr->first && pn <= curr->last)
			break;

		if (pn > curr->last + 1) {
			/* Range insertion befor <curr> */
			new_sack = pool_alloc(pool_head_quic_ack_range);
			if (!new_sack)
				return 0;

			new_sack->first = new_sack->last = pn;
			/* Add the size of this new encoded range and possibly
			 * increment by 1 the encoded number of ranges in this list.
			 */
			*enc_sz += quic_int_getsize(pn) + 1 + quic_incint_size_diff(*sz);
			/* Deduce the previous largest number acked. */
			*enc_sz -= quic_int_getsize(curr->last);
			if (prev) {
				/* Insert <new_sack> after <prev>, before <curr>. */
				new_sack->list.n = &curr->list;
				new_sack->list.p = &prev->list;
				prev->list.n = curr->list.p = &new_sack->list;
				/* Deduce the previous gap encoding size.
				 * Add thew new gaps between <prev> and <new_sack> and
				 * between <new_sack> and <curr>.
				 */
				*enc_sz += quic_int_getsize(sack_gap(prev, new_sack)) +
					quic_int_getsize(sack_gap(new_sack, curr)) -
					quic_int_getsize(sack_gap(prev, curr));
			}
			else {
				LIST_ADD(l, &new_sack->list);
				/* Add the encoded size of the new gap betwen <new_sack> and <cur>. */
				*enc_sz += quic_int_getsize(sack_gap(new_sack, curr));
			}
			++*sz;
			break;
		}
		else if (curr->last + 1 == pn) {
			/* Increment the encoded size of <curr> diff by 1. */
			*enc_sz += quic_incint_size_diff(curr->last - curr->first);
			if (prev) {
				/* Decrement the encoded size of the previous gap by 1. */
				*enc_sz -= quic_decint_size_diff(sack_gap(prev, curr));
			}
			else {
				/* Increment the encode size of the largest acked packet number. */
				*enc_sz += quic_incint_size_diff(curr->last);
			}
			curr->last = pn;
			break;
		}
		else if (curr->first == pn + 1) {
			if (&next->list != l && pn == next->last + 1) {
				/* Two ranges <curr> and <next> are merged.
				 * Dedude the encoded size of <curr> diff. */
				*enc_sz -= quic_int_getsize(curr->last - curr->first);
				/* Deduce the encoded size of the gap between <curr> and <next>. */
				*enc_sz -= quic_int_getsize(sack_gap(curr, next));
				/* Deduce the encode size of <next> diff. */
				*enc_sz -= quic_int_getsize(next->last - next->first);
				/* Add the new encoded size diff between curr->last and
				 * next->first.
				 */
				*enc_sz += quic_int_getsize(curr->last - next->first);
				next->last = curr->last;
				LIST_DEL(&curr->list);
				pool_free(pool_head_quic_ack_range, curr);
				/* Possibly decrement the encoded size of this list
				 * which is decremented by 1
				 */
				*enc_sz -= quic_decint_size_diff(*sz);
				--*sz;
			}
			else {
				/* Increment the encoded size of <curr> diff by 1. */
				*enc_sz += quic_incint_size_diff(curr->last - curr->first);
				/* Decrement the encoded size of the next gap by 1. */
				if (&next->list != l)
					*enc_sz -= quic_decint_size_diff(sack_gap(curr, next));
				curr->first = pn;
			}
			break;
		}
		else if (&next->list == l) {
			new_sack = pool_alloc(pool_head_quic_ack_range);
			if (!new_sack)
				return 0;

			new_sack->first = new_sack->last = pn;
			/* We only have to add the encoded size of the gap between <curr>
			 * and <new_sack> and <new_sack> diff (0).
			 */
			*enc_sz += quic_int_getsize(sack_gap(curr, new_sack)) + 1;
			LIST_ADDQ(l, &new_sack->list);
			++*sz;
			break;
		}
		prev = curr;
	}

	return 1;
}

/*
 * Remove the header protection of packets at <el> encryption level.
 * Always succeeds.
 */
static inline void qc_rm_hp_pkts(struct quic_enc_level *el, struct quic_conn_ctx *ctx)
{
	struct quic_tls_ctx *tls_ctx;
	struct quic_rx_packet *pqpkt, *qqpkt;
	struct quic_enc_level *app_qel;

	TRACE_ENTER(QUIC_EV_CONN_ELRMHP, ctx->conn);
	app_qel = &ctx->conn->quic_conn->els[QUIC_TLS_ENC_LEVEL_APP];
	/* A server must not process incoming 1-RTT packets before the handshake is complete. */
	if (el == app_qel && objt_listener(ctx->conn->target) && ctx->state < QUIC_HS_ST_COMPLETE) {
		TRACE_PROTO("hp not removed (handshake not completed)",
		            QUIC_EV_CONN_ELRMHP, ctx->conn);
		goto out;
	}
	tls_ctx = &el->tls_ctx;
	list_for_each_entry_safe(pqpkt, qqpkt, &el->rx.pqpkts, list) {
		if (!qc_do_rm_hp(pqpkt, tls_ctx, el->pktns->rx.largest_pn,
		                 pqpkt->data + pqpkt->pn_offset,
		                 pqpkt->data, pqpkt->data + pqpkt->len, ctx)) {
			TRACE_PROTO("hp removing error", QUIC_EV_CONN_ELRMHP, ctx->conn);
			/* XXX TO DO XXX */
		}
		else {
			/* The AAD includes the packet number field */
			pqpkt->aad_len = pqpkt->pn_offset + pqpkt->pnl;
			/* Store the packet into the tree of packets to decrypt. */
			pqpkt->pn_node.key = pqpkt->pn;
			quic_rx_packet_eb64_insert(&el->rx.pkts, &pqpkt->pn_node);
			TRACE_PROTO("hp removed", QUIC_EV_CONN_ELRMHP, ctx->conn, pqpkt);
		}
		quic_rx_packet_list_del(pqpkt);
	}

  out:
	TRACE_LEAVE(QUIC_EV_CONN_ELRMHP, ctx->conn);
}

/*
 * Process all the CRYPTO frame at <el> encryption level.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_treat_rx_crypto_frms(struct quic_enc_level *el,
                                          struct quic_conn_ctx *ctx)
{
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_RXCDATA, ctx->conn);
	node = eb64_first(&el->rx.crypto.frms);
	while (node) {
		struct quic_rx_crypto_frm *cf;

		cf = eb64_entry(&node->node, struct quic_rx_crypto_frm, offset_node);
		if (cf->offset_node.key != el->rx.crypto.offset)
			break;

		HEXDUMP(cf->data, cf->len, "CRYPTO frame:\n");
		if (!qc_provide_cdata(el, ctx, cf->data, cf->len, cf->pkt, cf))
			goto err;

		node = eb64_next(node);
		quic_rx_packet_refdec(cf->pkt);
		eb64_delete(&cf->offset_node);
		pool_free(pool_head_quic_rx_crypto_frm, cf);
	}

	TRACE_LEAVE(QUIC_EV_CONN_RXCDATA, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_RXCDATA, ctx->conn);
	return 0;
}

/*
 * Process all the packets at <el> encryption level.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_treat_rx_pkts(struct quic_enc_level *el, struct quic_conn_ctx *ctx)
{
	struct quic_tls_ctx *tls_ctx;
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_ELRXPKTS, ctx->conn);
	tls_ctx = &el->tls_ctx;
	node = eb64_first(&el->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(&node->node, struct quic_rx_packet, pn_node);
		if (!qc_pkt_decrypt(pkt, tls_ctx)) {
			/* Drop the packet */
			TRACE_PROTO("packet decryption failed -> dropped",
						QUIC_EV_CONN_ELRXPKTS, ctx->conn, pkt);
		}
		else {
			int drop;

			drop = 0;
			if (!qc_parse_pkt_frms(pkt, ctx, el))
				drop = 1;

			if (drop) {
				/* Drop the packet */
				TRACE_PROTO("packet parsing failed -> dropped",
							QUIC_EV_CONN_ELRXPKTS, ctx->conn, pkt);
			}
			else {
				if (pkt->flags & QUIC_FL_RX_PACKET_ACK_ELICITING) {
					el->pktns->rx.nb_ack_eliciting++;
					if (!(el->pktns->rx.nb_ack_eliciting & 1))
						el->pktns->flags |= QUIC_FL_PKTNS_ACK_REQUIRED;
				}

				/* Update the largest packet number. */
				if (pkt->pn > el->pktns->rx.largest_pn)
					el->pktns->rx.largest_pn = pkt->pn;

				/* Update the list of ranges to acknowledge. */
				if (!quic_update_ack_ranges_list(&el->pktns->rx.ack_ranges, pkt->pn)) {
					TRACE_DEVEL("Could not update ack range list",
					            QUIC_EV_CONN_ELRXPKTS, ctx->conn);
					goto err;
				}

			}
		}
		node = eb64_next(node);
		quic_rx_packet_eb64_delete(&pkt->pn_node);
		free_quic_rx_packet(pkt);
	}

	if (!qc_treat_rx_crypto_frms(el, ctx))
		goto err;

	TRACE_LEAVE(QUIC_EV_CONN_ELRXPKTS, ctx->conn);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ELRXPKTS, ctx->conn);
	return 0;
}

/*
 * Called during handshakes to parse and build Initial and Handshake packets for QUIC
 * connections with <ctx> as I/O handler context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_do_hdshk(struct quic_conn_ctx *ctx)
{
	int ssl_err;
	struct quic_conn *quic_conn;
	enum quic_tls_enc_level tel, next_tel;
	struct quic_enc_level *qel, *next_qel;
	struct quic_tls_ctx *tls_ctx;

	TRACE_ENTER(QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);

	ssl_err = SSL_ERROR_NONE;
	quic_conn = ctx->conn->quic_conn;
	if (!quic_get_tls_enc_levels(&tel, &next_tel, ctx->state))
		goto err;

	qel = &quic_conn->els[tel];
	next_qel = &quic_conn->els[next_tel];

 next_level:
	tls_ctx = &qel->tls_ctx;

	/* If the header protection key for this level has been derived,
	 * remove the packet header protections.
	 */
	if (!LIST_ISEMPTY(&qel->rx.pqpkts) &&
	    (tls_ctx->rx.flags & QUIC_FL_TLS_SECRETS_SET))
		qc_rm_hp_pkts(qel, ctx);

	if (!eb_is_empty(&qel->rx.pkts) &&
		!qc_treat_rx_pkts(qel, ctx))
		goto err;

	if (!qc_prep_hdshk_pkts(ctx))
		goto err;

	if (!qc_send_ppkts(ctx))
		goto err;

	/*
	 * Check if there is something to do for the next level.
	 */
	if ((next_qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET) &&
	    (!LIST_ISEMPTY(&next_qel->rx.pqpkts) || !eb_is_empty(&next_qel->rx.pkts))) {
		qel = next_qel;
		if (ctx->state == QUIC_HS_ST_CLIENT_INITIAL)
			ctx->state = QUIC_HS_ST_CLIENT_HANDSHAKE;
		goto next_level;
	}

	/* If the handshake has not been completed -> out! */
	if (ctx->state < QUIC_HS_ST_COMPLETE)
		goto out;

	if (!quic_build_post_handshake_frames(quic_conn) ||
	    !qc_prep_phdshk_pkts(quic_conn) ||
	    !qc_send_ppkts(ctx))
		goto err;

 out:
	TRACE_LEAVE(QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
	return 0;
}

/* QUIC connection packet handler task. */
static struct task *quic_conn_io_cb(struct task *t, void *context, unsigned short state)
{
	struct quic_conn_ctx *ctx = context;

	QDPRINTF("%s: tid: %u\n", __func__, tid);
	if (ctx->state < QUIC_HS_ST_COMPLETE) {
		if (!qc_do_hdshk(ctx))
			QDPRINTF("%s SSL handshake error\n", __func__);
	}
	else {
		struct quic_conn *qc = ctx->conn->quic_conn;

		/* XXX TO DO: may fail!!! XXX */
		qc_treat_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_APP], ctx);
	    qc_prep_phdshk_pkts(qc);
	    qc_send_ppkts(ctx);
	}

	return NULL;
}

/* We can't have an underlying XPRT, so just return -1 to signify failure */
static int quic_conn_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	QDPRINTF("%s\n", __func__);
	/* This is the lowest xprt we can have, so if we get there we didn't
	 * find the xprt we wanted to remove, that's a bug
	 */
	BUG_ON(1);
	return -1;
}

/*
 * Allocate a new QUIC connection and return it if succeeded, NULL if not.
 */
static struct quic_conn *new_quic_conn(uint32_t version)
{
	struct quic_conn *quic_conn;

	quic_conn = pool_alloc(pool_head_quic_conn);
	if (quic_conn) {
		memset(quic_conn, 0, sizeof *quic_conn);
		quic_conn->version = version;
	}

	return quic_conn;
}

/*
 * Unitialize <qel> QUIC encryption level.
 * Never fails.
 */
static void quic_conn_enc_level_uninit(struct quic_enc_level *qel)
{
	int i;

	for (i = 0; i < qel->tx.crypto.nb_buf; i++) {
		if (qel->tx.crypto.bufs[i]) {
			pool_free(pool_head_quic_crypto_buf, qel->tx.crypto.bufs[i]);
			qel->tx.crypto.bufs[i] = NULL;
		}
	}
	free(qel->tx.crypto.bufs);
	qel->tx.crypto.bufs = NULL;
}

/*
 * Initialize QUIC TLS encryption level with <level<> as level for <qc> QUIC
 * connetion allocating everything needed.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_enc_level_init(struct quic_conn *qc,
                                    enum quic_tls_enc_level level)
{
	struct quic_enc_level *qel;

	qel = &qc->els[level];
	qel->level = quic_to_ssl_enc_level(level);
	qel->tls_ctx.rx.aead = qel->tls_ctx.tx.aead = NULL;
	qel->tls_ctx.rx.md   = qel->tls_ctx.tx.md = NULL;
	qel->tls_ctx.rx.hp   = qel->tls_ctx.tx.hp = NULL;
	qel->tls_ctx.rx.flags = 0;
	qel->tls_ctx.tx.flags = 0;

	qel->rx.pkts = EB_ROOT;
	LIST_INIT(&qel->rx.pqpkts);

	/* Allocate only one buffer. */
	qel->tx.crypto.bufs = malloc(sizeof *qel->tx.crypto.bufs);
	if (!qel->tx.crypto.bufs)
		goto err;

	qel->tx.crypto.bufs[0] = pool_alloc(pool_head_quic_crypto_buf);
	if (!qel->tx.crypto.bufs[0]) {
		QDPRINTF("%s: could not allocated any crypto buffer\n", __func__);
		goto err;
	}

	qel->tx.crypto.bufs[0]->sz = 0;
	qel->tx.crypto.nb_buf = 1;

	qel->tx.crypto.sz = 0;
	qel->tx.crypto.offset = 0;
	LIST_INIT(&qel->tx.frms);

	return 1;

 err:
	free(qel->tx.crypto.bufs);
	qel->tx.crypto.bufs = NULL;
	return 0;
}

/*
 * Release the memory allocated for <buf> array of buffers, with <nb> as size.
 * Never fails.
 */
static inline void free_quic_conn_tx_bufs(struct q_buf **bufs, size_t nb)
{
	struct q_buf **p;

	if (!bufs)
		return;

	p = bufs;
	while (--nb) {
		if (!*p) {
			p++;
			continue;
		}
		free((*p)->area);
		(*p)->area = NULL;
		free(*p);
		*p = NULL;
		p++;
	}
	free(bufs);
}

/*
 * Allocate an array or <nb> buffers of <sz> bytes each.
 * Return this array if succeeded, NULL if failed.
 */
static inline struct q_buf **quic_conn_tx_bufs_alloc(size_t nb, size_t sz)
{
	int i;
	struct q_buf **bufs, **p;

	bufs = calloc(nb, sizeof *bufs);
	if (!bufs)
		return NULL;

	i = 0;
	p = bufs;
	while (i++ < nb) {
		*p = calloc(1, sizeof **p);
		if (!*p)
			goto err;

		(*p)->area = malloc(sz);
		if (!(*p)->area)
		    goto err;

		(*p)->pos = (*p)->area;
		(*p)->end = (*p)->area + sz;
		(*p)->data = 0;
		LIST_INIT(&(*p)->pkts);
		p++;
	}

	return bufs;

 err:
	free_quic_conn_tx_bufs(bufs, nb);
	return NULL;
}

/*
 * Release all the memory allocated for <conn> QUIC connection. */
static void quic_conn_free(struct quic_conn *conn)
{
	int i;

	free_quic_conn_cids(conn);
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++)
		quic_conn_enc_level_uninit(&conn->els[i]);
	free_quic_conn_tx_bufs(conn->tx.bufs, conn->tx.nb_buf);
	if (conn->timer_task)
		task_destroy(conn->timer_task);
	pool_free(pool_head_quic_conn, conn);
}

/* Callback called upon loss detection and PTO timer expirations. */
static struct task *process_timer(struct task *task, void *ctx, unsigned short state)
{
	struct quic_conn_ctx *conn_ctx;
	struct quic_conn *qc;
	struct quic_pktns *pktns;


	conn_ctx = task->context;
	qc = conn_ctx->conn->quic_conn;
	TRACE_ENTER(QUIC_EV_CONN_PTIMER, conn_ctx->conn);
	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

		qc_packet_loss_lookup(pktns, qc, &lost_pkts, 0);
		if (!LIST_ISEMPTY(&lost_pkts))
			qc_treat_lost_pkts(ctx, &lost_pkts, now_ms);
		goto out;
	}

	if (qc->path->in_flight)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);
	qc->path->loss.pto_count++;

 out:
	qc_set_timer(conn_ctx);
	TRACE_LEAVE(QUIC_EV_CONN_PTIMER, conn_ctx->conn);

	return task;
}

/*
 * Initialize <conn> QUIC connection with <quic_initial_clients> as root of QUIC
 * connections used to identify the first Initial packets of client connecting
 * to listeners. This parameter must be NULL for QUIC connections attached
 * to listeners. <dcid> is the destination connection ID with <dcid_len> as length.
 * <scid> is the source connection ID with <scid_len> as length.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_new_conn_init(struct quic_conn *conn, int ipv4,
                            struct eb_root *quic_initial_clients,
                            struct eb_root *quic_clients,
                            unsigned char *dcid, size_t dcid_len,
                            unsigned char *scid, size_t scid_len)
{
	int i;
	/* Initial CID. */
	struct quic_connection_id *icid;

	TRACE_ENTER(QUIC_EV_CONN_INIT, conn->conn);
	conn->cids = EB_ROOT;
	QDPRINTF("%s: new quic_conn @%p\n", __func__, conn);
	/* QUIC Server (or listener). */
	if (objt_listener(conn->conn->target)) {
		/* Copy the initial DCID. */
		conn->odcid.len = dcid_len;
		if (conn->odcid.len)
			memcpy(conn->odcid.data, dcid, dcid_len);

		/* Copy the SCID as our DCID for this connection. */
		if (scid_len)
			memcpy(conn->dcid.data, scid, scid_len);
		conn->dcid.len = scid_len;
	}
	/* QUIC Client (outoging connection to servers) */
	else {
		if (dcid_len)
			memcpy(conn->dcid.data, dcid, dcid_len);
		conn->dcid.len = dcid_len;
	}

	/* Initialize the output buffer */
	conn->obuf.pos = conn->obuf.data;

	icid = new_quic_connection_id(&conn->cids, 0);
	if (!icid)
		return 0;

	/* Select our SCID which is the first CID with 0 as sequence number. */
	conn->scid = icid->cid;

	/* Insert the DCID the QUIC client has choosen (only for listeners) */
	if (objt_listener(conn->conn->target))
		ebmb_insert(quic_initial_clients, &conn->odcid_node, conn->odcid.len);

	/* Insert our SCID, the connection ID for the QUIC client. */
	ebmb_insert(quic_clients, &conn->scid_node, conn->scid.len);

	/* Packet number spaces initialization. */
	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++) {
		quic_pktns_init(&conn->pktns[i]);
	}
	/* QUIC encryption level context initialization. */
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		if (!quic_conn_enc_level_init(conn, i))
			goto err;
		/* Initialize the packet number space. */
		conn->els[i].pktns = &conn->pktns[quic_tls_pktns(i)];
	}

	LIST_INIT(&conn->tx.frms_to_send);
	conn->tx.bufs = quic_conn_tx_bufs_alloc(QUIC_CONN_TX_BUFS_NB, QUIC_CONN_TX_BUF_SZ);
	if (!conn->tx.bufs)
		goto err;

	conn->tx.nb_buf = QUIC_CONN_TX_BUFS_NB;
	conn->tx.wbuf = conn->tx.rbuf = 0;

	conn->ifcdata = 0;

	/* XXX TO DO: Only one path at this time. */
	conn->path = &conn->paths[0];
	quic_path_init(conn->path, ipv4, default_quic_cc_algo, conn);

	/* Timer. */
	conn->timer_task = task_new(MAX_THREADS_MASK);
	if (!conn->timer_task)
		goto err;

	conn->timer = TICK_ETERNITY;
	conn->timer_task->process = process_timer;
	conn->timer_task->context = conn->conn->xprt_ctx;

	TRACE_LEAVE(QUIC_EV_CONN_INIT, conn->conn);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_INIT, conn->conn);
	quic_conn_free(conn);
	return 0;
}

/*
 * Derive the initial secrets with <ctx> as QUIC TLS context which is the
 * cryptographic context for the first encryption level (Initial) from
 * <cid> connection ID with <cidlen> as length (in bytes) for a server or not
 * depending on <server> boolean value.
 * Return 1 if succeeded or 0 if not.
 */
static int qc_new_isecs(struct connection *conn,
                        const unsigned char *cid, size_t cidlen, int server)
{
	unsigned char initial_secret[32];
	/* Initial secret to be derived for incoming packets */
	unsigned char rx_init_sec[32];
	/* Initial secret to be derived for outgoing packets */
	unsigned char tx_init_sec[32];
	struct quic_tls_secrets *rx_ctx, *tx_ctx;
	struct quic_tls_ctx *ctx;

	TRACE_ENTER(QUIC_EV_CONN_ISEC, conn);
	ctx = &conn->quic_conn->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;
	quic_initial_tls_ctx_init(ctx);
	if (!quic_derive_initial_secret(ctx->rx.md,
	                                initial_secret, sizeof initial_secret,
	                                cid, cidlen))
		goto err;

	if (!quic_tls_derive_initial_secrets(ctx->rx.md,
	                                     rx_init_sec, sizeof rx_init_sec,
	                                     tx_init_sec, sizeof tx_init_sec,
	                                     initial_secret, sizeof initial_secret, server))
		goto err;

	rx_ctx = &ctx->rx;
	tx_ctx = &ctx->tx;
	if (!quic_tls_derive_keys(ctx->rx.aead, ctx->rx.hp, ctx->rx.md,
	                          rx_ctx->key, sizeof rx_ctx->key,
	                          rx_ctx->iv, sizeof rx_ctx->iv,
	                          rx_ctx->hp_key, sizeof rx_ctx->hp_key,
	                          rx_init_sec, sizeof rx_init_sec))
		goto err;

	rx_ctx->flags |= QUIC_FL_TLS_SECRETS_SET;
	if (!quic_tls_derive_keys(ctx->tx.aead, ctx->tx.hp, ctx->tx.md,
	                          tx_ctx->key, sizeof tx_ctx->key,
	                          tx_ctx->iv, sizeof tx_ctx->iv,
	                          tx_ctx->hp_key, sizeof tx_ctx->hp_key,
	                          tx_init_sec, sizeof tx_init_sec))
		goto err;

	tx_ctx->flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_ISEC, conn, rx_init_sec, tx_init_sec);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_EISEC, conn);
	return 0;
}

/*
 * Initialize a QUIC connection (quic_conn struct) to be attached to <conn>
 * connection with <xprt_ctx> as address of the xprt context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_conn_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_conn_ctx *ctx;

	TRACE_ENTER(QUIC_EV_CONN_NEW, conn);

	if (*xprt_ctx)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	ctx = pool_alloc(pool_head_quic_conn_ctx);
	if (!ctx) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		goto err;
	}

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		goto err;
	}

	ctx->wait_event.tasklet->process = quic_conn_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->conn = conn;
	ctx->subs = NULL;
	ctx->xprt_ctx = NULL;

	ctx->xprt = xprt_get(XPRT_QUIC);
	if (objt_server(conn->target)) {
		/* Server */
		struct server *srv = __objt_server(conn->target);
		unsigned char dcid[QUIC_CID_LEN];
		struct quic_conn *quic_conn;
		int ssl_err, ipv4;

		ssl_err = SSL_ERROR_NONE;
		if (RAND_bytes(dcid, sizeof dcid) != 1)
			goto err;

		conn->quic_conn = new_quic_conn(QUIC_PROTOCOL_VERSION_DRAFT_28);
		if (!conn->quic_conn)
			goto err;

		quic_conn = conn->quic_conn;
		quic_conn->conn = conn;
		ipv4 = conn->dst->ss_family == AF_INET;
		if (!qc_new_conn_init(quic_conn, ipv4, NULL, &srv->cids,
		                      dcid, sizeof dcid, NULL, 0))
			goto err;

		if (!qc_new_isecs(conn, dcid, sizeof dcid, 0)) {
			QDPRINTF("Could not derive initial secrets\n");
			goto err;
		}

		ctx->state = QUIC_HS_ST_CLIENT_INITIAL;
		if (ssl_bio_and_sess_init(conn, srv->ssl_ctx.ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1) {
			QDPRINTF("Could not initiliaze SSL ctx\n");
			goto err;
		}

		quic_conn->params = srv->quic_params;
		/* Copy the initial source connection ID. */
		quic_cid_cpy(&quic_conn->params.initial_source_connection_id, &quic_conn->scid);
		quic_conn->enc_params_len =
			quic_transport_params_encode(quic_conn->enc_params,
			                             quic_conn->enc_params + sizeof quic_conn->enc_params,
			                             &quic_conn->params, 0);
		if (!quic_conn->enc_params_len) {
			QDPRINTF("QUIC transport parameters encoding failed");
			goto err;
		}
		SSL_set_quic_transport_params(ctx->ssl, quic_conn->enc_params, quic_conn->enc_params_len);
		SSL_set_connect_state(ctx->ssl);
		ssl_err = SSL_do_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake",
				            QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
			}
			else {
				TRACE_DEVEL("SSL handshake error",
							QUIC_EV_CONN_HDSHK, ctx->conn, &ctx->state, &ssl_err);
				goto err;
			}
		}
	}
	else if (objt_listener(conn->target)) {
		/* Listener */
		struct bind_conf *bc = __objt_listener(conn->target)->bind_conf;

		ctx->state = QUIC_HS_ST_SERVER_INITIAL;

		if (ssl_bio_and_sess_init(conn, bc->initial_ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1)
			goto err;

		SSL_set_accept_state(ctx->ssl);
	}

	*xprt_ctx = ctx;

	/* Leave init state and start handshake */
	conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
	/* Start the handshake */
	tasklet_wakeup(ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_NEW, conn);

	return 0;

 err:
	if (ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(pool_head_quic_conn_ctx, ctx);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_NEW|QUIC_EV_CONN_ENEW, conn);
	return -1;
}

/* Release the SSL context of <srv> server. */
void quic_conn_free_srv_ctx(struct server *srv)
{
	QDPRINTF("%s\n", __func__);
	if (srv->ssl_ctx.ctx)
		SSL_CTX_free(srv->ssl_ctx.ctx);
}

/*
 * Prepare the SSL context for <srv> server.
 * Returns an error count.
 */
int quic_conn_prepare_srv_ctx(struct server *srv)
{
	struct proxy *curproxy = srv->proxy;
	int cfgerr = 0;
	SSL_CTX *ctx = NULL;
	int verify = SSL_VERIFY_NONE;
	long mode =
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_RELEASE_BUFFERS |
		SSL_MODE_SMALL_BUFFERS;

	/* Make sure openssl opens /dev/urandom before the chroot */
	if (!ssl_initialize_random()) {
		ha_alert("OpenSSL random data generator initialization failed.\n");
		cfgerr++;
	}

	ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	SSL_CTX_set_mode(ctx, mode);
	QDPRINTF("%s SSL ctx mode: %ld\n", __func__, mode);

	srv->ssl_ctx.ctx = ctx;
	if (srv->ssl_ctx.client_crt) {
		if (SSL_CTX_use_PrivateKey_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt, SSL_FILETYPE_PEM) <= 0) {
			ha_alert("config : %s '%s', server '%s': unable to load SSL private key from PEM file '%s'.\n",
			         proxy_type_str(curproxy), curproxy->id,
			         srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_use_certificate_chain_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt) <= 0) {
			ha_alert("config : %s '%s', server '%s': unable to load ssl certificate from PEM file '%s'.\n",
			         proxy_type_str(curproxy), curproxy->id,
			         srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_check_private_key(srv->ssl_ctx.ctx) <= 0) {
			ha_alert("config : %s '%s', server '%s': inconsistencies between private key and certificate loaded from PEM file '%s'.\n",
			         proxy_type_str(curproxy), curproxy->id,
			         srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
	}

	if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
		verify = SSL_VERIFY_PEER;
	switch (srv->ssl_ctx.verify) {
	case SSL_SOCK_VERIFY_NONE:
		verify = SSL_VERIFY_NONE;
		break;
	case SSL_SOCK_VERIFY_REQUIRED:
		verify = SSL_VERIFY_PEER;
		break;
	}
	SSL_CTX_set_verify(srv->ssl_ctx.ctx, verify,
	                   (srv->ssl_ctx.verify_host || (verify & SSL_VERIFY_PEER)) ? ssl_sock_srv_verifycbk : NULL);
	if (verify & SSL_VERIFY_PEER) {
		if (srv->ssl_ctx.ca_file) {
			/* set CAfile to verify */
			if (!ssl_set_verify_locations_file(srv->ssl_ctx.ctx, srv->ssl_ctx.ca_file)) {
				ha_alert("Proxy '%s', server '%s' [%s:%d] unable to set CA file '%s'.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line, srv->ssl_ctx.ca_file);
				cfgerr++;
			}
		}
		else {
			if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
				ha_alert("Proxy '%s', server '%s' [%s:%d] verify is enabled by default "
				         "but no CA file specified. If you're running on a LAN where "
				         "you're certain to trust the server's certificate, please set "
				         "an explicit 'verify none' statement on the 'server' line, or "
				         "use 'ssl-server-verify none' in the global section to disable "
				         "server-side verifications by default.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line);
			else
				ha_alert("Proxy '%s', server '%s' [%s:%d] verify is enabled but no CA file specified.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line);
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (srv->ssl_ctx.crl_file) {
			X509_STORE *store = SSL_CTX_get_cert_store(srv->ssl_ctx.ctx);

			if (!ssl_set_cert_crl_file(store, srv->ssl_ctx.crl_file)) {
				ha_alert("Proxy '%s', server '%s' [%s:%d] unable to configure CRL file '%s'.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line, srv->ssl_ctx.crl_file);
				cfgerr++;
			}
			else {
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
			}
		}
#endif
	}

	SSL_CTX_set_session_cache_mode(srv->ssl_ctx.ctx, SSL_SESS_CACHE_CLIENT |
	                               SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(srv->ssl_ctx.ctx, ssl_sess_new_srv_cb);
	if (srv->ssl_ctx.ciphers &&
		!SSL_CTX_set_cipher_list(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphers)) {
		ha_alert("Proxy '%s', server '%s' [%s:%d] : unable to set SSL cipher list to '%s'.\n",
		         curproxy->id, srv->id,
		         srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphers);
		cfgerr++;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (srv->ssl_ctx.ciphersuites &&
		!SSL_CTX_set_ciphersuites(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphersuites)) {
		ha_alert("Proxy '%s', server '%s' [%s:%d] : unable to set TLS 1.3 cipher suites to '%s'.\n",
		         curproxy->id, srv->id,
		         srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphersuites);
		cfgerr++;
	}
#endif
	SSL_CTX_set_quic_method(ctx, &ha_quic_method);

    return cfgerr;
}

/* transport-layer operations for QUIC connections. */
static struct xprt_ops quic_conn = {
	.snd_buf  = quic_conn_from_buf,
	.rcv_buf  = quic_conn_to_buf,
	.subscribe = quic_conn_subscribe,
	.unsubscribe = quic_conn_unsubscribe,
	.remove_xprt = quic_conn_remove_xprt,
	.shutr    = NULL,
	.shutw    = NULL,
	.close    = NULL,
	.init     = qc_conn_init,
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.prepare_srv = quic_conn_prepare_srv_ctx,
	.destroy_srv = quic_conn_free_srv_ctx,
	.name     = "QUIC",
};


__attribute__((constructor))
static void __quic_conn_init(void)
{
	ha_quic_meth = BIO_meth_new(0x666, "ha QUIC methods");
	xprt_register(XPRT_QUIC, &quic_conn);
}

__attribute__((destructor))
static void __quic_conn_deinit(void)
{
	BIO_meth_free(ha_quic_meth);
}

/*
 * Inspired from session_accept_fd().
 * Instantiate a new connection (connection struct) to be attached to <quic_conn>
 * QUIC connection of <l> listener.
 * Returns 1 if succeeded, 0 if not.
 */
static int new_quic_cli_conn(struct quic_conn *quic_conn,
                             struct listener *l, struct sockaddr_storage *saddr)
{
	struct connection *cli_conn;
	struct proxy *p = l->bind_conf->frontend;
	struct session *sess;

	if (unlikely((cli_conn = conn_new()) == NULL))
		goto out;

	if (!sockaddr_alloc(&cli_conn->dst))
		goto out_free_conn;

	QDPRINTF("%s conn: @%p\n", __func__, cli_conn);
	quic_conn->conn = cli_conn;
	cli_conn->quic_conn = quic_conn;

	/* XXX Not sure it is safe to keep this statement. */
	cli_conn->handle.fd = l->fd;
	if (saddr)
		*cli_conn->dst = *saddr;
	cli_conn->flags |= CO_FL_ADDR_FROM_SET;
	cli_conn->target = &l->obj_type;
	cli_conn->proxy_netns = l->netns;

	conn_prepare(cli_conn, l->proto, l->bind_conf->xprt);

#if 0
	/* XXX DO NOT fd_insert() l->fd again with another I/O handler XXX
	 * This should be the case for an outgoing QUIC connection (haproxy as QUIC client).
	 */
	conn_ctrl_init(cli_conn);
#else
	cli_conn->flags |= CO_FL_CTRL_READY;
#endif

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY)
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;

	/* wait for a NetScaler client IP insertion protocol header */
	if (l->options & LI_O_ACC_CIP)
		cli_conn->flags |= CO_FL_ACCEPT_CIP;

	if (conn_xprt_init(cli_conn) < 0)
		goto out_free_conn;

	/* Add the handshake pseudo-XPRT */
	if (cli_conn->flags & (CO_FL_ACCEPT_PROXY | CO_FL_ACCEPT_CIP)) {
		if (xprt_add_hs(cli_conn) != 0)
			goto out_free_conn;
	}
	sess = session_new(p, l, &cli_conn->obj_type);
	if (!sess)
		goto out_free_conn;

	conn_set_owner(cli_conn, sess, NULL);


	/* OK let's complete stream initialization since there is no handshake */
	if (conn_complete_session(cli_conn) >= 0)
		return 1;

	/* error unrolling */
 out_free_sess:
	 /* prevent call to listener_release during session_free. It will be
	  * done below, for all errors. */
	sess->listener = NULL;
	session_free(sess);
 out_free_conn:
	conn_stop_tracking(cli_conn);
	conn_xprt_close(cli_conn);
	conn_free(cli_conn);
 out:

	return 0;
}

/*
 * Parse into <qpkt> a long header located at <*buf> buffer, <end> begin a pointer to the end
 * past one byte of this buffer.
 */
static inline int quic_packet_read_long_header(unsigned char **buf, const unsigned char *end,
                                               struct quic_rx_packet *qpkt)
{
	unsigned char dcid_len, scid_len;

	/* Version */
	if (!quic_read_uint32(&qpkt->version, (const unsigned char **)buf, end))
		return 0;

	if (!qpkt->version) { /* XXX TO DO XXX Version negotiation packet */ };

	/* Destination Connection ID Length */
	dcid_len = *(*buf)++;
	/* We want to be sure we can read <dcid_len> bytes and one more for <scid_len> value */
	if (dcid_len > QUIC_CID_MAXLEN || end - *buf < dcid_len + 1)
		/* XXX MUST BE DROPPED */
		return 0;

	if (dcid_len) {
		/*
		 * Check that the length of this received DCID matches the CID lengths
		 * of our implementation for non Initials packets only.
		 */
		if (qpkt->type != QUIC_PACKET_TYPE_INITIAL && dcid_len != QUIC_CID_LEN)
			return 0;

		memcpy(qpkt->dcid.data, *buf, dcid_len);
	}

	qpkt->dcid.len = dcid_len;
	*buf += dcid_len;

	/* Source Connection ID Length */
	scid_len = *(*buf)++;
	if (scid_len > QUIC_CID_MAXLEN || end - *buf < scid_len)
		/* XXX MUST BE DROPPED */
		return 0;

	if (scid_len)
		memcpy(qpkt->scid.data, *buf, scid_len);
	qpkt->scid.len = scid_len;
	*buf += scid_len;

	return 1;
}

/*
 * Try to remove the header protecttion of <qpkt> QUIC packet attached to <conn>
 * QUIC connection with <buf> as packet number field address, <end> a pointer to one
 * byte past the end of the buffer containing this packet and <beg> the address of
 * the packet first byte.
 * If succeeded, this function updates <*buf> to point to the next packet in the buffer.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int qc_try_rm_hp(struct quic_rx_packet *qpkt,
                               unsigned char **buf, unsigned char *beg,
                               const unsigned char *end,
                               struct quic_conn_ctx *ctx)
{
	unsigned char *pn = NULL; /* Packet number field */
	enum quic_tls_enc_level tel;
	struct quic_enc_level *qel;
	/* Only for traces. */
	struct quic_rx_packet *qpkt_trace;

	qpkt_trace = NULL;
	TRACE_ENTER(QUIC_EV_CONN_TRMHP, ctx->conn);
	/*
	 * The packet number is here. This is also the start minus
	 * QUIC_PACKET_PN_MAXLEN of the sample used to add/remove the header
	 * protection.
	 */
	pn = *buf;
	/* Increase the total length of this packet by the header length. */
	qpkt->len += pn - beg;
	if (qpkt->len > sizeof qpkt->data) {
		TRACE_PROTO("Too big packet", QUIC_EV_CONN_TRMHP, ctx->conn,, &qpkt->len);
		goto err;
	}

	tel = quic_packet_type_enc_level(qpkt->type);
	if (tel == QUIC_TLS_ENC_LEVEL_NONE) {
		TRACE_DEVEL("Wrong enc. level", QUIC_EV_CONN_TRMHP, ctx->conn);
		goto err;
	}

	qel = &ctx->conn->quic_conn->els[tel];

	if ((qel->tls_ctx.rx.flags & QUIC_FL_TLS_SECRETS_SET) &&
	    (tel != QUIC_TLS_ENC_LEVEL_APP || ctx->state >= QUIC_HS_ST_COMPLETE)) {
		/*
		 * Note that the following function enables us to unprotect the packet
		 * number and its length subsequently used to decrypt the entire
		 * packets.
		 */
		if (!qc_do_rm_hp(qpkt, &qel->tls_ctx,
		                 qel->pktns->rx.largest_pn, pn, beg, end, ctx)) {
			TRACE_PROTO("hp error", QUIC_EV_CONN_TRMHP, ctx->conn);
			goto err;
		}

		QDPRINTF("%s inserting packet number: %lu enc. level: %d\n",
		         __func__, qpkt->pn, tel);

		/* The AAD includes the packet number field found at <pn>. */
		qpkt->aad_len = pn - beg + qpkt->pnl;
		qpkt_trace = qpkt;
		/* Store the packet */
		qpkt->pn_node.key = qpkt->pn;
		quic_rx_packet_eb64_insert(&qel->rx.pkts, &qpkt->pn_node);
	}
	else {
		TRACE_PROTO("hp not removed", QUIC_EV_CONN_TRMHP, ctx->conn, qpkt);
		qpkt->pn_offset = pn - beg;
		quic_rx_packet_list_addq(&qel->rx.pqpkts, qpkt);
	}

	memcpy(qpkt->data, beg, qpkt->len);
	/* Updtate the offset of <*buf> for the next QUIC packet. */
	*buf = beg + qpkt->len;

	TRACE_LEAVE(QUIC_EV_CONN_TRMHP, ctx->conn, qpkt_trace);
	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_TRMHP, ctx->conn, qpkt_trace);
	return 0;
}

typedef ssize_t qpkt_read_func(unsigned char **buf,
                               const unsigned char *end,
                               struct quic_rx_packet *qpkt, void *ctx,
                               struct ebmb_node **dcid_node,
                               struct sockaddr_storage *saddr,
                               socklen_t *saddrlen);

/*
 * Parse the header form from <byte0> first byte of <pkt> pacekt to set type.
 * Also set <*long_header> to 1 if this form is long, 0 if not.
 */
static inline void qc_parse_hd_form(struct quic_rx_packet *pkt,
                                    unsigned char byte0, int *long_header)
{
	if (byte0 & QUIC_PACKET_LONG_HEADER_BIT) {
		pkt->type =
			(byte0 >> QUIC_PACKET_TYPE_SHIFT) & QUIC_PACKET_TYPE_BITMASK;
		*long_header = 1;
	}
	else {
		pkt->type = QUIC_PACKET_TYPE_SHORT;
		*long_header = 0;
	}
}

static ssize_t qc_srv_pkt_rcv(unsigned char **buf, const unsigned char *end,
                              struct quic_rx_packet *qpkt, void *ctx,
                              struct ebmb_node **dcid_node,
                              struct sockaddr_storage *saddr, socklen_t *saddrlen)
{
	unsigned char *beg;
	uint64_t len;
	struct quic_conn *conn;
	struct eb_root *cids;
	struct ebmb_node *node;
	struct connection *srv_conn;
	struct quic_conn_ctx *conn_ctx;
	int long_header;

	conn = NULL;
	TRACE_ENTER(QUIC_EV_CONN_SPKT);
	if (end <= *buf)
		goto err;

	/* Fixed bit */
	if (!(**buf & QUIC_PACKET_FIXED_BIT))
		/* XXX TO BE DISCARDED */
		goto err;

	srv_conn = ctx;
	beg = *buf;
	/* Header form */
	qc_parse_hd_form(qpkt, *(*buf)++, &long_header);
	if (long_header) {
		size_t cid_lookup_len;

		if (!quic_packet_read_long_header(buf, end, qpkt))
			goto err;

		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			cids = &((struct server *)__objt_server(srv_conn->target))->cids;
			cid_lookup_len = qpkt->dcid.len;
		}
		else {
			cids = &((struct server *)__objt_server(srv_conn->target))->cids;
			cid_lookup_len = QUIC_CID_LEN;
		}

		node = ebmb_lookup(cids, qpkt->dcid.data, cid_lookup_len);
		if (!node) {
			QDPRINTF("Connection not found.\n");
			goto err;
		}
		conn = ebmb_entry(node, struct quic_conn, scid_node);

		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			conn->dcid.len = qpkt->scid.len;
			if (qpkt->scid.len)
				memcpy(conn->dcid.data, qpkt->scid.data, qpkt->scid.len);
		}

		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;

			if (!quic_dec_int(&token_len, (const unsigned char **)buf, end) || end - *buf < token_len)
				goto err;

			/* XXX TO DO XXX 0 value means "the token is not present".
			 * A server which sends an Initial packet must not set the token.
			 * So, a client which receives an Initial packet with a token
			 * MUST discard the packet or generate a connection error with
			 * PROTOCOL_VIOLATION as type.
			 * The token must be provided in a Retry packet or NEW_TOKEN frame.
			 */
			qpkt->token_len = token_len;
		}
	}
	else {
		/* XXX TO DO: Short header XXX */
		if (end - *buf < QUIC_CID_LEN) {
			QDPRINTF("Too short short headder\n");
			goto err;
		}
		cids = &((struct server *)__objt_server(srv_conn->target))->cids;
		node = ebmb_lookup(cids, *buf, QUIC_CID_LEN);
		if (!node) {
			QDPRINTF("Unknonw connection ID\n");
			goto err;
		}

		conn = ebmb_entry(node, struct quic_conn, scid_node);
		*buf += QUIC_CID_LEN;
	}
	/* Store the DCID used for this packet to check the packet which
	 * come in this UDP datagram match with it.
	 */
	if (!*dcid_node)
		*dcid_node = node;
	else if (*dcid_node != node) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, conn->conn);
		goto err;
	}
	/*
	 * Only packets packets with long headers and not RETRY or VERSION as type
	 * have a length field.
	 */
	if (long_header && qpkt->type != QUIC_PACKET_TYPE_RETRY && qpkt->version) {
		if (!quic_dec_int(&len, (const unsigned char **)buf, end) || end - *buf < len) {
			QDPRINTF("Could not decode the packet length or "
			         "too short packet (%zu, %zu)\n", len, end - *buf);
			goto err;
		}
		qpkt->len = len;
	}
	else if (!long_header) {
		/* A short packet is the last one of an UDP datagram. */
		qpkt->len = end - *buf;
	}
	QDPRINTF("%s packet length: %zu\n", __func__, qpkt->len);

	conn_ctx = conn->conn->xprt_ctx;

	if (!qc_try_rm_hp(qpkt, buf, beg, end, conn_ctx))
		goto err;

	/* Wake the tasklet of the QUIC connection packet handler. */
	if (conn_ctx)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_SPKT, conn->conn);

	return qpkt->len;

 err:
	TRACE_DEVEL("Leaing in error", QUIC_EV_CONN_ESPKT, conn ? conn->conn : NULL);
	return -1;
}

static ssize_t qc_lstnr_pkt_rcv(unsigned char **buf, const unsigned char *end,
                                struct quic_rx_packet *qpkt, void *ctx, struct ebmb_node **dcid_node,
                                struct sockaddr_storage *saddr, socklen_t *saddrlen)
{
	unsigned char *beg;
	uint64_t len;
	struct quic_conn *conn;
	struct eb_root *cids;
	struct ebmb_node *node;
	struct listener *l;
	struct quic_conn_ctx *conn_ctx;
	int long_header = 0;

	conn = NULL;
	TRACE_ENTER(QUIC_EV_CONN_LPKT);
	if (end <= *buf)
		goto err;

	/* Fixed bit */
	if (!(**buf & QUIC_PACKET_FIXED_BIT))
		/* XXX TO BE DISCARDED */
		goto err;

	l = ctx;
	beg = *buf;
	/* Header form */
	qc_parse_hd_form(qpkt, *(*buf)++, &long_header);
	if (long_header) {
		unsigned char dcid_len;
		size_t saddr_len;

		if (!quic_packet_read_long_header(buf, end, qpkt))
			goto err;

		dcid_len = qpkt->dcid.len;
		saddr_len = 0;
		/* For Initial packets, and for servers (QUIC clients connections),
		 * there is no Initial connection IDs storage.
		 */
		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			/*
			 * DCIDs of first packets coming from clients may have the same values.
			 * Let's distinguish them concatenating the socket addresses to the DCIDs.
			 */
			saddr_len = quic_cid_saddr_cat(&qpkt->dcid, saddr);
			cids = &l->icids;
		}
		else {
			if (qpkt->dcid.len != QUIC_CID_LEN)
				goto err;

			cids = &l->cids;
		}

		node = ebmb_lookup(cids, qpkt->dcid.data, qpkt->dcid.len);
		if (!node && qpkt->type == QUIC_PACKET_TYPE_INITIAL && dcid_len == QUIC_CID_LEN &&
		    cids == &l->icids) {
			/* Switch to the definitive tree ->cids containing the final CIDs. */
			node = ebmb_lookup(&l->cids, qpkt->dcid.data, dcid_len);
			if (node) {
				/* If found, signal this with NULL as special value for <cids>. */
				qpkt->dcid.len = dcid_len;
				cids = NULL;
			}
		}
		if (!node) {
			struct quic_cid *odcid;
			int ipv4;

			if (qpkt->type != QUIC_PACKET_TYPE_INITIAL) {
				QDPRINTF("Connection not found.\n");
				goto err;
			}

			conn =  new_quic_conn(qpkt->version);
			if (!conn)
				goto err;

			if (!new_quic_cli_conn(conn, l, saddr)) {
				free(conn);
				goto err;
			}

			ipv4 = saddr->ss_family == AF_INET;
			if (!qc_new_conn_init(conn, ipv4, &l->icids, &l->cids,
			                      qpkt->dcid.data, qpkt->dcid.len,
			                      qpkt->scid.data, qpkt->scid.len))
				goto err;

			odcid = &conn->params.original_destination_connection_id;
			/* Copy the transport parameters. */
			conn->params = l->bind_conf->quic_params;
			/* Copy original_destination_connection_id transport parameter. */
			memcpy(odcid->data, &qpkt->dcid, dcid_len);
			odcid->len = dcid_len;
			/* Copy the initial source connection ID. */
			quic_cid_cpy(&conn->params.initial_source_connection_id, &conn->scid);
			conn->enc_params_len =
				quic_transport_params_encode(conn->enc_params,
				                             conn->enc_params + sizeof conn->enc_params,
				                             &conn->params, 1);
			if (!conn->enc_params_len)
				goto err;

			/* This is the DCID sent in this packet by the client. */
			node = &conn->odcid_node;
			conn_ctx = conn->conn->xprt_ctx;
			SSL_set_quic_transport_params(conn_ctx->ssl, conn->enc_params, conn->enc_params_len);
		}
		else {
			if (qpkt->type == QUIC_PACKET_TYPE_INITIAL && cids == &l->icids)
				conn = ebmb_entry(node, struct quic_conn, odcid_node);
			else
				conn = ebmb_entry(node, struct quic_conn, scid_node);
		}

		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;
			struct quic_tls_ctx *ctx = &conn->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;

			if (!quic_dec_int(&token_len, (const unsigned char **)buf, end) || end - *buf < token_len)
				goto err;

			/* XXX TO DO XXX 0 value means "the token is not present".
			 * A server which sends an Initial packet must not set the token.
			 * So, a client which receives an Initial packet with a token
			 * MUST discard the packet or generate a connection error with
			 * PROTOCOL_VIOLATION as type.
			 * The token must be provided in a Retry packet or NEW_TOKEN frame.
			 */
			qpkt->token_len = token_len;
			/*
			 * NOTE: the socket address it concatenated to the destination ID choosen by the client
			 * for Initial packets.
			 */
			if (!ctx->rx.hp && !qc_new_isecs(conn->conn, qpkt->dcid.data,
			                                 qpkt->dcid.len - saddr_len, 1)) {
				QDPRINTF("Could not derive initial secrets\n");
				goto err;
			}
		}
	}
	else {
		/* XXX TO DO: Short header XXX */
		if (end - *buf < QUIC_CID_LEN) {
			QDPRINTF("Too short short headder\n");
			goto err;
		}
		cids = &l->cids;
		node = ebmb_lookup(cids, *buf, QUIC_CID_LEN);
		if (!node) {
			QDPRINTF("Unknonw connection ID\n");
			goto err;
		}
		conn = ebmb_entry(node, struct quic_conn, scid_node);
		*buf += QUIC_CID_LEN;
	}
	/* Store the DCID used for this packet to check the packet which
	 * come in this UDP datagram match with it.
	 */
	if (!*dcid_node)
		*dcid_node = node;
	else if (*dcid_node != node) {
		TRACE_PROTO("Packet dropped", QUIC_EV_CONN_LPKT, conn->conn);
		goto err;
	}
	/*
	 * Only packets packets with long headers and not RETRY or VERSION as type
	 * have a length field.
	 */
	if (long_header && qpkt->type != QUIC_PACKET_TYPE_RETRY && qpkt->version) {
		if (!quic_dec_int(&len, (const unsigned char **)buf, end) || end - *buf < len) {
			QDPRINTF("Could not decode the packet length or "
			         "too short packet (%zu, %zu)\n", len, end - *buf);
			goto err;
		}
		qpkt->len = len;
	}
	else if (!long_header) {
		/* A short packet is the last one of an UDP datagram. */
		qpkt->len = end - *buf;
	}
	QDPRINTF("%s packet length: %zu\n", __func__, qpkt->len);

	/* Update the state if needed. */
	conn_ctx = conn->conn->xprt_ctx;

	if (!qc_try_rm_hp(qpkt, buf, beg, end, conn_ctx))
		goto err;

	if (conn_ctx->state == QUIC_HS_ST_SERVER_INITIAL && qpkt->type == QUIC_PACKET_TYPE_HANDSHAKE)
		conn_ctx->state = QUIC_HS_ST_SERVER_HANDSHAKE;

	/* Wake the tasklet of the QUIC connection packet handler. */
	if (conn_ctx)
		tasklet_wakeup(conn_ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_LPKT, conn->conn, qpkt);

	return qpkt->len;

 err:
	TRACE_DEVEL("Leaving in error", QUIC_EV_CONN_LPKT|QUIC_EV_CONN_ELPKT, conn ? conn->conn : NULL, qpkt);
	QDPRINTF("%s failed\n", __func__);
	return -1;
}

/*
 * This function builds into <buf> buffer a QUIC long packet header whose size may be computed
 * in advance. This is the reponsability of the caller to check there is enough room in this
 * buffer to build a long header.
 * Returns 0 if <type> QUIC packet type is not supported by long header, or 1 if succeeded.
 */
static int quic_build_packet_long_header(unsigned char **buf, const unsigned char *end,
                                         int type, size_t pn_len, struct quic_conn *conn)
{
	if (type > QUIC_PACKET_TYPE_RETRY)
		return 0;

	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | QUIC_PACKET_LONG_HEADER_BIT |
		(type << QUIC_PACKET_TYPE_SHIFT) | (pn_len - 1);
	/* Version */
	quic_write_uint32(buf, end, conn->version);
	*(*buf)++ = conn->dcid.len;
	/* Destination connection ID */
	if (conn->dcid.len) {
		memcpy(*buf, conn->dcid.data, conn->dcid.len);
		*buf += conn->dcid.len;
	}
	/* Source connection ID */
	*(*buf)++ = conn->scid.len;
	if (conn->scid.len) {
		memcpy(*buf, conn->scid.data, conn->scid.len);
		*buf += conn->scid.len;
	}

	return 1;
}

/*
 * This function builds into <buf> buffer a QUIC long packet header whose size may be computed
 * in advance. This is the reponsability of the caller to check there is enough room in this
 * buffer to build a long header.
 * Returns 0 if <type> QUIC packet type is not supported by long header, or 1 if succeeded.
 */
static int quic_build_packet_short_header(unsigned char **buf, const unsigned char *end,
                                          size_t pn_len, struct quic_conn *conn)
{
	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | (pn_len - 1);
	/* Destination connection ID */
	if (conn->dcid.len) {
		memcpy(*buf, conn->dcid.data, conn->dcid.len);
		*buf += conn->dcid.len;
	}

	return 1;
}

/*
 * Apply QUIC header protection to the packet with <buf> as first byte address,
 * <pn> as address of the Packet number field, <pnlen> being this field length
 * with <aead> as AEAD cipher and <key> as secret key.
 * Returns 1 if succeeded or 0 if failed.
 */
static int quic_apply_header_protection(unsigned char *buf, unsigned char *pn, size_t pnlen,
                                        const EVP_CIPHER *aead, const unsigned char *key)
{
	int i, ret, outlen;
	EVP_CIPHER_CTX *ctx;
	/*
	 * We need an IV of at least 5 bytes: one byte for bytes #0
	 * and at most 4 bytes for the packet number
	 */
	unsigned char mask[5] = {0};

	ret = 0;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, aead, NULL, key, pn + QUIC_PACKET_PN_MAXLEN) ||
	    !EVP_EncryptUpdate(ctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_EncryptFinal_ex(ctx, mask, &outlen))
		goto out;

	*buf ^= mask[0] & (*buf & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	for (i = 0; i < pnlen; i++)
		pn[i] ^= mask[i + 1];

	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/*
 * Reduce the encoded size of <ack_frm> ACK frame removing the last
 * ACK ranges if needed to a value below <limit> in bytes.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_ack_frm_reduce_sz(struct quic_frame *ack_frm, size_t limit)
{
	size_t room, ack_delay_sz;

	ack_delay_sz = quic_int_getsize(ack_frm->tx_ack.ack_delay);
	/* A frame is made of 1 byte for the frame type. */
	room = limit - ack_delay_sz - 1;
	if (!quic_rm_last_ack_ranges(ack_frm->tx_ack.ack_ranges, room))
		return 0;

	return 1 + ack_delay_sz + ack_frm->tx_ack.ack_ranges->enc_sz;
}

/*
 * Prepare as most as possible CRYPTO frames from prebuilt CRYPTO frames for <qel>
 * encryption level to be encoded in a buffer with <room> as available room,
 * and <*len> as number of bytes already present in this buffer.
 * Update consequently <*len> to reflect the size of these CRYPTO frames built
 * by this function. Also attach these CRYPTO frames to <pkt> QUIC packet.
 * Return 1 if succeeded, 0 if not.
 */
static inline int qc_build_cfrms(struct quic_tx_packet *pkt,
                                 size_t room, size_t *len, size_t max_cdata_len,
                                 struct quic_enc_level *qel,
                                 struct quic_conn *conn)
{
	struct quic_tx_frm *cf, *cfbak;

	list_for_each_entry_safe(cf, cfbak, &qel->tx.frms, list) {
		/* header length, data length, frame length. */
		size_t hlen, dlen, cflen;

		if (!max_cdata_len)
			break;

		/* Compute the length of this CRYPTO frame header */
		hlen = 1 + quic_int_getsize(cf->crypto.offset);
		/* Compute the data length of this CRyPTO frame. */
		dlen = max_stream_data_size(room, *len + hlen, cf->crypto.len);
		if (!dlen)
			break;

		if (dlen > max_cdata_len)
			dlen = max_cdata_len;
		max_cdata_len -= dlen;
		pkt->cdata_len += dlen;
		/* CRYPTO frame length. */
		cflen = hlen + quic_int_getsize(dlen) + dlen;
		/* Add the CRYPTO data length and its encoded length to the packet
		 * length and the length of this length.
		 */
		*len += cflen;
		if (dlen == cf->crypto.len) {
			/* <cf> CRYPTO data have been consumed. */
			LIST_DEL(&cf->list);
			LIST_ADDQ(&pkt->frms, &cf->list);
		}
		else {
			struct quic_tx_frm *new_cf;

			new_cf = pool_alloc(pool_head_quic_tx_frm);
			if (!new_cf) {
				TRACE_PROTO("No memory for new crypto frame", QUIC_EV_CONN_ECHPKT, conn->conn);
				return 0;
			}

			new_cf->type = QUIC_FT_CRYPTO;
			new_cf->crypto.len = dlen;
			new_cf->crypto.offset = cf->crypto.offset;
			LIST_ADDQ(&pkt->frms, &new_cf->list);
			/* Consume <dlen> bytes of the current frame. */
			cf->crypto.len -= dlen;
			cf->crypto.offset += dlen;
		}
	}

	return 1;
}

/*
 * This function builds a clear handshake packet used during a QUIC TLS handshakes
 * into <wbuf> the current <wbuf> for <conn> QUIC connection with <qel> as QUIC
 * TLS encryption level for outgoing packets filling it with as much as CRYPTO
 * data as possible from <offset> offset in the CRYPTO data stream. Note that
 * this offset value is updated by the length of the CRYPTO frame used to embed
 * the CRYPTO data if this packet and only if the packet is successfully built.
 * The trailing QUIC_TLS_TAG_LEN bytes of this packet are not built. But they are
 * reserved so that to be sure there is enough room to build this AEAD TAG after
 * having successfully returned from this function and to be sure the position
 * pointer of <wbuf> may be safely incremented by QUIC_TLS_TAG_LEN. After having
 * returned from this funciton, <wbuf> position will point one past the last
 * byte of the payload with the confidence there is at least QUIC_TLS_TAG_LEN bytes
 * available packet to encrypt this packet.
 * This function also update the value of <buf_pn> pointer to point to the packet
 * number field in this packet. <pn_len> will also have the packet number
 * length as value.
 *
 * Return the length of the packet if succeeded minus QUIC_TLS_TAG_LEN, or -1 if
 * failed (not enough room in <wbuf> to build this packet plus QUIC_TLS_TAG_LEN
 * bytes), -2 if there are too much CRYPTO data in flight to build a packet.
 */
static ssize_t qc_do_build_hdshk_pkt(struct q_buf *wbuf,
                                     struct quic_tx_packet *pkt, int pkt_type,
                                     int64_t pn, size_t *pn_len,
                                     unsigned char **buf_pn,
                                     struct quic_enc_level *qel,
                                     struct quic_conn *conn)
{
	unsigned char *beg, *pos;
	const unsigned char *end;
	/* This packet type. */
	/* Packet number. */
	/* The Length QUIC packet field value which is the length
	 * of the remaining data after this field after encryption.
	 */
	size_t len, token_fields_len, max_cdata_len, padding_len;
	struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
	struct quic_frame ack_frm = { .type = QUIC_FT_ACK, };
	struct quic_crypto *crypto = &frm.crypto;
	size_t ack_frm_len;
	int64_t largest_acked_pn;

	TRACE_ENTER(QUIC_EV_CONN_CHPKT, conn->conn);
	beg = pos = q_buf_getpos(wbuf);
	end = q_buf_end(wbuf);
	max_cdata_len = QUIC_CRYPTO_IN_FLIGHT_MAX - conn->ifcdata;
	if (!LIST_ISEMPTY(&qel->tx.frms) && !max_cdata_len) {
		TRACE_DEVEL("ifcdada limit reached", QUIC_EV_CONN_CHPKT, conn->conn);
		goto out;
	}

	/* For a server, the token field of an Initial packet is empty. */
	token_fields_len = pkt_type == QUIC_PACKET_TYPE_INITIAL ? 1 : 0;

	/* Check there is enough room to build the header followed by a token. */
	if (end - pos < QUIC_LONG_PACKET_MINLEN + conn->dcid.len +
	    conn->scid.len + token_fields_len + QUIC_TLS_TAG_LEN)
		goto err;

	/* Reserve enough room at the end of the packet for the AEAD TAG. */
	end -= QUIC_TLS_TAG_LEN;
	largest_acked_pn = qel->pktns->tx.largest_acked_pn;
	/* packet number length */
	*pn_len = quic_packet_number_length(pn, largest_acked_pn);

	quic_build_packet_long_header(&pos, end, pkt_type, *pn_len, conn);

	/* Encode the token length (0) for an Initial packet. */
	if (pkt_type == QUIC_PACKET_TYPE_INITIAL)
		*pos++ = 0;

	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	if ((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
	    !LIST_ISEMPTY(&qel->pktns->rx.ack_ranges.list)) {
		ack_frm.tx_ack.ack_delay = 0;
		ack_frm.tx_ack.ack_ranges = &qel->pktns->rx.ack_ranges;
		ack_frm_len = quic_ack_frm_reduce_sz(&ack_frm, end - pos);
		if (!ack_frm_len)
			goto err;

		qel->pktns->flags &= ~QUIC_FL_PKTNS_ACK_REQUIRED;
	}

	/* Length field value without the CRYPTO frames data length. */
	len = ack_frm_len + *pn_len;
	if (!LIST_ISEMPTY(&qel->tx.frms) &&
	    !qc_build_cfrms(pkt, end - pos, &len, max_cdata_len, qel, conn))
		goto err;

	padding_len = 0;
	if (objt_server(conn->conn->target) &&
	    pkt_type == QUIC_PACKET_TYPE_INITIAL &&
	    len < QUIC_INITIAL_PACKET_MINLEN)
		len += padding_len = QUIC_INITIAL_PACKET_MINLEN - len;

	/*
	 * Length (of the remaining data). Must not fail because, the buffer size
	 * has been checked above. Note that we have reserved QUIC_TLS_TAG_LEN bytes
	 * for the encryption TAG. It must be taken into an account for the length
	 * of this packet.
	 */
	quic_enc_int(&pos, end, len + QUIC_TLS_TAG_LEN);

	/* Packet number field address. */
	*buf_pn = pos;

	/* Packet number encoding. */
	quic_packet_number_encode(&pos, end, pn, *pn_len);

	if (ack_frm_len)
		qc_build_frm(&pos, end, &ack_frm, pkt, conn);

	/* Crypto frame */
	if (!LIST_ISEMPTY(&pkt->frms)) {
		struct quic_tx_frm *cf;

		list_for_each_entry(cf, &pkt->frms, list) {
			crypto->offset = cf->crypto.offset;
			crypto->len = cf->crypto.len;
			crypto->qel = qel;
			qc_build_frm(&pos, end, &frm, pkt, conn);
		}
	}

	/* Build a PADDING frame if needed. */
	if (padding_len) {
		frm.type = QUIC_FT_PADDING;
		frm.padding.len = padding_len;
		if (!qc_build_frm(&pos, end, &frm, pkt, conn))
			goto err;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CHPKT, conn->conn, (int *)(pos - beg));
	return pos - beg;

 err:
	TRACE_DEVEL("leaving in error (buffer full)", QUIC_EV_CONN_ECHPKT, conn->conn);
	return -1;
}

static inline void quic_tx_packet_init(struct quic_tx_packet *pkt)
{
	pkt->cdata_len = 0;
	pkt->in_flight_len = 0;
	LIST_INIT(&pkt->frms);
}

static inline void free_quic_tx_packet(struct quic_tx_packet *pkt)
{
	struct quic_tx_frm *frm, *frmbak;

	list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
		pool_free(pool_head_quic_tx_frm, frm);
		LIST_DEL(&frm->list);
	}
	pool_free(pool_head_quic_tx_packet, pkt);
}

/*
 * Build a handshake packet into <buf> packet buffer with <pkt_type> as packet
 * type for <qc> QUIC connection from CRYPTO data stream at <*offset> offset to
 * be encrypted at <qel> encryption level.
 * Return -2 if the packet could not be encrypted for any reason, -1 if there was
 * not enough room in <buf> to build the packet, or the size of the built packet
 * if succeeded (may be zero if there is too much crypto data in flight to build the packet).
 */
static ssize_t qc_build_hdshk_pkt(struct q_buf *buf, struct quic_conn *qc, int pkt_type,
                                  struct quic_enc_level *qel)
{
	/* The pointer to the packet number field. */
	unsigned char *buf_pn;
	unsigned char *beg, *end, *payload;
	int64_t pn;
	size_t pn_len, payload_len, aad_len;
	ssize_t pkt_len;
	struct quic_tls_ctx *tls_ctx;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_HPKT, qc->conn);
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_HPKT, qc->conn);
		return -2;
	}

	quic_tx_packet_init(pkt);
	beg = q_buf_getpos(buf);
	pn_len = 0;
	buf_pn = NULL;
	pn = qel->pktns->tx.next_pn + 1;
	pkt_len = qc_do_build_hdshk_pkt(buf, pkt, pkt_type, pn, &pn_len, &buf_pn, qel, qc);
	if (pkt_len <= 0) {
		free_quic_tx_packet(pkt);
		return pkt_len;
	}

	end = beg + pkt_len;
	payload = buf_pn + pn_len;
	payload_len = end - payload;
	aad_len = payload - beg;

	tls_ctx = &qel->tls_ctx;
	if (!quic_packet_encrypt(payload, payload_len, beg, aad_len, pn, tls_ctx, qc->conn))
		goto err;

	end += QUIC_TLS_TAG_LEN;
	pkt_len += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->tx.hp, tls_ctx->tx.hp_key)) {
		TRACE_DEVEL("Could not apply the header protection", QUIC_EV_CONN_HPKT, qc->conn);
		goto err;
	}

	/*
	 * Now that a correct packet is built, let us set the position pointer of
	 * <buf> buffer for the next packet.
	 */
	q_buf_setpos(buf, end);
	/* Consume a packet number. */
	++qel->pktns->tx.next_pn;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = qel->pktns->tx.next_pn;
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT)
		pkt->in_flight_len = pkt_len;
	pkt->pktns = qel->pktns;
	eb64_insert(&qel->pktns->tx.pkts, &pkt->pn_node);
	/* Increment the number of bytes in <buf> buffer by the length of this packet. */
	buf->data += pkt_len;
	/* Update the counter of the in flight CRYPTO data. */
	qc->ifcdata += pkt->cdata_len;
	/* Attach this packet to <buf>. */
	LIST_ADDQ(&buf->pkts, &pkt->list);
	TRACE_LEAVE(QUIC_EV_CONN_HPKT, qc->conn, pkt);

	return pkt_len;

 err:
	free_quic_tx_packet(pkt);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_HPKT, qc->conn);
	return -2;
}

/*
 * Prepare a clear post handhskake packet for <conn> QUIC connnection.
 * Return the length of this packet if succeeded, -1 <wbuf> was full.
 */
static ssize_t qc_do_build_phdshk_apkt(struct q_buf *wbuf,
                                       struct quic_tx_packet *pkt,
                                       int64_t pn, size_t *pn_len,
                                       unsigned char **buf_pn, struct quic_enc_level *qel,
                                       struct quic_conn *conn)
{
	const unsigned char *beg, *end;
	unsigned char *pos;
	struct quic_frame *frm, *sfrm;
	struct quic_frame ack_frm = { .type = QUIC_FT_ACK, };
	size_t fake_len, max_cdata_len, ack_frm_len;
	int64_t largest_acked_pn;

	TRACE_ENTER(QUIC_EV_CONN_CPAPKT, conn->conn);
	beg = pos = q_buf_getpos(wbuf);
	end = q_buf_end(wbuf);
	max_cdata_len = QUIC_CRYPTO_IN_FLIGHT_MAX - conn->ifcdata;
	if (!LIST_ISEMPTY(&qel->tx.frms) && !max_cdata_len) {
		TRACE_DEVEL("ifcdada limit reached", QUIC_EV_CONN_CPAPKT, conn->conn);
		goto out;
	}
	largest_acked_pn = qel->pktns->tx.largest_acked_pn;
	/* Packet number length */
	*pn_len = quic_packet_number_length(pn, largest_acked_pn);
	/* Check there is enough room to build this packet (without payload). */
	if (end - pos < QUIC_SHORT_PACKET_MINLEN + sizeof_quic_cid(&conn->dcid) +
	    *pn_len + QUIC_TLS_TAG_LEN)
		goto err;

	/* Reserve enough room at the end of the packet for the AEAD TAG. */
	end -= QUIC_TLS_TAG_LEN;
	quic_build_packet_short_header(&pos, end, *pn_len, conn);
	/* Packet number field. */
	*buf_pn = pos;
	/* Packet number encoding. */
	quic_packet_number_encode(&pos, end, pn, *pn_len);

	/* Build an ACK frame if required. */
	ack_frm_len = 0;
	if ((qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
	    !LIST_ISEMPTY(&qel->pktns->rx.ack_ranges.list)) {
		ack_frm.tx_ack.ack_delay = 0;
		ack_frm.tx_ack.ack_ranges = &qel->pktns->rx.ack_ranges;
		ack_frm_len = quic_ack_frm_reduce_sz(&ack_frm, end - pos);
		if (!ack_frm_len)
			goto err;

		qel->pktns->flags &= ~QUIC_FL_PKTNS_ACK_REQUIRED;
	}

	if (ack_frm_len)
		qc_build_frm(&pos, end, &ack_frm, pkt, conn);

	fake_len = ack_frm_len;
	if (!LIST_ISEMPTY(&qel->tx.frms) &&
	    !qc_build_cfrms(pkt, end - pos, &fake_len, max_cdata_len, qel, conn)) {
		TRACE_DEVEL("some CRYPTO frames could not be built",
		            QUIC_EV_CONN_CPAPKT, conn->conn);
		goto err;
	}

	/* Crypto frame */
	if (!LIST_ISEMPTY(&pkt->frms)) {
		struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
		struct quic_crypto *crypto = &frm.crypto;
		struct quic_tx_frm *cf;

		list_for_each_entry(cf, &pkt->frms, list) {
			crypto->offset = cf->crypto.offset;
			crypto->len = cf->crypto.len;
			crypto->qel = qel;
			qc_build_frm(&pos, end, &frm, pkt, conn);
		}
	}

	/* Encode a maximum of frames. */
	list_for_each_entry_safe(frm, sfrm, &conn->tx.frms_to_send, list) {
		unsigned char *ppos;

		ppos = pos;
		if (!qc_build_frm(&ppos, end, frm, pkt, conn)) {
			TRACE_DEVEL("Frames not built", QUIC_EV_CONN_CPAPKT, conn->conn);
			break;
		}

		LIST_DEL(&frm->list);
		LIST_ADDQ(&pkt->frms, &frm->list);
		pos = ppos;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CPAPKT, conn->conn, (int *)(pos - beg));
	return pos - beg;

 err:
	TRACE_DEVEL("leaving in error (buffer full)", QUIC_EV_CONN_CPAPKT, conn->conn);
	return -1;
}

/*
 * Prepare a post handhskake packet at Application encryption level for <conn>
 * QUIC connnection.
 * Return the length of this packet if succeeded, -1 if <wbuf> was full,
 * -2 in case of major error (encryption failure).
 */
static ssize_t qc_build_phdshk_apkt(struct q_buf *wbuf, struct quic_conn *qc)
{
	/* A pointer to the packet number fiel in <buf> */
	unsigned char *buf_pn;
	unsigned char *beg, *end, *payload;
	int64_t pn;
	size_t pn_len, aad_len, payload_len;
	ssize_t pkt_len;
	struct quic_tls_ctx *tls_ctx;
	struct quic_enc_level *qel;
	struct quic_tx_packet *pkt;

	TRACE_ENTER(QUIC_EV_CONN_PAPKT, qc->conn);
	pkt = pool_alloc(pool_head_quic_tx_packet);
	if (!pkt) {
		TRACE_DEVEL("Not enough memory for a new packet", QUIC_EV_CONN_PAPKT, qc->conn);
		return -2;
	}

	quic_tx_packet_init(pkt);
	beg = q_buf_getpos(wbuf);
	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	pn_len = 0;
	buf_pn = NULL;
	pn = qel->pktns->tx.next_pn + 1;
	pkt_len = qc_do_build_phdshk_apkt(wbuf, pkt, pn, &pn_len, &buf_pn, qel, qc);
	if (pkt_len <= 0) {
		QDPRINTF("%s returns %zd\n", __func__, pkt_len);
		free_quic_tx_packet(pkt);
		return pkt_len;
	}

	end = beg + pkt_len;
	payload = buf_pn + pn_len;
	payload_len = end - payload;
	aad_len = payload - beg;

	tls_ctx = &qel->tls_ctx;
	if (!quic_packet_encrypt(payload, payload_len, beg, aad_len, pn, tls_ctx, qc->conn))
		return -2;

	end += QUIC_TLS_TAG_LEN;
	pkt_len += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->tx.hp, tls_ctx->tx.hp_key)) {
		QDPRINTF("%s: could not apply header protection\n", __func__);
		return -2;
	}

	q_buf_setpos(wbuf, end);
	/* Consume a packet number. */
	++qel->pktns->tx.next_pn;
	/* Attach the built packet to its tree. */
	pkt->pn_node.key = qel->pktns->tx.next_pn;
	eb64_insert(&qel->pktns->tx.pkts, &pkt->pn_node);
	/* Set the packet in fligth length for in flight packet only. */
	if (pkt->flags & QUIC_FL_TX_PACKET_IN_FLIGHT)
		pkt->in_flight_len = pkt_len;
	pkt->pktns = qel->pktns;
	/* Increment the number of bytes in <buf> buffer by the length of this packet. */
	wbuf->data += pkt_len;
	/* Attach this packet to <buf>. */
	LIST_ADDQ(&wbuf->pkts, &pkt->list);

	TRACE_LEAVE(QUIC_EV_CONN_PAPKT, qc->conn);

	return pkt_len;
}

/*
 * Prepare a maximum of QUIC Application level packets from <ctx> QUIC
 * connection I/O handler context.
 * Returns 1 if succeeded, 0 if not.
 */
static int qc_prep_phdshk_pkts(struct quic_conn *qc)
{
	struct q_buf *wbuf;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_PAPKTS, qc->conn);
	wbuf = q_wbuf(qc);
	qel = &qc->els[QUIC_TLS_ENC_LEVEL_APP];
	while (q_buf_empty(wbuf)) {
		ssize_t ret;

		if (!(qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) &&
		    (LIST_ISEMPTY(&qel->tx.frms) ||
		     qc->ifcdata >= QUIC_CRYPTO_IN_FLIGHT_MAX)) {
			TRACE_DEVEL("nothing more to do",
			            QUIC_EV_CONN_PAPKTS, qc->conn);
			break;
		}

		ret = qc_build_phdshk_apkt(wbuf, qc);
		switch (ret) {
		case -1:
			/* Not enough room left in <wbuf>. */
			wbuf = q_next_wbuf(qc);
		case -2:
			return 0;
		default:
			/* XXX TO CHECK: consume a buffer. */
			wbuf = q_next_wbuf(qc);
			continue;
		}
	}
	TRACE_LEAVE(QUIC_EV_CONN_PAPKTS, qc->conn);

	return 1;
}

/*
 * Read all the QUIC packets found in <buf> with <len> as length (typically a UDP
 * datagram), <ctx> being the QUIC I/O handler context, from QUIC connections,
 * calling <func> function;
 * Return the number of bytes read if succeded, -1 if not.
 */
static ssize_t quic_packets_read(char *buf, size_t len, void *ctx,
                                 struct sockaddr_storage *saddr, socklen_t *saddrlen,
                                 qpkt_read_func *func)
{
	unsigned char *pos;
	const unsigned char *end;
	struct ebmb_node *dcid_node;

	pos = (unsigned char *)buf;
	end = pos + len;
	dcid_node = NULL;

	do {
		int ret;
		struct quic_rx_packet *qpkt;

		qpkt = pool_alloc(pool_head_quic_rx_packet);
		if (!qpkt) {
			QDPRINTF("Not enough memory to allocate a new packet\n");
			goto err;
		}

		memset(qpkt, 0, sizeof(*qpkt));
		qpkt->refcnt = 1;
		ret = func(&pos, end, qpkt, ctx, &dcid_node, saddr, saddrlen);
		if (ret == -1) {
			free_quic_rx_packet(qpkt);
			goto err;
		}

		QDPRINTF("long header? %d packet type: 0x%02x \n", qc_pkt_long(qpkt), qpkt->type);
	} while (pos < end);

	return pos - (unsigned char *)buf;

 err:
	return -1;
}

/*
 * QUIC I/O handler for connection to local listeners or remove servers
 * depending on <listener> boolean value, with <fd> as socket file
 * descriptor and <ctx> as context.
 */
static size_t quic_conn_handler(int fd, void *ctx, qpkt_read_func *func)
{
	ssize_t ret;
	size_t done = 0;
	struct buffer *buf = get_trash_chunk();
	/* Source address */
	struct sockaddr_storage saddr = {0};
	socklen_t saddrlen = sizeof saddr;

	if (!fd_recv_ready(fd))
		return 0;

	do {
		ret = recvfrom(fd, buf->area, buf->size, 0,
		               (struct sockaddr *)&saddr, &saddrlen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				fd_cant_recv(fd);
			goto out;
		}
	} while (0);

	QDPRINTF("-------------------------------------------"
	         "-----------------\n%s: recvfrom() server (%ld)\n", __func__, ret);

	done = buf->data = ret;
	quic_packets_read(buf->area, buf->data, ctx, &saddr, &saddrlen, func);

 out:
	return done;
}

/*
 * QUIC I/O handler for connections to local listeners with <fd> as socket
 * file descriptor.
 */
void quic_fd_handler(int fd)
{
	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_handler(fd, fdtab[fd].owner, &qc_lstnr_pkt_rcv);
}

/*
 * QUIC I/O handler for connections to remote servers with <fd> as socket
 * file descriptor.
 */
void quic_conn_fd_handler(int fd)
{
	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_handler(fd, fdtab[fd].owner, &qc_srv_pkt_rcv);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
