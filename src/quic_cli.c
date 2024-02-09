#include <import/eb64tree.h>

#include <haproxy/applet-t.h>
#include <haproxy/cli.h>
#include <haproxy/list.h>
#include <haproxy/tools.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_tp.h>

/* incremented by each "show quic". */
unsigned int qc_epoch = 0;

enum quic_dump_format {
	QUIC_DUMP_FMT_ONELINE,
	QUIC_DUMP_FMT_FULL,
};

/* appctx context used by "show quic" command */
struct show_quic_ctx {
	unsigned int epoch;
	struct bref bref; /* back-reference to the quic-conn being dumped */
	unsigned int thr;
	int flags;
	enum quic_dump_format format;
};

#define QC_CLI_FL_SHOW_ALL 0x1 /* show closing/draining connections */

static int cli_parse_show_quic(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_quic_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int argc = 2;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	ctx->epoch = _HA_ATOMIC_FETCH_ADD(&qc_epoch, 1);
	ctx->thr = 0;
	ctx->flags = 0;
	ctx->format = QUIC_DUMP_FMT_ONELINE;

	if (strcmp(args[argc], "oneline") == 0) {
		/* format already used as default value */
		++argc;
	}
	else if (strcmp(args[argc], "full") == 0) {
		ctx->format = QUIC_DUMP_FMT_FULL;
		++argc;
	}

	while (*args[argc]) {
		if (strcmp(args[argc], "all") == 0)
			ctx->flags |= QC_CLI_FL_SHOW_ALL;

		++argc;
	}

	LIST_INIT(&ctx->bref.users);

	return 0;
}

/* Dump for "show quic" with "oneline" format. */
static void dump_quic_oneline(struct show_quic_ctx *ctx, struct quic_conn *qc)
{
	char bufaddr[INET6_ADDRSTRLEN], bufport[6];
	int ret;
	unsigned char cid_len;

	ret = chunk_appendf(&trash, "%p[%02u]/%-.12s ", qc, ctx->thr,
	                    qc->li->bind_conf->frontend->id);
	chunk_appendf(&trash, "%*s", 36 - ret, " "); /* align output */

	/* State */
	if (qc->flags & QUIC_FL_CONN_CLOSING)
		chunk_appendf(&trash, "CLOSE   ");
	else if (qc->flags & QUIC_FL_CONN_DRAINING)
		chunk_appendf(&trash, "DRAIN   ");
	else if (qc->state < QUIC_HS_ST_COMPLETE)
		chunk_appendf(&trash, "HDSHK   ");
	else
		chunk_appendf(&trash, "ESTAB   ");

	/* Bytes in flight / Lost packets */
	chunk_appendf(&trash, "%9llu %6llu %6llu   ",
	              (ullong)qc->path->in_flight,
	              (ullong)qc->path->ifae_pkts,
	              (ullong)qc->path->loss.nb_lost_pkt);

	/* Socket */
	if (qc->local_addr.ss_family == AF_INET ||
	    qc->local_addr.ss_family == AF_INET6) {
		addr_to_str(&qc->local_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->local_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, "%15s:%-5s   ", bufaddr, bufport);

		addr_to_str(&qc->peer_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->peer_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, "%15s:%-5s ", bufaddr, bufport);

	}

	/* CIDs */
	for (cid_len = 0; cid_len < qc->scid.len; ++cid_len)
		chunk_appendf(&trash, "%02x", qc->scid.data[cid_len]);

	chunk_appendf(&trash, " ");
	for (cid_len = 0; cid_len < qc->dcid.len; ++cid_len)
		chunk_appendf(&trash, "%02x", qc->dcid.data[cid_len]);

	chunk_appendf(&trash, "\n");
}

/* Dump for "show quic" with "full" format. */
static void dump_quic_full(struct show_quic_ctx *ctx, struct quic_conn *qc)
{
	struct quic_pktns *pktns;
	struct eb64_node *node;
	struct qc_stream_desc *stream;
	char bufaddr[INET6_ADDRSTRLEN], bufport[6];
	int expire, i, addnl;
	unsigned char cid_len;

	addnl = 0;
	/* CIDs */
	chunk_appendf(&trash, "* %p[%02u]: scid=", qc, ctx->thr);
	for (cid_len = 0; cid_len < qc->scid.len; ++cid_len)
		chunk_appendf(&trash, "%02x", qc->scid.data[cid_len]);
	while (cid_len++ < 20)
		chunk_appendf(&trash, "..");

	chunk_appendf(&trash, " dcid=");
	for (cid_len = 0; cid_len < qc->dcid.len; ++cid_len)
		chunk_appendf(&trash, "%02x", qc->dcid.data[cid_len]);
	while (cid_len++ < 20)
		chunk_appendf(&trash, "..");

	chunk_appendf(&trash, "\n");

	chunk_appendf(&trash, "  loc. TPs:");
	quic_transport_params_dump(&trash, qc, &qc->rx.params);
	chunk_appendf(&trash, "\n");
	chunk_appendf(&trash, "  rem. TPs:");
	quic_transport_params_dump(&trash, qc, &qc->tx.params);
	chunk_appendf(&trash, "\n");

	/* Connection state */
	if (qc->flags & QUIC_FL_CONN_CLOSING)
		chunk_appendf(&trash, "  st=closing          ");
	else if (qc->flags & QUIC_FL_CONN_DRAINING)
		chunk_appendf(&trash, "  st=draining         ");
	else if (qc->state < QUIC_HS_ST_CONFIRMED)
		chunk_appendf(&trash, "  st=handshake        ");
	else
		chunk_appendf(&trash, "  st=opened           ");

	if (qc->mux_state == QC_MUX_NULL)
		chunk_appendf(&trash, "mux=null                                      ");
	else if (qc->mux_state == QC_MUX_READY)
		chunk_appendf(&trash, "mux=ready                                     ");
	else
		chunk_appendf(&trash, "mux=released                                  ");

	if (qc->idle_timer_task) {
		expire = qc->idle_timer_task->expire;
		chunk_appendf(&trash, "expire=%02ds ",
		              TICKS_TO_MS(tick_remain(now_ms, expire)) / 1000);
	}

	chunk_appendf(&trash, "\n");

	/* Socket */
	chunk_appendf(&trash, "  fd=%d", qc->fd);
	if (qc->local_addr.ss_family == AF_INET ||
	    qc->local_addr.ss_family == AF_INET6) {
		addr_to_str(&qc->local_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->local_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, "               local_addr=%s:%s", bufaddr, bufport);

		addr_to_str(&qc->peer_addr, bufaddr, sizeof(bufaddr));
		port_to_str(&qc->peer_addr, bufport, sizeof(bufport));
		chunk_appendf(&trash, " foreign_addr=%s:%s", bufaddr, bufport);
	}

	chunk_appendf(&trash, "\n");

	/* Packet number spaces information */
	pktns = qc->ipktns;
	if (pktns) {
		chunk_appendf(&trash, "  [initl]             rx.ackrng=%-6zu tx.inflight=%-6zu",
		              pktns->rx.arngs.sz, pktns->tx.in_flight);
	}

	pktns = qc->hpktns;
	if (pktns) {
		chunk_appendf(&trash, "           [hndshk] rx.ackrng=%-6zu tx.inflight=%-6zu\n",
		              pktns->rx.arngs.sz, pktns->tx.in_flight);
	}

	pktns = qc->apktns;
	if (pktns) {
		chunk_appendf(&trash, "  [01rtt]             rx.ackrng=%-6zu tx.inflight=%-6zu\n",
		              pktns->rx.arngs.sz, pktns->tx.in_flight);
	}

	chunk_appendf(&trash, "  srtt=%-4u rttvar=%-4u rttmin=%-4u ptoc=%-4u cwnd=%-6llu"
	                      " mcwnd=%-6llu sentpkts=%-6llu lostpkts=%-6llu pkt/srtt=%-6llu\n",
	              qc->path->loss.srtt, qc->path->loss.rtt_var,
	              qc->path->loss.rtt_min, qc->path->loss.pto_count, (ullong)qc->path->cwnd,
	              (ullong)qc->path->mcwnd, (ullong)qc->cntrs.sent_pkt, (ullong)qc->path->loss.nb_lost_pkt, (ullong)(qc->ma_rate.rate * 1000 ) / (qc->path->loss.srtt * QUIC_MOVING_AVERAGE_RATE_SAMPLE));

	if (qc->cntrs.dropped_pkt) {
		chunk_appendf(&trash, " droppkts=%-6llu", qc->cntrs.dropped_pkt);
		addnl = 1;
	}
	if (qc->cntrs.dropped_pkt_bufoverrun) {
		chunk_appendf(&trash, " dropbuff=%-6llu", qc->cntrs.dropped_pkt_bufoverrun);
		addnl = 1;
	}
	if (qc->cntrs.dropped_parsing) {
		chunk_appendf(&trash, " droppars=%-6llu", qc->cntrs.dropped_parsing);
		addnl = 1;
	}
	if (qc->cntrs.socket_full) {
		chunk_appendf(&trash, " sockfull=%-6llu", qc->cntrs.socket_full);
		addnl = 1;
	}
	if (qc->cntrs.sendto_err) {
		chunk_appendf(&trash, " sendtoerr=%-6llu", qc->cntrs.sendto_err);
		addnl = 1;
	}
	if (qc->cntrs.sendto_err_unknown) {
		chunk_appendf(&trash, " sendtounknerr=%-6llu", qc->cntrs.sendto_err);
		addnl = 1;
	}
	if (qc->cntrs.conn_migration_done) {
		chunk_appendf(&trash, " migrdone=%-6llu", qc->cntrs.conn_migration_done);
		addnl = 1;
	}
	if (qc->cntrs.data_blocked) {
		chunk_appendf(&trash, " datablocked=%-6llu", qc->cntrs.data_blocked);
		addnl = 1;
	}
	if (qc->cntrs.stream_data_blocked) {
		chunk_appendf(&trash, " sdatablocked=%-6llu", qc->cntrs.stream_data_blocked);
		addnl = 1;
	}
	if (qc->cntrs.streams_blocked_bidi) {
		chunk_appendf(&trash, " sblockebidi=%-6llu", qc->cntrs.streams_blocked_bidi);
		addnl = 1;
	}
	if (qc->cntrs.streams_blocked_uni) {
		chunk_appendf(&trash, " sblockeduni=%-6llu", qc->cntrs.streams_blocked_uni);
		addnl = 1;
	}
	if (addnl)
		chunk_appendf(&trash, "\n");

	/* Streams */
	node = eb64_first(&qc->streams_by_id);
	i = 0;
	while (node) {
		stream = eb64_entry(node, struct qc_stream_desc, by_id);
		node = eb64_next(node);

		chunk_appendf(&trash, "  | stream=%-8llu", (unsigned long long)stream->by_id.key);
		chunk_appendf(&trash, " off=%-8llu ack=%-8llu",
		              (unsigned long long)stream->buf_offset,
		              (unsigned long long)stream->ack_offset);

		if (!(++i % 3)) {
			chunk_appendf(&trash, "\n");
			i = 0;
		}
	}

	chunk_appendf(&trash, "\n");
}

static int cli_io_handler_dump_quic(struct appctx *appctx)
{
	struct show_quic_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct quic_conn *qc;

	thread_isolate();

	if (ctx->thr >= global.nbthread)
		goto done;

	/* FIXME: Don't watch the other side !*/
	if (unlikely(sc_opposite(sc)->flags & SC_FL_SHUT_DONE)) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last stream being dumped.
		 */
		if (!LIST_ISEMPTY(&ctx->bref.users))
			LIST_DEL_INIT(&ctx->bref.users);
		goto done;
	}

	chunk_reset(&trash);

	if (!LIST_ISEMPTY(&ctx->bref.users)) {
		/* Remove show_quic_ctx from previous quic_conn instance. */
		LIST_DEL_INIT(&ctx->bref.users);
	}
	else if (!ctx->bref.ref) {
		/* First invocation. */
		ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns.n;

		/* Print legend for oneline format. */
		if (ctx->format == QUIC_DUMP_FMT_ONELINE) {
			chunk_appendf(&trash, "# conn/frontend                     state   "
				      "in_flight infl_p lost_p         "
				      "Local Address           Foreign Address      "
				      "local & remote CIDs\n");
			applet_putchk(appctx, &trash);
		}
	}

	while (1) {
		int done = 0;

		if (ctx->bref.ref == &ha_thread_ctx[ctx->thr].quic_conns) {
			/* If closing connections requested through "all", move
			 * to quic_conns_clo list after browsing quic_conns.
			 * Else move directly to the next quic_conns thread.
			 */
			if (ctx->flags & QC_CLI_FL_SHOW_ALL) {
				ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns_clo.n;
				continue;
			}

			done = 1;
		}
		else if (ctx->bref.ref == &ha_thread_ctx[ctx->thr].quic_conns_clo) {
			/* Closing list entirely browsed, go to next quic_conns
			 * thread.
			 */
			done = 1;
		}
		else {
			/* Retrieve next element of the current list. */
			qc = LIST_ELEM(ctx->bref.ref, struct quic_conn *, el_th_ctx);
			if ((int)(qc->qc_epoch - ctx->epoch) > 0)
				done = 1;
		}

		if (done) {
			++ctx->thr;
			if (ctx->thr >= global.nbthread)
				break;
			/* Switch to next thread quic_conns list. */
			ctx->bref.ref = ha_thread_ctx[ctx->thr].quic_conns.n;
			continue;
		}

		switch (ctx->format) {
		case QUIC_DUMP_FMT_FULL:
			dump_quic_full(ctx, qc);
			break;
		case QUIC_DUMP_FMT_ONELINE:
			dump_quic_oneline(ctx, qc);
			break;
		}

		if (applet_putchk(appctx, &trash) == -1) {
			/* Register show_quic_ctx to quic_conn instance. */
			LIST_APPEND(&qc->back_refs, &ctx->bref.users);
			goto full;
		}

		ctx->bref.ref = qc->el_th_ctx.n;
	}

 done:
	thread_release();
	return 1;

 full:
	thread_release();
	return 0;
}

static void cli_release_show_quic(struct appctx *appctx)
{
	struct show_quic_ctx *ctx = appctx->svcctx;

	if (ctx->thr < global.nbthread) {
		thread_isolate();
		if (!LIST_ISEMPTY(&ctx->bref.users))
			LIST_DEL_INIT(&ctx->bref.users);
		thread_release();
	}
}

static struct cli_kw_list cli_kws = {{ }, {
	{ { "show", "quic", NULL }, "show quic [oneline|full] [all]          : display quic connections status", cli_parse_show_quic, cli_io_handler_dump_quic, cli_release_show_quic },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static void cli_quic_init()
{
	int thr;

	for (thr = 0; thr < MAX_THREADS; ++thr) {
		LIST_INIT(&ha_thread_ctx[thr].quic_conns);
		LIST_INIT(&ha_thread_ctx[thr].quic_conns_clo);
	}
}
INITCALL0(STG_INIT, cli_quic_init);
