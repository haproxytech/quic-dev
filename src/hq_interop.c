#include <haproxy/hq_interop.h>

#include <import/ist.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/htx.h>
#include <haproxy/http.h>
#include <haproxy/mux_quic.h>

static ssize_t hq_interop_recv(struct qcs *qcs, struct buffer *b, int fin)
{
	struct htx *htx;
	struct htx_sl *sl;
	struct stconn *sc;
	struct buffer htx_buf = BUF_NULL;
	struct ist path;
	char *ptr = b_head(b);
	char *end = b_wrap(b);
	size_t size = b_size(b);
	size_t data = b_data(b);

	b_alloc(&htx_buf);
	htx = htx_from_buf(&htx_buf);

	/* skip method */
	while (data && HTTP_IS_TOKEN(*ptr)) {
		if (++ptr == end)
			ptr -= size;
		data--;
	}

	if (!data || !HTTP_IS_SPHT(*ptr)) {
		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	if (++ptr == end)
		ptr -= size;

	if (!--data) {
		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	/* extract path */
	BUG_ON(HTTP_IS_LWS(*ptr));
	path.ptr = ptr;
	while (data && !HTTP_IS_LWS(*ptr)) {
		if (++ptr == end)
			ptr -= size;
		data--;
	}

	if (!data) {
		fprintf(stderr, "truncated stream\n");
		return 0;
	}

	BUG_ON(!HTTP_IS_LWS(*ptr));
	path.len = ptr - path.ptr;

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, 0, ist("GET"), path, ist("HTTP/1.0"));
	if (!sl)
		return -1;

	sl->flags |= HTX_SL_F_BODYLESS;
	sl->info.req.meth = find_http_meth("GET", 3);

	htx_add_endof(htx, HTX_BLK_EOH);
	htx_to_buf(htx, &htx_buf);

	sc = qc_attach_sc(qcs, &htx_buf);
	if (!sc)
		return -1;

	b_free(&htx_buf);

	if (fin)
		htx->flags |= HTX_FL_EOM;

	return b_data(b);
}

static struct buffer *mux_get_buf(struct qcs *qcs)
{
	if (!b_size(&qcs->tx.buf))
		b_alloc(&qcs->tx.buf);

	return &qcs->tx.buf;
}

static size_t hq_interop_send(struct qcs *qcs, struct buffer *buf,
                              size_t count, int flags)
{
	struct htx *htx;
	enum htx_blk_type btype;
	struct htx_blk *blk;
	int32_t idx;
	uint32_t bsize, fsize;
	struct buffer *res, outbuf;
	size_t total = 0;

	htx = htx_from_buf(buf);
	res = mux_get_buf(qcs);
	outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);

	while (count && !htx_is_empty(htx) && !(qcs->flags & QC_SF_BLK_MROOM)) {
		/* Not implemented : QUIC on backend side */
		idx = htx_get_head(htx);
		blk = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		fsize = bsize = htx_get_blksz(blk);

		BUG_ON(btype == HTX_BLK_REQ_SL);

		switch (btype) {
		case HTX_BLK_DATA:
			if (fsize > count)
				fsize = count;

			if (b_room(&outbuf) < fsize)
				fsize = b_room(&outbuf);

			if (!fsize) {
				qcs->flags |= QC_SF_BLK_MROOM;
				goto end;
			}

			b_putblk(&outbuf, htx_get_blk_ptr(htx, blk), fsize);
			total += fsize;
			count -= fsize;

			if (fsize == bsize)
				htx_remove_blk(htx, blk);
			else
				htx_cut_data_blk(htx, blk, fsize);
			break;

		/* only body is transferred on HTTP/0.9 */
		case HTX_BLK_RES_SL:
		case HTX_BLK_TLR:
		case HTX_BLK_EOT:
		default:
			htx_remove_blk(htx, blk);
			total += bsize;
			count -= bsize;
			break;
		}
	}

 end:
	if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx))
		qcs->flags |= QC_SF_FIN_STREAM;

	b_add(res, b_data(&outbuf));

	if (total) {
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	return total;
}

static int hq_interop_attach(struct qcs *qcs, void *conn_ctx)
{
	qcs_wait_http_req(qcs);
	return 0;
}

const struct qcc_app_ops hq_interop_ops = {
	.attach = hq_interop_attach,
	.recv   = hq_interop_recv,
	.send   = hq_interop_send,
};
