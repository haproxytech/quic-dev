/*
 * HTTP/3 protocol processing
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
#include <haproxy/dynbuf.h>
#include <haproxy/h3.h>
#include <haproxy/istbuf.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pool.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/tools.h>
#include <haproxy/xprt_quic.h>

#define DEBUG_H3

#if defined(DEBUG_H3)
#define h3_debug_printf fprintf
#define h3_debug_hexdump debug_hexdump
#else
#define h3_debug_printf(...) do { } while (0)
#define h3_debug_hexdump(...) do { } while (0)
#endif

#define H3_CF_SETTINGS_SENT  0x00000001

/* Default settings */
static uint64_t h3_settings_qpack_max_table_capacity = 4096;
static uint64_t h3_settings_qpack_blocked_streams = 100;
static uint64_t h3_settings_max_field_section_size; /* Unlimited */

struct h3_iuqcs {
	/* Underlying incoming QUIC uni-stream */
	struct iuqcs *qcs;
	int (*recv)(struct iuqcs *qcs, void *ctx);
	struct wait_event wait_event;
};

struct h3_ouqcs {
	/* Underlying outgoing QUIC uni-stream */
	struct ouqcs *qcs;
	void (*send)(struct h3_ouqcs *h3_ouqcs, void *ctx);
	struct wait_event wait_event;
};

struct h3 {
	struct qcc *qcc;
	enum h3_err err;
	uint32_t flags;
	/* Locally initiated uni-streams */
	struct h3_ouqcs oqpack_enc;
	struct h3_ouqcs oqpack_dec;
	struct h3_ouqcs octrl;
	/* Remotely initiated uni-streams */
	struct h3_iuqcs iqpack_enc;
	struct h3_iuqcs iqpack_dec;
	struct h3_iuqcs ictrl;
	/* Settings */
	uint64_t qpack_max_table_capacity;
	uint64_t qpack_blocked_streams;
	uint64_t max_field_section_size;
	struct buffer_wait buf_wait; /* wait list for buffer allocations */
};

DECLARE_STATIC_POOL(pool_head_h3, "h3", sizeof(struct h3));

/* Simple function to duplicate a buffer */
static inline struct buffer h3_b_dup(struct buffer *b)
{
	return b_make(b->area, b->size, b->head, b->data);
}

static int ouqcs_buf_available(void *target)
{
	struct h3_ouqcs *h3_ouqcs = target;
	struct ouqcs *qcs = h3_ouqcs->qcs;

	if ((qcs->flags & OUQCS_SF_TXBUF_MALLOC) && b_alloc(&qcs->txbuf)) {
		qcs->flags &= ~OUQCS_SF_TXBUF_MALLOC;
		tasklet_wakeup(h3_ouqcs->wait_event.tasklet);
		return 1;
	}

	return 0;
}

static struct buffer *h3_ouqcs_get_buf(struct h3_ouqcs *h3_ouqcs)
{
	struct buffer *buf = NULL;
	struct h3 *h3 = h3_ouqcs->qcs->qcc->ctx;

	if (likely(!LIST_ADDED(&h3->buf_wait.list)) &&
	    unlikely((buf = b_alloc(&h3_ouqcs->qcs->txbuf)) == NULL)) {
		h3->buf_wait.target = h3_ouqcs;
		h3->buf_wait.wakeup_cb = ouqcs_buf_available;
		LIST_ADDQ(&ti->buffer_wq, &h3->buf_wait.list);
	}

	return buf;
}

/* Decode a h3 frame header made of two QUIC varints from <b> buffer.
 * Returns the number of bytes consumed if there was enough data in <b>, 0 if not.
 * Note that this function update <b> buffer to reflect the number of bytes consumed
 * to decode the h3 frame header.
 */
static inline size_t h3_decode_frm_header(uint64_t *ftype, uint64_t *flen,
                                          struct buffer *b)
{
	size_t ret, hlen;

	hlen = 0;
	if (!b_quic_dec_int(ftype, b, &hlen) || !b_quic_dec_int(flen, b, &hlen))
		return 0;

	return hlen;
}

/* Decode <qcs> remotely initiated bidi-stream */
static int h3_decode_qcs(struct qcs *qcs, void *ctx)
{
	struct buffer *rxbuf = &qcs->rxbuf;
	struct h3 *h3 = ctx;
	uint64_t ftype, flen;

	h3_debug_printf(stderr, "%s: STREAM ID: %llu\n", __func__, qcs->by_id.key);
	if (!b_data(rxbuf))
		return 0;

	while (b_data(rxbuf)) {
		size_t hlen;
		uint64_t ftype, flen;
		struct buffer b;

		/* Work on a copy of <rxbuf> */
		b = h3_b_dup(rxbuf);
		hlen = h3_decode_frm_header(&ftype, &flen, &b);
		if (!hlen)
			break;

		h3_debug_printf(stderr, "%s: ftype: %llu, flen: %llu\n", __func__,
		        (unsigned long long)ftype, (unsigned long long)flen);
		if (flen > b_data(&b))
			break;

		b_del(rxbuf, hlen);
		switch (ftype) {
		case H3_FT_DATA:
			break;
		case H3_FT_HEADERS:
		{
			const unsigned char *buf = b_head(rxbuf);
			size_t len = b_data(rxbuf);
			struct buffer *tmp = get_trash_chunk();

			if (qpack_decode_fs(buf, len, tmp) < 0) {
				h3->err = QPACK_DECOMPRESSION_FAILED;
				return -1;
			}
			break;
		}
		case H3_FT_PUSH_PROMISE:
			/* Not supported */
			break;
		default:
			/* Error */
			h3->err = H3_FRAME_UNEXPECTED;
			return -1;
		}
		b_del(rxbuf, flen);
	}

	return 1;
}

/* Parse a SETTINGS frame which must not be truncated with <flen> as length from
 * <rxbuf> buffer. This function does not update this buffer.
 * Returns 0 if something wrong happened, 1 if not.
 */
static int h3_parse_settings_frm(struct h3 *h3, const struct buffer *rxbuf, size_t flen)
{
	uint64_t id, value;
	const unsigned char *buf, *end;

	buf = (const unsigned char *)b_head(rxbuf);
	end = buf + flen;

	while (buf <= end) {
		if (!quic_dec_int(&id, &buf, end) || !quic_dec_int(&value, &buf, end))
			return 0;

		h3_debug_printf(stderr, "%s id: %llu value: %llu\n", __func__, id, value);
		switch (id) {
		case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			h3->qpack_max_table_capacity = value;
			break;
		case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			h3->max_field_section_size = value;
			break;
		case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
			h3->qpack_blocked_streams = value;
			break;
		case H3_SETTINGS_RESERVED_2 ... H3_SETTINGS_RESERVED_5:
			h3->err = H3_SETTINGS_ERROR;
			return 0;
		default:
			/* MUST be ignored */
			break;
		}
	}

	return 1;
}

/* Decode <qcs> remotely initiated uni-stream. We stop parsing a frame as soon as
 * there is not enough received data.
 * Returns 0 if something wrong happened, 1 if not.
 */
static int h3_control_recv(struct iuqcs *qcs, void *ctx)
{
	struct buffer *rxbuf = &qcs->rxbuf;
	struct h3 *h3 = ctx;
	uint64_t ftype, flen;

	h3_debug_printf(stderr, "%s STREAM ID: %llu\n", __func__,  qcs->by_id.key);
	if (!b_data(rxbuf))
		return 1;

	while (b_data(rxbuf)) {
		size_t hlen;
		uint64_t ftype, flen;
		struct buffer b;

		/* Work on a copy of <rxbuf> */
		b = h3_b_dup(rxbuf);
		hlen = h3_decode_frm_header(&ftype, &flen, &b);
		if (!hlen)
			break;

		h3_debug_printf(stderr, "%s: ftype: %llu, flen: %llu\n", __func__,
		        (unsigned long long)ftype, (unsigned long long)flen);
		if (flen > b_data(&b))
			break;

		b_del(rxbuf, hlen);
		/* From here, a frame must not be truncated */
		switch (ftype) {
		case H3_FT_CANCEL_PUSH:
			break;
		case H3_FT_SETTINGS:
			if (!h3_parse_settings_frm(h3, rxbuf, flen))
				return 0;
			break;
		case H3_FT_GOAWAY:
			break;
		case H3_FT_MAX_PUSH_ID:
			break;
		default:
			/* Error */
			h3->err = H3_FRAME_UNEXPECTED;
			return 0;
		}
		b_del(rxbuf, flen);
	}

	if (b_data(rxbuf))
		h3->qcc->conn->mux->iuqcs_subscribe(qcs, SUB_RETRY_RECV, &h3->ictrl.wait_event);

	return 1;
}

int h3_txbuf_cpy(struct h3_ouqcs *h3_ouqcs, unsigned char *buf, size_t len)
{
	struct buffer *res = &h3_ouqcs->qcs->txbuf;
	struct qcc *qcc = h3_ouqcs->qcs->qcc;
	int ret;

	ret = 0;
	if (!h3_ouqcs_get_buf(h3_ouqcs)) {
		qcc->flags |= OUQCS_SF_TXBUF_MALLOC;
		goto out;
	}

	ret = b_istput(res, ist2((char *)buf, len));
	if (unlikely(!ret))
		qcc->flags |= OUQCS_SF_TXBUF_FULL;

 out:
	return ret;
}

/* Function used to emit stream data from <h3_ouqcs> control uni-stream */
static void h3_control_send(struct h3_ouqcs *h3_ouqcs, void *ctx)
{
	struct h3 *h3 = ctx;
	unsigned char data[(2 + 3) * 2 * QUIC_VARINT_MAX_SIZE]; /* enough for 3 settings */
	unsigned char *pos, *end;

	pos = data;
	end = pos + sizeof data;
	if (!(h3->flags & H3_CF_SETTINGS_SENT)) {
		int ret;
		struct ouqcs *qcs = h3_ouqcs->qcs;
		size_t frm_len;

		frm_len = quic_int_getsize(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY) +
			quic_int_getsize(h3_settings_qpack_max_table_capacity) +
			quic_int_getsize(H3_SETTINGS_QPACK_BLOCKED_STREAMS) +
			quic_int_getsize(h3_settings_qpack_blocked_streams);
		if (h3_settings_max_field_section_size) {
			quic_int_getsize(H3_SETTINGS_MAX_FIELD_SECTION_SIZE) +
			quic_int_getsize(h3_settings_max_field_section_size);
		}

		/* Build a SETTINGS frame */
		quic_enc_int(&pos, end, H3_FT_SETTINGS);
		quic_enc_int(&pos, end, frm_len);
		quic_enc_int(&pos, end, H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
		quic_enc_int(&pos, end, h3_settings_qpack_max_table_capacity);
		quic_enc_int(&pos, end, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
		quic_enc_int(&pos, end, h3_settings_qpack_blocked_streams);
		if (h3_settings_max_field_section_size) {
			quic_enc_int(&pos, end, H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
			quic_enc_int(&pos, end, h3_settings_max_field_section_size);
		}
		ret = h3_txbuf_cpy(h3_ouqcs, data, pos - data);
		if (ret < 0) {
			qc_error(qcs->qcc, H3_INTERNAL_ERROR);
			return;
		}

		if (ret > 0) {
			h3->flags |= H3_CF_SETTINGS_SENT;
			ouqcs_snd_buf(h3_ouqcs->qcs, &qcs->txbuf, b_data(&qcs->txbuf), 0);
		}
		if (b_data(&qcs->txbuf))
			qcs->qcc->conn->mux->ouqcs_subscribe(qcs, SUB_RETRY_SEND, &h3->octrl.wait_event);
	}

}

/* Finalize the initialization of remotely initiated uni-stream <qcs>.
 * Return 1 if succeeded, 0 if not. In this latter case, set the ->err h3 error
 * to inform the QUIC mux layer of the encountered error.
 */
static int h3_attach_iuqcs(struct iuqcs *qcs, void *ctx)
{
	uint64_t strm_type;
	struct h3 *h3 = ctx;
	struct buffer *rxbuf = &qcs->rxbuf;

	/* First octets: the uni-stream type */
	if (!b_quic_dec_int(&strm_type, rxbuf, NULL) || strm_type > H3_UNI_STRM_TP_MAX)
		return 0;

	/* Note that for all the uni-streams below, this is an error to receive two times the
	 * same type of uni-stream (even for Push stream which is not supported at this time.
	 */
	qcs->type = strm_type;
	switch (strm_type) {
	case H3_UNI_STRM_TP_CONTROL_STREAM:
		if (h3->ictrl.qcs) {
			h3->err = H3_STREAM_CREATION_ERROR;
			return 0;
		}

		h3->ictrl.qcs = qcs;
		h3->ictrl.recv = h3_control_recv;
		h3->qcc->conn->mux->iuqcs_subscribe(qcs, SUB_RETRY_RECV, &h3->ictrl.wait_event);
		break;
	case H3_UNI_STRM_TP_PUSH_STREAM:
		/* NOT SUPPORTED */
		break;
	case H3_UNI_STRM_TP_QPACK_ENCODER:
		if (h3->iqpack_enc.qcs) {
			h3->err = H3_STREAM_CREATION_ERROR;
			return 0;
		}

		h3->iqpack_enc.qcs = qcs;
		h3->iqpack_enc.recv = qpack_decode_enc;
		h3->qcc->conn->mux->iuqcs_subscribe(qcs, SUB_RETRY_RECV, &h3->iqpack_enc.wait_event);
		break;
	case H3_UNI_STRM_TP_QPACK_DECODER:
		if (h3->iqpack_dec.qcs) {
			h3->err = H3_STREAM_CREATION_ERROR;
			return 0;
		}

		h3->iqpack_dec.qcs = qcs;
		h3->iqpack_dec.recv = qpack_decode_dec;
		h3->qcc->conn->mux->iuqcs_subscribe(qcs, SUB_RETRY_RECV, &h3->iqpack_dec.wait_event);
		break;
	default:
		/* Error */
		h3->err = H3_STREAM_CREATION_ERROR;
		return 0;
	}

	return 1;
}

static int h3_finalize(void *ctx)
{
	struct h3 *h3 = ctx;

	h3->octrl.qcs = ouqcs_new(h3->qcc);
	if (!h3->octrl.qcs)
		return 0;

	/* Wakeup ->octrl uni-stream */
	tasklet_wakeup(h3->octrl.wait_event.tasklet);

	return 1;
}

/* Tasklet dedicated to h3 incoming uni-streams */
static struct task *h3_iuqcs_recv(struct task *t, void *ctx, unsigned int state)
{
	struct h3_iuqcs *h3_iuqcs = ctx;
	struct h3 *h3 = h3_iuqcs->qcs->qcc->ctx;

	h3_iuqcs->recv(h3_iuqcs->qcs, h3);
	return NULL;
}

/* Initialiaze <h3_iuqcs> uni-stream with <t> as tasklet */
static int h3_iuqcs_init(struct h3_iuqcs *h3_iuqcs,
                         struct task *(*t)(struct task *, void *, unsigned int))
{
	h3_iuqcs->qcs = NULL;
	h3_iuqcs->recv = NULL;
	h3_iuqcs->wait_event.tasklet = tasklet_new();
	if (!h3_iuqcs->wait_event.tasklet)
		return 0;

	h3_iuqcs->wait_event.tasklet->process = t;
	h3_iuqcs->wait_event.tasklet->context = h3_iuqcs;
	return 1;
}

/* Release all the tasklet attached to <h3_iuqcs> uni-stream */
static inline void h3_iuqcs_tasklet_release(struct h3_iuqcs *h3_iuqcs)
{
	struct tasklet *t = h3_iuqcs->wait_event.tasklet;

	tasklet_free(t);
}

/* Release all the tasklet attached to <h3> uni-streams */
static void h3_iuqcs_tasklets_release(struct h3 *h3)
{
	h3_iuqcs_tasklet_release(&h3->iqpack_enc);
	h3_iuqcs_tasklet_release(&h3->iqpack_dec);
	h3_iuqcs_tasklet_release(&h3->ictrl);
}

/* Tasklet dedicated to h3 outgoing uni-streams */
static struct task *h3_ouqcs_send_task(struct task *t, void *ctx, unsigned int state)
{
	struct h3_ouqcs *h3_ouqcs = ctx;
	struct h3 *h3 = h3_ouqcs->qcs->qcc->ctx;

	h3_ouqcs->send(h3_ouqcs, h3);
	return NULL;
}

/* Initialiaze <h3_ouqcs> uni-stream with <t> as tasklet */
static int h3_ouqcs_init(struct h3_ouqcs *h3_ouqcs, struct h3 *h3,
                         void (*send)(struct h3_ouqcs *h3_ouqcs, void *ctx),
                         struct task *(*t)(struct task *, void *, unsigned int))
{
	h3_ouqcs->qcs = NULL;
	h3_ouqcs->send = send;
	h3_ouqcs->wait_event.tasklet = tasklet_new();
	if (!h3_ouqcs->wait_event.tasklet)
		return 0;

	h3_ouqcs->wait_event.tasklet->process = t;
	h3_ouqcs->wait_event.tasklet->context = h3_ouqcs;
	return 1;

 err:
	tasklet_free(h3_ouqcs->wait_event.tasklet);
	return 0;
}

/* Release all the tasklet attached to <h3_ouqcs> uni-stream */
static inline void h3_ouqcs_tasklet_release(struct h3_ouqcs *h3_ouqcs)
{
	struct tasklet *t = h3_ouqcs->wait_event.tasklet;

	if (t)
		tasklet_free(t);
}

static inline void h3_ouqcs_qcs_release(struct h3_ouqcs *h3_ouqcs)
{
	if (h3_ouqcs->qcs)
		ouqcs_release(h3_ouqcs->qcs);
}

static inline void h3_ouqcs_qcs_release_all(struct h3 *h3)
{
	h3_ouqcs_tasklet_release(&h3->octrl);
	h3_ouqcs_qcs_release(&h3->octrl);
	h3_ouqcs_tasklet_release(&h3->oqpack_enc);
	h3_ouqcs_qcs_release(&h3->oqpack_enc);
	h3_ouqcs_tasklet_release(&h3->oqpack_dec);
	h3_ouqcs_qcs_release(&h3->oqpack_dec);
}

/* Initialize the HTTP/3 context for <qcc> mux.
 * Return 1 if succeeded, 0 if not.
 */
static int h3_init(struct qcc *qcc)
{
	struct h3 *h3;

	h3 = pool_alloc(pool_head_h3);
	if (!h3)
		goto fail_no_h3;

	h3->qcc = qcc;
	h3->err = H3_NO_ERROR;
	h3->flags = 0;

	if (!h3_iuqcs_init(&h3->iqpack_enc, h3_iuqcs_recv) ||
	    !h3_iuqcs_init(&h3->iqpack_dec, h3_iuqcs_recv) ||
	    !h3_iuqcs_init(&h3->ictrl, h3_iuqcs_recv))
		goto fail_no_h3_iuqcs;

	if (!h3_ouqcs_init(&h3->octrl, h3, h3_control_send, h3_ouqcs_send_task) ||
	    !h3_ouqcs_init(&h3->oqpack_enc, h3, NULL, h3_ouqcs_send_task) ||
	    !h3_ouqcs_init(&h3->oqpack_dec, h3, NULL, h3_ouqcs_send_task))
		goto fail_no_h3_ouqcs;

	qcc->ctx = h3;
	LIST_INIT(&h3->buf_wait.list);

	return 1;

 fail_no_h3_ouqcs:
	h3_ouqcs_qcs_release_all(h3);
 fail_no_h3_iuqcs:
	h3_iuqcs_tasklets_release(h3);
	pool_free(pool_head_h3, h3);
 fail_no_h3:
	return 0;
}

/* HTTP/3 application layer operations */
const struct qcc_app_ops h3_ops = {
	.init         = h3_init,
	.attach_iuqcs = h3_attach_iuqcs,
	.decode_qcs   = h3_decode_qcs,
	.finalize     = h3_finalize,
};
