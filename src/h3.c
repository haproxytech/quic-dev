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
#include <haproxy/h3.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pool.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/tools.h>
#include <haproxy/xprt_quic.h>

#define DEBUG_H3

#if defined(DEBUG_H3)
#define h3_debug_printf printf
#define h3_debug_hexdump debug_hexdump
#else
#define h3_debug_printf(...) do { } while (0)
#define h3_debug_hexdump(...) do { } while (0)
#endif

struct h3 {
	enum h3_err err;
	struct iuqcs *qpack_dec_qcs;
	struct iuqcs *control;
};

DECLARE_STATIC_POOL(pool_head_h3, "h3", sizeof(struct h3));

static int h3_set_iuqcs(struct h3 *h3, struct iuqcs *iuqcs);

/* Decode <qcs> remotely initiated uni-stream.
 * Return 1 if succeded, 0 if not. Note that this function fails
 * only if this stream has just been opened (->rx.offset == 0)
 * and if we could not retrieve its type.
 */
static int h3_decode_iuqcs(struct iuqcs *qcs, void *ctx)
{
	struct h3 *h3 = ctx;

	if (!qcs->rx.offset && !h3_set_iuqcs(h3, qcs))
		return 0;

	if (qcs->decode)
		qcs->decode(qcs, ctx);

	return 1;
}

/* Decode <qcs> remotely initiated bidi-stream */
static int h3_decode_qcs(struct qcs *qcs, void *ctx)
{
	struct buffer *rxbuf = &qcs->rxbuf;
	struct h3 *h3 = ctx;
	uint64_t h3_ftype, h3_flen;

	fprintf(stderr, "STREAM ID: %llu\n", qcs->by_id.key);
	if (!b_data(rxbuf))
		return 0;

	while (b_data(rxbuf)) {
		if (!b_quic_dec_int(&h3_ftype, rxbuf) ||
		    !b_quic_dec_int(&h3_flen, rxbuf))
			return 0;

		fprintf(stderr, "%s: h3_ftype: %llu, h3_flen: %llu\n", __func__,
		        (unsigned long long)h3_ftype, (unsigned long long)h3_flen);
		if (h3_flen > b_data(rxbuf))
			return 0;

		switch (h3_ftype) {
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
			break;
		default:
			/* Error */
			h3->err = H3_FRAME_UNEXPECTED;
			return -1;
		}
		b_del(rxbuf, h3_flen);
	}

	return 1;
}

/* Decode <qcs> remotely initiated bidi-stream */
static int h3_control_decode(struct iuqcs *qcs, void *ctx)
{
	struct buffer *rxbuf = &qcs->rxbuf;
	struct h3 *h3 = ctx;
	uint64_t h3_ftype, h3_flen;

	fprintf(stderr, "STREAM ID: %llu\n", qcs->by_id.key);
	if (!b_data(rxbuf))
		return 0;

	while (b_data(rxbuf)) {
		if (!b_quic_dec_int(&h3_ftype, rxbuf) ||
		    !b_quic_dec_int(&h3_flen, rxbuf))
			return 0;

		fprintf(stderr, "%s: h3_ftype: %llu, h3_flen: %llu\n", __func__,
		        (unsigned long long)h3_ftype, (unsigned long long)h3_flen);
		if (h3_flen > b_data(rxbuf))
			return 0;

		switch (h3_ftype) {
		case H3_FT_CANCEL_PUSH:
			break;
		case H3_FT_SETTINGS:
			break;
		case H3_FT_GOAWAY:
			break;
		case H3_FT_MAX_PUSH_ID:
			break;
		default:
			/* Error */
			h3->err = H3_FRAME_UNEXPECTED;
			return -1;
		}
		b_del(rxbuf, h3_flen);
	}

	return 1;
}

/* Finalize the initialization of remotely initiated uni-stream <iuqcs> */
static int h3_set_iuqcs(struct h3 *h3, struct iuqcs *iuqcs)
{
	uint64_t strm_type;
	struct buffer *rxbuf = &iuqcs->rxbuf;

	/* First octets: the uni-stream type */
	if (!b_quic_dec_int(&strm_type, rxbuf))
		return 0;

	if (strm_type > H3_UNI_STRM_TP_MAX)
		return 0;

	iuqcs->type = strm_type;
	switch (strm_type) {
	case H3_UNI_STRM_TP_CONTROL_STREAM:
		h3->control = iuqcs;
		h3->control->decode = h3_control_decode;
		break;
	case H3_UNI_STRM_TP_PUSH_STREAM:
		break;
	case H3_UNI_STRM_TP_QPACK_ENCODER:
		h3->qpack_dec_qcs = iuqcs;
		h3->qpack_dec_qcs->decode = qpack_decode_enc;
		break;
	case H3_UNI_STRM_TP_QPACK_DECODER:
		h3->qpack_dec_qcs = iuqcs;
		h3->qpack_dec_qcs->decode = qpack_decode_dec;
		break;
	default:
		/* Error */
		h3->err = H3_STREAM_CREATION_ERROR;
		return 0;
	}

	return 1;
}

/* Initialize the HTTP/3 context for <qcc> mux */
static int h3_init(struct qcc *qcc)
{
	struct h3 *h3;

	h3 = pool_alloc(pool_head_h3);
	if (!h3)
		goto err;

	h3->err = H3_NO_ERROR;
	h3->qpack_dec_qcs = NULL;
	qcc->ctx = h3;

	return 1;

 err:
	return 0;
}

/* HTTP/3 application layer operations */
const struct qcc_app_ops h3_ops = {
	.init         = h3_init,
	.decode_iuqcs = h3_decode_iuqcs,
	.decode_qcs   = h3_decode_qcs,
};
