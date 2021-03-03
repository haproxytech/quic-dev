/*
 * HTTP/3 protocol processing
 *
 * Copyright 2021 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

struct h3 {
	struct iuqcs *qpack_dec;
};

DECLARE_STATIC_POOL(pool_head_h3, "h3", sizeof(struct h3));

/* Finalize the initialization of remotely initiated uni-stream <iuqcs> */
static int h3_set_iuqcs(struct h3 *h3, struct iuqcs *iuqcs)
{
	int strm_type;

	strm_type = *b_head(&iuqcs->rxbuf);
	/* First octet: the uni-stream type. */
	if (strm_type > H3_UNI_STRM_TP_MAX)
		return 0;

	iuqcs->type = strm_type;
	b_del(&iuqcs->rxbuf, 1);
	switch (strm_type) {
	case H3_UNI_STRM_TP_CONTROL_STREAM:
		break;
	case H3_UNI_STRM_TP_PUSH_STREAM:
		break;
	case H3_UNI_STRM_TP_QPACK_ENCODER:
		h3->qpack_dec = iuqcs;
		h3->qpack_dec->decode = qpack_decode;
		break;
	case H3_UNI_STRM_TP_QPACK_DECODER:
		h3->qpack_dec = iuqcs;
		h3->qpack_dec->decode = qpack_decode;
		break;
	}

	return 1;
}

static int h3_decode_iuqcs(struct iuqcs *qcs, void *ctx)
{
	struct h3 *h3 = ctx;

	if (!qcs->rx.offset && !h3_set_iuqcs(h3, qcs))
		return 0;

	if (qcs->decode)
		qcs->decode(&qcs->rxbuf);

	return 1;
}

static int h3_decode_qcs(struct qcs *qcs, void *ctx)
{
}

static int h3_init(struct qcc *qcc)
{
	struct h3 *h3;

	h3 = pool_alloc(pool_head_h3);
	if (!h3)
		goto err;

	h3->qpack_dec = NULL;
	qcc->ctx = h3;

	return 1;

 err:
	return 0;
}

const struct qcc_app_ops h3_ops = {
	.init         = h3_init,
	.decode_iuqcs = h3_decode_iuqcs,
	.decode_qcs   = h3_decode_qcs,
};
