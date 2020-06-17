/*
 * include/proto/quic_conn.h
 * This file contains definitions for QUIC connections.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _PROTO_QUIC_FRAME_H
#define _PROTO_QUIC_FRAME_H

#define TRACE_SOURCE    &trace_quic

#include <types/quic_frame.h>

#include <proto/trace.h>
#include <proto/xprt_quic.h>

static inline const char *quic_frame_type_string(enum quic_frame_type ft)
{
	switch (ft) {
	case QUIC_FT_PADDING:
		return "PADDING";
	case QUIC_FT_PING:
		return "PING";
	case QUIC_FT_ACK:
		return "ACK";
	case QUIC_FT_ACK_ECN:
		return "ACK_ENC";
	case QUIC_FT_RESET_STREAM:
		return "RESET_STREAM";
	case QUIC_FT_STOP_SENDING:
		return "STOP_SENDING";
	case QUIC_FT_CRYPTO:
		return "CRYPTO";
	case QUIC_FT_NEW_TOKEN:
		return "NEW_TOKEN";

	case QUIC_FT_STREAM_8:
		return "STREAM_8";
	case QUIC_FT_STREAM_9:
		return "STREAM_9";
	case QUIC_FT_STREAM_A:
		return "STREAM_A";
	case QUIC_FT_STREAM_B:
		return "STREAM_B";
	case QUIC_FT_STREAM_C:
		return "STREAM_C";
	case QUIC_FT_STREAM_D:
		return "STREAM_D";
	case QUIC_FT_STREAM_E:
		return "STREAM_E";
	case QUIC_FT_STREAM_F:
		return "STREAM_F";

	case QUIC_FT_MAX_DATA:
		return "MAX_DATA";
	case QUIC_FT_MAX_STREAM_DATA:
		return "MAX_STREAM_DATA";
	case QUIC_FT_MAX_STREAMS_BIDI:
		return "MAX_STREAMS_BIDI";
	case QUIC_FT_MAX_STREAMS_UNI:
		return "MAX_STREAMS_UNI";
	case QUIC_FT_DATA_BLOCKED:
		return "DATA_BLOCKED";
	case QUIC_FT_STREAM_DATA_BLOCKED:
		return "STREAM_DATA_BLOCKED";
	case QUIC_FT_STREAMS_BLOCKED_BIDI:
		return "STREAMS_BLOCKED_BIDI";
	case QUIC_FT_STREAMS_BLOCKED_UNI:
		return "STREAMS_BLOCKED_UNI";
	case QUIC_FT_NEW_CONNECTION_ID:
		return "NEW_CONNECTION_ID";
	case QUIC_FT_RETIRE_CONNECTION_ID:
		return "RETIRE_CONNECTION_ID";
	case QUIC_FT_PATH_CHALLENGE:
		return "PATH_CHALLENGE";
	case QUIC_FT_PATH_RESPONSE:
		return "PATH_RESPONSE";
	case QUIC_FT_CONNECTION_CLOSE:
		return "CONNECTION_CLOSE";
	case QUIC_FT_CONNECTION_CLOSE_APP:
		return "CONNECTION_CLOSE_APP";
	case QUIC_FT_HANDSHAKE_DONE:
		return "HANDSHAKE_DONE";
	default:
		return "UNKNOWN";
	}
}

/*
 * Encode <frm> PADDING frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_padding_frame(unsigned char **buf, const unsigned char *end,
                                           struct quic_frame *frm)
{
	struct quic_padding *padding = &frm->padding;

	if (end - *buf < padding->len - 1)
		return 0;

	memset(*buf, 0, padding->len - 1);
	*buf += padding->len - 1;

	return 1;
}

/*
 * Parse a PADDING frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_padding_frame(struct quic_frame *frm,
                                           const unsigned char **buf, const unsigned char *end)
{
	const unsigned char *beg;
	struct quic_padding *padding = &frm->padding;

	beg = *buf;
	padding->len = 1;
	while (*buf < end && !**buf)
		(*buf)++;
	padding->len += *buf - beg;

	return 1;
}

/*
 * Encode a ACK frame into <buf> buffer.
 * Always succeeds.
 */
static int inline quic_build_ping_frame(unsigned char **buf, const unsigned char *end,
                                        struct quic_frame *frm)
{
	/* No field */
	return 1;
}

/*
 * Parse a PADDING frame from <buf> buffer with <end> as end into <frm> frame.
 * Always succeeds.
 */
static int inline quic_parse_ping_frame(struct quic_frame *frm,
                                        const unsigned char **buf, const unsigned char *end)
{
	/* No field */
	return 1;
}

/*
 * Encode a ACK frame.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_ack_frame(unsigned char **buf, const unsigned char *end,
                                       struct quic_frame *frm)
{
	struct quic_tx_ack *tx_ack = &frm->tx_ack;
	struct quic_ack_range *ack_range, *next_ack_range;

	ack_range =  LIST_NEXT(&tx_ack->ack_ranges->list, struct quic_ack_range *, list);
	TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,, &ack_range->last, &ack_range->first);
	if (!quic_enc_int(buf, end, ack_range->last) ||
	    !quic_enc_int(buf, end, tx_ack->ack_delay) ||
	    !quic_enc_int(buf, end, tx_ack->ack_ranges->sz - 1) ||
	    !quic_enc_int(buf, end, ack_range->last - ack_range->first))
		return 0;

	next_ack_range = LIST_NEXT(&ack_range->list, struct quic_ack_range *, list);
	while (&next_ack_range->list != &tx_ack->ack_ranges->list) {
		TRACE_PROTO("ack range", QUIC_EV_CONN_PRSAFRM,, &ack_range->last, &ack_range->first);
		if (!quic_enc_int(buf, end, ack_range->first - next_ack_range->last - 2) ||
		    !quic_enc_int(buf, end, next_ack_range->last - next_ack_range->first))
			return 0;

		ack_range = next_ack_range;
		next_ack_range = LIST_NEXT(&ack_range->list, struct quic_ack_range *, list);
	}

	return 1;
}

/*
 * Parse an ACK frame header from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_ack_frame_header(struct quic_frame *frm,
                                              const unsigned char **buf, const unsigned char *end)
{
	int ret;
	struct quic_ack *ack = &frm->ack;

	ret = quic_dec_int(&ack->largest_ack, buf, end);
	if (!ret)
		return 0;

	QDPRINTF("+++++++++++\nlargest_ack    : %lu\n", ack->largest_ack);
	ret = quic_dec_int(&ack->ack_delay, buf, end);
	if (!ret)
		return 0;

	QDPRINTF("ack_delay      : %lu\n", ack->ack_delay);
	ret = quic_dec_int(&ack->ack_range_num, buf, end);
	if (!ret)
		return 0;

	QDPRINTF("ack_range_num  : %lu\n", ack->ack_range_num);
	ret = quic_dec_int(&ack->first_ack_range, buf, end);
	if (!ret)
		return 0;

	QDPRINTF("first_ack_range: %lu\n", ack->first_ack_range);
	QDPRINTF("acks from %lu -> %lu\n",
	         ack->largest_ack - ack->first_ack_range, ack->largest_ack);

	return 1;
}

/*
 * Encode a ACK_ECN frame.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_ack_ecn_frame(unsigned char **buf, const unsigned char *end,
                                           struct quic_frame *frm)
{
	struct quic_ack *ack = &frm->ack;

	return quic_enc_int(buf, end, ack->largest_ack) &&
		quic_enc_int(buf, end, ack->ack_delay) &&
		quic_enc_int(buf, end, ack->first_ack_range) &&
		quic_enc_int(buf, end, ack->ack_range_num);
}

/*
 * Parse an ACK_ECN frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_ack_ecn_frame(struct quic_frame *frm,
                                           const unsigned char **buf, const unsigned char *end)
{
	struct quic_ack *ack = &frm->ack;

	return quic_dec_int(&ack->largest_ack, buf, end) &&
		quic_dec_int(&ack->ack_delay, buf, end) &&
		quic_dec_int(&ack->first_ack_range, buf, end) &&
		quic_dec_int(&ack->ack_range_num, buf, end);
}

/*
 * Encode a RESET_STREAM frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_reset_stream_frame(unsigned char **buf, const unsigned char *end,
                                                struct quic_frame *frm)
{
	struct quic_reset_stream *reset_stream = &frm->reset_stream;

	return quic_enc_int(buf, end, reset_stream->id) &&
		quic_enc_int(buf, end, reset_stream->app_error_code) &&
		quic_enc_int(buf, end, reset_stream->final_size);
}

/*
 * Parse a RESET_STREAM frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_reset_stream_frame(struct quic_frame *frm,
                                               const unsigned char **buf, const unsigned char *end)
{
	struct quic_reset_stream *reset_stream = &frm->reset_stream;

	return quic_dec_int(&reset_stream->id, buf, end) &&
		quic_dec_int(&reset_stream->app_error_code, buf, end) &&
		quic_dec_int(&reset_stream->final_size, buf, end);
}

/*
 * Encode a STOP_SENDING frame.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_stop_sending_frame(unsigned char **buf, const unsigned char *end,
                                                struct quic_frame *frm)
{
	struct quic_stop_sending_frame *stop_sending_frame = &frm->stop_sending_frame;

	return quic_enc_int(buf, end, stop_sending_frame->id) &&
		quic_enc_int(buf, end, stop_sending_frame->app_error_code);
}

/*
 * Parse a STOP_SENDING frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_stop_sending_frame(struct quic_frame *frm,
                                                const unsigned char **buf, const unsigned char *end)
{
	struct quic_stop_sending_frame *stop_sending_frame = &frm->stop_sending_frame;

	return quic_dec_int(&stop_sending_frame->id, buf, end) &&
		quic_dec_int(&stop_sending_frame->app_error_code, buf, end);
}

/*
 * Encode a CRYPTO frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_crypto_frame(unsigned char **buf, const unsigned char *end,
                                          struct quic_frame *frm)
{
	struct quic_crypto *crypto = &frm->crypto;
	const struct quic_enc_level *qel = crypto->qel;
	size_t offset, len;

	if (!quic_enc_int(buf, end, crypto->offset) ||
	    !quic_enc_int(buf, end, crypto->len) || end - *buf < crypto->len)
		return 0;

	len = crypto->len;
	offset = crypto->offset;
	while (len) {
		int idx;
		size_t to_copy;
		const unsigned char *data;

		idx = offset >> QUIC_CRYPTO_BUF_SHIFT;
		to_copy = qel->tx.crypto.bufs[idx]->sz - (offset & QUIC_CRYPTO_BUF_MASK);
		if (to_copy > len)
			to_copy = len;
		data = qel->tx.crypto.bufs[idx]->data + (offset & QUIC_CRYPTO_BUF_MASK);
		memcpy(*buf, data, to_copy);
		*buf += to_copy;
		offset += to_copy;
		len -= to_copy;
	}

	return 1;
}

/*
 * Parse a CRYPTO frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_crypto_frame(struct quic_frame *frm,
                                          const unsigned char **buf, const unsigned char *end)
{
	struct quic_crypto *crypto = &frm->crypto;

	if (!quic_dec_int(&crypto->offset, buf, end) ||
	    !quic_dec_int(&crypto->len, buf, end) || end - *buf < crypto->len)
		return 0;

	crypto->data = *buf;
	*buf += crypto->len;

	return 1;
}

/*
 * Encode a NEW_TOKEN frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_new_token_frame(unsigned char **buf, const unsigned char *end,
                                             struct quic_frame *frm)
{
	struct quic_new_token *new_token = &frm->new_token;

	if (!quic_enc_int(buf, end, new_token->len) || end - *buf < new_token->len)
		return 0;

	memcpy(*buf, new_token->data, new_token->len);

	return 1;
}

/*
 * Parse a NEW_TOKEN frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_new_token_frame(struct quic_frame *frm,
                                             const unsigned char **buf, const unsigned char *end)
{
	struct quic_new_token *new_token = &frm->new_token;

	if (!quic_dec_int(&new_token->len, buf, end) || end - *buf < new_token->len)
		return 0;

	new_token->data = *buf;
	*buf += new_token->len;

	return 1;
}

/*
 * Encode a STREAM frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static int inline quic_build_stream_frame(unsigned char **buf, const unsigned char *end,
                                          struct quic_frame *frm)
{
	struct quic_stream *stream = &frm->stream;

	if (!quic_enc_int(buf, end, stream->id) ||
	    ((frm->type & QUIC_STREAM_FRAME_OFF_BIT) && !quic_enc_int(buf, end, stream->offset)) ||
	    ((frm->type & QUIC_STREAM_FRAME_LEN_BIT) &&
	     (!quic_enc_int(buf, end, stream->len) || end - *buf < stream->len)))
		return 0;

	memcpy(*buf, stream->data, stream->len);
	*buf += stream->len;

	return 1;
}

/*
 * Parse a STREAM frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_stream_frame(struct quic_frame *frm,
                                          const unsigned char **buf, const unsigned char *end)
{
	struct quic_stream *stream = &frm->stream;

	if (!quic_dec_int(&stream->id, buf, end) ||
	    ((frm->type & QUIC_STREAM_FRAME_OFF_BIT) && !quic_dec_int(&stream->offset, buf, end)) ||
	    ((frm->type & QUIC_STREAM_FRAME_LEN_BIT) &&
	     (!quic_dec_int(&stream->len, buf, end) || end - *buf < stream->len)))
		return 0;

	stream->data = *buf;
	*buf += stream->len;

	return 1;
}

/*
 * Encode a MAX_DATA frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_max_data_frame(unsigned char **buf, const unsigned char *end,
                                            struct quic_frame *frm)
{
	struct quic_max_data *max_data = &frm->max_data;

	return quic_enc_int(buf, end, max_data->max_data);
}

/*
 * Parse a MAX_DATA frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_max_data_frame(struct quic_frame *frm,
                                            const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_data *max_data = &frm->max_data;

	return quic_dec_int(&max_data->max_data, buf, end);
}

/*
 * Encode a MAX_STREAM_DATA frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_max_stream_data_frame(unsigned char **buf, const unsigned char *end,
                                                   struct quic_frame *frm)
{
	struct quic_max_stream_data *max_stream_data = &frm->max_stream_data;

	return quic_enc_int(buf, end, max_stream_data->id) &&
		quic_enc_int(buf, end, max_stream_data->max_stream_data);
}

/*
 * Parse a MAX_STREAM_DATA frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_max_stream_data_frame(struct quic_frame *frm,
                                                   const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_stream_data *max_stream_data = &frm->max_stream_data;

	return quic_dec_int(&max_stream_data->id, buf, end) &&
		quic_dec_int(&max_stream_data->max_stream_data, buf, end);
}

/*
 * Encode a MAX_STREAMS frame for bidirectional streams into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_max_streams_bidi_frame(unsigned char **buf, const unsigned char *end,
                                                    struct quic_frame *frm)
{
	struct quic_max_streams *max_streams_bidi = &frm->max_streams_bidi;

	return quic_enc_int(buf, end, max_streams_bidi->max_streams);
}

/*
 * Parse a MAX_STREAMS frame for bidirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_max_streams_bidi_frame(struct quic_frame *frm,
                                                    const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_streams *max_streams_bidi = &frm->max_streams_bidi;

	return quic_dec_int(&max_streams_bidi->max_streams, buf, end);
}

/*
 * Encode a MAX_STREAMS frame for unidirectional streams into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_max_streams_uni_frame(unsigned char **buf, const unsigned char *end,
                                                   struct quic_frame *frm)
{
	struct quic_max_streams *max_streams_uni = &frm->max_streams_uni;

	return quic_enc_int(buf, end, max_streams_uni->max_streams);
}

/*
 * Parse a MAX_STREAMS frame for undirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_max_streams_uni_frame(struct quic_frame *frm,
                                                   const unsigned char **buf, const unsigned char *end)
{
	struct quic_max_streams *max_streams_uni = &frm->max_streams_uni;

	return quic_dec_int(&max_streams_uni->max_streams, buf, end);
}

/*
 * Encode a DATA_BLOCKED frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_data_blocked_frame(unsigned char **buf, const unsigned char *end,
                                                struct quic_frame *frm)
{
	struct quic_data_blocked *data_blocked = &frm->data_blocked;

	return quic_enc_int(buf, end, data_blocked->limit);
}

/*
 * Parse a DATA_BLOCKED frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_data_blocked_frame(struct quic_frame *frm,
                                                const unsigned char **buf, const unsigned char *end)
{
	struct quic_data_blocked *data_blocked = &frm->data_blocked;

	return quic_dec_int(&data_blocked->limit, buf, end);
}

/*
 * Encode a STREAM_DATA_BLOCKED into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_stream_data_blocked_frame(unsigned char **buf, const unsigned char *end,
                                                       struct quic_frame *frm)
{
	struct quic_stream_data_blocked *stream_data_blocked = &frm->stream_data_blocked;

	return quic_enc_int(buf, end, stream_data_blocked->id) &&
		quic_enc_int(buf, end, stream_data_blocked->limit);
}

/*
 * Parse a STREAM_DATA_BLOCKED frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_stream_data_blocked_frame(struct quic_frame *frm,
                                                       const unsigned char **buf, const unsigned char *end)
{
	struct quic_stream_data_blocked *stream_data_blocked = &frm->stream_data_blocked;

	return quic_dec_int(&stream_data_blocked->id, buf, end) &&
		quic_dec_int(&stream_data_blocked->limit, buf, end);
}

/*
 * Encode a STREAMS_BLOCKED frame for bidirectional streams into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_streams_blocked_bidi_frame(unsigned char **buf, const unsigned char *end,
                                                        struct quic_frame *frm)
{
	struct quic_streams_blocked *streams_blocked_bidi = &frm->streams_blocked_bidi;

	return quic_enc_int(buf, end, streams_blocked_bidi->limit);
}

/*
 * Parse a STREAMS_BLOCKED frame for bidirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_streams_blocked_bidi_frame(struct quic_frame *frm,
                                                        const unsigned char **buf, const unsigned char *end)
{
	struct quic_streams_blocked *streams_blocked_bidi = &frm->streams_blocked_bidi;

	return quic_dec_int(&streams_blocked_bidi->limit, buf, end);
}

/*
 * Encode a STREAMS_BLOCKED frame for unidirectional streams into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_streams_blocked_uni_frame(unsigned char **buf, const unsigned char *end,
                                                       struct quic_frame *frm)
{
	struct quic_streams_blocked *streams_blocked_uni = &frm->streams_blocked_uni;

	return quic_enc_int(buf, end, streams_blocked_uni->limit);
}

/*
 * Parse a STREAMS_BLOCKED frame for unidirectional streams from <buf> buffer with <end>
 * as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static int inline quic_parse_streams_blocked_uni_frame(struct quic_frame *frm,
                                                       const unsigned char **buf, const unsigned char *end)
{
	struct quic_streams_blocked *streams_blocked_uni = &frm->streams_blocked_uni;

	return quic_dec_int(&streams_blocked_uni->limit, buf, end);
}

/*
 * Encode a NEW_CONNECTION_ID frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_new_connection_id_frame(unsigned char **buf, const unsigned char *end,
                                                     struct quic_frame *frm)
{
	struct quic_new_connection_id *new_cid = &frm->new_connection_id;

	if (!quic_enc_int(buf, end, new_cid->seq_num) ||
	    !quic_enc_int(buf, end, new_cid->retire_prior_to) ||
	    end - *buf < sizeof new_cid->cid.len + new_cid->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN)
		return 0;

	*(*buf)++ = new_cid->cid.len;

	if (new_cid->cid.len) {
		memcpy(*buf, new_cid->cid.data, new_cid->cid.len);
		*buf += new_cid->cid.len;
	}
	memcpy(*buf, new_cid->stateless_reset_token, QUIC_STATELESS_RESET_TOKEN_LEN);
	*buf += QUIC_STATELESS_RESET_TOKEN_LEN;

	return 1;
}

/*
 * Parse a NEW_CONNECTION_ID frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static inline int quic_parse_new_connection_id_frame(struct quic_frame *frm,
                                                     const unsigned char **buf, const unsigned char *end)
{
	struct quic_new_connection_id *new_cid = &frm->new_connection_id;

	if (!quic_dec_int(&new_cid->seq_num, buf, end) ||
	    !quic_dec_int(&new_cid->retire_prior_to, buf, end) || end <= *buf)
		return 0;

	new_cid->cid.len = *(*buf)++;
	if (end - *buf < new_cid->cid.len + QUIC_STATELESS_RESET_TOKEN_LEN)
		return 0;

	if (new_cid->cid.len) {
		new_cid->cid.data = *buf;
		*buf += new_cid->cid.len;
	}
	new_cid->stateless_reset_token = *buf;
	*buf += QUIC_STATELESS_RESET_TOKEN_LEN;

	return 1;
}

/*
 * Encode a RETIRE_CONNECTION_ID frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_retire_connection_id_frame(unsigned char **buf, const unsigned char *end,
                                                        struct quic_frame *frm)
{
	struct quic_retire_connection_id *retire_connection_id = &frm->retire_connection_id;

	return quic_enc_int(buf, end, retire_connection_id->seq_num);
}

/*
 * Parse a RETIRE_CONNECTION_ID frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static inline int quic_parse_retire_connection_id_frame(struct quic_frame *frm,
                                                        const unsigned char **buf, const unsigned char *end)
{
	struct quic_retire_connection_id *retire_connection_id = &frm->retire_connection_id;

	return quic_dec_int(&retire_connection_id->seq_num, buf, end);
}

/*
 * Encode a PATH_CHALLENGE frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_path_challenge_frame(unsigned char **buf, const unsigned char *end,
                                                  struct quic_frame *frm)
{
	struct quic_path_challenge *path_challenge = &frm->path_challenge;

	if (end - *buf < sizeof path_challenge->data)
		return 0;

	memcpy(*buf, path_challenge->data, sizeof path_challenge->data);
	*buf += sizeof path_challenge->data;

	return 1;
}

/*
 * Parse a PATH_CHALLENGE frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static inline int quic_parse_path_challenge_frame(struct quic_frame *frm,
                                                  const unsigned char **buf, const unsigned char *end)
{
	struct quic_path_challenge *path_challenge = &frm->path_challenge;

	if (end - *buf < sizeof path_challenge->data)
		return 0;

	memcpy(path_challenge->data, *buf, sizeof path_challenge->data);
	*buf += sizeof path_challenge->data;

	return 1;
}


/*
 * Encode a PATH_RESPONSE frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_path_response_frame(unsigned char **buf, const unsigned char *end,
                                                 struct quic_frame *frm)
{
	struct quic_path_challenge_response *path_challenge_response = &frm->path_challenge_response;

	if (end - *buf < sizeof path_challenge_response->data)
		return 0;

	memcpy(*buf, path_challenge_response->data, sizeof path_challenge_response->data);
	*buf += sizeof path_challenge_response->data;

	return 1;
}

/*
 * Parse a PATH_RESPONSE frame from <buf> buffer with <end> as end into <frm> frame.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static inline int quic_parse_path_response_frame(struct quic_frame *frm,
                                                 const unsigned char **buf, const unsigned char *end)
{
	struct quic_path_challenge_response *path_challenge_response = &frm->path_challenge_response;

	if (end - *buf < sizeof path_challenge_response->data)
		return 0;

	memcpy(path_challenge_response->data, *buf, sizeof path_challenge_response->data);
	*buf += sizeof path_challenge_response->data;

	return 1;
}

/*
 * Encode a CONNECTION_CLOSE frame at QUIC layer into <buf> buffer.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_connection_close_frame(unsigned char **buf, const unsigned char *end,
                                                    struct quic_frame *frm)
{
	struct quic_connection_close *connection_close = &frm->connection_close;

	if (!quic_enc_int(buf, end, connection_close->error_code) ||
	    !quic_enc_int(buf, end, connection_close->frame_type) ||
	    !quic_enc_int(buf, end, connection_close->reason_phrase_len) ||
	    end - *buf < connection_close->reason_phrase_len)
		return 0;

	memcpy(*buf, connection_close->reason_phrase, connection_close->reason_phrase_len);
	*buf += connection_close->reason_phrase_len;

	return 1;
}

/*
 * Parse a CONNECTION_CLOSE frame at QUIC layer from <buf> buffer with <end> as end into <frm> frame.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static inline int quic_parse_connection_close_frame(struct quic_frame *frm,
                                                    const unsigned char **buf, const unsigned char *end)
{
	struct quic_connection_close *connection_close = &frm->connection_close;

	if (!quic_dec_int(&connection_close->error_code, buf, end) ||
	    !quic_dec_int(&connection_close->frame_type, buf, end) ||
	    !quic_dec_int(&connection_close->reason_phrase_len, buf, end) ||
	    end - *buf < connection_close->reason_phrase_len)
		return 0;

	if (connection_close->reason_phrase_len) {
		memcpy(connection_close->reason_phrase, *buf, connection_close->reason_phrase_len);
		*buf += connection_close->reason_phrase_len;
	}

	return 1;
}

/*
 * Encode a CONNECTION_CLOSE frame at application layer into <buf> buffer.
 * Note there exist two types of CONNECTION_CLOSE frame, one for application layer
 * and another at QUIC layer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int quic_build_connection_close_app_frame(unsigned char **buf, const unsigned char *end,
                                                        struct quic_frame *frm)
{
	struct quic_connection_close_app *connection_close_app = &frm->connection_close_app;

	if (!quic_enc_int(buf, end, connection_close_app->error_code) ||
	    !quic_enc_int(buf, end, connection_close_app->reason_phrase_len) ||
	    end - *buf < connection_close_app->reason_phrase_len)
		return 0;

	if (connection_close_app->reason_phrase_len) {
		memcpy(*buf, connection_close_app->reason_phrase, connection_close_app->reason_phrase_len);
		*buf += connection_close_app->reason_phrase_len;
	}

	return 1;
}

/*
 * Parse a CONNECTION_CLOSE frame at QUIC layer from <buf> buffer with <end> as end into <frm> frame.
 * Note there exist two types of CONNECTION_CLOSE frame, one for the application layer
 * and another at QUIC layer.
 * Return 1 if succeeded (enough room to parse this frame), 0 if not.
 */
static inline int quic_parse_connection_close_app_frame(struct quic_frame *frm,
                                                        const unsigned char **buf, const unsigned char *end)
{
	struct quic_connection_close_app *connection_close_app = &frm->connection_close_app;

	if (!quic_dec_int(&connection_close_app->error_code, buf, end) ||
	    !quic_dec_int(&connection_close_app->reason_phrase_len, buf, end) ||
	    end - *buf < connection_close_app->reason_phrase_len)
		return 0;

	memcpy(connection_close_app->reason_phrase, *buf, connection_close_app->reason_phrase_len);
	*buf += connection_close_app->reason_phrase_len;

	return 1;
}

/*
 * Encode a HANDSHAKE_DONE frame into <buf> buffer.
 * Always succeeds.
 */
static int inline quic_build_handshake_done_frame(unsigned char **buf, const unsigned char *end,
                                                  struct quic_frame *frm)
{
	/* No field */
	return 1;
}

/*
 * Parse a HANDSHAKE_DONE frame at QUIC layer from <buf> buffer with <end> as end into <frm> frame.
 * Always succeed.
 */
static inline int quic_parse_handshake_done_frame(struct quic_frame *frm,
                                                  const unsigned char **buf, const unsigned char *end)
{
	/* No field */
	return 1;
}

/*
 * Decode a QUIC frame from <buf> buffer into <frm> frame.
 * Returns 1 if succeded (enough data to parse the frame), 0 if not.
 */
static inline int qc_parse_frm(struct quic_frame *frm,
                               const unsigned char **buf, const unsigned char *end)
{
	if (end <= *buf) {
		TRACE_DEVEL("wrong frame", QUIC_EV_CONN_PRSFRM);
		return 0;
	}

	frm->type = *(*buf)++;
	if (frm->type > QUIC_FT_MAX) {
		TRACE_DEVEL("wrong frame type", QUIC_EV_CONN_PRSFRM, frm);
		return 0;
	}

	QDPRINTF("%s: %s frame\n", __func__, quic_frame_type_string(frm->type));
	TRACE_PROTO("frame", QUIC_EV_CONN_BFRM,, frm);
	if (!quic_parse_frame_funcs[frm->type](frm, buf, end)) {
		TRACE_DEVEL("parsing error", QUIC_EV_CONN_PRSFRM, frm);
		return 0;
	}

	return 1;
}

/*
 * Encode <frm> QUIC frame into <buf> buffer.
 * Returns 1 if succeded (enough room in <buf> to encode the frame), 0 if not.
 */
static inline int qc_build_frm(unsigned char **buf, const unsigned char *end,
                               struct quic_frame *frm)
{
	if (end <= *buf) {
		TRACE_DEVEL("not enough room", QUIC_EV_CONN_BFRM, frm);
		return 0;
	}

	QDPRINTF("%s: %s frame\n", __func__, quic_frame_type_string(frm->type));
	TRACE_PROTO("frame", QUIC_EV_CONN_BFRM,, frm);
	*(*buf)++ = frm->type;
	if (!quic_build_frame_funcs[frm->type](buf, end, frm)) {
		TRACE_DEVEL("frame building error", QUIC_EV_CONN_BFRM, frm);
		return 0;
	}

	return 1;
}

#endif /* _PROTO_QUIC_FRAME_H */
