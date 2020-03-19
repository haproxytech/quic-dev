/*
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <proto/quic_frame.h>

int quic_parse_packet_frames(struct quic_rx_packet *qpkt)
{
	struct quic_frame frm;
	const unsigned char *pos, *end;

	/* Skip the AAD */
	pos = qpkt->data + qpkt->aad_len;
	end = qpkt->data + qpkt->len;

	while (pos < end) {
		if (!quic_parse_frame(&frm, &pos, end))
			return 0;

		switch (frm.type) {
			case QUIC_FT_CRYPTO:
				break;

			case QUIC_FT_PADDING:
				/* This frame must be the last found in the packet. */
				if (pos != end) {
					fprintf(stderr, "Wrong frame! (%ld len: %lu)\n", end - pos, frm.padding.len);
					return 0;
				}
				break;

			case QUIC_FT_ACK:
				break;

			case QUIC_FT_PING:
				break;

			case QUIC_FT_CONNECTION_CLOSE:
			case QUIC_FT_CONNECTION_CLOSE_APP:
				break;
			case QUIC_FT_NEW_CONNECTION_ID:
			case QUIC_FT_STREAM_A:
			case QUIC_FT_STREAM_B:
				break;
			default:
				return 0;
		}
	}

	return 1;
}

int (*quic_build_frame_funcs[])(unsigned char **, const unsigned char *,
                                    struct quic_frame *) = {
	[QUIC_FT_PADDING]      = quic_build_padding_frame,
	[QUIC_FT_PING]         = quic_build_ping_frame,
	[QUIC_FT_ACK]          = quic_build_ack_frame,
	[QUIC_FT_ACK_ECN]      = quic_build_ack_ecn_frame,
	[QUIC_FT_RESET_STREAM] = quic_build_reset_stream_frame,
	[QUIC_FT_STOP_SENDING] = quic_build_stop_sending_frame,
	[QUIC_FT_CRYPTO]       = quic_build_crypto_frame,
	[QUIC_FT_NEW_TOKEN]    = quic_build_new_token_frame,
	[QUIC_FT_STREAM_8]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_9]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_A]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_B]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_C]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_D]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_E]     = quic_build_stream_frame,
	[QUIC_FT_STREAM_F]     = quic_build_stream_frame,
	[QUIC_FT_MAX_DATA]     = quic_build_max_data_frame,
	[QUIC_FT_MAX_STREAM_DATA]      = quic_build_max_stream_data_frame,
	[QUIC_FT_MAX_STREAMS_BIDI]     = quic_build_max_streams_bidi_frame,
	[QUIC_FT_MAX_STREAMS_UNI]      = quic_build_max_streams_uni_frame,
	[QUIC_FT_DATA_BLOCKED]         = quic_build_data_blocked_frame,
	[QUIC_FT_STREAM_DATA_BLOCKED]  = quic_build_stream_data_blocked_frame,
	[QUIC_FT_STREAMS_BLOCKED_BIDI] = quic_build_streams_blocked_bidi_frame,
	[QUIC_FT_STREAMS_BLOCKED_UNI]  = quic_build_streams_blocked_uni_frame,
	[QUIC_FT_NEW_CONNECTION_ID]    = quic_build_new_connection_id_frame,
	[QUIC_FT_RETIRE_CONNECTION_ID] = quic_build_retire_connection_id_frame,
	[QUIC_FT_PATH_CHALLENGE]       = quic_build_path_challenge_frame,
	[QUIC_FT_PATH_RESPONSE]        = quic_build_path_response_frame,
	[QUIC_FT_CONNECTION_CLOSE]     = quic_build_connection_close_frame,
	[QUIC_FT_CONNECTION_CLOSE_APP] = quic_build_connection_close_app_frame,
	[QUIC_FT_HANDSHAKE_DONE]       = quic_build_handshake_done_frame,
};

int (*quic_parse_frame_funcs[])(struct quic_frame *frm,
                                const unsigned char **, const unsigned char *) = {
	[QUIC_FT_PADDING]      = quic_parse_padding_frame,
	[QUIC_FT_PING]         = quic_parse_ping_frame,
	[QUIC_FT_ACK]          = quic_parse_ack_frame_header,
	[QUIC_FT_ACK_ECN]      = quic_parse_ack_ecn_frame,
	[QUIC_FT_RESET_STREAM] = quic_parse_reset_stream_frame,
	[QUIC_FT_STOP_SENDING] = quic_parse_stop_sending_frame,
	[QUIC_FT_CRYPTO]       = quic_parse_crypto_frame,
	[QUIC_FT_NEW_TOKEN]    = quic_parse_new_token_frame,
	[QUIC_FT_STREAM_8]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_9]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_A]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_B]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_C]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_D]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_E]     = quic_parse_stream_frame,
	[QUIC_FT_STREAM_F]     = quic_parse_stream_frame,
	[QUIC_FT_MAX_DATA]     = quic_parse_max_data_frame,
	[QUIC_FT_MAX_STREAM_DATA]      = quic_parse_max_stream_data_frame,
	[QUIC_FT_MAX_STREAMS_BIDI]     = quic_parse_max_streams_bidi_frame,
	[QUIC_FT_MAX_STREAMS_UNI]      = quic_parse_max_streams_uni_frame,
	[QUIC_FT_DATA_BLOCKED]         = quic_parse_data_blocked_frame,
	[QUIC_FT_STREAM_DATA_BLOCKED]  = quic_parse_stream_data_blocked_frame,
	[QUIC_FT_STREAMS_BLOCKED_BIDI] = quic_parse_streams_blocked_bidi_frame,
	[QUIC_FT_STREAMS_BLOCKED_UNI]  = quic_parse_streams_blocked_uni_frame,
	[QUIC_FT_NEW_CONNECTION_ID]    = quic_parse_new_connection_id_frame,
	[QUIC_FT_RETIRE_CONNECTION_ID] = quic_parse_retire_connection_id_frame,
	[QUIC_FT_PATH_CHALLENGE]       = quic_parse_path_challenge_frame,
	[QUIC_FT_PATH_RESPONSE]        = quic_parse_path_response_frame,
	[QUIC_FT_CONNECTION_CLOSE]     = quic_parse_connection_close_frame,
	[QUIC_FT_CONNECTION_CLOSE_APP] = quic_parse_connection_close_app_frame,
	[QUIC_FT_HANDSHAKE_DONE]       = quic_parse_handshake_done_frame,
};

