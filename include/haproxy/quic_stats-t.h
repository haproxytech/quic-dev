#ifndef _HAPROXY_QUIC_STATS_T_H
#define _HAPROXY_QUIC_STATS_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

extern struct stats_module quic_stats_module;

enum {
	QUIC_ST_DROPPED_PACKETS,
	QUIC_ST_TOO_SHORT_INITIAL_DGRAM,
	QUIC_ST_RETRY_SENT,
	QUIC_ST_RETRY_VALIDATED,
	QUIC_ST_RETRY_ERRORS,
	QUIC_ST_CONN_OPENINGS,
	QUIC_ST_HDSHK_FAILS,
	/* Transport errors */
	QUIC_ST_TRANSP_ERR_NO_ERROR,
	QUIC_ST_TRANSP_ERR_INTERNAL_ERROR,
	QUIC_ST_TRANSP_ERR_CONNECTION_REFUSED,
	QUIC_ST_TRANSP_ERR_FLOW_CONTROL_ERROR,
	QUIC_ST_TRANSP_ERR_STREAM_LIMIT_ERROR,
	QUIC_ST_TRANSP_ERR_STREAM_STATE_ERROR,
	QUIC_ST_TRANSP_ERR_FINAL_SIZE_ERROR,
	QUIC_ST_TRANSP_ERR_FRAME_ENCODING_ERROR,
	QUIC_ST_TRANSP_ERR_TRANSPORT_PARAMETER_ERROR,
	QUIC_ST_TRANSP_ERR_CONNECTION_ID_LIMIT_ERROR,
	QUIC_ST_TRANSP_ERR_PROTOCOL_VIOLATION,
	QUIC_ST_TRANSP_ERR_INVALID_TOKEN,
	QUIC_ST_TRANSP_ERR_APPLICATION_ERROR,
	QUIC_ST_TRANSP_ERR_CRYPTO_BUFFER_EXCEEDED,
	QUIC_ST_TRANSP_ERR_KEY_UPDATE_ERROR,
	QUIC_ST_TRANSP_ERR_AEAD_LIMIT_REACHED,
	QUIC_ST_TRANSP_ERR_NO_VIABLE_PATH,
	QUIC_ST_TRANSP_ERR_CRYPTO_ERROR,
	QUIC_ST_TRANSP_ERR_UNKNOWN_ERROR,
	/* Stream related counters */
	QUIC_ST_DATA_BLOCKED,
	QUIC_ST_STREAM_DATA_BLOCKED,
	QUIC_ST_STREAMS_DATA_BLOCKED_BIDI,
	QUIC_ST_STREAMS_DATA_BLOCKED_UNI,
	QUIC_STATS_COUNT /* must be the last */
};

struct quic_counters {
	long long dropped_pkt;       /* total number of dropped packets */
	long long too_short_initial_dgram; /* total number of too short datagrams with Initial packets */
	long long retry_sent;        /* total number of Retry sent */
	long long retry_validated;   /* total number of validated Retry tokens */
	long long retry_error;       /* total number of Retry token errors */
	long long conn_opening;      /* total number of connection openings */
	long long hdshk_fail;        /* total number of handshake failures */
	/* Transport errors */
	long long quic_transp_err_no_error; /* total number of NO_ERROR connection errors */
	long long quic_transp_err_internal_error; /* total number of INTERNAL_ERROR connection errors */
	long long quic_transp_err_connection_refused; /* total number of CONNECTION_REFUSED connection errors */
	long long quic_transp_err_flow_control_error; /* total number of FLOW_CONTROL_ERROR connection errors */
	long long quic_transp_err_stream_limit_error; /* total number of STREAM_LIMIT_ERROR connection errors */
	long long quic_transp_err_stream_state_error; /* total number of STREAM_STATE_ERROR connection errors */
	long long quic_transp_err_final_size_error;          /* total number of FINAL_SIZE_ERROR connection errors */
	long long quic_transp_err_frame_encoding_error;      /* total number of FRAME_ENCODING_ERROR connection errors */
	long long quic_transp_err_transport_parameter_error; /* total number of TRANSPORT_PARAMETER_ERROR connection errors */
	long long quic_transp_err_connection_id_limit;       /* total number of CONNECTION_ID_LIMIT_ERROR connection errors */
	long long quic_transp_err_protocol_violation;        /* total number of PROTOCOL_VIOLATION connection errors */
	long long quic_transp_err_invalid_token;             /* total number of INVALID_TOKEN connection errors */
	long long quic_transp_err_application_error;         /* total number of APPLICATION_ERROR connection errors */
	long long quic_transp_err_crypto_buffer_exceeded;    /* total number of CRYPTO_BUFFER_EXCEEDED connection errors */
	long long quic_transp_err_key_update_error;   /* total number of KEY_UPDATE_ERROR connection errors */
	long long quic_transp_err_aead_limit_reached; /* total number of AEAD_LIMIT_REACHED connection errors */
	long long quic_transp_err_no_viable_path;     /* total number of NO_VIABLE_PATH connection errors */
	long long quic_transp_err_crypto_error;       /* total number of CRYPTO_ERROR connection errors */
	long long quic_transp_err_unknown_error;      /* total number of UNKNOWN_ERROR connection errors */
	/* Streams related counters */
	long long data_blocked;              /* total number of times DATA_BLOCKED frame was received */
	long long stream_data_blocked;       /* total number of times STEAM_DATA_BLOCKED frame was received */
	long long streams_data_blocked_bidi; /* total number of times STREAMS_DATA_BLOCKED_BIDI frame was received */
	long long streams_data_blocked_uni;  /* total number of times STREAMS_DATA_BLOCKED_UNI frame was received */
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_STATS_T_H */
