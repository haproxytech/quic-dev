#ifndef _HAPROXY_MUX_QUIC_T_H
#define _HAPROXY_MUX_QUIC_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/htx-t.h>
#include <haproxy/list-t.h>
#include <haproxy/ncbuf-t.h>
#include <haproxy/quic_frame-t.h>
#include <haproxy/quic_stream-t.h>
#include <haproxy/stconn-t.h>

/* Stream types */
enum qcs_type {
	QCS_CLT_BIDI,
	QCS_SRV_BIDI,
	QCS_CLT_UNI,
	QCS_SRV_UNI,

	/* Must be the last one */
	QCS_MAX_TYPES
};

#define QC_CF_ERRL      0x00000001 /* fatal error detected locally, connection should be closed soon */
#define QC_CF_ERRL_DONE 0x00000002 /* local error properly handled, connection can be released */
#define QC_CF_BLK_MFCTL 0x00000004 /* sending blocked due to connection flow-control */
#define QC_CF_CONN_FULL 0x00000008 /* no stream buffers available on connection */
#define QC_CF_APP_SHUT  0x00000010 /* Application layer shutdown done. */
#define QC_CF_ERR_CONN  0x00000020 /* fatal error reported by transport layer */
#define QC_CF_CONN_SHUT 0x00000040 /* empty buffer on read after a fatal transport error */

struct qcc {
	struct connection *conn;
	uint64_t nb_sc; /* number of attached stream connectors */
	uint64_t nb_hreq; /* number of in-progress http requests */
	uint32_t flags; /* QC_CF_* */

	struct {
		uint64_t max_streams; /* maximum number of concurrent streams */
		uint64_t nb_streams;  /* Number of open streams */
		struct {
			uint64_t max_data; /* Maximum number of bytes which may be received */
			uint64_t bytes;    /* Number of bytes received */
		} rx;
		struct {
			uint64_t max_data; /* Maximum number of bytes which may be sent */
			uint64_t bytes;    /* Number of bytes sent */
		} tx;
	} strms[QCS_MAX_TYPES];

	/* flow-control fields set by us enforced on our side. */
	struct {
		struct list frms; /* prepared frames related to flow-control  */

		uint64_t ms_bidi_init; /* max initial sub-ID of bidi stream allowed for the peer */
		uint64_t ms_bidi; /* max sub-ID of bidi stream allowed for the peer */
		uint64_t cl_bidi_r; /* total count of closed remote bidi stream since last MAX_STREAMS emission */

		uint64_t ms_uni; /* max sub-ID of uni stream allowed for the peer */

		uint64_t msd_bidi_l; /* initial max-stream-data on local bidi streams */
		uint64_t msd_bidi_r; /* initial max-stream-data on remote bidi streams */
		uint64_t msd_uni_r; /* initial max-stream-data on remote uni streams */

		uint64_t md; /* current max-data allowed for the peer */
		uint64_t md_init; /* initial max-data */
		uint64_t offsets_recv; /* sum of offsets received */
		uint64_t offsets_consume; /* sum of offsets consumed */
	} lfctl;

	/* flow-control fields set by the peer which we must respect. */
	struct {
		uint64_t md; /* connection flow control limit updated on MAX_DATA frames reception */
		uint64_t msd_bidi_l; /* initial max-stream-data from peer on local bidi streams */
		uint64_t msd_bidi_r; /* initial max-stream-data from peer on remote bidi streams */
		uint64_t msd_uni_l; /* initial max-stream-data from peer on local uni streams */
	} rfctl;

	struct {
		uint64_t max_data; /* Maximum number of bytes which may be received */
	} rx;
	struct {
		uint64_t offsets; /* sum of all offsets prepared */
		uint64_t sent_offsets; /* sum of all offset sent */
	} tx;

	uint64_t largest_bidi_r; /* largest remote bidi stream ID opened. */
	uint64_t largest_uni_r;  /* largest remote uni stream ID opened. */
	uint64_t next_bidi_l; /* next stream ID to use for local bidi stream */
	uint64_t next_uni_l;  /* next stream ID to use for local uni stream */

	struct eb_root streams_by_id; /* all active streams by their ID */

	struct list send_retry_list; /* list of qcs eligible to send retry */
	struct list send_list; /* list of qcs ready to send (STREAM, STOP_SENDING or RESET_STREAM emission) */

	struct wait_event wait_event;  /* To be used if we're waiting for I/Os */

	struct proxy *proxy;

	/* haproxy timeout management */
	struct task *task;
	struct list opening_list; /* list of not already attached streams (http-request timeout) */
	int timeout;
	int shut_timeout;
	int idle_start; /* base time for http-keep-alive timeout */
	struct quic_err err; /* code for locally detected error */

	const struct qcc_app_ops *app_ops;
	void *ctx; /* Application layer context */
};

#define QC_SF_NONE              0x00000000
#define QC_SF_SIZE_KNOWN        0x00000001  /* last frame received for this stream */
#define QC_SF_FIN_STREAM        0x00000002  /* FIN bit must be set for last frame of the stream */
#define QC_SF_BLK_MROOM         0x00000004  /* app layer is blocked waiting for room in the qcs.tx.buf */
#define QC_SF_DETACH            0x00000008  /* sc is detached but there is remaining data to send */
#define QC_SF_BLK_SFCTL         0x00000010  /* stream blocked due to stream flow control limit */
#define QC_SF_DEM_FULL          0x00000020  /* demux blocked on request channel buffer full */
#define QC_SF_READ_ABORTED      0x00000040  /* Rx closed using STOP_SENDING*/
#define QC_SF_TO_RESET          0x00000080  /* a RESET_STREAM must be sent */
#define QC_SF_HREQ_RECV         0x00000100  /* a full HTTP request has been received */
#define QC_SF_TO_STOP_SENDING   0x00000200  /* a STOP_SENDING must be sent */
#define QC_SF_UNKNOWN_PL_LENGTH 0x00000400  /* HTX EOM may be missing from the stream layer */

/* Maximum size of stream Rx buffer. */
#define QC_S_RX_BUF_SZ   (global.tune.bufsize - NCB_RESERVED_SZ)

/* QUIC stream states
 *
 * On initialization a stream is put on idle state. It is opened as soon as
 * data has been successfully sent or received on it.
 *
 * A bidirectional stream has two channels which can be closed separately. The
 * local channel is closed when the STREAM frame with FIN or a RESET_STREAM has
 * been emitted. The remote channel is closed as soon as all data from the peer
 * has been received. The stream goes instantely to the close state once both
 * channels are closed.
 *
 * A unidirectional stream has only one channel of communication. Thus, it does
 * not use half closed states and transition directly from open to close state.
 */
enum qcs_state {
	QC_SS_IDLE = 0, /* initial state */
	QC_SS_OPEN,     /* opened */
	QC_SS_HLOC,     /* half-closed local */
	QC_SS_HREM,     /* half-closed remote */
	QC_SS_CLO,      /* closed */
} __attribute__((packed));

struct qcs {
	struct qcc *qcc;
	struct sedesc *sd;
	uint32_t flags;      /* QC_SF_* */
	enum qcs_state st;   /* QC_SS_* state */
	void *ctx;           /* app-ops context */

	struct {
		uint64_t offset; /* absolute current base offset of ncbuf */
		uint64_t offset_max; /* maximum absolute offset received */
		struct ncbuf ncbuf; /* receive buffer - can handle out-of-order offset frames */
		struct buffer app_buf; /* receive buffer used by stconn layer */
		uint64_t msd; /* current max-stream-data limit to enforce */
		uint64_t msd_init; /* initial max-stream-data */
	} rx;
	struct {
		uint64_t offset; /* last offset of data ready to be sent */
		uint64_t sent_offset; /* last offset sent by transport layer */
		struct buffer buf; /* transmit buffer before sending via xprt */
		uint64_t msd; /* fctl bytes limit to respect on emission */
	} tx;

	struct eb64_node by_id;
	uint64_t id;
	struct qc_stream_desc *stream;

	struct list el; /* element of qcc.send_retry_list */
	struct list el_send; /* element of qcc.send_list */
	struct list el_opening; /* element of qcc.opening_list */

	struct wait_event wait_event;
	struct wait_event *subs;

	uint64_t err; /* error code to transmit via RESET_STREAM */

	int start; /* base timestamp for http-request timeout */
};

/* Used as qcc_app_ops.close callback argument. */
enum qcc_app_ops_close_side {
	QCC_APP_OPS_CLOSE_SIDE_RD, /* Read channel closed (RESET_STREAM received). */
	QCC_APP_OPS_CLOSE_SIDE_WR /* Write channel closed (STOP_SENDING received). */
};

/* QUIC application layer operations */
struct qcc_app_ops {
	int (*init)(struct qcc *qcc);
	int (*attach)(struct qcs *qcs, void *conn_ctx);
	ssize_t (*decode_qcs)(struct qcs *qcs, struct buffer *b, int fin);
	size_t (*snd_buf)(struct qcs *qcs, struct htx *htx, size_t count);
	int (*close)(struct qcs *qcs, enum qcc_app_ops_close_side side);
	void (*detach)(struct qcs *qcs);
	int (*finalize)(void *ctx);
	void (*shutdown)(void *ctx);                    /* Close a connection. */
	void (*release)(void *ctx);
	void (*inc_err_cnt)(void *ctx, int err_code);
};

#endif /* USE_QUIC */

#endif /* _HAPROXY_MUX_QUIC_T_H */
