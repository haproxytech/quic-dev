#ifndef _HAPROXY_MUX_QUIC_H
#define _HAPROXY_MUX_QUIC_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/mux_quic-t.h>
#include <haproxy/xprt_quic-t.h>

struct qcs *qcs_new(struct qcc *qcc, uint64_t id, enum qcs_type type);
void uni_qcs_free(struct qcs *qcs);

struct buffer *qc_get_buf(struct qcs *qcs, struct buffer *bptr);

int qcs_subscribe(struct qcs *qcs, int event_type, struct wait_event *es);
void qcs_notify_recv(struct qcs *qcs);
void qcs_notify_send(struct qcs *qcs);

int qcc_recv(struct qcc *qcc, uint64_t id, uint64_t len, uint64_t offset,
             char fin, char *data, struct qcs **out_qcs);
int qcc_decode_qcs(struct qcc *qcc, struct qcs *qcs);
void qcc_streams_sent_done(struct qcs *qcs, uint64_t data, uint64_t offset);

/* Bit shift to get the stream sub ID for internal use which is obtained
 * shifting the stream IDs by this value, knowing that the
 * QCS_ID_TYPE_SHIFT less significant bits identify the stream ID
 * types (client initiated bidirectional, server initiated bidirectional,
 * client initiated unidirectional, server initiated bidirectional).
 * Note that there is no reference to such stream sub IDs in the RFC.
 */
#define QCS_ID_TYPE_MASK         0x3
#define QCS_ID_TYPE_SHIFT          2
/* The less significant bit of a stream ID is set for a server initiated stream */
#define QCS_ID_SRV_INTIATOR_BIT  0x1
/* This bit is set for unidirectional streams */
#define QCS_ID_DIR_BIT           0x2

static inline enum qcs_type qcs_id_type(uint64_t id)
{
	return id & QCS_ID_TYPE_MASK;
}

/* Return true if stream has been opened locally. */
static inline int quic_stream_is_local(struct qcc *qcc, uint64_t id)
{
	return conn_is_back(qcc->conn) == !(id & QCS_ID_SRV_INTIATOR_BIT);
}

/* Return true if stream is opened by peer. */
static inline int quic_stream_is_remote(struct qcc *qcc, uint64_t id)
{
	return !quic_stream_is_local(qcc, id);
}

static inline int quic_stream_is_uni(uint64_t id)
{
	return id & QCS_ID_DIR_BIT;
}

static inline int quic_stream_is_bidi(uint64_t id)
{
	return !quic_stream_is_uni(id);
}

struct eb64_node *qcc_get_qcs(struct qcc *qcc, uint64_t id);

/* Install the <app_ops> applicative layer of a QUIC connection on mux <qcc>.
 * Returns 0 on success else non-zero.
 */
static inline int qcc_install_app_ops(struct qcc *qcc,
                                      const struct qcc_app_ops *app_ops)
{
	qcc->app_ops = app_ops;
	if (qcc->app_ops->init && !qcc->app_ops->init(qcc))
		return 1;

	if (qcc->app_ops->finalize)
		qcc->app_ops->finalize(qcc->ctx);

	return 0;
}

#endif /* USE_QUIC */

#endif /* _HAPROXY_MUX_QUIC_H */
