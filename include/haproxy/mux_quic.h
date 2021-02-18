/*
 * include/haproxy/mux_quic-t.h
 * This file containts prototypes for QUIC mux-demux. 
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

#ifndef _HAPROXY_MUX_QUIC_H
#define _HAPROXY_MUX_QUIC_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/mux_quic-t.h>

struct qcs *qcc_get_stream(struct qcc *qcc, uint64_t id);
struct qcs *qcs_new(struct qcc *qcc, uint64_t id);

/* Return 1 if the stream with <id> as ID attached to <qcc> connection
 * has been locally initiated, 0 if not.
 */
static inline int qc_local_stream_id(struct qcc *qcc, uint64_t id)
{
	if ((objt_listener(qcc->conn->target) && (id & QCS_ID_SRV_INTIATOR_BIT)) ||
	    (objt_server(qcc->conn->target) && !(id & QCS_ID_SRV_INTIATOR_BIT)))
		return 1;

	return 0;
}

/* Return 1 if <qcs> stream  has been locally initiated, 0 if not. */
static inline int qcs_local(struct qcs *qcs)
{
	if ((objt_listener(qcs->qcc->conn->target) && (qcs->id & QCS_ID_SRV_INTIATOR_BIT)) ||
	    (objt_server(qcs->qcc->conn->target) && !(qcs->id & QCS_ID_SRV_INTIATOR_BIT)))
		return 1;

	return 0;
}

/* Return the direction of a stream with <id> as ID. */
static inline enum qcs_dir qcs_id_dir(uint64_t id)
{
	return (id & QCS_ID_DIR_BIT) >> QCS_ID_DIR_BIT_SHIFT;
}

/* Return the direction of <qcs> QUIC stream. */
static inline enum qcs_dir qcs_dir(struct qcs *qcs)
{
	return (qcs->id & QCS_ID_DIR_BIT) >> QCS_ID_DIR_BIT_SHIFT;
}

static inline enum qcs_type qcs_id_type(uint64_t id)
{
	return id & QCS_ID_TYPE_MASK;
}

static inline enum qcs_type qcs_type_from_dir(struct qcc *qcc, enum qcs_dir dir)
{
	return (dir << QCS_ID_DIR_BIT_SHIFT) |
		!!objt_listener(qcc->conn->target) ? QCS_ID_SRV_INTIATOR_BIT : 0;
}

static inline int64_t qcc_wnd(struct qcc *qcc)
{
	return qcc->tx.max_data - qcc->tx.bytes;
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_MUX_QUIC_H */
