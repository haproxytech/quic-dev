/*
 * include/haproxy/quic_conn.h
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_CONN_H
#define _HAPROXY_QUIC_CONN_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>

#include <import/eb64tree.h>
#include <import/ebmbtree.h>

#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/ncbuf-t.h>
#include <haproxy/net_helper.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ticks.h>

#include <haproxy/listener.h>
#include <haproxy/proto_quic.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/mux_quic.h>

#include <openssl/rand.h>

extern struct pool_head *pool_head_quic_connection_id;

int qc_conn_finalize(struct quic_conn *qc, int server);
int ssl_quic_initial_ctx(struct bind_conf *bind_conf);
struct quic_cstream *quic_cstream_new(struct quic_conn *qc);
void quic_cstream_free(struct quic_cstream *cs);
void quic_free_arngs(struct quic_conn *qc, struct quic_arngs *arngs);
struct quic_cstream *quic_cstream_new(struct quic_conn *qc);
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state);

struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                        struct quic_conn *qc,
                                        const struct quic_cid *orig,
                                        const struct sockaddr_storage *addr);
void qc_cc_err_count_inc(struct quic_conn *qc, struct quic_frame *frm);
int qc_h3_request_reject(struct quic_conn *qc, uint64_t id);
int qc_build_new_connection_id_frm(struct quic_conn *qc,
                                   struct quic_connection_id *conn_id);
struct quic_conn *qc_new_conn(const struct quic_version *qv, int ipv4,
                              struct quic_cid *dcid, struct quic_cid *scid,
                              const struct quic_cid *token_odcid,
                              struct quic_connection_id *conn_id,
                              struct sockaddr_storage *local_addr,
                              struct sockaddr_storage *peer_addr,
                              int server, int token, void *owner);
const struct quic_version *qc_supported_version(uint32_t version);
int quic_peer_validated_addr(struct quic_conn *qc);
void qc_set_timer(struct quic_conn *qc);
void qc_detach_th_ctx_list(struct quic_conn *qc, int closing);
void qc_idle_timer_do_rearm(struct quic_conn *qc, int arm_ack);
void qc_idle_timer_rearm(struct quic_conn *qc, int read, int arm_ack);
void qc_check_close_on_released_mux(struct quic_conn *qc);
int quic_stateless_reset_token_cpy(unsigned char *pos, size_t len,
                                   const unsigned char *salt, size_t saltlen);

/* Return the long packet type matching with <qv> version and <type> */
static inline int quic_pkt_type(int type, uint32_t version)
{
	if (version != QUIC_PROTOCOL_VERSION_2)
		return type;

	switch (type) {
	case QUIC_PACKET_TYPE_INITIAL:
		return 1;
	case QUIC_PACKET_TYPE_0RTT:
		return 2;
	case QUIC_PACKET_TYPE_HANDSHAKE:
		return 3;
	case QUIC_PACKET_TYPE_RETRY:
		return 0;
	}

	return -1;
}

static inline int qc_is_listener(struct quic_conn *qc)
{
	return qc->flags & QUIC_FL_CONN_LISTENER;
}

/* Copy <src> QUIC CID to <dst>.
 * This is the responsibility of the caller to check there is enough room in
 * <dst> to copy <src>.
 * Always succeeds.
 */
static inline void quic_cid_cpy(struct quic_cid *dst, const struct quic_cid *src)
{
	memcpy(dst->data, src->data, src->len);
	dst->len = src->len;
}

/* Copy <saddr> socket address data into <buf> buffer.
 * This is the responsibility of the caller to check the output buffer is big
 * enough to contain these socket address data.
 * Return the number of bytes copied.
 */
static inline size_t quic_saddr_cpy(unsigned char *buf,
                                    const struct sockaddr_storage *saddr)
{
	void *port, *addr;
	unsigned char *p;
	size_t port_len, addr_len;

	p = buf;
	if (saddr->ss_family == AF_INET6) {
		port = &((struct sockaddr_in6 *)saddr)->sin6_port;
		addr = &((struct sockaddr_in6 *)saddr)->sin6_addr;
		port_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_port;
		addr_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_addr;
	}
	else {
		port = &((struct sockaddr_in *)saddr)->sin_port;
		addr = &((struct sockaddr_in *)saddr)->sin_addr;
		port_len = sizeof ((struct sockaddr_in *)saddr)->sin_port;
		addr_len = sizeof ((struct sockaddr_in *)saddr)->sin_addr;
	}
	memcpy(p, port, port_len);
	p += port_len;
	memcpy(p, addr, addr_len);
	p += addr_len;

	return p - buf;
}

/* Dump the QUIC connection ID value if present (non null length). Used only for
 * debugging purposes.
 * Always succeeds.
 */
static inline void quic_cid_dump(struct buffer *buf,
                                 const struct quic_cid *cid)
{
	int i;

	chunk_appendf(buf, "(%d", cid->len);
	if (cid->len)
		chunk_appendf(buf, ",");
	for (i = 0; i < cid->len; i++)
		chunk_appendf(buf, "%02x", cid->data[i]);
	chunk_appendf(buf, ")");
}

/* Return tree index where <cid> is stored. */
static inline uchar _quic_cid_tree_idx(const unsigned char *cid)
{
	return cid[0];
}

/* Return tree index where <cid> is stored. */
static inline uchar quic_cid_tree_idx(const struct quic_cid *cid)
{
	return _quic_cid_tree_idx(cid->data);
}

/* Insert <conn_id> into global CID tree as a thread-safe operation. */
static inline void quic_cid_insert(struct quic_connection_id *conn_id)
{
	const uchar idx = quic_cid_tree_idx(&conn_id->cid);
	struct quic_cid_tree *tree = &quic_cid_trees[idx];

	HA_RWLOCK_WRLOCK(QC_CID_LOCK, &tree->lock);
	ebmb_insert(&tree->root, &conn_id->node, conn_id->cid.len);
	HA_RWLOCK_WRUNLOCK(QC_CID_LOCK, &tree->lock);
}

/* Remove <conn_id> from global CID tree as a thread-safe operation. */
static inline void quic_cid_delete(struct quic_connection_id *conn_id)
{
	const uchar idx = quic_cid_tree_idx(&conn_id->cid);
	struct quic_cid_tree __maybe_unused *tree = &quic_cid_trees[idx];

	HA_RWLOCK_WRLOCK(QC_CID_LOCK, &tree->lock);
	ebmb_delete(&conn_id->node);
	HA_RWLOCK_WRUNLOCK(QC_CID_LOCK, &tree->lock);
}

/* Free the CIDs attached to <conn> QUIC connection. */
static inline void free_quic_conn_cids(struct quic_conn *conn)
{
	struct eb64_node *node;

	if (!conn->cids)
		return;

	node = eb64_first(conn->cids);
	while (node) {
		struct quic_connection_id *conn_id;

		conn_id = eb64_entry(node, struct quic_connection_id, seq_num);

		/* remove the CID from the receiver tree */
		quic_cid_delete(conn_id);

		/* remove the CID from the quic_conn tree */
		node = eb64_next(node);
		eb64_delete(&conn_id->seq_num);
		pool_free(pool_head_quic_connection_id, conn_id);
	}
}

/* Move all the connection IDs from <conn> QUIC connection to <cc_conn> */
static inline void quic_conn_mv_cids_to_cc_conn(struct quic_cc_conn *cc_conn,
                                                struct quic_conn *conn)
{
	struct eb64_node *node;

	node = eb64_first(conn->cids);
	while (node) {
		struct quic_connection_id *conn_id;

		conn_id = eb64_entry(node, struct quic_connection_id, seq_num);
		conn_id->qc = (struct quic_conn *)cc_conn;
		node = eb64_next(node);
	}

}

/* Copy <src> new connection ID information to <dst> NEW_CONNECTION_ID frame.
 * Always succeeds.
 */
static inline void quic_connection_id_to_frm_cpy(struct quic_frame *dst,
                                                 struct quic_connection_id *src)
{
	struct qf_new_connection_id *ncid_frm = &dst->new_connection_id;

	ncid_frm->seq_num = src->seq_num.key;
	ncid_frm->retire_prior_to = src->retire_prior_to;
	ncid_frm->cid.len = src->cid.len;
	ncid_frm->cid.data = src->cid.data;
	ncid_frm->stateless_reset_token = src->stateless_reset_token;
}

/* Return a 32-bits integer in <val> from QUIC packet with <buf> as address.
 * Makes <buf> point to the data after this 32-bits value if succeeded.
 * Note that these 32-bits integers are network bytes ordered.
 * Returns 0 if failed (not enough data in the buffer), 1 if succeeded.
 */
static inline int quic_read_uint32(uint32_t *val,
                                   const unsigned char **buf,
                                   const unsigned char *end)
{
	if (end - *buf < sizeof *val)
		return 0;

	*val = ntohl(*(uint32_t *)*buf);
	*buf += sizeof *val;

	return 1;
}

/* Write a 32-bits integer to a buffer with <buf> as address.
 * Make <buf> point to the data after this 32-buts value if succeeded.
 * Note that these 32-bits integers are networkg bytes ordered.
 * Returns 0 if failed (not enough room in the buffer), 1 if succeeded.
 */
static inline int quic_write_uint32(unsigned char **buf,
                                    const unsigned char *end, uint32_t val)
{
	if (end - *buf < sizeof val)
		return 0;

	*(uint32_t *)*buf = htonl(val);
	*buf += sizeof val;

	return 1;
}


/* Return the maximum number of bytes we must use to completely fill a
 * buffer with <sz> as size for a data field of bytes prefixed by its QUIC
 * variable-length (may be 0).
 * Also put in <*len_sz> the size of this QUIC variable-length.
 * So after returning from this function we have : <*len_sz> + <ret> <= <sz>
 * (<*len_sz> = { max(i), i + ret <= <sz> }) .
 */
static inline size_t max_available_room(size_t sz, size_t *len_sz)
{
	size_t sz_sz, ret;
	size_t diff;

	sz_sz = quic_int_getsize(sz);
	if (sz <= sz_sz)
		return 0;

	ret = sz - sz_sz;
	*len_sz = quic_int_getsize(ret);
	/* Difference between the two sizes. Note that <sz_sz> >= <*len_sz>. */
	diff = sz_sz - *len_sz;
	if (unlikely(diff > 0)) {
		/* Let's try to take into an account remaining bytes.
		 *
		 *                  <----------------> <sz_sz>
		 *  <--------------><-------->  +----> <max_int>
		 *       <ret>       <len_sz>   |
		 *  +---------------------------+-----------....
		 *  <--------------------------------> <sz>
		 */
		size_t max_int = quic_max_int(*len_sz);

		if (max_int + *len_sz <= sz)
			ret = max_int;
		else
			ret = sz - diff;
	}

	return ret;
}

/* This function computes the maximum data we can put into a buffer with <sz> as
 * size prefixed with a variable-length field "Length" whose value is the
 * remaining data length, already filled of <ilen> bytes which must be taken
 * into an account by "Length" field, and finally followed by the data we want
 * to put in this buffer prefixed again by a variable-length field.
 * <sz> is the size of the buffer to fill.
 * <ilen> the number of bytes already put after the "Length" field.
 * <dlen> the number of bytes we want to at most put in the buffer.
 * Also set <*dlen_sz> to the size of the data variable-length we want to put in
 * the buffer. This is typically this function which must be used to fill as
 * much as possible a QUIC packet made of only one CRYPTO or STREAM frames.
 * Returns this computed size if there is enough room in the buffer, 0 if not.
 */
static inline size_t max_stream_data_size(size_t sz, size_t ilen, size_t dlen)
{
	size_t ret, len_sz, dlen_sz;

	/*
	 * The length of variable-length QUIC integers are powers of two.
	 * Look for the first 3length" field value <len_sz> which match our need.
	 * As we must put <ilen> bytes in our buffer, the minimum value for
	 * <len_sz> is the number of bytes required to encode <ilen>.
	 */
	for (len_sz = quic_int_getsize(ilen);
	     len_sz <= QUIC_VARINT_MAX_SIZE;
	     len_sz <<= 1) {
		if (sz < len_sz + ilen)
			return 0;

		ret = max_available_room(sz - len_sz - ilen, &dlen_sz);
		if (!ret)
			return 0;

		/* Check that <*len_sz> matches <ret> value */
		if (len_sz + ilen + dlen_sz + ret <= quic_max_int(len_sz))
			return ret < dlen ? ret : dlen;
	}

	return 0;
}

/* Return the length in bytes of <pn> packet number depending on
 * <largest_acked_pn> the largest ackownledged packet number.
 */
static inline size_t quic_packet_number_length(int64_t pn,
                                               int64_t largest_acked_pn)
{
	int64_t max_nack_pkts;

	/* About packet number encoding, the RFC says:
	 * The sender MUST use a packet number size able to represent more than
	 * twice as large a range than the difference between the largest
	 * acknowledged packet and packet number being sent.
	 */
	max_nack_pkts = 2 * (pn - largest_acked_pn) + 1;
	if (max_nack_pkts > 0xffffff)
		return 4;
	if (max_nack_pkts > 0xffff)
		return 3;
	if (max_nack_pkts > 0xff)
		return 2;

	return 1;
}

/* Encode <pn> packet number with <pn_len> as length in byte into a buffer with
 * <buf> as current copy address and <end> as pointer to one past the end of
 * this buffer. This is the responsibility of the caller to check there is
 * enough room in the buffer to copy <pn_len> bytes.
 * Never fails.
 */
static inline int quic_packet_number_encode(unsigned char **buf,
                                            const unsigned char *end,
                                            uint64_t pn, size_t pn_len)
{
	if (end - *buf < pn_len)
		return 0;

	/* Encode the packet number. */
	switch (pn_len) {
	case 1:
		**buf = pn;
		break;
	case 2:
		write_n16(*buf, pn);
		break;
	case 3:
		(*buf)[0] = pn >> 16;
		(*buf)[1] = pn >> 8;
		(*buf)[2] = pn;
		break;
	case 4:
		write_n32(*buf, pn);
		break;
	}
	*buf += pn_len;

	return 1;
}

/* Returns the <ack_delay> field value in milliseconds from <ack_frm> ACK frame for
 * <conn> QUIC connection. Note that the value of <ack_delay> coming from
 * ACK frame is in microseconds.
 */
static inline unsigned int quic_ack_delay_ms(struct qf_ack *ack_frm,
                                             struct quic_conn *conn)
{
	return (ack_frm->ack_delay << conn->tx.params.ack_delay_exponent) / 1000;
}

/* Returns the <ack_delay> field value in microsecond to be set in an ACK frame
 * depending on the time the packet with a new largest packet number was received.
 */
static inline uint64_t quic_compute_ack_delay_us(unsigned int time_received,
                                                 struct quic_conn *conn)
{
	return ((now_ms - time_received) * 1000) >> conn->tx.params.ack_delay_exponent;
}

/* Initialize <p> QUIC network path depending on <ipv4> boolean
 * which is true for an IPv4 path, if not false for an IPv6 path.
 */
static inline void quic_path_init(struct quic_path *path, int ipv4,
                                  struct quic_cc_algo *algo, struct quic_conn *qc)
{
	unsigned int max_dgram_sz;

	max_dgram_sz = ipv4 ? QUIC_INITIAL_IPV4_MTU : QUIC_INITIAL_IPV6_MTU;
	quic_loss_init(&path->loss);
	path->mtu = max_dgram_sz;
	path->cwnd = QUIC_MIN(10 * max_dgram_sz, QUIC_MAX(max_dgram_sz << 1, 14720U));
	path->mcwnd = path->cwnd;
	path->min_cwnd = max_dgram_sz << 1;
	path->prep_in_flight = 0;
	path->in_flight = 0;
	path->ifae_pkts = 0;
	quic_cc_init(&path->cc, algo, qc);
}

/* Return the remaining <room> available on <path> QUIC path for prepared data
 * (before being sent). Almost the same that for the QUIC path room, except that
 * here this is the data which have been prepared which are taken into an account.
 */
static inline size_t quic_path_prep_data(struct quic_path *path)
{
	if (path->prep_in_flight > path->cwnd)
		return 0;

	return path->cwnd - path->prep_in_flight;
}

/* Return the number of bytes which may be sent from <qc> connection when
 * it has not already been validated. Note that this is the responsability
 * of the caller to check that the case with quic_peer_validated_addr().
 * This latter BUG_ON() if 3 * qc->rx.bytes < qc->tx.prep_bytes.
 */
static inline size_t quic_may_send_bytes(struct quic_conn *qc)
{
	return 3 * qc->bytes.rx - qc->bytes.prep;
}

/* CRYPTO data buffer handling functions. */
static inline unsigned char *c_buf_getpos(struct quic_enc_level *qel, uint64_t offset)
{
	int idx;
	unsigned char *data;

	idx = offset >> QUIC_CRYPTO_BUF_SHIFT;
	data = qel->tx.crypto.bufs[idx]->data;
	return data + (offset & QUIC_CRYPTO_BUF_MASK);
}

/* Returns 1 if the CRYPTO buffer at <qel> encryption level has been
 * consumed (sent to the peer), 0 if not.
 */
static inline int c_buf_consumed(struct quic_enc_level *qel)
{
	return qel->tx.crypto.offset == qel->tx.crypto.sz;
}

/* Return 1 if <pkt> header form is long, 0 if not. */
static inline int qc_pkt_long(const struct quic_rx_packet *pkt)
{
	return pkt->type != QUIC_PACKET_TYPE_SHORT;
}

/* Return 1 if there is RX packets for <qel> QUIC encryption level, 0 if not */
static inline int qc_el_rx_pkts(struct quic_enc_level *qel)
{
	int ret;

	ret = !eb_is_empty(&qel->rx.pkts);

	return ret;
}

/* Increment the reference counter of <pkt> */
static inline void quic_rx_packet_refinc(struct quic_rx_packet *pkt)
{
	pkt->refcnt++;
}

/* Decrement the reference counter of <pkt> while remaining positive */
static inline void quic_rx_packet_refdec(struct quic_rx_packet *pkt)
{
	if (pkt->refcnt)
		pkt->refcnt--;
}

/* Delete all RX packets for <qel> QUIC encryption level */
static inline void qc_el_rx_pkts_del(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt =
			eb64_entry(node, struct quic_rx_packet, pn_node);

		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
		quic_rx_packet_refdec(pkt);
	}
}

static inline void qc_list_qel_rx_pkts(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(node, struct quic_rx_packet, pn_node);
		fprintf(stderr, "pkt@%p type=%d pn=%llu\n",
		        pkt, pkt->type, (ull)pkt->pn_node.key);
		node = eb64_next(node);
	}
}

void chunk_frm_appendf(struct buffer *buf, const struct quic_frame *frm);

void quic_set_connection_close(struct quic_conn *qc, const struct quic_err err);
void quic_set_tls_alert(struct quic_conn *qc, int alert);
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len);
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len);
int quic_get_dgram_dcid(unsigned char *buf, const unsigned char *end,
                        unsigned char **dcid, size_t *dcid_len);
struct quic_cid quic_derive_cid(const struct quic_cid *orig,
                                const struct sockaddr_storage *addr);
int quic_get_cid_tid(const unsigned char *cid, size_t cid_len,
                     const struct sockaddr_storage *cli_addr,
                     unsigned char *buf, size_t buf_len);
int qc_send_mux(struct quic_conn *qc, struct list *frms);

void qc_notify_err(struct quic_conn *qc);
int qc_notify_send(struct quic_conn *qc);

void qc_check_close_on_released_mux(struct quic_conn *qc);

void quic_conn_release(struct quic_conn *qc);

void qc_kill_conn(struct quic_conn *qc);

int qc_parse_hd_form(struct quic_rx_packet *pkt,
                     unsigned char **buf, const unsigned char *end);
int quic_dgram_parse(struct quic_dgram *dgram, struct quic_conn *qc,
                     struct listener *li);

/* Wake up every QUIC connections on closing/draining state if process stopping
 * is active. They will be immediately released so this ensures haproxy process
 * stopping is not delayed by them.
 */
static inline void quic_handle_stopping(void)
{
	struct quic_conn *qc;

	if (stopping) {
		list_for_each_entry(qc, &th_ctx->quic_conns_clo, el_th_ctx)
			task_wakeup(qc->idle_timer_task, TASK_WOKEN_OTHER);
	}
}

int qc_set_tid_affinity(struct quic_conn *qc, uint new_tid, struct listener *new_li);
void qc_finalize_affinity_rebind(struct quic_conn *qc);

uint64_t qc_cwnd(const struct quic_conn *qc);

/* Function pointer that can be used to compute a hash from first generated CID (derived from ODCID) */
extern uint64_t (*quic_hash64_from_cid)(const unsigned char *cid, int size, const unsigned char *secret, size_t secretlen);
/* Function pointer that can be used to derive a new CID from the previously computed hash */
extern void (*quic_newcid_from_hash64)(unsigned char *cid, int size, uint64_t hash, const unsigned char *secret, size_t secretlen);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CONN_H */
