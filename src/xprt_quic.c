/*
 * QUIC transport layer over SOCK_DGRAM sockets.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/proxy.h>
#include <proto/quic_frame.h>
#include <proto/quic_tls.h>
#include <proto/ssl_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/trace.h>
#include <proto/xprt_quic.h>

#include <types/global.h>

struct quic_conn_ctx {
	struct connection *conn;
	SSL *ssl;
	BIO *bio;
	int state;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *subs;
};

struct quic_transport_params quid_dflt_transport_params = {
	.max_packet_size    = QUIC_DFLT_MAX_PACKET_SIZE,
	.ack_delay_exponent = QUIC_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay      = QUIC_DFLT_MAX_ACK_DELAY,
};

/* trace source and events */
static void quic_trace(enum trace_level level, uint64_t mask, \
                       const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event quic_trace_events[] = {
#define           QUIC_EV_CONN_NEW       (1ULL <<  0)
	{ .mask = QUIC_EV_CONN_NEW,      .name = "quic_conn_new",     .desc = "new QUIC connection" },
#define           QUIC_EV_CONN_ERR       (1ULL <<  10)
	{ .mask = QUIC_EV_CONN_ERR,      .name = "quic_conn_err",     .desc = "error on QUIC connection" },
	{ /* end */ }
};

static const struct name_desc quic_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { .name="quic", .desc="QUIC transport" },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc quic_trace_decoding[] = {
#define QUIC_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
	{ /* end */ }
};


static struct trace_source trace_quic = {
	.name = IST("quic"),
	.desc = "QUIC xprt",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a connection */
	.default_cb = quic_trace,
	.known_events = quic_trace_events,
	.lockon_args = quic_trace_lockon_args,
	.decoding = quic_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

#define TRACE_SOURCE &trace_quic
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

#if 1
__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...)
{
	int i;
	va_list ap;
	const unsigned char *p;
	char str_buf[2 + 1 + 16 + 1 + 1];

	va_start(ap, title_fmt);
	vfprintf(stderr, title_fmt, ap);
	va_end(ap);

	p = buf;
	str_buf[0] = str_buf[1] = ' ';
	str_buf[2] = '|';

	for (i = 0; i < buflen; i++) {
		if (!(i & 0xf))
			fprintf(stderr, "%08X: ", i);
		fprintf(stderr, " %02x", *p);
		if (isalnum(*p))
			str_buf[(i & 0xf) + 3] = *p;
		else
			str_buf[(i & 0xf) + 3] = '.';
		if ((i & 0xf) == 0xf || i == buflen -1) {
			int k;

			for (k = 0; k < (0x10 - (i & 0xf) - 1); k++)
				fprintf(stderr, "   ");
			str_buf[(i & 0xf) + 4] = '|';
			str_buf[(i & 0xf) + 5 ] = '\0';
			fprintf(stderr, "%s\n", str_buf);
		}
		p++;
	}
}
#else
__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...) {}
#endif

DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));

DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connnection_id_pool", sizeof(struct quic_connection_id));

DECLARE_STATIC_POOL(pool_head_quic_rx_packet, "quic_rx_packet_pool", sizeof(struct quic_rx_packet));

DECLARE_STATIC_POOL(pool_head_quic_conn_ctx, "quic_conn_ctx_pool", sizeof(struct quic_conn_ctx));

DECLARE_STATIC_POOL(pool_head_quic_tx_crypto_frm, "quic_tx_crypto_frm_pool", sizeof(struct quic_tx_crypto_frm));

DECLARE_STATIC_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf_pool", sizeof(struct quic_crypto_buf));

DECLARE_STATIC_POOL(pool_head_quic_frame, "quic_frame_pool", sizeof(struct quic_frame));

static BIO_METHOD *ha_quic_meth;

static ssize_t quic_build_handshake_packet(unsigned char **buf, const unsigned char *end,
                                           const unsigned char **data, const unsigned char *end_data,
                                           uint64_t *offset,
                                           enum quic_tls_enc_level level, struct quic_conn *conn);

static int quic_send_app_packets(struct quic_conn_ctx *ctx);


/*
 * the QUIC traces always expect that arg1, if non-null, is of type connection.
 */
static void quic_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct connection *conn = a1;

	chunk_appendf(&trace_buf, " : conn=%p %p %p %p", conn, a2, a3, a4);
}

int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *read_secret,
                                   const uint8_t *write_secret, size_t secret_len)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct quic_tls_ctx *tls_ctx =
		&conn->quic_conn->enc_levels[ssl_to_quic_enc_level(level)].tls_ctx;
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

	tls_ctx->aead = tls_aead(cipher);
	tls_ctx->md = tls_md(cipher);
	tls_ctx->hp = tls_hp(cipher);

	hexdump(read_secret, secret_len, "read_secret (level %d):\n", level);
	hexdump(write_secret, secret_len, "write_secret:\n");

	if (!quic_tls_derive_packet_protection_keys(tls_ctx->aead, tls_ctx->hp, tls_ctx->md,
	                                            tls_ctx->rx.key, sizeof tls_ctx->rx.key,
	                                            tls_ctx->rx.iv, sizeof tls_ctx->rx.iv,
	                                            tls_ctx->rx.hp_key, sizeof tls_ctx->rx.hp_key,
	                                            read_secret, secret_len)) {
		fprintf(stderr, "%s: RX key derivation failed\n", __func__);
		return 0;
	}

	if (!quic_tls_derive_packet_protection_keys(tls_ctx->aead, tls_ctx->hp, tls_ctx->md,
	                                            tls_ctx->tx.key, sizeof tls_ctx->tx.key,
	                                            tls_ctx->tx.iv, sizeof tls_ctx->tx.iv,
	                                            tls_ctx->tx.hp_key, sizeof tls_ctx->tx.hp_key,
	                                            write_secret, secret_len)) {
		fprintf(stderr, "%s: TX key derivation failed\n", __func__);
		return 0;
	}
	return 1;
}

/*
 * This function copies the CRYPTO data provided by the TLS stack found at <data>
 * with <len> as size in CRYPTO buffers dedicated to store the information about outgoing
 * CRYPTO frames so that to be able to replay the CRYPTO data streams.
 * It fails only if it could not managed to allocate enough CRYPTO buffers to store all the data.
 * Note that CRYPTO data may exist at any encryption level except at 0-RTT.
 */
static int quic_crypto_data_cpy(struct quic_enc_level *qel,
                                const unsigned char *data, size_t len)
{
	struct quic_crypto_buf **qcb;
	/* The remaining byte to store in CRYPTO buffers. */
	size_t *nb_buf;
	unsigned char *pos;

	nb_buf = &qel->tx.crypto.nb_buf;
	qcb = &qel->tx.crypto.bufs[*nb_buf - 1];
	pos = (*qcb)->data + (*qcb)->sz;

	while (len > 0) {
		size_t to_copy;

		to_copy = len > QUIC_CRYPTO_BUF_SZ  - (*qcb)->sz ? QUIC_CRYPTO_BUF_SZ - (*qcb)->sz : len;
		memcpy(pos, data, to_copy);
		/* Increment the total size of this CRYPTO buffers by <to_copy>. */
		qel->tx.crypto.sz += to_copy;
		(*qcb)->sz += to_copy;
		pos += to_copy;
		len -= to_copy;
		data += to_copy;
		if ((*qcb)->sz >= QUIC_CRYPTO_BUF_SZ) {
			struct quic_crypto_buf **tmp;

			tmp = realloc(qel->tx.crypto.bufs, (*nb_buf + 1) * sizeof *qel->tx.crypto.bufs);
			if (tmp) {
				qel->tx.crypto.bufs = tmp;
				qcb = &qel->tx.crypto.bufs[*nb_buf];
				*qcb = pool_alloc(pool_head_quic_crypto_buf);
				if (!*qcb) {
					fprintf(stderr, "%s: crypto allocation failed\n", __func__);
					return 0;
				}
				(*qcb)->sz = 0;
				pos = (*qcb)->data;
				++*nb_buf;
			}
			else {
				/* XXX deallocate everything */
			}
		}
	}

	return len == 0;
}


int ha_quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len)
{
	struct connection *conn;
	enum quic_tls_enc_level tls_enc_level;
	struct quic_enc_level *qel;

	conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	tls_enc_level = ssl_to_quic_enc_level(level);
	qel = &conn->quic_conn->enc_levels[tls_enc_level];

	if (tls_enc_level != QUIC_TLS_ENC_LEVEL_INITIAL &&
	    tls_enc_level != QUIC_TLS_ENC_LEVEL_HANDSHAKE)
		return 0;

	if (!qel->tx.crypto.bufs) {
		fprintf(stderr, "Crypto buffers could not be allacated\n");
		return 0;
	}
	if (!quic_crypto_data_cpy(qel, data, len)) {
		fprintf(stderr, "Too much crypto data (%zu bytes)\n", len);
		return 0;
	}

	return 1;
}

int ha_quic_flush_flight(SSL *ssl)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	fprintf(stderr, "%s\n", __func__);
	tasklet_wakeup(((struct quic_conn_ctx *)conn->xprt_ctx)->wait_event.tasklet);

	return 1;
}

int ha_quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
	fprintf(stderr, "%s\n", __func__);
	return 1;
}

static SSL_QUIC_METHOD ha_quic_method = {
	.set_encryption_secrets = ha_quic_set_encryption_secrets,
	.add_handshake_data     = ha_quic_add_handshake_data,
	.flush_flight           = ha_quic_flush_flight,
	.send_alert             = ha_quic_send_alert,
};

int ssl_quic_initial_ctx(struct bind_conf *bind_conf)
{
	struct proxy *curproxy = bind_conf->frontend;
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	int cfgerr = 0;

#if 0
	/* XXX Did not manage to use this. */
	const char *ciphers =
		"TLS_AES_128_GCM_SHA256:"
		"TLS_AES_256_GCM_SHA384:"
		"TLS_CHACHA20_POLY1305_SHA256:"
		"TLS_AES_128_CCM_SHA256";
#endif
	const char *groups = "P-256:X25519:P-384:P-521";
	long options =
		(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	bind_conf->initial_ctx = ctx;

	SSL_CTX_set_options(ctx, options);
#if 0
	if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 cipher list to '%s' "
		         "for bind '%s' at [%s:%d].\n",
		         curproxy->id, ciphers,
		         bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}
#endif

	if (SSL_CTX_set1_curves_list(ctx, groups) != 1) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 curves list to '%s' "
		         "for bind '%s' at [%s:%d].\n",
		         curproxy->id, groups,
		         bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_default_verify_paths(ctx);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef OPENSSL_IS_BORINGSSL
	SSL_CTX_set_select_certificate_cb(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#elif (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (bind_conf->ssl_conf.early_data) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_max_early_data(ctx, global.tune.bufsize - global.tune.maxrewrite);
	}
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#else
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
#endif
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif
	SSL_CTX_set_quic_method(ctx, &ha_quic_method);

	return cfgerr;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 * errno is cleared before starting so that the caller knows that if it spots an
 * error without errno, it's pending and can be retrieved via getsockopt(SO_ERROR).
 */
static size_t quic_conn_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	errno = 0;

	if (unlikely(!(fdtab[conn->handle.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			goto leave;
		}
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = recvfrom(conn->handle.fd, b_tail(buf), try, 0, NULL, 0);

		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			if (ret < try) {
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, unless the poller supports POLL_RDHUP. If
				 * we know this is the case, we don't try to read more
				 * as we know there's no more available. Similarly, if
				 * there's no problem with lingering we don't even try
				 * to read an unlikely close from the client since we'll
				 * close first anyway.
				 */
				if (fdtab[conn->handle.fd].ev & FD_POLL_HUP)
					goto read0;

				if ((!fdtab[conn->handle.fd].linger_risk) ||
				    (cur_poller.flags & HAP_POLL_F_RDHUP)) {
					fd_done_recv(conn->handle.fd);
					break;
				}
			}
			count -= ret;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN || errno == ENOTCONN) {
			fd_cant_recv(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	return done;

 read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Now a final check for a possible asynchronous low-level error
	 * report. This can happen when a connection receives a reset
	 * after a shutdown, both POLL_HUP and POLL_ERR are queued, and
	 * we might have come from there by just checking POLL_HUP instead
	 * of recv()'s return value 0, so we have no way to tell there was
	 * an error without checking.
	 */
	if (unlikely(fdtab[conn->handle.fd].ev & FD_POLL_ERR))
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto leave;
}


/* Send up to <count> pending bytes from buffer <buf> to connection <conn>'s
 * socket. <flags> may contain some CO_SFL_* flags to hint the system about
 * other pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this. It's up to the caller to update the buffer's contents
 * based on the return value.
 */
static size_t quic_conn_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < count || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = sendto(conn->handle.fd, b_peek(buf, done), try, send_flag,
		             (struct sockaddr *)conn->dst, get_addr_len(conn->dst));
		if (ret > 0) {
			count -= ret;
			done += ret;

			/* A send succeeded, so we can consier ourself connected */
			conn->flags |= CO_FL_WAIT_L4L6;
			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN || errno == EINPROGRESS) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (done > 0) {
		/* we count the total bytes sent, and the send rate for 32-byte
		 * blocks. The reason for the latter is that freq_ctr are
		 * limited to 4GB and that it's not enough per second.
		 */
		_HA_ATOMIC_ADD(&global.out_bytes, done);
		update_freq_ctr(&global.out_32bps, (done + 16) / 32);
	}
	return done;
}

static int quic_conn_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_subscribe(conn, xprt_ctx, event_type, es);
}

static int quic_conn_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_unsubscribe(conn, xprt_ctx, event_type, es);
}

static int quic_packet_decrypt(struct quic_rx_packet *qpkt, struct quic_tls_ctx *tls_ctx)
{
	int ret;
	unsigned char iv[12];
	unsigned char *rx_iv = tls_ctx->rx.iv;
	size_t rx_iv_sz = sizeof tls_ctx->rx.iv;

	if (!quic_aead_iv_build(iv, sizeof iv, rx_iv, rx_iv_sz, qpkt->pn)) {
		fprintf(stderr, "%s AEAD IV building failed\n", __func__);
		return 0;
	}

	ret = quic_tls_decrypt(qpkt->data + qpkt->aad_len, qpkt->len - qpkt->aad_len,
	                       qpkt->data, qpkt->aad_len,
	                       tls_ctx->aead, tls_ctx->rx.key, iv);
	if (!ret) {
		fprintf(stderr, "%s: qpkt #%lu long %d decryption failed\n",
		        __func__, qpkt->pn, qpkt->long_header);
		return 0;
	}

	/* Update the packet length (required to parse the frames). */
	qpkt->len = qpkt->aad_len + ret;
	fprintf(stderr, "QUIC packet #%lu long header? %d decryption done\n",
	        qpkt->pn, qpkt->long_header);

	return 1;
}

/*
 * Remove <largest> down to <smallest> node entries from <frms> root of CRYPTO frames
 * deallocating them.
 */
static inline struct eb64_node *quic_ack_range_crypto_frames(struct eb_root *frms, uint64_t *crypto_in_flight,
                                                             uint64_t largest, uint64_t smallest)
{
	struct eb64_node *node;
	struct quic_tx_crypto_frm *frm;

	node = eb64_lookup(frms, largest);
	while (node && node->key >= smallest) {
		frm = eb64_entry(&node->node, struct quic_tx_crypto_frm, pn);
		fprintf(stderr, "Removing CRYPTO frame #%llu\n", frm->pn.key);
		*crypto_in_flight -= frm->len;
		node = eb64_prev(node);
		eb64_delete(&frm->pn);
		pool_free(pool_head_quic_tx_crypto_frm, frm);
	}

	return node;
}

/*
 * Remove <largest> down to <smallest> node entries from <frms> root of CRYPTO frames
 * deallocating them and accumulate the CRYPTO frames belonging to the same gap
 * <smallest> -> <next_largest> non inclusive in a unique frame to be retransmitted if any.
 * It is possible that this frame does not exist if the ranges have been already parsed
 * (but not acknowledged).
 * Note that <largest> >= <smallest> > <next_largest>.
 */
static inline struct quic_tx_crypto_frm *
quic_ack_range_with_gap_crypto_frames(struct eb_root *frms, uint64_t *crypto_in_flight,
                                      uint64_t largest, uint64_t smallest, uint64_t next_largest)
{
	struct eb64_node *node;
	struct quic_tx_crypto_frm *frm;

	node = quic_ack_range_crypto_frames(frms, crypto_in_flight, largest, smallest);
	if (!node)
		return NULL;

	/* Aggregate the consecutive CRYPTO frames belonging to the same gap. */
	do {
		struct quic_tx_crypto_frm *prev_frm;

		frm = eb64_entry(&node->node, struct quic_tx_crypto_frm, pn);
		fprintf(stderr, "Should retransmit CRYPTO frame #%llu offset: %lu len: %zu\n",
		        frm->pn.key, frm->offset, frm->len);
		node = eb64_prev(node);
		if (node && node->key > next_largest) {
			prev_frm = eb64_entry(&node->node, struct quic_tx_crypto_frm, pn);
			prev_frm->len += frm->len;
			eb64_delete(&frm->pn);
			pool_free(pool_head_quic_tx_crypto_frm, frm);
		}
	} while (node);

	return frm;
}

static int quic_parse_handshake_packet(struct quic_rx_packet *qpkt, struct quic_conn_ctx *ctx,
                                       struct quic_enc_level *enc_level)
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
			if (frm.crypto.offset == enc_level->rx.crypto.offset) {
				fprintf(stderr, "crypto frame as expected\n");
				hexdump(frm.crypto.data, frm.crypto.len, "CRYPTO frame:\n");
				if (SSL_provide_quic_data(ctx->ssl, SSL_quic_read_level(ctx->ssl),
				                          frm.crypto.data, frm.crypto.len) != 1) {
					fprintf(stderr, "%s SSL providing QUIC data error\n", __func__);
				}
				else {
					enc_level->rx.crypto.offset += frm.crypto.len;
					fprintf(stderr, "SSL_provide_quic_data() succeded \n");
				}
			}
			break;
		case QUIC_FT_PADDING:
			if (pos != end) {
				fprintf(stderr, "Wrong frame (remainging: %ld padding len: %lu)\n",
				        end - pos, frm.padding.len);
			}
			break;
		case QUIC_FT_ACK:
		{
			struct quic_ack *ack = &frm.ack;
			uint64_t smallest, largest;

			if (ack->largest_ack > enc_level->pktns->tx.next_pn) {
				fprintf(stderr, "ACK for not sent packet #%lu (%lu)\n",
				        ack->largest_ack, enc_level->pktns->tx.next_pn);
				return 0;
			}

			if (ack->first_ack_range > ack->largest_ack) {
				fprintf(stderr, "Too big first ACK range #%lu\n", ack->first_ack_range);
				return 0;
			}

			largest = ack->largest_ack;
			smallest = largest - ack->first_ack_range;
			do {
				uint64_t gap, ack_range;
				struct quic_tx_crypto_frm *frm;

				if (!ack->ack_range_num--) {
					quic_ack_range_crypto_frames(&enc_level->tx.crypto.frms,
					                             &ctx->conn->quic_conn->crypto_in_flight,
					                             largest, smallest);
					break;
				}

				if (!quic_dec_int(&gap, &pos, end) || smallest < gap + 2)
					return 0;

				if (!quic_dec_int(&ack_range, &pos, end) || smallest - gap - 2 < ack_range)
					return 0;

				frm = quic_ack_range_with_gap_crypto_frames(&enc_level->tx.crypto.frms,
				                                            &ctx->conn->quic_conn->crypto_in_flight,
				                                            largest, smallest, smallest - gap - 2);
				if (frm) {
					eb64_delete(&frm->pn);
					eb64_insert(&enc_level->tx.crypto.retransmit_frms, &frm->pn);
					ctx->conn->quic_conn->retransmit = 1;
				}
				/* Next range */
				largest = smallest - gap - 2;
				smallest = largest - ack_range;

				fprintf(stderr, "acks from %lu -> %lu\n", smallest, largest);
			} while (1);
			tasklet_wakeup(ctx->wait_event.tasklet);

			break;
		}
		case QUIC_FT_PING:
			break;
		case QUIC_FT_CONNECTION_CLOSE:
			break;
		default:
			return 0;
		}
	}

	return 1;
}

static int quic_retransmit_handshake_packets(struct quic_conn_ctx *ctx)
{
	struct quic_conn *quic_conn;
	unsigned char **obuf_pos;
	const unsigned char *obuf_end;
	enum quic_tls_enc_level tls_enc_level;
	struct quic_enc_level *qel;
	struct buffer tmpbuf = { };
	struct eb_root *frms;
	struct eb64_node *node;
	struct quic_tx_crypto_frm *frm;
	size_t len;

	size_t max_flight;
	const unsigned char *ppos, *pos, *data, *end;
	int idx;

	quic_conn = ctx->conn->quic_conn;

	/* Initialize the output buffer pointers. */
	obuf_pos = &quic_conn->obuf.pos;
	obuf_end = quic_conn->obuf.data + sizeof quic_conn->obuf.data;

	tmpbuf.area = (char *)quic_conn->obuf.data;
	tmpbuf.size = sizeof quic_conn->obuf.data;
	tmpbuf.data = *obuf_pos - quic_conn->obuf.data;

	tls_enc_level = QUIC_TLS_ENC_LEVEL_INITIAL;

 next_level:
	frms = &quic_conn->enc_levels[tls_enc_level].tx.crypto.retransmit_frms;
	if (eb_is_empty(frms)) {
		if (tls_enc_level == QUIC_TLS_ENC_LEVEL_INITIAL) {
			tls_enc_level = QUIC_TLS_ENC_LEVEL_HANDSHAKE;
			goto next_level;
		}
		else if (tls_enc_level == QUIC_TLS_ENC_LEVEL_HANDSHAKE && tmpbuf.data) {
			if (ctx->xprt->snd_buf(quic_conn->conn, quic_conn->conn->xprt_ctx,
								   &tmpbuf, tmpbuf.data, 0) <= 0)
				goto out;
			return 1;
		}
	}

	qel = &quic_conn->enc_levels[tls_enc_level];
	node = eb64_first(frms);
	while (node) {
		frm = eb64_entry(&node->node, struct quic_tx_crypto_frm, pn);
		/* Note that <frm> CRYPTO frame may overlap several CRYPTO buffers */
		idx = frm->offset >> QUIC_CRYPTO_BUF_SHIFT;
		data = (const unsigned char *)qel->tx.crypto.bufs[idx]->data;
		ppos = pos = data + (frm->offset & QUIC_CRYPTO_BUF_MASK);
		end = data + qel->tx.crypto.bufs[idx]->sz;

		max_flight = QUIC_CRYPTO_IN_FLIGHT_MAX - quic_conn->crypto_in_flight;
		end = end - ppos > max_flight ? ppos + max_flight : end;
		len = frm->len > end - ppos ? end - ppos : frm->len;
		if (!len)
			break;

		end = ppos + len;

		fprintf(stderr, "Remaining number of bytes to send for frame #%llu: %zu offset: %lu\n",
		        frm->pn.key, len, frm->offset);

		while (pos < end) {
			ssize_t ret, to_send;
			uint64_t offset = frm->offset;

			to_send = quic_build_handshake_packet(obuf_pos, obuf_end,  &ppos, end, &frm->offset,
			                                      tls_enc_level, quic_conn);
			fprintf(stderr, "%s: to send: %zd\n", __func__, to_send);
			switch (to_send) {
			case -2:
				fprintf(stderr, "%s: Encryption error\n", __func__);
				goto err;
			case -1:
				fprintf(stderr, "%s: Buffer full left: %zu\n", __func__, tmpbuf.data);
				break;
			default:
				tmpbuf.data += to_send;
				frm->len -= frm->offset - offset;
			}

			quic_conn->crypto_in_flight += ppos - pos;
			/* If all the data for this encryption level has been prepared, select the next level. */
			if (!frm->len && ctx->state == QUIC_HS_ST_SERVER_INITIAL) {
				ctx->state = QUIC_HS_ST_SERVER_HANSHAKE;
				goto next_level;
			}
			/*
			 * If we have reached the end of a CRYPTO frame or buffer (ppos == end) and
			 * if the output buffer is not full (*obuf_pos != obuf_end && to_send != -1) and
			 * if there is remaining data to send (qel->tx.crypto.offset != qel->tx.crypto.sz),
			 * let's go out to to come back later to completely fill the output buffer.
			 */
			if (ppos == end && *obuf_pos != obuf_end && to_send != -1 && frm->len > 0)
				goto out;

			ret = ctx->xprt->snd_buf(quic_conn->conn, quic_conn->conn->xprt_ctx,
									 &tmpbuf, tmpbuf.data, 0);
			if (ret <= 0)
				goto out;

			fprintf(stderr, "%s: sending %zu bytes at offset %lu\n", __func__, tmpbuf.data, offset);
			tmpbuf.data = 0;
			*obuf_pos = quic_conn->obuf.data;
			pos = ppos;
		}
		if (!frm->len) {
			node = eb64_next(node);
			eb64_delete(&frm->pn);
			pool_free(pool_head_quic_tx_crypto_frm, frm);
		}
	}

 out:
	if (ctx->state == QUIC_HS_ST_SERVER_HANSHAKE && eb_is_empty(frms))
		quic_conn->retransmit = 0;

	if (quic_conn->crypto_in_flight < QUIC_CRYPTO_IN_FLIGHT_MAX &&
	    (!eb_is_empty(frms) || tmpbuf.data))
		tasklet_wakeup(((struct quic_conn_ctx *)quic_conn->conn->xprt_ctx)->wait_event.tasklet);
	return 1;

 err:
	return 0;
}

static int quic_send_handshake_packets(struct quic_conn_ctx *ctx)
{
	struct quic_conn *quic_conn;
	unsigned char **obuf_pos;
	const unsigned char *obuf_end;
	enum quic_tls_enc_level tls_enc_level;
	struct quic_enc_level *qel;
	struct buffer tmpbuf = { };

	size_t max_flight;
	const unsigned char *ppos, *pos, *data, *end;
	int idx;

	quic_conn = ctx->conn->quic_conn;

	/* Initialize the output buffer pointers. */
	obuf_pos = &quic_conn->obuf.pos;
	obuf_end = quic_conn->obuf.data + sizeof quic_conn->obuf.data;

	tmpbuf.area = (char *)quic_conn->obuf.data;
	tmpbuf.size = sizeof quic_conn->obuf.data;
	tmpbuf.data = *obuf_pos - quic_conn->obuf.data;

 next_level:
	switch (ctx->state) {
	case QUIC_HS_ST_SERVER_INITIAL:
		tls_enc_level = QUIC_TLS_ENC_LEVEL_INITIAL;
		break;
	case QUIC_HS_ST_SERVER_HANSHAKE:
		tls_enc_level = QUIC_TLS_ENC_LEVEL_HANDSHAKE;
		break;
	default:
		return 0;
	}

	qel = &quic_conn->enc_levels[tls_enc_level];

	/* Nothing to do? */
	fprintf(stderr, "%s nothing to do? %lu %lu left: %zu in flight: %zu\n",
	        __func__, qel->tx.crypto.offset, qel->tx.crypto.sz, tmpbuf.data, quic_conn->crypto_in_flight);

	/* No CRYPTO data to send. */
	if (!qel->tx.crypto.sz)
		return 1;

	if (qel->tx.crypto.offset == qel->tx.crypto.sz && tmpbuf.data) {
	    if (ctx->xprt->snd_buf(quic_conn->conn, quic_conn->conn->xprt_ctx,
	                           &tmpbuf, tmpbuf.data, 0) <= 0)
			goto out;
		return 1;
	}

	idx = qel->tx.crypto.offset >> QUIC_CRYPTO_BUF_SHIFT;
	data = (const unsigned char *)qel->tx.crypto.bufs[idx]->data;
	ppos = pos = data + (qel->tx.crypto.offset & QUIC_CRYPTO_BUF_MASK);
	end = data + qel->tx.crypto.bufs[idx]->sz;

	max_flight = QUIC_CRYPTO_IN_FLIGHT_MAX - quic_conn->crypto_in_flight;
	end = end - ppos > max_flight ? ppos + max_flight : end;

	fprintf(stderr, "Remaining number of bytes to send: %zu (crypto buf #%d)\n",
	        qel->tx.crypto.sz - qel->tx.crypto.offset, idx);

	while (pos < end) {
		ssize_t ret, to_send;

		to_send = quic_build_handshake_packet(obuf_pos, obuf_end,  &ppos, end, &qel->tx.crypto.offset,
		                                      tls_enc_level, quic_conn);
		fprintf(stderr, "%s: to send: %zd\n", __func__, to_send);
		switch (to_send) {
		case -2:
			fprintf(stderr, "%s: Encryption error\n", __func__);
			goto err;
		case -1:
			fprintf(stderr, "%s: Buffer full left: %zu\n", __func__, tmpbuf.data);
			break;
		default:
			tmpbuf.data += to_send;
		}

		quic_conn->crypto_in_flight += ppos - pos;
		/* If all the data for this encryption level has been prepared, select the next level. */
		if (qel->tx.crypto.offset == qel->tx.crypto.sz) {
			if (ctx->state == QUIC_HS_ST_SERVER_INITIAL) {
				ctx->state = QUIC_HS_ST_SERVER_HANSHAKE;
				goto next_level;
			}
		}

		/*
		 * If we have reached the end of a crypto buffer (ppos == end) and
		 * if the output buffer is not full (*obuf_pos != obuf_end && to_send != -1) and
		 * if there is remaining data to send (qel->tx.crypto.offset != qel->tx.crypto.sz),
		 * let go out to to come back later to completely fill the output buffer.
		 */
		if (ppos == end && *obuf_pos != obuf_end && to_send != -1 &&
		    qel->tx.crypto.offset != qel->tx.crypto.sz)
			goto out;

		ret = ctx->xprt->snd_buf(quic_conn->conn, quic_conn->conn->xprt_ctx,
		                         &tmpbuf, tmpbuf.data, 0);
		if (ret <= 0)
			goto out;

		fprintf(stderr, "%s: sending %zu bytes\n", __func__, tmpbuf.data);
		tmpbuf.data = 0;
		*obuf_pos = quic_conn->obuf.data;
		pos = ppos;
	}

 out:
	if (quic_conn->crypto_in_flight < QUIC_CRYPTO_IN_FLIGHT_MAX &&
	    (qel->tx.crypto.offset != qel->tx.crypto.sz || tmpbuf.data))
		tasklet_wakeup(((struct quic_conn_ctx *)quic_conn->conn->xprt_ctx)->wait_event.tasklet);
	return 1;

 err:
	return 0;
}

static int quic_build_post_handshake_frames(struct quic_conn *conn)
{
	int i;
	struct quic_frame *frm;

	frm = pool_alloc(pool_head_quic_frame);
	frm->type = QUIC_FT_HANDSHAKE_DONE;
	LIST_ADDQ(&conn->tx.frms_to_send, &frm->list);

	for (i = 1; i < conn->rx_tps.active_connection_id_limit; i++) {
		struct quic_connection_id *cid;

		frm = pool_alloc(pool_head_quic_frame);
		memset(frm, 0, sizeof *frm);
		cid = new_quic_connection_id(&conn->cids, i);
		if (!frm || !cid)
			goto err;

		quic_connection_id_to_frm_cpy(frm, cid);
		LIST_ADDQ(&conn->tx.frms_to_send, &frm->list);
	}

    return 1;

 err:
	free_quic_conn_cids(conn);
	return 0;
}

static int quic_conn_do_handshake(struct quic_conn_ctx *ctx)
{
	struct quic_conn *quic_conn;
	struct quic_enc_level *enc_level;
	struct quic_rx_packet *qpkt;
	struct eb64_node *qpkt_node;
	struct quic_tls_ctx *tls_ctx;
	struct eb_root *rx_qpkts;
	int ret;

	fprintf(stderr, "%s ctx state: %d\n", __func__, ctx->state);
	quic_conn = ctx->conn->quic_conn;

	if (quic_conn->retransmit && !quic_retransmit_handshake_packets(ctx))
		return 0;

	if (!quic_send_handshake_packets(ctx))
		return 0;

	switch (ctx->state) {
	case QUIC_HS_ST_SERVER_INITIAL:
		enc_level = &quic_conn->enc_levels[QUIC_TLS_ENC_LEVEL_INITIAL];
		break;
	case QUIC_HS_ST_SERVER_HANSHAKE:
		enc_level = &quic_conn->enc_levels[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
		break;
	default:
		return 0;
	}

	tls_ctx = &enc_level->tls_ctx;
	rx_qpkts = &enc_level->rx.qpkts;

	qpkt_node = eb64_first(rx_qpkts);
	while (qpkt_node) {
		qpkt = eb64_entry(&qpkt_node->node, struct quic_rx_packet, pn_node);
		if (!quic_packet_decrypt(qpkt, tls_ctx))
			return 0;

		if (!quic_parse_handshake_packet(qpkt, ctx, enc_level)) {
			fprintf(stderr,  "Could not parse the packet frames\n");
			return 0;
		}

		qpkt_node = eb64_next(qpkt_node);
		eb64_delete(&qpkt->pn_node);
		pool_free(pool_head_quic_rx_packet, qpkt);
	}

	ret = SSL_do_handshake(ctx->ssl);
	if (ret != 1) {
		ret = SSL_get_error(ctx->ssl, ret);
		fprintf(stderr, "SSL_do_handshake() error: %d\n", ret);
		return ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE;
	}

	fprintf(stderr, "SSL_do_handhake() succeeded\n");

	if (ctx->state == QUIC_HS_ST_SERVER_HANSHAKE)
		ctx->conn->flags &= ~CO_FL_SSL_WAIT_HS;

	ret = SSL_process_quic_post_handshake(ctx->ssl);
	if (ret != 1) {
		fprintf(stderr, "SSL_process_quic_post_handshake() error: %d\n", ret);
		return 0;
	}

	fprintf(stderr, "SSL_process_quic_post_handshake() succeeded\n");

	quic_build_post_handshake_frames(quic_conn);

	quic_send_app_packets(ctx);


	return 1;
}

static int quic_treat_packets(struct quic_conn_ctx *ctx)
{
	struct quic_conn *quic_conn;
	struct quic_enc_level *enc_level;
	struct quic_tls_ctx *tls_ctx;
	struct eb_root *rx_qpkts;
	struct quic_rx_packet *qpkt;
	struct eb64_node *qpkt_node;

	quic_conn = ctx->conn->quic_conn;
	enc_level = &quic_conn->enc_levels[QUIC_TLS_ENC_LEVEL_APP];
	if (eb_is_empty(&enc_level->rx.qpkts)) {
		fprintf(stderr, "empty tree for APP level encryption\n");
		enc_level = &quic_conn->enc_levels[QUIC_TLS_ENC_LEVEL_HANDSHAKE];
	}
	tls_ctx = &enc_level->tls_ctx;
	rx_qpkts = &enc_level->rx.qpkts;

	qpkt_node = eb64_first(rx_qpkts);
	while (qpkt_node) {
		qpkt = eb64_entry(&qpkt_node->node, struct quic_rx_packet, pn_node);
		if (!quic_packet_decrypt(qpkt, tls_ctx))
			return 0;

		if (!quic_parse_packet_frames(qpkt)) {
			fprintf(stderr,  "Could not parse the packet frames\n");
			return 0;
		}
		qpkt_node = eb64_next(qpkt_node);
		eb64_delete(&qpkt->pn_node);
		pool_free(pool_head_quic_rx_packet, qpkt);
	}

	return 1;
}

/* QUIC connection packet handler. */
static struct task *quic_conn_io_cb(struct task *t, void *context, unsigned short state)
{
	struct quic_conn_ctx *ctx = context;

	fprintf(stderr, "%s: tid: %u\n", __func__, tid);
	if (ctx->conn->flags & CO_FL_SSL_WAIT_HS) {
		if (!quic_conn_do_handshake(ctx))
			fprintf(stderr, "%s SSL handshake error\n", __func__);
	}
	else {
		quic_treat_packets(ctx);
	}

	return NULL;
}

/* We can't have an underlying XPRT, so just return -1 to signify failure */
static int quic_conn_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	fprintf(stderr, "%s\n", __func__);
	/* This is the lowest xprt we can have, so if we get there we didn't
	 * find the xprt we wanted to remove, that's a bug
	 */
	BUG_ON(1);
	return -1;
}

/*
 * Allocate a new QUIC connection and return it if succeeded, NULL if not.
 */
static struct quic_conn *quic_new_conn(uint32_t version, struct quic_transport_params *tps)
{
	struct quic_conn *quic_conn;

	quic_conn = pool_alloc(pool_head_quic_conn);
	if (quic_conn) {
		memset(quic_conn, 0, sizeof *quic_conn);
		quic_conn->version = version;
		quic_conn->tx_tps = tps;
	}

	return quic_conn;
}

static int quic_new_conn_init(struct quic_conn *conn,
                              struct eb_root *quic_initial_clients,
                              struct eb_root *quic_clients,
                              unsigned char *dcid, size_t dcid_len,
                              unsigned char *scid, size_t scid_len)
{
	int i;
	/* Initial CID. */
	struct quic_connection_id *icid;

	conn->cids = EB_ROOT;
	fprintf(stderr, "%s: new quic_conn @%p\n", __func__, conn);
	/* Server */
	if (objt_listener(conn->conn->target)) {
		/* Copy the initial DCID. */
		conn->idcid.len = dcid_len;
		memcpy(conn->idcid.data, dcid, dcid_len);

		/* Copy the SCID as our DCID for this connection. */
		memcpy(conn->dcid.data, scid, scid_len);
		conn->dcid.len = scid_len;
	}
	/* Client */
	else {
		memcpy(conn->dcid.data, dcid, dcid_len);
		conn->dcid.len = dcid_len;
	}

	/* Initialize the output buffer */
	conn->obuf.pos = conn->obuf.data;

	icid = new_quic_connection_id(&conn->cids, 0);
	if (!icid)
		return 0;

	/* Select our SCID which is the first CID with 0 as sequence number. */
	conn->scid = icid->cid;

	/* Insert the DCIC the client has choosen (only for servers) */
	if (objt_listener(conn->conn->target))
		ebmb_insert(quic_initial_clients, &conn->idcid_node, conn->idcid.len);

	/* Insert our SCID, the connection ID for the client. */
	ebmb_insert(quic_clients, &conn->scid_node, conn->scid.len);

	/* Initialize the Initial level TLS encryption context. */
	quic_initial_tls_ctx_init(&conn->enc_levels[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx);
	/* Packet number spaces initialization. */
	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++) {
		quic_pktns_init(&conn->pktns[i]);
	}
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++) {
		struct quic_enc_level *qel= &conn->enc_levels[i];

		qel->rx.qpkts = EB_ROOT;
		qel->tx.crypto.bufs = malloc(sizeof *qel->tx.crypto.bufs);
		if (qel->tx.crypto.bufs) {
			qel->tx.crypto.bufs[0] = pool_alloc(pool_head_quic_crypto_buf);
			if (!qel->tx.crypto.bufs[0]) {
				fprintf(stderr, "%s: could not allocated any crypto buffer\n", __func__);
				free(qel->tx.crypto.bufs);
				qel->tx.crypto.bufs = NULL;
				return 0;
			}
			qel->tx.crypto.bufs[0]->sz = 0;
			qel->tx.crypto.nb_buf = 1;
		}
		else {
			qel->tx.crypto.nb_buf = 0;
		}
		qel->tx.crypto.sz = 0;
		qel->tx.crypto.offset = 0;
		qel->tx.crypto.frms = EB_ROOT;
		qel->tx.crypto.retransmit_frms = EB_ROOT;
		/* Initialize the packet number space */
		qel->pktns = &conn->pktns[quic_tls_pktns(i)];
	}
	conn->retransmit = 0;
	conn->crypto_in_flight = 0;
	LIST_INIT(&conn->tx.frms_to_send);

	return 1;
}

static int quic_conn_derive_initial_secrets(struct quic_tls_ctx *ctx,
                                            const unsigned char *cid, size_t cidlen,
                                            int server)
{
	unsigned char initial_secret[32];
	/* Initial secret to be derived for incoming packets */
	unsigned char rx_init_sec[32];
	/* Initial secret to be derived for outgoing packets */
	unsigned char tx_init_sec[32];
	struct quic_tls_secrets *rx_ctx, *tx_ctx;


	hexdump(cid, cidlen, "%s CID(%zu)\n", __func__, cidlen);
	if (!quic_derive_initial_secret(ctx->md, initial_secret, sizeof initial_secret,
	                                cid, cidlen))
		return 0;
	if (!quic_tls_derive_initial_secrets(ctx->md,
	                                     rx_init_sec, sizeof rx_init_sec,
	                                     tx_init_sec, sizeof tx_init_sec,
	                                     initial_secret, sizeof initial_secret, server))
	    return 0;

	rx_ctx = &ctx->rx;
	tx_ctx = &ctx->tx;
	if (!quic_tls_derive_packet_protection_keys(ctx->aead, ctx->hp, ctx->md,
	                                            rx_ctx->key, sizeof rx_ctx->key,
	                                            rx_ctx->iv, sizeof rx_ctx->iv,
	                                            rx_ctx->hp_key, sizeof rx_ctx->hp_key,
	                                            rx_init_sec, sizeof rx_init_sec))
		return 0;
	if (!quic_tls_derive_packet_protection_keys(ctx->aead, ctx->hp, ctx->md,
	                                            tx_ctx->key, sizeof tx_ctx->key,
	                                            tx_ctx->iv, sizeof tx_ctx->iv,
	                                            tx_ctx->hp_key, sizeof tx_ctx->hp_key,
	                                            tx_init_sec, sizeof tx_init_sec))
		return 0;
	return 1;
}

static int quic_conn_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_conn_ctx *ctx;

	TRACE_ENTER(QUIC_EV_CONN_NEW);

	if (*xprt_ctx)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	ctx = pool_alloc(pool_head_quic_conn_ctx);
	if (!ctx) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		goto err;
	}

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		goto err;
	}

	ctx->wait_event.tasklet->process = quic_conn_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->conn = conn;
	ctx->subs = NULL;
	ctx->xprt_ctx = NULL;

	ctx->xprt = xprt_get(XPRT_QUIC);
	if (objt_server(conn->target)) {
		struct server *srv = __objt_server(conn->target);
		unsigned char dcid[QUIC_CID_LEN];
		unsigned char scid[QUIC_CID_LEN];
		struct quic_tls_ctx *tls_ctx;

		if (RAND_bytes(dcid, sizeof dcid) != 1 || RAND_bytes(scid, sizeof scid) != 1)
			goto err;

		conn->quic_conn = quic_new_conn(QUIC_PROTOCOL_VERSION_DRAFT_27, &srv->quic_params);
		if (!conn->quic_conn)
			goto err;

		conn->quic_conn->conn = conn;
		if (!quic_new_conn_init(conn->quic_conn, NULL, &srv->cids,
		                        dcid, sizeof dcid, scid, sizeof scid))
			goto err;

		tls_ctx = &conn->quic_conn->enc_levels[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;
		if (!quic_conn_derive_initial_secrets(tls_ctx, dcid, sizeof dcid, 0)) {
			fprintf(stderr, "Could not derive initial secrets\n");
			goto err;
		}

		/* Client */
		ctx->state = QUIC_HS_ST_CLIENT_INITIAL;
		if (ssl_bio_and_sess_init(conn, srv->ssl_ctx.ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1) {
			fprintf(stderr, "Could not initiliaze SSL ctx\n");
			goto err;
		}

		if (conn->quic_conn->version >= QUIC_PROTOCOL_VERSION_DRAFT_27) {
			srv->enc_quic_params_len =
				quic_transport_params_encode_draft27(srv->enc_quic_params,
				                                     srv->enc_quic_params + sizeof srv->enc_quic_params,
				                                     &srv->quic_params, 0);
		}
		else {
			srv->enc_quic_params_len =
				quic_transport_params_encode(srv->enc_quic_params,
				                             srv->enc_quic_params + sizeof srv->enc_quic_params,
				                             &srv->quic_params, 0);
		}
		if (!srv->enc_quic_params_len) {
			fprintf(stderr, "QUIC transport parameters encoding failed");
			goto err;
		}
		SSL_set_quic_transport_params(ctx->ssl, srv->enc_quic_params, srv->enc_quic_params_len);
		SSL_set_connect_state(ctx->ssl);
	}
	else if (objt_listener(conn->target)) {
		/* Listener */
		struct bind_conf *bc = __objt_listener(conn->target)->bind_conf;

		ctx->state = QUIC_HS_ST_SERVER_INITIAL;

		if (ssl_bio_and_sess_init(conn, bc->initial_ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1)
			goto err;

		if (conn->quic_conn->version >= QUIC_PROTOCOL_VERSION_DRAFT_27) {
			bc->enc_quic_params_len =
				quic_transport_params_encode_draft27(bc->enc_quic_params,
				                                     bc->enc_quic_params + sizeof bc->enc_quic_params,
				                                     &bc->quic_params, 1);
		}
		else {
			bc->enc_quic_params_len =
				quic_transport_params_encode(bc->enc_quic_params,
				                             bc->enc_quic_params + sizeof bc->enc_quic_params,
				                             &bc->quic_params, 1);
		}
		if (!bc->enc_quic_params_len) {
			fprintf(stderr, "QUIC transport parameters encoding failed");
			goto err;
		}
		SSL_set_quic_transport_params(ctx->ssl, bc->enc_quic_params, bc->enc_quic_params_len);
		SSL_set_accept_state(ctx->ssl);
	}

	*xprt_ctx = ctx;

	/* Leave init state and start handshake */
	conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
	/* Start the handshake */
	tasklet_wakeup(ctx->wait_event.tasklet);

	TRACE_LEAVE(QUIC_EV_CONN_NEW, conn);

	return 0;

 err:
	if (ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(pool_head_quic_conn_ctx, ctx);
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_NEW|QUIC_EV_CONN_ERR, conn);
	return -1;
}

/* Release the SSL context of <srv> server. */
void quic_conn_free_srv_ctx(struct server *srv)
{
	fprintf(stderr, "%s\n", __func__);
	if (srv->ssl_ctx.ctx)
		SSL_CTX_free(srv->ssl_ctx.ctx);
}

/*
 * Prepare the SSL context for <srv> server.
 * Returns an error count.
 */
int quic_conn_prepare_srv_ctx(struct server *srv)
{
	struct proxy *curproxy = srv->proxy;
	int cfgerr = 0;
	SSL_CTX *ctx = NULL;
	int verify = SSL_VERIFY_NONE;
	long mode =
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_RELEASE_BUFFERS |
		SSL_MODE_SMALL_BUFFERS;

	/* Make sure openssl opens /dev/urandom before the chroot */
	if (!ssl_initialize_random()) {
		ha_alert("OpenSSL random data generator initialization failed.\n");
		cfgerr++;
	}

	ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	SSL_CTX_set_mode(ctx, mode);
	fprintf(stderr, "%s SSL ctx mode: %ld\n", __func__, mode);

	srv->ssl_ctx.ctx = ctx;
	if (srv->ssl_ctx.client_crt) {
		if (SSL_CTX_use_PrivateKey_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt, SSL_FILETYPE_PEM) <= 0) {
			ha_alert("config : %s '%s', server '%s': unable to load SSL private key from PEM file '%s'.\n",
			         proxy_type_str(curproxy), curproxy->id,
			         srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_use_certificate_chain_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt) <= 0) {
			ha_alert("config : %s '%s', server '%s': unable to load ssl certificate from PEM file '%s'.\n",
			         proxy_type_str(curproxy), curproxy->id,
			         srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_check_private_key(srv->ssl_ctx.ctx) <= 0) {
			ha_alert("config : %s '%s', server '%s': inconsistencies between private key and certificate loaded from PEM file '%s'.\n",
			         proxy_type_str(curproxy), curproxy->id,
			         srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
	}

	if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
		verify = SSL_VERIFY_PEER;
	switch (srv->ssl_ctx.verify) {
	case SSL_SOCK_VERIFY_NONE:
		verify = SSL_VERIFY_NONE;
		break;
	case SSL_SOCK_VERIFY_REQUIRED:
		verify = SSL_VERIFY_PEER;
		break;
	}
	SSL_CTX_set_verify(srv->ssl_ctx.ctx, verify,
	                   (srv->ssl_ctx.verify_host || (verify & SSL_VERIFY_PEER)) ? ssl_sock_srv_verifycbk : NULL);
	if (verify & SSL_VERIFY_PEER) {
		if (srv->ssl_ctx.ca_file) {
			/* set CAfile to verify */
			if (!ssl_set_verify_locations_file(srv->ssl_ctx.ctx, srv->ssl_ctx.ca_file)) {
				ha_alert("Proxy '%s', server '%s' [%s:%d] unable to set CA file '%s'.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line, srv->ssl_ctx.ca_file);
				cfgerr++;
			}
		}
		else {
			if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
				ha_alert("Proxy '%s', server '%s' [%s:%d] verify is enabled by default "
				         "but no CA file specified. If you're running on a LAN where "
				         "you're certain to trust the server's certificate, please set "
				         "an explicit 'verify none' statement on the 'server' line, or "
				         "use 'ssl-server-verify none' in the global section to disable "
				         "server-side verifications by default.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line);
			else
				ha_alert("Proxy '%s', server '%s' [%s:%d] verify is enabled but no CA file specified.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line);
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (srv->ssl_ctx.crl_file) {
			X509_STORE *store = SSL_CTX_get_cert_store(srv->ssl_ctx.ctx);

			if (!ssl_set_cert_crl_file(store, srv->ssl_ctx.crl_file)) {
				ha_alert("Proxy '%s', server '%s' [%s:%d] unable to configure CRL file '%s'.\n",
				         curproxy->id, srv->id,
				         srv->conf.file, srv->conf.line, srv->ssl_ctx.crl_file);
				cfgerr++;
			}
			else {
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
			}
		}
#endif
	}

	SSL_CTX_set_session_cache_mode(srv->ssl_ctx.ctx, SSL_SESS_CACHE_CLIENT |
	                               SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(srv->ssl_ctx.ctx, ssl_sess_new_srv_cb);
	if (srv->ssl_ctx.ciphers &&
		!SSL_CTX_set_cipher_list(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphers)) {
		ha_alert("Proxy '%s', server '%s' [%s:%d] : unable to set SSL cipher list to '%s'.\n",
		         curproxy->id, srv->id,
		         srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphers);
		cfgerr++;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (srv->ssl_ctx.ciphersuites &&
		!SSL_CTX_set_ciphersuites(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphersuites)) {
		ha_alert("Proxy '%s', server '%s' [%s:%d] : unable to set TLS 1.3 cipher suites to '%s'.\n",
		         curproxy->id, srv->id,
		         srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphersuites);
		cfgerr++;
	}
#endif
	SSL_CTX_set_quic_method(ctx, &ha_quic_method);

    return cfgerr;
}

/* transport-layer operations for QUIC sockets */
static struct xprt_ops quic_conn = {
	.snd_buf  = quic_conn_from_buf,
	.rcv_buf  = quic_conn_to_buf,
	.subscribe = quic_conn_subscribe,
	.unsubscribe = quic_conn_unsubscribe,
	.remove_xprt = quic_conn_remove_xprt,
	.shutr    = NULL,
	.shutw    = NULL,
	.close    = NULL,
	.init     = quic_conn_init,
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.prepare_srv = quic_conn_prepare_srv_ctx,
	.destroy_srv = quic_conn_free_srv_ctx,
	.name     = "QUIC",
};


__attribute__((constructor))
static void __quic_conn_init(void)
{
	ha_quic_meth = BIO_meth_new(0x666, "ha QUIC methods");
	xprt_register(XPRT_QUIC, &quic_conn);
}

__attribute__((destructor))
static void __quic_conn_deinit(void)
{
	BIO_meth_free(ha_quic_meth);
}

static uint64_t *quic_max_pn(struct quic_conn *conn, int server, int long_header, int packet_type)
{
	/* Packet number space */
    int pn_space;

    if (long_header && packet_type == QUIC_PACKET_TYPE_INITIAL) {
        pn_space = QUIC_TLS_PKTNS_INITIAL;
    } else if (long_header && packet_type == QUIC_PACKET_TYPE_HANDSHAKE) {
        pn_space = QUIC_TLS_PKTNS_HANDSHAKE;
    } else {
        pn_space = QUIC_TLS_PKTNS_01RTT;
    }

    if (server) {
        return &conn->server_max_pn[pn_space];
    } else {
        return &conn->client_max_pn[pn_space];
    }
}

/*
 * See https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-encoding
 * The comments come from this draft.
 */
static uint64_t decode_packet_number(uint64_t largest_pn, uint32_t truncated_pn, unsigned int pn_nbits)
{
   uint64_t expected_pn = largest_pn + 1;
   uint64_t pn_win = (uint64_t)1 << pn_nbits;
   uint64_t pn_hwin = pn_win / 2;
   uint64_t pn_mask = pn_win - 1;
   uint64_t candidate_pn;


   // The incoming packet number should be greater than
   // expected_pn - pn_hwin and less than or equal to
   // expected_pn + pn_hwin
   //
   // This means we can't just strip the trailing bits from
   // expected_pn and add the truncated_pn because that might
   // yield a value outside the window.
   //
   // The following code calculates a candidate value and
   // makes sure it's within the packet number window.
   candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
   if (candidate_pn + pn_hwin <= expected_pn)
      return candidate_pn + pn_win;

   // Note the extra check for underflow when candidate_pn
   // is near zero.
   if (candidate_pn > expected_pn + pn_hwin && candidate_pn > pn_win)
      return candidate_pn - pn_win;

   return candidate_pn;
}

static int quic_remove_header_protection(struct quic_conn *conn, struct quic_rx_packet *pkt,
                                         struct quic_tls_ctx *tls_ctx,
                                         unsigned char *pn, unsigned char *byte0, const unsigned char *end)
{
	int ret, outlen, i, pnlen;
	uint64_t *largest_pn, packet_number;
	uint32_t truncated_pn = 0;
	unsigned char mask[5] = {0};
	unsigned char *sample;
	EVP_CIPHER_CTX *ctx;
	unsigned char *hp_key;

	/* Check there is enough data in this packet. */
	if (end - pn < QUIC_PACKET_PN_MAXLEN + sizeof mask)
		return 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	ret = 0;
	sample = pn + QUIC_PACKET_PN_MAXLEN;

	hp_key = tls_ctx->rx.hp_key;
	if (!EVP_DecryptInit_ex(ctx, tls_ctx->hp, NULL, hp_key, sample) ||
	    !EVP_DecryptUpdate(ctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_DecryptFinal_ex(ctx, mask, &outlen))
	    goto out;

	*byte0 ^= mask[0] & (*byte0 & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	pnlen = (*byte0 & QUIC_PACKET_PNL_BITMASK) + 1;
	for (i = 0; i < pnlen; i++) {
		pn[i] ^= mask[i + 1];
		truncated_pn = (truncated_pn << 8) | pn[i];
	}

	largest_pn = quic_max_pn(conn, 0, *byte0 & QUIC_PACKET_LONG_HEADER_BIT, pkt->type);
	packet_number = decode_packet_number(*largest_pn, truncated_pn, pnlen * 8);
	/* Store remaining information for this unprotected header */
	pkt->pn = packet_number;
	pkt->pnl = pnlen;

	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/*
 * Inspired from session_accept_fd().
 */
static int quic_new_cli_conn(struct quic_conn *quic_conn,
                             struct listener *l, struct sockaddr_storage *saddr)
{
	struct connection *cli_conn;
	struct proxy *p = l->bind_conf->frontend;
	struct session *sess;

	if (unlikely((cli_conn = conn_new()) == NULL))
		goto out;

	if (!sockaddr_alloc(&cli_conn->dst))
		goto out_free_conn;

	fprintf(stderr, "%s conn: @%p\n", __func__, cli_conn);
	quic_conn->conn = cli_conn;
	cli_conn->quic_conn = quic_conn;

	/* XXX Not sure it is safe to keep this statement. */
	cli_conn->handle.fd = l->fd;
	if (saddr)
		*cli_conn->dst = *saddr;
	cli_conn->flags |= CO_FL_ADDR_FROM_SET;
	cli_conn->target = &l->obj_type;
	cli_conn->proxy_netns = l->netns;

	conn_prepare(cli_conn, l->proto, l->bind_conf->xprt);

#if 0
	/* XXX DO NOT fd_insert() l->fd again with another I/O handler XXX
	 * This should be the case for an outgoing QUIC connection (haproxy as QUIC client).
	 */
	conn_ctrl_init(cli_conn);
#else
	cli_conn->flags |= CO_FL_CTRL_READY;
#endif

	/* wait for a PROXY protocol header */
	if (l->options & LI_O_ACC_PROXY)
		cli_conn->flags |= CO_FL_ACCEPT_PROXY;

	/* wait for a NetScaler client IP insertion protocol header */
	if (l->options & LI_O_ACC_CIP)
		cli_conn->flags |= CO_FL_ACCEPT_CIP;

	if (conn_xprt_init(cli_conn) < 0)
		goto out_free_conn;

	/* Add the handshake pseudo-XPRT */
	if (cli_conn->flags & (CO_FL_ACCEPT_PROXY | CO_FL_ACCEPT_CIP)) {
		if (xprt_add_hs(cli_conn) != 0)
			goto out_free_conn;
	}
	sess = session_new(p, l, &cli_conn->obj_type);
	if (!sess)
		goto out_free_conn;

	conn_set_owner(cli_conn, sess, NULL);


	/* OK let's complete stream initialization since there is no handshake */
	if (conn_complete_session(cli_conn) >= 0)
		return 1;

	/* error unrolling */
 out_free_sess:
	 /* prevent call to listener_release during session_free. It will be
	  * done below, for all errors. */
	sess->listener = NULL;
	session_free(sess);
 out_free_conn:
	conn_stop_tracking(cli_conn);
	conn_xprt_close(cli_conn);
	conn_free(cli_conn);
 out:

	return 0;
}

static ssize_t quic_packet_read(unsigned char **buf, const unsigned char *end,
                                struct quic_rx_packet *qpkt, struct listener *l,
                                struct sockaddr_storage *saddr, socklen_t *saddrlen)
{
	unsigned char *beg;
	unsigned char dcid_len, scid_len;
	uint64_t len;
	unsigned char *pn = NULL; /* Packet number */
	struct quic_conn *conn;
	struct ebmb_node *node;
	struct quic_tls_ctx *tls_ctx;
	enum quic_tls_enc_level qpkt_enc_level;

	if (end <= *buf)
		goto err;

	/* Fixed bit */
	if (!(**buf & QUIC_PACKET_FIXED_BIT))
		/* XXX TO BE DISCARDED */
		goto err;

	dcid_len = 0;
	beg = *buf;
	/* Header form */
	qpkt->long_header = **buf & QUIC_PACKET_LONG_HEADER_BIT;
	/* Packet type XXX does not exist for short headers XXX */
	qpkt->type = (*(*buf)++ >> QUIC_PACKET_TYPE_SHIFT) & QUIC_PACKET_TYPE_BITMASK;
	if (qpkt->long_header) {
		struct eb_root *quic_clients;
		size_t cid_lookup_len;

		/* Version */
	    if (!quic_read_uint32(&qpkt->version, (const unsigned char **)buf, end))
			goto err;

	    if (!qpkt->version) { /* XXX TO DO XXX Version negotiation packet */ };

		/* Destination Connection ID Length */
		dcid_len = *(*buf)++;
		/* We want to be sure we can read <dcid_len> bytes and one more for <scid_len> value */
		if (dcid_len > QUIC_CID_MAXLEN || end - *buf < dcid_len + 1)
			/* XXX MUST BE DROPPED */
			goto err;

		if (dcid_len) {
			/*
			 * Check that the length of this received DCID matches the CID lengths
			 * of our implementation for non Initials packets only.
			 */
			if (qpkt->type != QUIC_PACKET_TYPE_INITIAL && dcid_len != QUIC_CID_LEN)
				goto err;

			memcpy(qpkt->dcid.data, *buf, dcid_len);
		}

		qpkt->dcid.len = dcid_len;
		*buf += dcid_len;

		/*
		 * DCIDs of first packets coming from clients may have the same values.
		 * Let's distinguish them concatenating the socket addresses to the DCIDs.
		 */
		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			memcpy(qpkt->dcid.data + qpkt->dcid.len, saddr, sizeof *saddr);
			qpkt->dcid.len += sizeof *saddr;
		}

		/* Source Connection ID Length */
		scid_len = *(*buf)++;
		if (scid_len > QUIC_CID_MAXLEN || end - *buf < scid_len)
			/* XXX MUST BE DROPPED */
			goto err;

		if (scid_len)
			memcpy(qpkt->scid.data, *buf, scid_len);
		qpkt->scid.len = scid_len;
		*buf += scid_len;

		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			quic_clients = &l->icids;
			cid_lookup_len = qpkt->dcid.len;
		}
		else {
			quic_clients = &l->cids;
			cid_lookup_len = QUIC_CID_LEN;
		}

		node = ebmb_lookup(quic_clients, qpkt->dcid.data, cid_lookup_len);
		if (!node) {
			if (qpkt->type != QUIC_PACKET_TYPE_INITIAL) {
				fprintf(stderr, "Connection not found.\n");
				goto err;
			}

			conn =  quic_new_conn(qpkt->version, &l->bind_conf->quic_params);
			if (!conn)
				goto err;

			if (!quic_new_cli_conn(conn, l, saddr)) {
				free(conn);
				goto err;
			}

			if (!quic_new_conn_init(conn, &l->icids, &l->cids,
			                        qpkt->dcid.data, cid_lookup_len, qpkt->scid.data, qpkt->scid.len))
				goto err;
		}
		else {
			if (qpkt->type == QUIC_PACKET_TYPE_INITIAL)
				conn = ebmb_entry(node, struct quic_conn, idcid_node);
			else
				conn = ebmb_entry(node, struct quic_conn, scid_node);
		}

		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			uint64_t token_len;
			struct quic_tls_ctx *ctx = &conn->enc_levels[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;

			if (!quic_dec_int(&token_len, (const unsigned char **)buf, end) || end - *buf < token_len)
				goto err;

			/* XXX TO DO XXX 0 value means "the token is not present".
			 * A server which sends an Initial packet must not set the token.
			 * So, a client which receives an Initial packet with a token
			 * MUST discard the packet or generate a connection error with
			 * PROTOCOL_VIOLATION as type.
			 * The token must be provided in a Retry packet or NEW_TOKEN frame.
			 */
			qpkt->token_len = token_len;
			/*
			 * NOTE: the socket address it concatenated to the destination ID choosen by the client
			 * for Initial packets.
			 */
			if (!quic_conn_derive_initial_secrets(ctx, qpkt->dcid.data, qpkt->dcid.len - sizeof *saddr, 1)) {
				fprintf(stderr, "Could not derive initial secrets\n");
				goto err;
			}
		}
	}
	else {
		/* XXX TO DO: Short header XXX */
		if (end - *buf < QUIC_CID_LEN) {
			fprintf(stderr, "Too short short headder\n");
			goto err;
		}
		node = ebmb_lookup(&l->cids, *buf, QUIC_CID_LEN);
		if (!node) {
			fprintf(stderr, "Unknonw connection ID\n");
			goto err;
		}
		conn = ebmb_entry(node, struct quic_conn, scid_node);
		*buf += QUIC_CID_LEN;
	}

	/*
	 * Only packets packets with long headers and not RETRY or VERSION as type
	 * have a length field.
	 */
	if (qpkt->long_header && qpkt->type != QUIC_PACKET_TYPE_RETRY && qpkt->version) {
		if (!quic_dec_int(&len, (const unsigned char **)buf, end) || end - *buf < len) {
			fprintf(stderr, "Could not decode the packet length or too short packet (%zu, %zu)\n", len, end - *buf);
			goto err;
		}
		qpkt->len = len;
	}
	else if (!qpkt->long_header) {
		/* A short packet is the last one of an UDP datagram. */
		qpkt->len = end - *buf;
	}
	fprintf(stderr, "%s packet length: %zu\n", __func__, qpkt->len);

	/*
	 * The packet number is here. This is also the start minus QUIC_PACKET_PN_MAXLEN
	 * of the sample used to add/remove the header protection.
	 */
	pn = *buf;

	if (qpkt->long_header)
		qpkt_enc_level = quic_packet_type_enc_level(qpkt->type);
	else
		qpkt_enc_level = QUIC_TLS_ENC_LEVEL_APP;
	tls_ctx = &conn->enc_levels[qpkt_enc_level].tls_ctx;

	if (!quic_remove_header_protection(conn, qpkt, tls_ctx, pn, beg, end)) {
		fprintf(stderr, "Could not remove packet header protection\n");
		goto err;
	}
	fprintf(stderr, "%s packet number: %lu enc. level: %d\n", __func__, qpkt->pn, qpkt_enc_level);

	if (pn - beg + qpkt->len > sizeof qpkt->data) {
		fprintf(stderr, "Too big packet %zu\n", pn - beg + qpkt->len);
		goto err;
	}

	/* Store the packet */
	qpkt->pn_node.key = qpkt->pn;
	eb64_insert(&conn->enc_levels[qpkt_enc_level].rx.qpkts, &qpkt->pn_node);

	/* The length of the packet includes the packet number field. */
	qpkt->len += pn - beg;
	memcpy(qpkt->data, beg, qpkt->len);
	/* The AAD includes the packet number field found at <pn>. */
	qpkt->aad_len = pn - beg + qpkt->pnl;
	/* Updtate the offset of <*buf> for the next QUIC packet. */
	*buf = beg + qpkt->len;
	/* Wake the tasklet of the QUIC connection packet handler. */
	if (conn->conn && conn->conn->xprt_ctx)
		tasklet_wakeup(((struct quic_conn_ctx *)conn->conn->xprt_ctx)->wait_event.tasklet);

	return qpkt->len;

 err:
	fprintf(stderr, "%s failed\n", __func__);
	return -1;
}

static ssize_t quic_packets_read(char *buf, size_t len, struct listener *l,
                                 struct sockaddr_storage *saddr, socklen_t *saddrlen)
{
	unsigned char *pos;
	const unsigned char *end;

	pos = (unsigned char *)buf;
	end = pos + len;

	do {
		int ret;
		struct quic_rx_packet *qpkt;

		qpkt = pool_alloc(pool_head_quic_rx_packet);
		if (!qpkt) {
			fprintf(stderr, "Not enough memory to allocate a new packet\n");
			goto err;
		}

		ret = quic_packet_read(&pos, end, qpkt, l, saddr, saddrlen);
		if (ret == -1) {
			pool_free(pool_head_quic_rx_packet, qpkt);
			goto err;
		}

		/* XXX Servers SHOULD be able to read longer (than QUIC_CID_MAXLEN)
		 * connection IDs from other QUIC versions in order to properly form a
		 * version negotiation packet.
		 */

		/* https://tools.ietf.org/pdf/draft-ietf-quic-transport-22.pdf#53:
		 *
		 * Valid packets sent to clients always include a Destination Connection
		 * ID that matches a value the client selects.  Clients that choose to
		 * receive zero-length connection IDs can use the address/port tuple to
		 * identify a connection.  Packets that don’t match an existing
		 * connection are discarded.
		 */
		fprintf(stderr, "long header? %d packet type: 0x%02x \n", !!qpkt->long_header, qpkt->type);
	} while (pos < end);

	return pos - (unsigned char *)buf;

 err:
	return -1;
}

/*
 * This function builds into <buf> buffer a QUIC long packet header whose size may be computed
 * in advance. This is the reponsability of the caller to check there is enough room in this
 * buffer to build a long header.
 * Returns 0 if <type> QUIC packet type is not supported by long header, or 1 if succeeded.
 */
static int quic_build_packet_long_header(unsigned char **buf, const unsigned char *end,
                                         int type, size_t pn_len, struct quic_conn *conn)
{
	if (type > QUIC_PACKET_TYPE_RETRY)
		return 0;

	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | QUIC_PACKET_LONG_HEADER_BIT |
		(type << QUIC_PACKET_TYPE_SHIFT) | (pn_len - 1);
	/* Version */
	quic_write_uint32(buf, end, conn->version);
	*(*buf)++ = conn->dcid.len;
	/* Destination connection ID */
	if (conn->dcid.len) {
		memcpy(*buf, conn->dcid.data, conn->dcid.len);
		*buf += conn->dcid.len;
	}
	/* Source connection ID */
	*(*buf)++ = conn->scid.len;
	if (conn->scid.len) {
		memcpy(*buf, conn->scid.data, conn->scid.len);
		*buf += conn->scid.len;
	}

	return 1;
}

/*
 * This function builds into <buf> buffer a QUIC long packet header whose size may be computed
 * in advance. This is the reponsability of the caller to check there is enough room in this
 * buffer to build a long header.
 * Returns 0 if <type> QUIC packet type is not supported by long header, or 1 if succeeded.
 */
static int quic_build_packet_short_header(unsigned char **buf, const unsigned char *end,
                                          size_t pn_len, struct quic_conn *conn)
{
	/* #0 byte flags */
	*(*buf)++ = QUIC_PACKET_FIXED_BIT | (pn_len - 1);
	/* Destination connection ID */
	if (conn->dcid.len) {
		memcpy(*buf, conn->dcid.data, conn->dcid.len);
		*buf += conn->dcid.len;
	}

	return 1;
}

static int quic_apply_header_protection(unsigned char *buf, unsigned char *pn, size_t pnlen,
                                        const EVP_CIPHER *aead, const unsigned char *key)
{
	int i, ret, outlen;
	EVP_CIPHER_CTX *ctx;
	/*
	 * We need an IV of at least 5 bytes: one byte for bytes #0
	 * and at most 4 bytes for the packet number
	 */
	unsigned char mask[5] = {0};

	ret = 0;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	hexdump(pn + QUIC_PACKET_PN_MAXLEN, 16, "%s sample:\n", __func__);
	if (!EVP_EncryptInit_ex(ctx, aead, NULL, key, pn + QUIC_PACKET_PN_MAXLEN) ||
	    !EVP_EncryptUpdate(ctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_EncryptFinal_ex(ctx, mask, &outlen))
		goto out;

	*buf ^= mask[0] & (*buf & QUIC_PACKET_LONG_HEADER_BIT ? 0xf : 0x1f);
	for (i = 0; i < pnlen; i++)
		pn[i] ^= mask[i + 1];

	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/*
 * This function builds a handshake packet used during a QUIC TLS handshake in <buf> buffer.
 * Return the length of the packet if succeeded minus QUIC_TLS_TAG_LEN, or -1 if failed (not
 * enough room in <buf> to build this packet plus QUIC_TLS_TAG_LEN bytes).
 * So, the trailing QUIC_TLS_TAG_LEN bytes of this packet are not built. But after having
 * successfully retured from this function, we are sure there is enough room the build this AEAD tag.
 * So, the <buf> address will point after the last byte of the payload after having built the handshake
 * with the confidence there is at least QUIC_TLS_TAG_LEN bytes available packet to encrypt it.
 */
static ssize_t quic_do_build_handshake_packet(unsigned char **buf, const unsigned char *end,
                                              unsigned char **buf_pn, size_t *pn_len,
                                              const unsigned char **data, const unsigned char *end_data, uint64_t offset,
                                              enum quic_tls_enc_level level, struct quic_conn *conn)
{
	unsigned char *beg;
	/* This packet type. */
	int packet_type;
	/* Packet number. */
	int64_t pn;
	/* The Length QUIC packet field value which is the length
	 * of the remaining data after this field after encryption.
	 */
	size_t len;
	size_t token_fields_len;
	/* The size of the CRYPTO frame heaeder (without the data). */
	size_t frm_header_sz;
	struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
	struct quic_crypto *crypto = &frm.crypto;
	struct quic_enc_level *enc_level;
	size_t padding_len;

	beg = *buf;
	enc_level = &conn->enc_levels[level];
	packet_type = quic_tls_level_pkt_type(level);

	crypto->data = *data;
	crypto->offset = offset;

	/* For a server, the token field of an Initial packet is empty. */
	token_fields_len = packet_type == QUIC_PACKET_TYPE_INITIAL ? 1 : 0;

	/* Check there is enough room to build the header followed by a token. */
	if (end - *buf < QUIC_LONG_PACKET_MINLEN + conn->dcid.len +
	    conn->scid.len + token_fields_len)
		return -1;

	/* packet number */
	pn = enc_level->pktns->tx.next_pn + 1;

	/* packet number length */
	*pn_len = quic_packet_number_length(pn, enc_level->pktns->rx.largest_acked_pn);

	quic_build_packet_long_header(buf, end, packet_type, *pn_len, conn);

	/* Token */
	if (packet_type == QUIC_PACKET_TYPE_INITIAL) {
		/* Encode the token length (0) for an Initial packet of a server */
		*(*buf)++ = 0;
	}

	/* Crypto frame header size (without data) */
	frm_header_sz = sizeof frm.type + quic_int_getsize(crypto->offset);

	crypto->len = max_stream_data_size(end - *buf,
	                                   *pn_len + frm_header_sz + QUIC_TLS_TAG_LEN,
	                                   end_data - *data);
	frm_header_sz += quic_int_getsize(crypto->len);
	/* packet length (after encryption) */
	len = *pn_len + frm_header_sz + crypto->len + QUIC_TLS_TAG_LEN;

	padding_len = 0;
	if (objt_server(conn->conn->target) &&
	    packet_type == QUIC_PACKET_TYPE_INITIAL && len < QUIC_INITIAL_PACKET_MINLEN)
		len += padding_len = QUIC_INITIAL_PACKET_MINLEN - len;

	/* Length (of the remaining data). Must not fail because, buffer size checked above. */
	quic_enc_int(buf, end, len);

	/* Packet number field address. */
	*buf_pn = *buf;

	/* Packet number encoding. */
	quic_packet_number_encode(buf, end, pn, *pn_len);

	/* Crypto frame */
	if (!quic_build_frame(buf, end, &frm))
		return -1;

	if (padding_len) {
		frm.type = QUIC_FT_PADDING;
		frm.padding.len = padding_len;
		if (!quic_build_frame(buf, end, &frm))
			return -1;
	}

	*data += crypto->len;

	return *buf - beg;
}

static ssize_t quic_build_handshake_packet(unsigned char **buf, const unsigned char *end,
                                           const unsigned char **data, const unsigned char *end_data,
                                           uint64_t *offset,
                                           enum quic_tls_enc_level level, struct quic_conn *conn)
{
	/* A pointer to the packet number fiel in <buf> */
	unsigned char *buf_pn;
	unsigned char *beg, *pos, *payload;
	const unsigned char *pdata;
	size_t pn_len, aad_len;
	ssize_t pkt_len;
	int payload_len;
	struct quic_tls_ctx *tls_ctx;
	struct quic_enc_level *enc_level;
	unsigned char iv[12];
	uint64_t pn;
	struct quic_tx_crypto_frm *cf;

	beg = pos = *buf;
	pdata = *data;
	enc_level = &conn->enc_levels[level];
	pn = enc_level->pktns->tx.next_pn + 1;

	/* <pkt_len> is the length of this packet before encryption. */
	pkt_len = quic_do_build_handshake_packet(&pos, end, &buf_pn, &pn_len,
	                                         &pdata, end_data, *offset, level, conn);
	if (pkt_len == -1)
		return -1;

	payload = (unsigned char *)buf_pn + pn_len;
	payload_len = pos - payload;
	aad_len = payload - beg;

	tls_ctx = &enc_level->tls_ctx;
	if (!quic_aead_iv_build(iv, sizeof iv, tls_ctx->tx.iv, sizeof tls_ctx->tx.iv, pn)) {
		fprintf(stderr, "%s AEAD IV building failed\n", __func__);
		return -2;
	}

	if (!quic_tls_encrypt(payload, payload_len, beg, aad_len,
	                     tls_ctx->aead, tls_ctx->tx.key, iv)) {
		fprintf(stderr, "QUIC packet encryption failed\n");
	    return -2;
	}

	pos += QUIC_TLS_TAG_LEN;

	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->hp, tls_ctx->tx.hp_key)) {
		fprintf(stderr, "Could not apply the header protection\n");
		return -2;
	}

	cf = pool_alloc(pool_head_quic_tx_crypto_frm);
	if (!cf) {
		fprintf(stderr, "CRYPTO frame allocation failed\n");
		return -2;
	}


	cf->len = pdata - *data;
	/* Increment the offset of this crypto data stream */
	cf->pn.key = ++enc_level->pktns->tx.next_pn;
	cf->offset = *offset;
	*offset += cf->len;
	eb64_insert(&enc_level->tx.crypto.frms, &cf->pn);
	/* Update the CRYPTO data pointer. */
	*data = pdata;

	*buf = pos;

	return *buf - beg;
}

static ssize_t quic_do_build_app_packet(unsigned char **buf, const unsigned char *end,
                                        uint64_t pn, size_t *pn_len,
                                        unsigned char **buf_pn,
                                        struct quic_enc_level *qel, struct quic_conn *conn)
{
	unsigned char *pos, *ppos;
	struct quic_frame *frm;

	/* Reserve enough room at the end of the packet for the AEAD TAG. */
	end -= QUIC_TLS_TAG_LEN;

	if (end - *buf < QUIC_SHORT_PACKET_MINLEN + sizeof_quic_cid(&conn->dcid))
		return -1;

	pos = *buf;
	/* Packet number length */
	*pn_len = quic_packet_number_length(pn, qel->pktns->rx.largest_acked_pn);
	quic_build_packet_short_header(&pos, end, *pn_len, conn);

	if (end - pos < *pn_len)
		return -1;

	*buf_pn = pos;

	/* Packet number encoding. */
	quic_packet_number_encode(&pos, end, pn, *pn_len);

	/* Encode a maximum of frames. */
	list_for_each_entry(frm, &conn->tx.frms_to_send, list) {
		ppos = pos;
		if (!quic_build_frame(&ppos, end, frm)) {
			fprintf(stderr, "Could not build frame %s\n", quic_frame_type_string(frm->type));
			break;
		}
		pos = ppos;
	}
	*buf = pos;

	return 1;
}

static ssize_t quic_build_app_packet(unsigned char **buf, const unsigned char *end,
                                     struct quic_conn *conn)
{
	/* A pointer to the packet number fiel in <buf> */
	unsigned char *buf_pn;
	unsigned char *beg, *pos, *payload;
	struct quic_enc_level *qel;
	struct quic_tls_ctx *tls_ctx;
	unsigned char iv[12];
	size_t pn_len, aad_len, payload_len;
	uint64_t pn;

	beg = pos = *buf;
	qel = &conn->enc_levels[QUIC_TLS_ENC_LEVEL_APP];
	pn = qel->pktns->tx.next_pn + 1;

	if (quic_do_build_app_packet(&pos, end, pn, &pn_len, &buf_pn, qel, conn) == -1)
		return -1;

	payload = (unsigned char *)buf_pn + pn_len;
	payload_len = pos - payload;
	aad_len = payload - beg;

	tls_ctx = &qel->tls_ctx;
	if (!quic_aead_iv_build(iv, sizeof iv, tls_ctx->tx.iv, sizeof tls_ctx->tx.iv, pn)) {
		fprintf(stderr, "%s AEAD IV building failed\n", __func__);
		return -2;
	}

	if (!quic_tls_encrypt(payload, payload_len, beg, aad_len,
	                      tls_ctx->aead, tls_ctx->tx.key, iv)) {
		fprintf(stderr, "%s: QUIC packet encryption failed\n", __func__);
		return -2;
	}

	pos += QUIC_TLS_TAG_LEN;
	if (!quic_apply_header_protection(beg, buf_pn, pn_len,
	                                  tls_ctx->hp, tls_ctx->tx.hp_key)) {
		fprintf(stderr, "%s: could not apply header protection\n", __func__);
		return -2;
	}

	*buf = pos;

	return *buf - beg;
}

static int quic_send_app_packets(struct quic_conn_ctx *ctx)
{
	struct quic_conn *quic_conn;
	unsigned char **obuf_pos;
	const unsigned char *obuf_end;
	struct buffer tmpbuf = { };

	(void)tmpbuf;

	quic_conn = ctx->conn->quic_conn;

	obuf_pos = &quic_conn->obuf.pos;
	obuf_end = quic_conn->obuf.data + sizeof quic_conn->obuf.data;

	tmpbuf.area = (char *)quic_conn->obuf.data;
	tmpbuf.size = sizeof quic_conn->obuf.data;
	tmpbuf.data = *obuf_pos - quic_conn->obuf.data;

	do {
		ssize_t to_send;

		(void)to_send;

		to_send = quic_build_app_packet(obuf_pos, obuf_end, quic_conn);
		tmpbuf.data += to_send;

		if (ctx->xprt->snd_buf(quic_conn->conn, quic_conn->conn->xprt_ctx,
		                       &tmpbuf, tmpbuf.data, 0) <= 0)
			return -1;
	} while (0);

	return 1;
}

static size_t quic_conn_handler(int fd, void *ctx)
{
	ssize_t ret;
	size_t done = 0;
	struct listener *l = ctx;
	struct buffer *buf = get_trash_chunk();

	if (!fd_recv_ready(fd))
		return 0;

	do {
		/* Source address */
		struct sockaddr_storage saddr = {0};
		socklen_t saddrlen;

		saddrlen = sizeof saddr;
		ret = recvfrom(fd, buf->area, buf->size, 0,
		               (struct sockaddr *)&saddr, &saddrlen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				fd_cant_recv(fd);
			break;
		}
		else {
			hexdump(buf->area, ret, "------------------------------------------------------------\n"
			        "%s: recvfrom() (%ld)\n", __func__, ret);
			done = buf->data = ret;
			/*
			 * Senders MUST NOT coalesce QUIC packets for different connections into a single
			 * UDP datagram. Receivers SHOULD ignore any subsequent packets with a different
			 * Destination Connection ID than the first packet in the datagram.
			 */
			quic_packets_read(buf->area, buf->data, l, &saddr, &saddrlen);
			//fd_done_recv(fd);
		}
	} while (0);

 out:
	return done;
}

void quic_fd_handler(int fd)
{
	struct listener *l = fdtab[fd].owner;

	fprintf(stderr, "%s: tid: %u\n", __func__, tid);
	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_handler(fd, l);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
