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
#include <proto/quic_frame.h>
#include <proto/quic_tls.h>
#include <proto/ssl_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/xprt_quic.h>

#include <types/global.h>

struct quic_conn_ctx {
	struct connection *conn;
	SSL *ssl;
	BIO *bio;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *recv_wait;
	struct wait_event *send_wait;
};

struct quic_transport_params quid_dflt_transport_params = {
	.max_packet_size    = QUIC_DFLT_MAX_PACKET_SIZE,
	.ack_delay_exponent = QUIC_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay      = QUIC_DFLT_MAX_ACK_DELAY,
};

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

DECLARE_POOL(pool_head_quic_conn, "quic_conn",
             sizeof(struct quic_conn) + QUIC_CID_MAXLEN);
DECLARE_STATIC_POOL(pool_head_quic_packet, "quic_packet", sizeof(struct quic_packet));

DECLARE_STATIC_POOL(quic_conn_ctx_pool, "quic_conn_ctx_pool", sizeof(struct quic_conn_ctx));

static BIO_METHOD *ha_quic_meth;

int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *read_secret,
                                   const uint8_t *write_secret, size_t secret_len)
{
	fprintf(stderr, "%s\n", __func__);
	hexdump(read_secret, secret_len, "read_secret:\n");
	hexdump(write_secret, secret_len, "write_secret:\n");
	return 1;
}

int ha_quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len)
{
	fprintf(stderr, "%s\n", __func__);
	hexdump(data, len, "===> %s:\n", __func__);
	return 1;
}

int ha_quic_flush_flight(SSL *ssl)
{
	fprintf(stderr, "%s\n", __func__);
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
		             (struct sockaddr *)conn->src, get_addr_len(conn->src));
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

static struct task *quic_conn_io_cb(struct task *t, void *context, unsigned short state)
{
	return NULL;
}

/* We can't have an underlying XPRT, so just return -1 to signify failure */
static int quic_conn_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	/* This is the lowest xprt we can have, so if we get there we didn't
	 * find the xprt we wanted to remove, that's a bug
	 */
	BUG_ON(1);
	return -1;
}

static int quic_conn_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_conn_ctx *ctx;

	if (*xprt_ctx)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	ctx = pool_alloc(quic_conn_ctx_pool);
	if (!ctx) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		return -1;
	}

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		pool_free(quic_conn_ctx_pool, ctx);
		return -1;
	}

	ctx->wait_event.tasklet->process = quic_conn_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->conn = conn;
	ctx->send_wait = NULL;
	ctx->recv_wait = NULL;


	if (objt_server(conn->target)) {
		/* Client */
		/* XXX TO DO XXX */
	}
	else if (objt_listener(conn->target)) {
		/* Listener */
		struct bind_conf *bc = __objt_listener(conn->target)->bind_conf;

		if (ssl_bio_and_sess_init(conn, bc->initial_ctx,
		                          &ctx->ssl, &ctx->bio, ha_quic_meth, ctx) == -1)
			goto err;
	}

	*xprt_ctx = ctx;
	/* Start the handshake */
	tasklet_wakeup(ctx->wait_event.tasklet);

	return 0;

 err:
	return -1;
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
	.prepare_srv = ssl_sock_prepare_srv_ctx,
	.destroy_srv = ssl_sock_free_srv_ctx,
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
        pn_space = 0;
    } else if (long_header && packet_type == QUIC_PACKET_TYPE_HANDSHAKE) {
        pn_space = 1;
    } else {
        pn_space = 2;
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

static int quic_remove_header_protection(struct quic_conn *conn, struct quic_packet *pkt,
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

	hexdump(sample, sizeof mask, "packet sample:\n");

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

static void quic_aead_iv_build(struct quic_tls_ctx *tls_ctx, uint64_t pn, uint32_t pnl)
{
	int i;
	unsigned int shift;
	unsigned char *iv = tls_ctx->rx.iv;
	unsigned char *aead_iv = tls_ctx->aead_iv;
	size_t iv_size = sizeof tls_ctx->rx.iv;

	hexdump(iv, iv_size, "%s: IV:\n", __func__);

	for (i = 0; i < iv_size - sizeof pn; i++)
		*aead_iv++ = *iv++;

	shift = 56;
	for (i = iv_size - sizeof pn; i < iv_size; i++, shift -= 8)
		*aead_iv++ = *iv++ ^ (pn >> shift);

	hexdump(tls_ctx->aead_iv, iv_size, "%s: BUILD IV:\n", __func__);
}

static int quic_parse_packet_frames(struct quic_conn *conn, struct quic_packet *pkt,
                                    unsigned char *pn, unsigned char *buf, const unsigned char *end)
{
	struct quic_frame frm;
	const unsigned char *pos;

	pos = buf;

	while (pos < end) {

		if (!quic_parse_frame(&frm, &pos, end))
			return 0;

		switch (frm.type) {
		case QUIC_FT_CRYPTO:
		{
			struct crypto_frame *cf;

			cf = &conn->icfs[conn->curr_icf];
			if (frm.crypto.len > sizeof cf->data)
				return 0;

			cf->offset = frm.crypto.offset;
			cf->datalen = frm.crypto.len;
			memcpy(cf->data, frm.crypto.data, frm.crypto.len);
			conn->curr_icf++;
			conn->curr_icf &= sizeof conn->icfs / sizeof *conn->icfs - 1;
			break;
		}

		case QUIC_FT_PADDING:
			if (pos != end) {
				fprintf(stderr, "Wrong frame! (%ld len: %lu)\n", end - pos, frm.padding.len);
				return 0;
			}
			break;

		default:
			break;
		}
	}

	return 1;
}

/*
 * Inspired from session_accept_fd().
 */
static int quic_new_conn(struct quic_conn *quic_conn,
                         struct listener *l, struct sockaddr_storage *saddr)
{
	struct connection *cli_conn;
	struct proxy *p = l->bind_conf->frontend;
	struct session *sess;

	if (unlikely((cli_conn = conn_new()) == NULL))
		goto out;

	if (!sockaddr_alloc(&cli_conn->src))
		goto out_free_conn;

	cli_conn->quic_conn = quic_conn;

	/* XXX Not sure it is safe to keep this statement. */
	cli_conn->handle.fd = l->fd;
	if (saddr)
		*cli_conn->src = *saddr;
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


	if (!quic_derive_initial_secret(ctx->md, initial_secret, sizeof initial_secret,
	                                cid, cidlen))
		return 0;
	if (!quic_tls_derive_initial_secrets(ctx->md,
	                                     rx_init_sec, sizeof rx_init_sec,
	                                     tx_init_sec, sizeof tx_init_sec,
	                                     initial_secret, sizeof initial_secret, server))
	    return 0;

	if (server) {
		rx_ctx = &ctx->rx;
		tx_ctx = &ctx->tx;
	}
	else {
		rx_ctx = &ctx->tx;
		tx_ctx = &ctx->rx;
	}
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

static int quic_new_conn_init(struct listener *l, struct quic_conn *conn, uint32_t version,
                              unsigned char *dcid, size_t dcid_len, unsigned char *scid, size_t scid_len)
{
	int i;

	fprintf(stderr, "%s: new conn @%p\n", __func__, conn);
	conn->version = version;
	/* Copy the initial DCID. */
	conn->idcid.len = dcid_len;
	memcpy(conn->idcid.data, dcid, dcid_len);

	/* Copy the SCID as our DCID for this connection. */
	memcpy(conn->dcid.data, scid, scid_len);
	conn->dcid.len = scid_len;

	/* Select our SCID which is the connection ID use to match the client connections. */
	conn->scid.len = QUIC_CID_LEN;
	RAND_bytes(conn->scid.data, conn->scid.len);

	/* Insert the DCIC the client has choosen. */
	ebmb_insert(&l->quic_initial_clients, &conn->idcid_node, conn->idcid.len);

	/* Insert our SCID, the connection ID for the client. */
	ebmb_insert(&l->quic_clients, &conn->scid_node, conn->scid.len);

	/* Initialize the Initial level TLS encryption context. */
	quic_initial_tls_ctx_init(&conn->tls_ctx[QUIC_TLS_ENC_LEVEL_INITIAL]);
	/* Packet number spaces initialization. */
	for (i = 0; i < QUIC_TLS_PKTNS_MAX; i++) {
		quic_tls_ctx_pktns_init(&conn->tx_ns[i]);
		quic_tls_ctx_pktns_init(&conn->rx_ns[i]);
	}
	for (i = 0; i < QUIC_TLS_ENC_LEVEL_MAX; i++)
		conn->iqpkts[i] = EB_ROOT;

	return 1;
}

static ssize_t quic_packet_read(unsigned char **buf, const unsigned char *end,
                                struct quic_packet *qpkt, struct listener *l,
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
			quic_clients = &l->quic_initial_clients;
			cid_lookup_len = qpkt->dcid.len;
		}
		else {
			quic_clients = &l->quic_clients;
			cid_lookup_len = QUIC_CID_LEN;
		}

		node = ebmb_lookup(quic_clients, qpkt->dcid.data, cid_lookup_len);
		if (!node) {
			int ret;

			if (qpkt->type != QUIC_PACKET_TYPE_INITIAL) {
				fprintf(stderr, "Connection not found.\n");
				goto err;
			}

			conn = pool_alloc(pool_head_quic_conn);
			memset(conn, 0, sizeof *conn);
			ret = quic_new_conn(conn, l, saddr);

			if (!conn || ret == -1)
				goto err;

			if (!quic_new_conn_init(l, conn, qpkt->version,
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
			struct quic_tls_ctx *ctx = &conn->tls_ctx[QUIC_TLS_ENC_LEVEL_INITIAL];

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
		node = ebmb_lookup(&l->quic_clients, *buf, QUIC_CID_LEN);
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
	tls_ctx = &conn->tls_ctx[qpkt_enc_level];

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
	eb64_insert(&conn->iqpkts[qpkt_enc_level], &qpkt->pn_node);

	/* The length of the packet includes the packet number field. */
	qpkt->len += pn - beg;
	memcpy(qpkt->data, beg, qpkt->len);
	/* Build the AEAD IV. */
	quic_aead_iv_build(tls_ctx, qpkt->pn, qpkt->pnl);
	/* The AAD includes the packet number field found at <pn>. */
	qpkt->aad_len = pn - beg + qpkt->pnl;
	/* Updtate the offset of <*buf> for the next QUIC packet. */
	*buf = beg + qpkt->len;

	return qpkt->len;

 err:
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
		struct quic_packet *qpkt;

		qpkt = pool_alloc(pool_head_quic_packet);
		if (!qpkt) {
			fprintf(stderr, "Not enough memory to allocate a new packet\n");
			goto err;
		}

		ret = quic_packet_read(&pos, end, qpkt, l, saddr, saddrlen);
		if (ret == -1) {
			pool_free(pool_head_quic_packet, qpkt);
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
 * This function builds a QUIC long packet header whose size may be computed
 * in advance in <buf> buffer. This is the reponsability of the caller to check
 * there is enought room in this buffer to build a long header.
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

static int quic_apply_header_protection(unsigned char *buf, unsigned char *pn, size_t pnlen, int type,
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
static ssize_t __quic_build_handshake_packet(unsigned char **buf, const unsigned char *end,
                                             unsigned char **buf_pn, size_t *buf_pn_len,
                                             const unsigned char *data, size_t datalen,
                                             enum quic_tls_enc_level level, struct quic_conn *conn)
{
	unsigned char *beg;
	struct quic_pktns *rx_pktns, *tx_pktns;
	int packet_type;
	int64_t pn, last_acked_pn;
	size_t len;
	size_t token_fields_len;
	size_t frm_sz;
	struct quic_frame frm = { .type = QUIC_FT_CRYPTO, };
	struct quic_crypto *crypto = &frm.crypto;

	if ((level != QUIC_TLS_ENC_LEVEL_INITIAL && level != QUIC_TLS_ENC_LEVEL_HANDSHAKE))
		return -1;


	beg = *buf;
	tx_pktns = &conn->tx_ns[quic_tls_pktns(level)];
	crypto->len = datalen;
	crypto->data = data;
	crypto->offset = tx_pktns->offset;
	rx_pktns = &conn->rx_ns[quic_tls_pktns(level)];
	packet_type = quic_tls_level_pkt_type(level);

	/* Crypto frame information */
	frm_sz = sizeof frm.type + quic_int_getsize(crypto->offset) +
		quic_int_getsize(crypto->len) + datalen;

	/* packet number */
	pn = tx_pktns->last_pn + 1;
	last_acked_pn = rx_pktns->last_acked_pn;

	/* packet number length */
	*buf_pn_len = quic_packet_number_length(pn, last_acked_pn);
	/* packet length (after encryption) */
	len = *buf_pn_len + frm_sz + QUIC_TLS_TAG_LEN;

	if (packet_type == QUIC_PACKET_TYPE_INITIAL) {
		/* Zero-length token field */
		token_fields_len = 1;
	}
	else {
		token_fields_len = 1; /* plus something XXX TO DO XXX */
	}

	if (end - *buf < QUIC_LONG_PACKET_MINLEN + conn->dcid.len + conn->scid.len +
	    token_fields_len + quic_int_getsize(len) + len)
		return -1;

	quic_build_packet_long_header(buf, end, packet_type, *buf_pn_len, conn);

	/* Token */
	if (packet_type == QUIC_PACKET_TYPE_INITIAL) {
		/* Encode the token length which is zero for a client or for an
		 * Initial packet of a server.
		 */
		*(*buf)++ = 0;
	}

	/* Length (of the remaining data) */
	quic_enc_int(buf, end, len);

	/* Packet number */
	*buf_pn = *buf;
	switch (*buf_pn_len) {
	case 1:
		**buf = pn;
		break;
	case 2:
		write_n16(*buf, pn);
		break;
	case 3:
		pn = htonl(pn);
		memcpy(*buf, &pn, *buf_pn_len);
		break;
	case 4:
		write_n32(*buf, pn);
		break;
	}
	*buf += *buf_pn_len;

	/* Crypto frame */
	if (!quic_build_frame(buf, end, &frm))
		return -1;

	return *buf - beg;
}

static ssize_t quic_build_handshake_packet(unsigned char **buf, const unsigned char *end,
                                           const unsigned char *data, size_t datalen,
                                           enum quic_tls_enc_level level, struct quic_conn *conn)
{
	/* A pointer to the packet number fiel in <buf> */
	unsigned char *buf_pn;
	unsigned char *beg, *payload;
	size_t pn_len, aad_len;
	ssize_t pkt_len;
	int payload_len;
	struct quic_tls_ctx *tls_ctx;

	beg = *buf;
	/* <pkt_len> is the length of this packet before encryption. */
	pkt_len = __quic_build_handshake_packet(buf, end, &buf_pn, &pn_len,
	                                        data, datalen, level, conn);
	if (pkt_len == -1)
		return -1;

	hexdump(beg, pkt_len, "%s PKT (%zd)\n", __func__, pkt_len);
	payload = (unsigned char *)buf_pn + pn_len;
	payload_len = *buf - payload;
	aad_len = payload - beg;

	tls_ctx = &conn->tls_ctx[level];
	if (!quic_tls_encrypt(payload, payload_len, beg, aad_len,
	                     tls_ctx->aead, tls_ctx->tx.key, tls_ctx->tx.iv))
	    return -1;

	*buf += QUIC_TLS_TAG_LEN;

	if (!quic_apply_header_protection(beg, buf_pn, pn_len, level,
	                                  tls_ctx->hp, tls_ctx->tx.hp_key))
		return -1;

	return *buf - beg;
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
			fd_done_recv(fd);
		}
	} while (0);

 out:
	return done;
}

void quic_fd_handler(int fd)
{
	struct listener *l = fdtab[fd].owner;

	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_handler(fd, l);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
