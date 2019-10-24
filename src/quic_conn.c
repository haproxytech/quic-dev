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

#include <stdlib.h>
#include <errno.h>

#include <common/chunk.h>

#include <types/global.h>
#include <types/quic.h>
#include <types/quic_tls.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/listener.h>
#include <proto/quic_conn.h>
#include <proto/quic_tls.h>

struct quic_transport_params quid_dflt_transport_params = {
	.max_packet_size    = QUIC_DFLT_MAX_PACKET_SIZE,
	.ack_delay_exponent = QUIC_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay      = QUIC_DFLT_MAX_ACK_DELAY,
};

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

DECLARE_POOL(pool_head_quic_conn, "quic_conn",
             sizeof(struct quic_conn) + QUIC_CID_MAXLEN);


/* Return a 32-bits integer in <val> from QUIC packet with <buf> as address.
 * Returns 0 if failed (not enough data), 1 if succeeded.
 * Makes <buf> point to the data after this 32-bits value if succeeded.
 * Note that these 32-bits integers are network bytes ordered objects.
 */
static int quic_read_uint32(uint32_t *val, const unsigned char **buf, const unsigned char *end)
{
	if (end - *buf < sizeof *val)
		return 0;

	*val = ntohl(*(uint32_t *)*buf);
	*buf += sizeof *val;

	return 1;
}


uint64_t *quic_max_pn(struct quic_conn *conn, int server, int long_header, int packet_type)
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
uint64_t decode_packet_number(uint64_t largest_pn, uint32_t truncated_pn, unsigned int pn_nbits)
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
                                         unsigned char *pn, unsigned char *byte0, const unsigned char *end)
{
	int ret, outlen, i, pnlen;
	uint64_t *largest_pn, packet_number;
	uint32_t truncated_pn = 0;
	unsigned char mask[16] = {0};
	unsigned char *sample;
	EVP_CIPHER_CTX *ctx;
	struct quic_tls_ctx *tls_ctx;
	unsigned char *hp_key;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	ret = 0;
	sample = pn + QUIC_PACKET_PN_MAXLEN;
	tls_ctx = &conn->tls_ctx[QUIC_TLS_ENC_LEVEL_INITIAL];

	hexdump(sample, 16, "packet sample:\n");
	hp_key = tls_ctx->rx.hp_key;
	if (!EVP_DecryptInit_ex(ctx, tls_ctx->hp, NULL, hp_key, NULL))
		goto out;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL);

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, sample) ||
	    !EVP_DecryptUpdate(ctx, mask, &outlen, mask, sizeof mask) ||
	    !EVP_DecryptFinal_ex(ctx, mask, &outlen))
	    goto out;


	*byte0 ^= mask[0] & (pkt->type == QUIC_PACKET_TYPE_INITIAL ? 0xf : 0x1f);
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
	fprintf(stderr, "%s packet_number: %lu\n", __func__, packet_number);
	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

static void quic_aead_iv_build(struct quic_conn *conn, uint64_t pn, uint32_t pnl)
{
	int i;
	unsigned int shift;
	struct quic_tls_ctx *ctx = &conn->tls_ctx[QUIC_TLS_ENC_LEVEL_INITIAL];
	unsigned char *iv = ctx->rx.iv;
	unsigned char *aead_iv = ctx->aead_iv;
	size_t iv_size = sizeof ctx->rx.iv;

	hexdump(iv, iv_size, "%s: IV:\n", __func__);
	for (i = 0; i < iv_size - sizeof pn; i++)
		*aead_iv++ = *iv++;

	shift = 56;
	for (i = iv_size - sizeof pn; i < iv_size; i++, shift -= 8)
		*aead_iv++ = *iv++ ^ (pn >> shift);
	hexdump(ctx->aead_iv, iv_size, "%s: BUILD IV:\n", __func__);
}

/*
 * https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#aead
 *
 * 5.3. AEAD Usage
 *
 * Packets are protected prior to applying header protection (Section 5.4).
 * The unprotected packet header is part of the associated data (A). When removing
 * packet protection, an endpoint first removes the header protection.
 * (...)
 * These ciphersuites have a 16-byte authentication tag and produce an output 16
 * bytes larger than their input.
 * The key and IV for the packet are computed as described in Section 5.1. The nonce,
 * N, is formed by combining the packet protection IV with the packet number. The 62
 * bits of the reconstructed QUIC packet number in network byte order are left-padded
 * with zeros to the size of the IV. The exclusive OR of the padded packet number and
 * the IV forms the AEAD nonce.
 *
 * The associated data, A, for the AEAD is the contents of the QUIC header, starting
 * from the flags byte in either the short or long header, up to and including the
 * unprotected packet number.
 *
 * The input plaintext, P, for the AEAD is the payload of the QUIC packet, as described
 * in [QUIC-TRANSPORT].
 *
 * The output ciphertext, C, of the AEAD is transmitted in place of P.
 *
 * Some AEAD functions have limits for how many packets can be encrypted under the same
 * key and IV (see for example [AEBounds]). This might be lower than the packet number limit.
 * An endpoint MUST initiate a key update (Section 6) prior to exceeding any limit set for
 * the AEAD that is in use.
 */
static int quic_decrypt_payload(struct quic_conn *conn, struct quic_packet *pkt,
                                unsigned char *pn, unsigned char **buf, const unsigned char *end)
{
	uint32_t algo;
	int  outlen, payload_len, aad_len;
	unsigned char *payload;
	size_t off;
	unsigned char *key;
	struct quic_tls_ctx *tls_ctx;

	EVP_CIPHER_CTX *ctx;

	algo = pkt->type == QUIC_PACKET_TYPE_INITIAL ? TLS1_3_CK_AES_128_GCM_SHA256 : -1;
	tls_ctx = pkt->type == QUIC_PACKET_TYPE_INITIAL ? &conn->tls_ctx[QUIC_PACKET_TYPE_INITIAL] : NULL;

	key = tls_ctx->rx.key;

	aad_len = pn + pkt->pnl - *buf;
	hexdump(key, 16, "\n\n%s key: (aad_len: %d)\n", __func__, aad_len);

	/* The payload is after the Packet Number field. */
	payload = pn + pkt->pnl;
	payload_len = pkt->len - pkt->pnl;
	off = 0;

	quic_aead_iv_build(conn, pkt->pn, pkt->pnl);

	ctx = EVP_CIPHER_CTX_new();
	switch (algo) {
		case TLS1_3_CK_AES_128_GCM_SHA256:
			if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, conn->tls_ctx[QUIC_PACKET_TYPE_INITIAL].aead_iv) ||
			    !EVP_DecryptUpdate(ctx, NULL, &outlen, *buf, aad_len) ||
			    !EVP_DecryptUpdate(ctx, payload, &outlen, payload, payload_len - 16))
			    return 0;

			off += outlen;

			if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, payload + payload_len - 16) ||
			    !EVP_DecryptFinal_ex(ctx, payload + off, &outlen))
				return 0;

			off += outlen;
			*buf = payload;

			hexdump(payload, off, "Decrypted payload(%zu):\n", off);
			break;
	}

	EVP_CIPHER_CTX_free(ctx);

	return 1;
}

static int quic_parse_packet_frames(struct quic_conn *conn, struct quic_packet *pkt,
                                    unsigned char *pn, unsigned char *buf, const unsigned char *end)
{
	const unsigned char *pos;

	pos = buf;

	while (pos < end) {
		switch (*pos++) {
		case QUIC_FT_CRYPTO:
		{
			struct crypto_frame *cf;

			fprintf(stderr, "%s CRYPTO frame\n", __func__);
			cf = &conn->icfs[conn->curr_icf];

			cf->offset = quic_dec_int(&pos, end);
			if (cf->offset == -1)
				return 0;

			cf->datalen = quic_dec_int(&pos, end);
			if (cf->datalen == -1)
				return 0;
			fprintf(stderr, "%s frame length %zu\n", __func__, cf->datalen);

			if (end - pos < cf->datalen)
				return 0;

			cf->data = pos;
			pos += cf->datalen;
			conn->curr_icf++;
			conn->curr_icf &= sizeof conn->icfs / sizeof *conn->icfs - 1;
			break;
		}

		case QUIC_FT_PADDING:
			fprintf(stderr, "%s PADDING frame\n", __func__);
			pos = end;
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
int quic_new_conn(struct quic_conn *quic_conn,
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
	if (!quic_tls_derive_packet_protection_keys(ctx->aead, ctx->md,
	                                            rx_ctx->key, sizeof rx_ctx->key,
	                                            rx_ctx->iv, sizeof rx_ctx->iv,
	                                            rx_ctx->hp_key, sizeof rx_ctx->hp_key,
	                                            rx_init_sec, sizeof rx_init_sec))
		return 0;
	if (!quic_tls_derive_packet_protection_keys(ctx->aead, ctx->md,
	                                            tx_ctx->key, sizeof tx_ctx->key,
	                                            tx_ctx->iv, sizeof tx_ctx->iv,
	                                            tx_ctx->hp_key, sizeof tx_ctx->hp_key,
	                                            tx_init_sec, sizeof tx_init_sec))
		return 0;
	return 1;
}

ssize_t quic_packet_read_header(struct quic_packet *qpkt,
                                 unsigned char **buf, const unsigned char *end,
                                 struct listener *l,
                                 struct sockaddr_storage *saddr, socklen_t *saddrlen)
{
	unsigned char *beg;
	unsigned char dcid_len, scid_len;
	uint64_t len;
	unsigned char *pn = NULL; /* Packet number */
	struct quic_conn *conn;

	if (end - *buf <= QUIC_PACKET_MINLEN)
		goto err;

	/* Fixed bit */
	if (!(**buf & QUIC_PACKET_FIXED_BIT))
		/* XXX TO BE DISCARDED */
		goto err;

	beg = *buf;
	/* Header form */
	qpkt->long_header = **buf & QUIC_PACKET_LONG_HEADER_BIT;
	/* Packet type */
	qpkt->type = (*(*buf)++ >> QUIC_PACKET_TYPE_SHIFT) & QUIC_PACKET_TYPE_BITMASK;
	/* Version */
	if (!quic_read_uint32(&qpkt->version, (const unsigned char **)buf, end))
		goto err;

	if (!qpkt->version) { /* XXX TO DO XXX Version negotiation packet */ };

	if (qpkt->long_header) {
		/* Destination Connection ID Length */
		dcid_len = *(*buf)++;
		/* We want to be sure we can read <dcid_len> bytes and one more for <scid_len> value */
		if (dcid_len > QUIC_CID_MAXLEN || end - *buf < dcid_len + 1)
			/* XXX MUST BE DROPPED */
			goto err;

		if (dcid_len)
			memcpy(qpkt->dcid.data, *buf, dcid_len);
		qpkt->dcid.len = dcid_len;
		*buf += dcid_len;

		if (qpkt->dcid.len)
			hexdump(qpkt->dcid.data, qpkt->dcid.len, "\n%s: DCID:\n", __func__);

		/* Source Connection ID Length */
		scid_len = *(*buf)++;
		if (scid_len > QUIC_CID_MAXLEN || end - *buf < scid_len)
			/* XXX MUST BE DROPPED */
			goto err;

		if (scid_len)
			memcpy(qpkt->scid.data, *buf, scid_len);
		qpkt->scid.len = scid_len;
		*buf += scid_len;

		if (qpkt->dcid.len) {
			struct ebmb_node *node;

			node = ebmb_lookup(&l->quic_clients, qpkt->dcid.data, qpkt->dcid.len);
			if (!node) {
				int ret;

				conn = pool_alloc(pool_head_quic_conn);
				memset(conn, 0, sizeof *conn);
				ret = quic_new_conn(conn, l, saddr);
				if (conn && ret != -1) {
					quic_initial_tls_ctx_init(&conn->tls_ctx[QUIC_TLS_ENC_LEVEL_INITIAL]);
					conn->cid_len = qpkt->dcid.len;
					memcpy(conn->cid.key, qpkt->dcid.data, qpkt->dcid.len);
					ebmb_insert(&l->quic_clients, &conn->cid, conn->cid_len);
				}
				else {
					/* XXX TODO XXX */
				}
			}
			else {
				conn = ebmb_entry(node, struct quic_conn, cid);
			}
		}
	}
	else {
		/* XXX TO DO: Short header XXX */
	}

	if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
		uint64_t token_len;
		struct quic_tls_ctx *ctx = &conn->tls_ctx[QUIC_TLS_ENC_LEVEL_INITIAL];

		token_len = quic_dec_int((const unsigned char **)buf, end);
		if (token_len == -1 || end - *buf < token_len)
			goto err;

		/* XXX TO DO XXX 0 value means "the token is not present".
		 * A server which sends an Initial packet must not set the token.
		 * So, a client which receives an Initial packet with a token
		 * MUST discard the packet or generate a connection error with
		 * PROTOCOL_VIOLATION as type.
		 * The token must be provided in a Retry packet or NEW_TOKEN frame.
		 */
		qpkt->token_len = token_len;
		quic_conn_derive_initial_secrets(ctx, qpkt->dcid.data, qpkt->dcid.len, 1);
	}

	if (qpkt->type != QUIC_PACKET_TYPE_RETRY && qpkt->version) {
		len = quic_dec_int((const unsigned char **)buf, end);
		if (len == -1 || end - *buf < len)
			goto err;

		qpkt->len = len;
		/*
		 * The packet number is here. This is also the start minus QUIC_PACKET_PN_MAXLEN
		 * of the sample used to add/remove the header protection.
		 */
		pn = *buf;

		hexdump(pn, 2, "Packet Number two first bytes:\n");
		if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
			if (!quic_remove_header_protection(conn, qpkt, pn, beg, end)) {
				fprintf(stderr, "Could not remove packet header protection\n");
				goto err;
			}

			if (!quic_decrypt_payload(conn, qpkt, pn, &beg, end)) {
				fprintf(stderr, "Could not decrypt the payload\n");
				goto err;
			}

			memcpy(&conn->pkts[conn->curr_pkt++].data, beg, end - beg);
			conn->curr_pkt &= sizeof conn->pkts / sizeof *conn->pkts - 1;

			if (!quic_parse_packet_frames(conn, qpkt, pn, beg, end)) {
				fprintf(stderr, "Could not parse the packet frames\n");
			}
		}
	}

	fprintf(stderr, "\ttoken_len: %lu len: %lu pnl: %u\n",
	        qpkt->token_len, qpkt->len, qpkt->pnl);

	return *buf - beg;

 err:
	return -1;
}

ssize_t quic_packets_read(char *buf, size_t len, struct listener *l,
                          struct sockaddr_storage *saddr, socklen_t *saddrlen)
{
	unsigned char *pos;
	const unsigned char *end;
	struct quic_packet qpkt = {0};

	pos = (unsigned char *)buf;
	end = pos + len;

	if (quic_packet_read_header(&qpkt, &pos, end, l, saddr, saddrlen) == -1)
		goto err;

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
	fprintf(stderr, "long header? %d packet type: 0x%02x version: 0x%08x\n",
	        !!qpkt.long_header, qpkt.type, qpkt.version);

	return pos - (unsigned char *)buf;

 err:
	return -1;
}

/* XXX TODO: adapt these comments */
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

size_t quic_conn_to_buf(int fd, void *ctx)
{
	ssize_t ret;
	size_t done = 0;
	struct listener *l = ctx;
	struct buffer *buf = get_trash_chunk();

	if (!fd_recv_ready(fd))
		return 0;

	if (unlikely(!(fdtab[fd].ev & FD_POLL_IN))) {
		if ((fdtab[fd].ev & FD_POLL_ERR))
			goto out;
	}

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
			hexdump(buf->area, ret, "%s: recvfrom() (%ld)\n", __func__, ret);
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


/* XXX TODO: adapt these comments */
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
__attribute__((unused))
static size_t quic_conn_from_buf(int fd, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	fprintf(stderr, "# %s ctx @%p\n", __func__, xprt_ctx);

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

		ret = send(fd, b_peek(buf, done), try, send_flag);

		if (ret > 0) {
			count -= ret;
			done += ret;

			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(fd);
			break;
		}
		else if (errno != EINTR) {
			/* XXX TODO */
			break;
		}
	}

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

