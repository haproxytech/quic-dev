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
#include <types/quic_frame.h>
#include <types/quic_tls.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/listener.h>
#include <proto/quic_conn.h>
#include <proto/quic_frame.h>
#include <proto/quic_tls.h>

#define QUIC_DEBUG

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
static int quic_decrypt_payload(unsigned char *payload, size_t payload_len,
                                const EVP_CIPHER *aead, const unsigned char *key, const unsigned char *iv,
                                unsigned char **buf, const unsigned char **end)
{
	int ret, outlen, aad_len;
	size_t off;
	EVP_CIPHER_CTX *ctx;

	ret = 0;
	off = 0;
	aad_len = payload - *buf;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_DecryptInit_ex(ctx, aead, NULL, key, iv) ||
		!EVP_DecryptUpdate(ctx, NULL, &outlen, *buf, aad_len) ||
		!EVP_DecryptUpdate(ctx, payload, &outlen, payload, payload_len - QUIC_TLS_TAG_LEN))
		goto out;

	off += outlen;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN,
	                         payload + payload_len - QUIC_TLS_TAG_LEN) ||
	    !EVP_DecryptFinal_ex(ctx, payload + off, &outlen))
		goto out;

	off += outlen;
	*buf = payload;
	*end = *buf + off;

	hexdump(payload, off, "Decrypted payload(%zu):\n", off);
	ret = 1;
 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

static int quic_encrypt_payload(const unsigned char *aad, size_t aad_len,
								unsigned char *payload, size_t payload_len,
                                const EVP_CIPHER *aead, const unsigned char *key, const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;
	int ret, outlen;
#ifdef QUIC_DEBUG
	unsigned char dec_buf[2048], *dec_bufp = dec_buf;
	const unsigned char *end_dec_buf = dec_bufp + sizeof dec_buf;
#endif

	ret = 0;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, aead, NULL, key, iv) ||
		!EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len) ||
		!EVP_EncryptUpdate(ctx, payload, &outlen, payload, payload_len) ||
		!EVP_EncryptFinal_ex(ctx, payload + outlen, &outlen) ||
		!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, QUIC_TLS_TAG_LEN, payload + payload_len))
		goto out;

#ifdef QUIC_DEBUG
	hexdump(payload, payload_len + QUIC_TLS_TAG_LEN, "%s FINAL ENCRYPTED PAYLOAD\n", __func__);
	hexdump(aad, aad_len + payload_len + QUIC_TLS_TAG_LEN, "%s FINAL ENCRYPTED PACKET\n", __func__);
	/* Make a copy of this encrypted packet. */
	memcpy(dec_buf, aad, aad_len + payload_len + QUIC_TLS_TAG_LEN);
	if (!quic_decrypt_payload(dec_buf + aad_len, payload_len + QUIC_TLS_TAG_LEN,
	                          aead, key, iv, &dec_bufp, &end_dec_buf))
		goto out;
#endif
	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);

	return ret;
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

static int quic_conn_init(struct listener *l, struct quic_conn *conn, uint32_t version,
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
	struct ebmb_node *node;
	struct quic_tls_ctx *tls_ctx;

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

			if (!quic_conn_init(l, conn, qpkt->version,
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
	fprintf(stderr, "%s packet length: %zu version: %08x\n", __func__, qpkt->len, qpkt->version);

	/*
	 * The packet number is here. This is also the start minus QUIC_PACKET_PN_MAXLEN
	 * of the sample used to add/remove the header protection.
	 */
	pn = *buf;

	if (qpkt->long_header)
		/* XXX Check the relation between the packet type and the encryption level. */
		tls_ctx = &conn->tls_ctx[quic_packet_type_enc_level(qpkt->type)];
	else
		tls_ctx = &conn->tls_ctx[QUIC_TLS_ENC_LEVEL_APP];

	if (!quic_remove_header_protection(conn, qpkt, tls_ctx, pn, beg, end)) {
		fprintf(stderr, "Could not remove packet header protection\n");
		goto err;
	}
	fprintf(stderr, "%s packet number: %lu\n", __func__, qpkt->pn);

	/* Build the AEAD IV. */
	quic_aead_iv_build(tls_ctx, qpkt->pn, qpkt->pnl);
	/* The payload is just after the packet number field */
	if (!quic_decrypt_payload(pn + qpkt->pnl, qpkt->len - qpkt->pnl,
	                          tls_ctx->aead, tls_ctx->rx.key, tls_ctx->aead_iv, &beg, &end)) {
		fprintf(stderr, "Could not decrypt the payload\n");
		goto err;
	}

	memcpy(&conn->pkts[conn->curr_pkt++].data, beg, end - beg);
	conn->curr_pkt &= sizeof conn->pkts / sizeof *conn->pkts - 1;

	if (!quic_parse_packet_frames(conn, qpkt, pn, beg, end)) {
		fprintf(stderr, "Could not parse the packet frames\n");
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

/*
 * This function builds a handshake packet used during a QUIC TLS handshake in <buf> buffer.
 * Return the length of the packet if succeeded minus QUIC_TLS_TAG_LEN, or -1 if failed (not
 * enough room in <buf> to build this packet plus QUIC_TLS_TAG_LEN bytes).
 * So, the trailing QUIC_TLS_TAG_LEN bytes of this packet are not built. But after having
 * successfully retured from this function, we are sure there is enough room the build this AEAD tag.
 * So, the <buf> address will point after the last byte of the payload after having built the handshake
 * with the confidence there is at least QUIC_TLS_TAG_LEN bytes available packet to encrypt it.
 */
ssize_t __quic_build_handshake_packet(unsigned char **buf, const unsigned char *end,
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

ssize_t quic_build_handshake_packet(unsigned char **buf, const unsigned char *end,
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
	if (!quic_encrypt_payload(beg, aad_len, payload, payload_len,
	                          tls_ctx->aead, tls_ctx->tx.key, tls_ctx->tx.iv))
	    return -1;

	*buf += QUIC_TLS_TAG_LEN;

	if (!quic_apply_header_protection(beg, buf_pn, pn_len, level,
	                                  tls_ctx->hp, tls_ctx->tx.hp_key))
		return -1;

	return *buf - beg;
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

