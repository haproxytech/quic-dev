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

#include <proto/fd.h>

#include <types/global.h>
#include <types/quic.h>

struct quic_cid {
	unsigned char len;
	unsigned char data[QUIC_CID_MAXLEN];
};

struct quic_packet {
	int from_server;
	int long_header;
	unsigned char type;
	uint32_t version;
	struct quic_cid dcid;
	struct quic_cid scid;
	/* Packet number length */
	uint32_t pnl;
	/* Packet number */
	uint32_t pn;
	uint64_t token_len;
	uint64_t len;
};


struct quic_conn {
	size_t cid_len;
	/* Do not insert anything after <key> which contains a flexible array member!!! */
	struct ebmb_node cid;
};


/* The first two bits of byte #0 gives the 2 logarithm of the encoded length. */
#define QUIC_VARINT_BYTE_0_BITMASK 0x3f
#define QUIC_VARINT_BYTE_0_SHIFT   6

/*
 * Decode a QUIC variable length integer.
 * Note that the result is a 64-bits integer but with the less significant
 * 62 bits as relevant information. The most significant bits encode the length
 * of the integer to be decoded. So, this function can return (uint64_t)-1
 * in case of any error.
 * Return the 64-bits decoded value when succeeded, -1 if not: <buf> provided buffer
 * was not big enough.
 */
uint64_t quic_dec_int(const unsigned char **buf,
                      const unsigned char *end)
{
	uint64_t ret;
	size_t len;

	if (*buf == end)
		return -1;

	ret = **buf & QUIC_VARINT_BYTE_0_BITMASK;
	len = 1 << (*(*buf)++ >> QUIC_VARINT_BYTE_0_SHIFT);

	while (--len)
		ret = (ret << 8) | *(*buf)++;


	return ret;
}

int quic_enc_int(unsigned char **buf, const unsigned char *end, uint64_t val)
{
	switch (val) {
	case (1UL << 30) ... (1UL << 62) - 1:
		if (end - *buf < 8)
			return 0;
		*(*buf)++ = 0xc0 | (val >> 56);
		*(*buf)++ = val >> 48;
		*(*buf)++ = val >> 40;
		*(*buf)++ = val >> 32;
		*(*buf)++ = val >> 24;
		*(*buf)++ = val >> 16;
		*(*buf)++ = val >> 8;
		break;

	case (1UL << 14) ... (1UL << 30) - 1:
		if (end - *buf < 4)
			return 0;
		*(*buf)++ = 0x80 | (val >> 24);
		*(*buf)++ = val >> 16;
		*(*buf)++ = val >> 8;
		break;

	case (1UL <<  6) ... (1UL << 14) - 1:
		if (end - *buf < 2)
			return 0;
		*(*buf)++ = 0x40 | (val >> 8);
		break;

	case 0 ... (1UL <<  6) - 1:
		if (end - *buf < 1)
			return 0;
		break;

	default:
		return 0;
	}
	*(*buf)++ = val;

	return 1;
}

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

__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...);

ssize_t quic_packet_read_header(struct quic_packet *qpkt,
                                const unsigned char **buf, const unsigned char *end,
                                struct listener *l)
{
	const unsigned char *beg;
	unsigned char dcid_len, scid_len;
	uint64_t len;


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
				struct quic_conn *conn;
				conn = calloc(1, sizeof *conn + qpkt->dcid.len);
				if (conn) {
					conn->cid_len = qpkt->dcid.len;
					memcpy(conn->cid.key, qpkt->dcid.data, qpkt->dcid.len);
					ebmb_insert(&l->quic_clients, &conn->cid, conn->cid_len);
				}
			}
		}
	}
	else {
		/* Short header */
	}

	if (qpkt->type == QUIC_PACKET_TYPE_INITIAL) {
		uint64_t token_len;

		fprintf(stderr, "QUIC_PACKET_TYPE_INITIAL packet\n");
		token_len = quic_dec_int(buf, end);
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

		/* The following payload contains an initial handshake message. */

	}

	if (qpkt->type != QUIC_PACKET_TYPE_RETRY) {
		len = quic_dec_int(buf, end);
		if (len == -1 || end - *buf < len)
			goto err;
		qpkt->len = len;
	}


	fprintf(stderr, "\ttoken_len: %lu len: %lu pnl: %u\n",
	        qpkt->token_len, qpkt->len, qpkt->pnl);

	return *buf - beg;

 err:
	return -1;
}

ssize_t quic_packet_read(char *buf, size_t len, struct listener *l)
{
	const unsigned char *pos, *end;
	struct quic_packet qpkt = {0};

	pos = (const unsigned char *)buf;
	end = pos + len;

	if (quic_packet_read_header(&qpkt, &pos, end, l) == -1)
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

	if (!fd_recv_ready(fd))
		return 0;

	if (unlikely(!(fdtab[fd].ev & FD_POLL_IN))) {
		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[fd].ev & FD_POLL_ERR))
			goto out;
	}

	do {
		ret = recvfrom(fd, trash.area, trash.size, 0, NULL, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				fd_cant_recv(fd);
			break;
		}
		else {
			hexdump(trash.area, 32, "%s: recvfrom()\n", __func__);
			done = trash.data = ret;
			quic_packet_read(trash.area, trash.size, l);
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

