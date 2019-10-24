/*
 * include/proto/quic_conn.h
 * This file contains definitions for QUIC connections.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _PROTO_QUIC_CONN_H
#define _PROTO_QUIC_CONN_H

#include <stdint.h>

#include <common/net_helper.h>

#include <types/quic_conn.h>

size_t quic_conn_to_buf(int fd, void *ctx);

/*
 * The two most significant bits of byte #0 gives the 2 logarithm of the encoded length
 * of a variable length integer for QUIC
 */
#define QUIC_VARINT_BYTE_0_BITMASK 0x3f
#define QUIC_VARINT_BYTE_0_SHIFT   6

/*
 * Returns enough log2 of first powers of two to encode QUIC variable length integers.
 * Returns -1 if <val> if out of the range of lengths supported by QUIC.
 */
static inline int my_log2(unsigned int val)
{
	switch (val) {
	case 8:
		return 3;
	case 4:
		return 2;
	case 2:
		return 1;
	case 1:
		return 0;
	default:
		return -1;
	}
}

/*
 * Returns the size in bytes required to encode a 64bits integer if
 * not out of range (< (1 << 62)), or 0 if out of range.
 */
static inline uint16_t quic_int_getsize(uint64_t val)
{
	switch (val) {
	case 0 ... (1UL <<  6) - 1:
		return 1;
	case (1UL <<  6) ... (1UL << 14) - 1:
		return 2;
	case (1UL << 14) ... (1UL << 30) - 1:
		return 4;
	case (1UL << 30) ... (1UL << 62) - 1:
		return 8;
	default:
		return 0;
	}
}

/*
 * Decode a QUIC variable length integer.
 * Note that the result is a 64-bits integer but with the less significant
 * 62 bits as relevant information. The most significant 2 remaining bits encode
 * the length of the integer. So, this function can return (uint64_t)-1 in case of any error.
 * Return the 64-bits decoded value when succeeded, -1 if not (i.e. <buf> provided buffer
 * was not big enough).
 */
static inline uint64_t quic_dec_int(const unsigned char **buf, const unsigned char *end)
{
	uint64_t ret;
	size_t len;

	if (*buf >= end)
		return -1;

	len = 1 << (**buf >> QUIC_VARINT_BYTE_0_SHIFT);
	if (*buf + len > end)
		return -1;

	ret = *(*buf)++ & QUIC_VARINT_BYTE_0_BITMASK;
	while (--len)
		ret = (ret << 8) | *(*buf)++;


	return ret;
}

static inline int quic_enc_int(unsigned char **buf, const unsigned char *end, uint64_t val)
{
	uint16_t len;
	unsigned int shift;
	unsigned char size_bits, *head;

	len = quic_int_getsize(val);
	if (!len || end - *buf < len)
		return 0;

	shift = (len - 1) * 8;
	/* set the bits of byte#0 which gives the length of the encoded integer */
	size_bits = my_log2(len) << QUIC_VARINT_BYTE_0_SHIFT;
	head = *buf;
	while (len--) {
		*(*buf)++ = val >> shift;
		shift -= 8;
	}
	*head |= size_bits;

	return 1;
}

static inline void quic_dflt_transport_params_cpy(struct quic_transport_params *dst)
{
	dst->max_packet_size    = quid_dflt_transport_params.max_packet_size;
	dst->ack_delay_exponent = quid_dflt_transport_params.ack_delay_exponent;
	dst->max_ack_delay      = quid_dflt_transport_params.max_ack_delay;
}

static inline void quic_transport_params_init(struct quic_transport_params *p, int server)
{
	quic_dflt_transport_params_cpy(p);

	p->idle_timeout                        = 30000;

	p->initial_max_data                    = 1 * 1024 * 1024;
	p->initial_max_stream_data_bidi_local  = 256 * 1024;
	p->initial_max_stream_data_bidi_remote = 256 * 1024;
	p->initial_max_stream_data_uni         = 256 * 1024;
	p->initial_max_streams_bidi            = 100;
	p->initial_max_streams_uni             = 3;

	if (server)
		p->with_stateless_reset_token      = 1;
	p->active_connection_id_limit          = 8;

}

/*
 * Encode <type> and <len> 16bits values in <buf>.
 * It is the responsability of the caller to check there is enough room in
 * buf to encode these values.
 */
static inline void quic_transport_param_encode_type_len(unsigned char **buf, const unsigned char *end,
														uint16_t type, uint16_t len)
{
	write_n16(*buf, type);
	*buf += sizeof type;
	write_n16(*buf, len);
	*buf += sizeof len;
}

/*
 * Encode <param> bytes tream with <type> as type and <length> as length in buf.
 * Returns 1 if succeded, 0 if not.
 */
static inline int quic_transport_param_enc_mem(unsigned char **buf, const unsigned char *end, uint16_t type,
                                               void *param, uint16_t length)
{
	if (end - *buf < sizeof type + sizeof length + length)
		return 0;

	quic_transport_param_encode_type_len(buf, end, type, length);
	memcpy(*buf, param, length);

	return 1;
}

/*
 * Encode <val> 64bits value as variable length integer in <buf>.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_enc_int(unsigned char **buf, const unsigned char *end,
                                               uint16_t type, uint64_t val)
{
	uint16_t len;
	unsigned int shift;
	unsigned char *head;

	len = quic_int_getsize(val);
	if (!len || end - *buf < len + sizeof type + sizeof len)
		return 0;

	/* Encode the type and the length of <val> */
	quic_transport_param_encode_type_len(buf, end, type, len);

	shift = (len - 1) * 8;
	head = *buf;
	while (len--) {
		*(*buf)++ = val >> shift;
		shift -= 8;
	}
	*head |= my_log2(len) << QUIC_VARINT_BYTE_0_SHIFT;

	return 1;
}

/*
 * Encode <addr> preferred address in <buf>.
 * Note that the IP addresses must be encoded in network byte order.
 * So ->ipv4_addr and ->ipv6_addr, which are buffers, must contained
 * values already encoded in network byte order.
 */
static inline int quic_transport_param_enc_pref_addr(unsigned char **buf, const unsigned char *end,
                                                     struct preferred_address *addr)
{
	size_t addr_len = 0;

	addr_len += sizeof addr->ipv4_port + sizeof addr->ipv4_addr;
	addr_len += sizeof addr->ipv6_port + sizeof addr->ipv6_addr;
	addr_len += sizeof addr->cid.len;
	if (addr->cid.len)
		addr_len += addr->cid.len;
	addr_len += sizeof addr->stateless_reset_token;

	if (end - *buf < addr_len)
		return 0;

	write_n16(*buf, QUIC_TP_PREFERRED_ADDRESS);
	*buf += sizeof(uint16_t);
	write_n16(*buf, addr_len);
	*buf += sizeof(uint16_t);

	write_n16(*buf, addr->ipv4_port);
	*buf += sizeof addr->ipv4_port;

	memcpy(*buf, addr->ipv4_addr, sizeof addr->ipv4_addr);
	*buf += sizeof addr->ipv4_addr;

	write_n16(*buf, addr->ipv6_port);
	*buf += sizeof addr->ipv6_port;

	memcpy(*buf, addr->ipv6_addr, sizeof addr->ipv6_addr);
	*buf += sizeof addr->ipv6_addr;

	*(*buf)++ = addr->cid.len;
	if (addr->cid.len) {
		memcpy(*buf, addr->cid.data, addr->cid.len);
		*buf += addr->cid.len;
	}

	memcpy(*buf, addr->stateless_reset_token, sizeof addr->stateless_reset_token);
	*buf += sizeof addr->stateless_reset_token;

	return 1;
}

static inline int quic_transport_params_encode(unsigned char *buf, const unsigned char *end,
                                               struct quic_transport_params *p, int server)
{
	/* Total length of the transport parameters after encoding. */
	uint16_t params_len;
	unsigned char *head;
	unsigned char *pos;

	head = pos = buf;
	/* Skip the room in <buf> to store the length of these encoded QUIC
	 * transport parameters.
	 */
	pos += sizeof params_len;

	if (server) {
		if (p->with_original_connection_id &&
			!quic_transport_param_enc_mem(&pos, end, QUIC_TP_ORIGINAL_CONNECTION_ID,
			                              p->original_connection_id.data,
			                              p->original_connection_id.len))
			return 0;
		if (p->with_stateless_reset_token &&
			!quic_transport_param_enc_mem(&pos, end, QUIC_TP_STATELESS_RESET_TOKEN,
			                              p->stateless_reset_token,
			                              sizeof p->stateless_reset_token))
			return 0;
		if (p->with_preferred_address &&
			!quic_transport_param_enc_pref_addr(&pos, end, &p->preferred_address))
			return 0;
	}

	if (p->idle_timeout &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_IDLE_TIMEOUT, p->idle_timeout))
		return 0;

	/*
	 * "max_packet_size" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->max_packet_size != QUIC_DFLT_MAX_PACKET_SIZE &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_MAX_PACKET_SIZE, p->max_packet_size))
		return 0;

	if (p->initial_max_data &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_DATA, p->initial_max_data))
	    return 0;

	if (p->initial_max_stream_data_bidi_local &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
	                                  p->initial_max_stream_data_bidi_local))
	    return 0;

	if (p->initial_max_stream_data_bidi_remote &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
	                                  p->initial_max_stream_data_bidi_remote))
	    return 0;

	if (p->initial_max_stream_data_uni &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
	                                  p->initial_max_stream_data_uni))
	    return 0;

	if (p->initial_max_streams_bidi &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
	                                  p->initial_max_streams_bidi))
	    return 0;

	if (p->initial_max_streams_uni &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAMS_UNI,
	                                  p->initial_max_streams_uni))
	    return 0;

	/*
	 * "ack_delay_exponent" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->ack_delay_exponent != QUIC_DFLT_ACK_DELAY_COMPONENT  &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_ACK_DELAY_EXPONENT, p->ack_delay_exponent))
	    return 0;

	/*
	 * "max_ack_delay" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->max_ack_delay != QUIC_DFLT_MAX_ACK_DELAY &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_MAX_ACK_DELAY, p->max_ack_delay))
	    return 0;

	/* 0-length value */
	if (p->disable_active_migration) {
	    if (end - pos < 4)
		    return 0;
	    quic_transport_param_encode_type_len(&pos, end, QUIC_TP_DISABLE_ACTIVE_MIGRATION, 0);
	}

	if (p->active_connection_id_limit &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
	                                  p->active_connection_id_limit))
	    return 0;

	/* Finally encode the length of these encoded QUIC transport parameters. */
	params_len = pos - head - sizeof params_len;
	write_n16(head, params_len);

	return pos - head;
}

#endif /* _PROTO_QUIC_CONN_H */
