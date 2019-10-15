/*
 * include/types/quic_tls.h
 * This file provides definitions for QUIC-TLS.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _TYPES_QUIC_TLS_H
#define _TYPES_QUIC_TLS_H

#include <openssl/evp.h>

/* It seems TLS 1.3 ciphersuites macros differ between openssl and boringssl */

#if defined(OPENSSL_IS_BORINGSSL)
#if !defined(TLS1_3_CK_AES_128_GCM_SHA256)
#define TLS1_3_CK_AES_128_GCM_SHA256       TLS1_CK_AES_128_GCM_SHA256
#endif
#if !defined(TLS1_3_CK_AES_256_GCM_SHA384)
#define TLS1_3_CK_AES_256_GCM_SHA384       TLS1_CK_AES_256_GCM_SHA384
#endif
#if !defined(TLS1_3_CK_CHACHA20_POLY1305_SHA256)
#define TLS1_3_CK_CHACHA20_POLY1305_SHA256 TLS1_CK_CHACHA20_POLY1305_SHA256
#endif
#if !defined(TLS1_3_CK_AES_128_CCM_SHA256)
/* Note that TLS1_CK_AES_128_CCM_SHA256 is not defined in boringssl */
#define TLS1_3_CK_AES_128_CCM_SHA256       0x03001304
#endif
#endif

/* The TLS extension (enum) for QUIC transport parameters */
#define TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS 0xffa5

/* QUIC transport parameters */
#define TLS_QUIC_TP_ORIGINAL_CONNECTION_ID               0
#define TLS_QUIC_TP_IDLE_TIMEOUT                         1
#define TLS_QUIC_TP_STATELESS_RESET_TOKEN                2
#define TLS_QUIC_TP_MAX_PACKET_SIZE                      3
#define TLS_QUIC_TP_INITIAL_MAX_DATA                     4
#define TLS_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL   5
#define TLS_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE  6
#define TLS_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI          7
#define TLS_QUIC_TP_INITIAL_MAX_STREAM_BIDI              8
#define TLS_QUIC_TP_INITIAL_MAX_STREAM_UNI               9
#define TLS_QUIC_TP_ACK_DELAY_EXPONENT                  10
#define TLS_QUIC_TP_MAX_ACK_DELAY                       11
#define TLS_QUIC_TP_DISABLE_ACTIVE_MIGRATION            12
#define TLS_QUIC_TP_PREFERRED_ADDRESS                   13
#define TLS_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT          14

extern unsigned char initial_salt[20];

struct quic_tls_ctx {
	SSL_CIPHER *aead;
	EVP_MD *md;
	unsigned char initial_secret[32];
	unsigned char rx_initial_secret[32];
	unsigned char tx_initial_secret[32];
	unsigned char key[16];
	unsigned char iv[12];
	unsigned char aead_iv[16];
	/* Header protection key.
	* Note: the header protection is applied after packet protection.
	* As the header belong to the data, its protection must be removed before removing
	* the packet protection.
	*/
	unsigned char hp[16];
};

#endif /* _TYPES_QUIC_TLS_H */

