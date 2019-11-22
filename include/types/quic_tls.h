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

/* QUIC TLS level encryption */
#define QUIC_TLS_ENC_LEVEL_INITIAL    0
#define QUIC_TLS_ENC_LEVEL_EARLY_DATA 1
#define QUIC_TLS_ENC_LEVEL_HANDSHAKE  2
#define QUIC_TLS_ENC_LEVEL_APP        3

/* The ciphersuites for AEAD QUIC-TLS have 16-bytes authentication tag */
#define QUIC_TLS_TAG_LEN             16

extern unsigned char initial_salt[20];

struct quic_tls_secrets {
	unsigned char key[32];
	unsigned char iv[12];
	/* Header protection key.
	* Note: the header protection is applied after packet protection.
	* As the header belong to the data, its protection must be removed before removing
	* the packet protection.
	*/
	unsigned char hp_key[16];
};

/* QUIC packet number space */
struct quic_pkt_ns {
	/* Last packet number */
	int64_t last_pn;
	/* Last acked packet number */
	int64_t last_acked_pn;
	/* Offset of the CRYPTO stream of data */
	int64_t offset;
};

struct quic_tls_ctx {
	const EVP_CIPHER *aead;
	unsigned char aead_iv[12];
	const EVP_MD *md;
	const EVP_CIPHER *hp;
	struct quic_tls_secrets rx;
	struct quic_tls_secrets tx;
	struct quic_pkt_ns tx_ns;
	struct quic_pkt_ns rx_ns;
};

#endif /* _TYPES_QUIC_TLS_H */

