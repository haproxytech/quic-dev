/*
 * include/proto/quic_tls.h
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

#ifndef _PROTO_QUIC_TLS_H
#define _PROTO_QUIC_TLS_H

#include <types/quic_tls.h>

int quic_hdkf_extract(unsigned char *buf, size_t *buflen, const EVP_MD *md,
                      unsigned char *key, size_t keylen,
                      unsigned char *salt, size_t saltlen);

int quic_hdkf_expand_label(unsigned char *buf, size_t *buflen, const EVP_MD *md,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *label, size_t labellen);

int quic_client_setup_crypto_ctx(struct quic_tls_ctx *ctx, unsigned char *cid, size_t cid_len);
#endif /* _PROTO_QUIC_TLS_H */

