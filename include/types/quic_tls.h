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

#include <stdint.h>

/* Initial salt depending on QUIC version to derive client/server initial secrets.
 * This one is for draft-22 QUIC version.
 */
unsigned char initial_salt[20] = {
	0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
	0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
	0xbe, 0xf9, 0xf5, 0x02,
};

/* TLS1.3 definitions */

/* Handshake protocol message type */
enum hdshk_msg_type {
	client_hello = 1,
	server_hello = 2,
	new_session_ticket = 4,
	end_of_early_data = 5,
	encrypted_extensions = 8,
	certificate = 11,
	certificate_request = 13,
	certificate_verify = 15,
	finished = 20,
	key_update = 24,
	message_hash = 254,
};

/* Handshake protocol message header */
struct hdshk_msg_header {
	uint8_t type;
	uint8_t length[3];
};

/* Extension types */
enum extension_type {
	server_name = 0,                             /* RFC 6066 */
	max_fragment_length = 1,                     /* RFC 6066 */
	status_request = 5,                          /* RFC 6066 */
	supported_groups = 10,                       /* RFC 8422, 7919 */
	signature_algorithms = 13,                   /* RFC 8446 */
	use_srtp = 14,                               /* RFC 5764 */
	heartbeat = 15,                              /* RFC 6520 */
	application_layer_protocol_negotiation = 16, /* RFC 7301 */
	signed_certificate_timestamp = 18,           /* RFC 6962 */
	client_certificate_type = 19,                /* RFC 7250 */
	server_certificate_type = 20,                /* RFC 7250 */
	padding = 21,                                /* RFC 7685 */
	pre_shared_key = 41,                         /* RFC 8446 */
	early_data = 42,                             /* RFC 8446 */
	supported_versions = 43,                     /* RFC 8446 */
	cookie = 44,                                 /* RFC 8446 */
	psk_key_exchange_modes = 45,                 /* RFC 8446 */
	certificate_authorities = 47,                /* RFC 8446 */
	oid_filters = 48,                            /* RFC 8446 */
	post_handshake_auth = 49,                    /* RFC 8446 */
	signature_algorithms_cert = 50,              /* RFC 8446 */
	key_share = 51,                              /* RFC 8446 */
};

#define CLIENT_HELLO          (1 << 0)
#define SERVER_HELLO          (1 << 1)
#define ENCRYPTED_EXTENSTIONS (1 << 2)
#define CERTIFICATE           (1 << 3)
#define CERTIFICATE_REQUEST   (1 << 4)
#define NEW_SESSION_TICKET    (1 << 5)
#define HELLO_RETRY_REQUEST   (1 << 6)

/* Supported extensions by handshake protocol message type with extensions */
uint16_t hdshk_msg_extensions[] = {
   [server_name] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [max_fragment_length] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [status_request] = CLIENT_HELLO | CERTIFICATE_REQUEST | CERTIFICATE,
   [supported_groups] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [signature_algorithms] = CLIENT_HELLO | CERTIFICATE_REQUEST,
   [use_srtp] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [heartbeat] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [application_layer_protocol_negotiation] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [signed_certificate_timestamp] = CLIENT_HELLO | CERTIFICATE_REQUEST | CERTIFICATE,
   [client_certificate_type] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [server_certificate_type] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS,
   [padding] = CLIENT_HELLO,
   [key_share] = CLIENT_HELLO | SERVER_HELLO | HELLO_RETRY_REQUEST,
   [pre_shared_key] = CLIENT_HELLO | SERVER_HELLO,
   [psk_key_exchange_modes] = CLIENT_HELLO,
   [early_data] = CLIENT_HELLO | ENCRYPTED_EXTENSTIONS | NEW_SESSION_TICKET,
   [cookie] = CLIENT_HELLO | HELLO_RETRY_REQUEST,
   [supported_versions] = CLIENT_HELLO | SERVER_HELLO | HELLO_RETRY_REQUEST,
   [certificate_authorities] = CLIENT_HELLO | CERTIFICATE_REQUEST,
   [oid_filters] = CERTIFICATE_REQUEST,
   [post_handshake_auth] = CLIENT_HELLO,
   [signature_algorithms_cert] = CLIENT_HELLO | CERTIFICATE_REQUEST,
};

#endif /* _TYPES_QUIC_TLS_H */

