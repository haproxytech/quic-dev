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

/* Initial salt depending on QUIC version to derive client/server initial secrets.
 * This one is for draft-22 QUIC version.
 */
unsigned char initial_salt[20] = {
	0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9,
	0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd,
	0x7a, 0x02, 0x64, 0x4a,
};

#endif /* _TYPES_QUIC_TLS_H */

