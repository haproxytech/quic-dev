/*
 * QUIC protocol definitions (TX side).
 *
 * Copyright (C) 2023
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

#ifndef _HAPROXY_QUIC_TX_H
#define _HAPROXY_QUIC_TX_H

#include <haproxy/buf-t.h>
#include <haproxy/list-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_tls-t.h>
#include <haproxy/quic_tx-t.h>

void quic_tx_packet_refdec(struct quic_conn *qc, struct quic_tx_packet *pkt);
struct buffer *qc_txb_alloc(struct quic_conn *qc);
void qc_txb_release(struct quic_conn *qc);
int qc_purge_txbuf(struct quic_conn *qc, struct buffer *buf);
struct buffer *qc_get_txb(struct quic_conn *qc);

int qc_need_sending(struct quic_conn *qc, struct quic_enc_level *qel);
int qc_prep_hpkts(struct quic_conn *qc, struct buffer *buf, struct list *qels);
int qc_send_ppkts(struct buffer *buf, struct ssl_sock_ctx *ctx);
int qc_may_probe_ipktns(struct quic_conn *qc);
int quic_build_post_handshake_frames(struct quic_conn *qc);
int qc_send_app_pkts(struct quic_conn *qc, struct list *frms);
int qc_dgrams_retransmit(struct quic_conn *qc);
int qc_notify_send(struct quic_conn *qc);
void free_quic_tx_pkts(struct quic_conn *qc, struct list *pkts);
void qc_prep_hdshk_fast_retrans(struct quic_conn *qc,
                                struct list *ifrms, struct list *hfrms);
int quic_generate_retry_token_aad(unsigned char *aad,
                                  uint32_t version,
                                  const struct quic_cid *dcid,
                                  const struct quic_cid *scid,
                                  const struct sockaddr_storage *addr);
int send_retry(int fd, struct sockaddr_storage *addr,
               struct quic_rx_packet *pkt, const struct quic_version *qv);
int send_stateless_reset(struct listener *l, struct sockaddr_storage *dstaddr,
                         struct quic_rx_packet *rxpkt);
int send_version_negotiation(int fd, struct sockaddr_storage *addr,
                             struct quic_rx_packet *pkt);

/* The TX packets sent in the same datagram are linked to each others in
 * the order they are built. This function detach a packet from its successor
 * and predecessor in the same datagram.
 */
static inline void quic_tx_packet_dgram_detach(struct quic_tx_packet *pkt)
{
	if (pkt->prev)
		pkt->prev->next = pkt->next;
	if (pkt->next)
		pkt->next->prev = pkt->prev;
}

#endif /* _HAPROXY_QUIC_TX_H */
