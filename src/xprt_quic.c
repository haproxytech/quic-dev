/*
 * QUIC transport layer over SOCK_DGRAM sockets.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/quic_conn.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#include <types/global.h>

struct quic_sock_ctx {
	struct connection *conn;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *recv_wait;
	struct wait_event *send_wait;
};

DECLARE_STATIC_POOL(quic_sock_ctx_pool, "quic_sock_ctx_pool", sizeof(struct quic_sock_ctx));

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
static size_t quic_sock_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	errno = 0;

	if (unlikely(!(fdtab[conn->handle.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			goto leave;
		}
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = recvfrom(conn->handle.fd, b_tail(buf), try, 0, NULL, 0);

		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			if (ret < try) {
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, unless the poller supports POLL_RDHUP. If
				 * we know this is the case, we don't try to read more
				 * as we know there's no more available. Similarly, if
				 * there's no problem with lingering we don't even try
				 * to read an unlikely close from the client since we'll
				 * close first anyway.
				 */
				if (fdtab[conn->handle.fd].ev & FD_POLL_HUP)
					goto read0;

				if ((!fdtab[conn->handle.fd].linger_risk) ||
				    (cur_poller.flags & HAP_POLL_F_RDHUP)) {
					fd_done_recv(conn->handle.fd);
					break;
				}
			}
			count -= ret;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN || errno == ENOTCONN) {
			fd_cant_recv(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	return done;

 read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Now a final check for a possible asynchronous low-level error
	 * report. This can happen when a connection receives a reset
	 * after a shutdown, both POLL_HUP and POLL_ERR are queued, and
	 * we might have come from there by just checking POLL_HUP instead
	 * of recv()'s return value 0, so we have no way to tell there was
	 * an error without checking.
	 */
	if (unlikely(fdtab[conn->handle.fd].ev & FD_POLL_ERR))
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto leave;
}


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
static size_t quic_sock_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->handle.fd))
		return 0;

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

		ret = sendto(conn->handle.fd, b_peek(buf, done), try, send_flag,
		             (struct sockaddr *)conn->src, get_addr_len(conn->src));
		if (ret > 0) {
			count -= ret;
			done += ret;

			/* A send succeeded, so we can consier ourself connected */
			conn->flags |= CO_FL_WAIT_L4L6;
			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN || errno == EINPROGRESS) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

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

static int quic_sock_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_subscribe(conn, xprt_ctx, event_type, es);
}

static int quic_sock_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_unsubscribe(conn, xprt_ctx, event_type, es);
}

static struct task *quic_sock_io_cb(struct task *t, void *context, unsigned short state)
{
	return NULL;
}

/* We can't have an underlying XPRT, so just return -1 to signify failure */
static int quic_sock_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	/* This is the lowest xprt we can have, so if we get there we didn't
	 * find the xprt we wanted to remove, that's a bug
	 */
	BUG_ON(1);
	return -1;
}

void quic_fd_handler(int fd)
{
	struct listener *l = fdtab[fd].owner;

	if (fdtab[fd].ev & FD_POLL_IN)
		quic_conn_to_buf(fd, l);
}

static int quic_sock_init(struct connection *conn, void **xprt_ctx)
{
	struct quic_sock_ctx *ctx;

	if (*xprt_ctx)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	ctx = pool_alloc(quic_sock_ctx_pool);
	if (!ctx) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		return -1;
	}

	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SYS_MEMLIM;
		pool_free(quic_sock_ctx_pool, ctx);
		return -1;
	}

	ctx->wait_event.tasklet->process = quic_sock_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->conn = conn;
	ctx->send_wait = NULL;
	ctx->recv_wait = NULL;

	*xprt_ctx = ctx;

	return 0;
}

/* transport-layer operations for QUIC sockets */
static struct xprt_ops quic_sock = {
	.snd_buf  = quic_sock_from_buf,
	.rcv_buf  = quic_sock_to_buf,
	.subscribe = quic_sock_subscribe,
	.unsubscribe = quic_sock_unsubscribe,
	.remove_xprt = quic_sock_remove_xprt,
	.shutr    = NULL,
	.shutw    = NULL,
	.close    = NULL,
	.init     = quic_sock_init,
	.name     = "QUIC",
};


__attribute__((constructor))
static void __quic_sock_init(void)
{
	xprt_register(XPRT_QUIC, &quic_sock);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
