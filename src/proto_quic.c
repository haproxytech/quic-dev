/*
 * AF_CUST_QUIC/AF_CUST_QUIC6 QUIC protocol layer
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/udp.h>
#include <netinet/in.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/initcall.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/namespace.h>

#include <types/action.h>
#include <types/connection.h>
#include <types/global.h>
#include <types/stream.h>

#include <proto/arg.h>
#include <proto/channel.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/port_range.h>
#include <proto/protocol.h>
#include <proto/proto_quic.h>
#include <proto/proxy.h>
#include <proto/server.h>
#include <proto/task.h>

static int quic_bind_listeners(struct protocol *proto, char *errmsg, int errlen);
static int quic_bind_listener(struct listener *listener, char *errmsg, int errlen);
static void quic4_add_listener(struct listener *listener, int port);
static void quic6_add_listener(struct listener *listener, int port);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_quic4 = {
	.name = "quic4",
	.sock_domain = AF_CUST_QUIC,
	.sock_type = SOCK_DGRAM,
	.sock_prot = IPPROTO_UDP,
	.sock_family = AF_CUST_QUIC,
	.sock_addrlen = sizeof(struct sockaddr_in),
	.l3_addrlen = 32/8,
	.accept = NULL,
	.connect = quic_connect_server,
	.bind = quic_bind_listener,
	.bind_all = quic_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.get_src = quic_get_src,
	.get_dst = quic_get_dst,
	.pause = quic_pause_listener,
	.add = quic4_add_listener,
	.listeners = LIST_HEAD_INIT(proto_quic4.listeners),
	.nb_listeners = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_quic4);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_quic6 = {
	.name = "quic6",
	.sock_domain = AF_CUST_QUIC6,
	.sock_type = SOCK_DGRAM,
	.sock_prot = IPPROTO_UDP,
	.sock_family = AF_CUST_QUIC6,
	.sock_addrlen = sizeof(struct sockaddr_in6),
	.l3_addrlen = 128/8,
	.accept = NULL,
	.connect = quic_connect_server,
	.bind = quic_bind_listener,
	.bind_all = quic_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.get_src = quic_get_src,
	.get_dst = quic_get_dst,
	.pause = quic_pause_listener,
	.add = quic6_add_listener,
	.listeners = LIST_HEAD_INIT(proto_quic6.listeners),
	.nb_listeners = 0,
};

INITCALL1(STG_REGISTER, protocol_register, &proto_quic6);

/* Binds ipv4/ipv6 address <local> to socket <fd>, unless <flags> is set, in which
 * case we try to bind <remote>. <flags> is a 2-bit field consisting of :
 *  - 0 : ignore remote address (may even be a NULL pointer)
 *  - 1 : use provided address
 *  - 2 : use provided port
 *  - 3 : use both
 *
 * The function supports multiple foreign binding methods :
 *   - linux_tproxy: we directly bind to the foreign address
 * The second one can be used as a fallback for the first one.
 * This function returns 0 when everything's OK, 1 if it could not bind, to the
 * local address, 2 if it could not bind to the foreign address.
 */
int quic_bind_socket(int fd, int flags, struct sockaddr_storage *local, struct sockaddr_storage *remote)
{
	struct sockaddr_storage bind_addr;
	int foreign_ok = 0;
	int ret;
	static THREAD_LOCAL int ip_transp_working = 1;
	static THREAD_LOCAL int ip6_transp_working = 1;


	switch (local->ss_family) {
	case AF_INET:
		if (flags && ip_transp_working) {
			/* This deserves some explanation. Some platforms will support
			 * multiple combinations of certain methods, so we try the
			 * supported ones until one succeeds.
			 */
			if (0
#if defined(IP_TRANSPARENT)
			    || (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) == 0)
#endif
#if defined(IP_FREEBIND)
			    || (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == 0)
#endif
#if defined(IP_BINDANY)
			    || (setsockopt(fd, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) == 0)
#endif
#if defined(SO_BINDANY)
			    || (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == 0)
#endif
			    )
				foreign_ok = 1;
			else
				ip_transp_working = 0;
		}
		break;
	case AF_INET6:
		if (flags && ip6_transp_working) {
			if (0
#if defined(IPV6_TRANSPARENT) && defined(SOL_IPV6)
			    || (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) == 0)
#endif
#if defined(IP_FREEBIND)
			    || (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == 0)
#endif
#if defined(IPV6_BINDANY)
			    || (setsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) == 0)
#endif
#if defined(SO_BINDANY)
			    || (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == 0)
#endif
			    )
				foreign_ok = 1;
			else
				ip6_transp_working = 0;
		}
		break;
	}

	if (flags) {
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.ss_family = remote->ss_family;
		switch (remote->ss_family) {
		case AF_INET:
			if (flags & 1)
				((struct sockaddr_in *)&bind_addr)->sin_addr = ((struct sockaddr_in *)remote)->sin_addr;
			if (flags & 2)
				((struct sockaddr_in *)&bind_addr)->sin_port = ((struct sockaddr_in *)remote)->sin_port;
			break;
		case AF_INET6:
			if (flags & 1)
				((struct sockaddr_in6 *)&bind_addr)->sin6_addr = ((struct sockaddr_in6 *)remote)->sin6_addr;
			if (flags & 2)
				((struct sockaddr_in6 *)&bind_addr)->sin6_port = ((struct sockaddr_in6 *)remote)->sin6_port;
			break;
		default:
			/* we don't want to try to bind to an unknown address family */
			foreign_ok = 0;
		}
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (foreign_ok) {
		if (is_inet_addr(&bind_addr)) {
			ret = bind(fd, (struct sockaddr *)&bind_addr, get_addr_len(&bind_addr));
			if (ret < 0)
				return 2;
		}
	}
	else {
		if (is_inet_addr(local)) {
			ret = bind(fd, (struct sockaddr *)local, get_addr_len(local));
			if (ret < 0)
				return 1;
		}
	}

	if (!flags)
		return 0;

	if (!foreign_ok)
		/* we could not bind to a foreign address */
		return 2;

	return 0;
}

static int create_server_socket(struct connection *conn)
{
	const struct netns_entry *ns = NULL;
	sa_family_t sa_family;

#ifdef USE_NS
	if (objt_server(conn->target)) {
		if (__objt_server(conn->target)->flags & SRV_F_USE_NS_FROM_PP)
			ns = conn->proxy_netns;
		else
			ns = __objt_server(conn->target)->netns;
	}
#endif
	sa_family = conn->dst->ss_family == AF_CUST_QUIC ? AF_INET :
		conn->dst->ss_family == AF_CUST_QUIC6 ? AF_INET6 : -1;

	return my_socketat(ns, sa_family, SOCK_DGRAM, IPPROTO_UDP);
}

/*
 * This function initiates a QUIC connection establishment to the target assigned
 * to connection <conn> using (si->{target,addr.to}). A source address may be
 * pointed to by conn->src in case of transparent proxying. Normal source
 * bind addresses are still determined locally (due to the possible need of a
 * source port). conn->target may point either to a valid server or to a backend,
 * depending on conn->target. Only OBJ_TYPE_PROXY and OBJ_TYPE_SERVER are
 * supported. The <data> parameter is a boolean indicating whether there are data
 * waiting for being sent or not, in order to adjust data write polling and on
 * some platforms, the ability to avoid an empty initial ACK. The <flags> argument
 * is not used for QUIC "connections".
 *
 * Note that a pending send_proxy message accounts for data.
 *
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_SRVTO if there are no more servers
 *  - SF_ERR_SRVCL if the connection was refused by the server
 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SF_ERR_INTERNAL for any other purely internal errors
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 *
 * The connection's fd is inserted only when SF_ERR_NONE is returned, otherwise
 * it's invalid and the caller has nothing to do.
 */

int quic_connect_server(struct connection *conn, int flags)
{
	int fd, ret;
	struct server *srv;
	struct proxy *be;
	struct conn_src *src;
	struct sockaddr_storage *addr;

	conn->flags |= CO_FL_WAIT_L4_CONN; /* connection in progress */

	switch (obj_type(conn->target)) {
	case OBJ_TYPE_PROXY:
		be = objt_proxy(conn->target);
		srv = NULL;
		break;
	case OBJ_TYPE_SERVER:
		srv = objt_server(conn->target);
		be = srv->proxy;
		break;
	default:
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	fd = conn->handle.fd = create_server_socket(conn);

	if (fd == -1) {
		qfprintf(stderr, "Cannot get a server socket.\n");

		if (errno == ENFILE) {
			conn->err_code = CO_ER_SYS_FDLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system FD limit (maxsock=%d). Please check system tunables.\n",
				 be->id, global.maxsock);
		}
		else if (errno == EMFILE) {
			conn->err_code = CO_ER_PROC_FDLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached process FD limit (maxsock=%d). Please check 'ulimit-n' and restart.\n",
				 be->id, global.maxsock);
		}
		else if (errno == ENOBUFS || errno == ENOMEM) {
			conn->err_code = CO_ER_SYS_MEMLIM;
			send_log(be, LOG_EMERG,
				 "Proxy %s reached system memory limit (maxsock=%d). Please check system tunables.\n",
				 be->id, global.maxsock);
		}
		else if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			conn->err_code = CO_ER_NOPROTO;
		}
		else
			conn->err_code = CO_ER_SOCK_ERR;

		/* this is a resource error */
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_RESOURCE;
	}

	if (fd >= global.maxsock) {
		/* do not log anything there, it's a normal condition when this option
		 * is used to serialize connections to a server !
		 */
		ha_alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
		close(fd);
		conn->err_code = CO_ER_CONF_FDLIM;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_PRXCOND; /* it is a configuration limit */
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
		close(fd);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	if (master == 1 && (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)) {
		ha_alert("Cannot set CLOEXEC on client socket.\n");
		close(fd);
		conn->err_code = CO_ER_SOCK_ERR;
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_INTERNAL;
	}

	/* allow specific binding :
	 * - server-specific at first
	 * - proxy-specific next
	 */
	if (srv && srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (be->conn_src.opts & CO_SRC_BIND)
		src = &be->conn_src;
	else
		src = NULL;

	if (src) {
		int ret, flags = 0;

		if (is_inet_addr(conn->src)) {
			switch (src->opts & CO_SRC_TPROXY_MASK) {
			case CO_SRC_TPROXY_CLI:
				conn->flags |= CO_FL_PRIVATE;
				/* fall through */
			case CO_SRC_TPROXY_ADDR:
				flags = 3;
				break;
			case CO_SRC_TPROXY_CIP:
			case CO_SRC_TPROXY_DYN:
				conn->flags |= CO_FL_PRIVATE;
				flags = 1;
				break;
			}
		}

#ifdef SO_BINDTODEVICE
		/* Note: this might fail if not CAP_NET_RAW */
		if (src->iface_name)
			setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, src->iface_name, src->iface_len + 1);
#endif

		if (src->sport_range) {
			int attempts = 10; /* should be more than enough to find a spare port */
			struct sockaddr_storage sa;

			ret = 1;
			memcpy(&sa, &src->source_addr, sizeof(sa));

			do {
				/* note: in case of retry, we may have to release a previously
				 * allocated port, hence this loop's construct.
				 */
				port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
				fdinfo[fd].port_range = NULL;

				if (!attempts)
					break;
				attempts--;

				fdinfo[fd].local_port = port_range_alloc_port(src->sport_range);
				if (!fdinfo[fd].local_port) {
					conn->err_code = CO_ER_PORT_RANGE;
					break;
				}

				fdinfo[fd].port_range = src->sport_range;
				set_host_port(&sa, fdinfo[fd].local_port);

				ret = quic_bind_socket(fd, flags, &sa, conn->src);
				if (ret != 0)
					conn->err_code = CO_ER_CANT_BIND;
			} while (ret != 0); /* binding NOK */
		}
		else {
#ifdef IP_BIND_ADDRESS_NO_PORT
			static THREAD_LOCAL int bind_address_no_port = 1;
			setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, (const void *) &bind_address_no_port, sizeof(int));
#endif
			ret = quic_bind_socket(fd, flags, &src->source_addr, conn->src);
			if (ret != 0)
				conn->err_code = CO_ER_CANT_BIND;
		}

		if (unlikely(ret != 0)) {
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);

			if (ret == 1) {
				ha_alert("Cannot bind to source address before connect() for backend %s. Aborting.\n",
					 be->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to source address before connect() for backend %s.\n",
					 be->id);
			} else {
				ha_alert("Cannot bind to tproxy source address before connect() for backend %s. Aborting.\n",
					 be->id);
				send_log(be, LOG_EMERG,
					 "Cannot bind to tproxy source address before connect() for backend %s.\n",
					 be->id);
			}
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_RESOURCE;
		}
	}

	if (global.tune.server_sndbuf)
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.server_sndbuf, sizeof(global.tune.server_sndbuf));

	if (global.tune.server_rcvbuf)
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.server_rcvbuf, sizeof(global.tune.server_rcvbuf));

	addr = (conn->flags & CO_FL_SOCKS4) ? &srv->socks4_addr : conn->dst;
	addr->ss_family = addr->ss_family == AF_CUST_QUIC ? AF_INET :
		addr->ss_family == AF_CUST_QUIC6 ? AF_INET6 : -1;
	ret = connect(fd, (const struct sockaddr *)addr, get_addr_len(addr));
	if (ret == -1) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			/* common case, let's wait for connect status */
			conn->flags |= CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EISCONN) {
			/* should normally not happen but if so, indicates that it's OK */
			conn->flags &= ~CO_FL_WAIT_L4_CONN;
		}
		else if (errno == EAGAIN || errno == EADDRINUSE || errno == EADDRNOTAVAIL) {
			char *msg;
			if (errno == EAGAIN || errno == EADDRNOTAVAIL) {
				msg = "no free ports";
				conn->err_code = CO_ER_FREE_PORTS;
			}
			else {
				msg = "local address already in use";
				conn->err_code = CO_ER_ADDR_INUSE;
			}

			qfprintf(stderr,"Connect() failed for backend %s: %s.\n", be->id, msg);
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			send_log(be, LOG_ERR, "Connect() failed for backend %s: %s.\n", be->id, msg);
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_RESOURCE;
		} else if (errno == ETIMEDOUT) {
			//qfprintf(stderr,"Connect(): ETIMEDOUT");
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			conn->err_code = CO_ER_SOCK_ERR;
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_SRVTO;
		} else {
			// (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EACCES || errno == EPERM)
			//qfprintf(stderr,"Connect(): %d", errno);
			port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
			fdinfo[fd].port_range = NULL;
			close(fd);
			conn->err_code = CO_ER_SOCK_ERR;
			conn->flags |= CO_FL_ERROR;
			return SF_ERR_SRVCL;
		}
	}
	else {
		/* connect() == 0, this is great! */
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	}

	conn->flags |= CO_FL_ADDR_TO_SET;

	conn_ctrl_init(conn);       /* registers the FD */
	fdtab[fd].linger_risk = 1;  /* close hard if needed */

	if (conn_xprt_init(conn) < 0) {
		conn_full_close(conn);
		conn->flags |= CO_FL_ERROR;
		return SF_ERR_RESOURCE;
	}

	fd_want_send(fd);  /* for connect status, proxy protocol or SSL */
	return SF_ERR_NONE;  /* connection is OK */
}


/*
 * Retrieves the source address for the socket <fd>, with <dir> indicating
 * if we're a listener (=0) or an initiator (!=0). It returns 0 in case of
 * success, -1 in case of error. The socket's source address is stored in
 * <sa> for <salen> bytes.
 */
int quic_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getsockname(fd, sa, &salen);
	else
		return getpeername(fd, sa, &salen);
}


/*
 * Retrieves the original destination address for the socket <fd>, with <dir>
 * indicating if we're a listener (=0) or an initiator (!=0). In the case of a
 * listener, if the original destination address was translated, the original
 * address is retrieved. It returns 0 in case of success, -1 in case of error.
 * The socket's source address is stored in <sa> for <salen> bytes.
 */
int quic_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir)
{
	if (dir)
		return getpeername(fd, sa, &salen);
	else {
		int ret = getsockname(fd, sa, &salen);

		if (ret < 0)
			return ret;

#if defined(USE_TPROXY) && defined(SO_ORIGINAL_DST)
		/* For TPROXY and Netfilter's NAT, we can retrieve the original
		 * IPv4 address before DNAT/REDIRECT. We must not do that with
		 * other families because v6-mapped IPv4 addresses are still
		 * reported as v4.
		 */
		if (((struct sockaddr_storage *)sa)->ss_family == AF_INET
		    && getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) == 0)
			return 0;
#endif
		return ret;
	}
}

/* XXX: Should probably be elsewhere */
static int compare_sockaddr(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family) {
		return (-1);
	}
	switch (a->ss_family) {
	case AF_CUST_QUIC:
		{
			struct sockaddr_in *a4 = (void *)a, *b4 = (void *)b;
			if (a4->sin_port != b4->sin_port)
				return (-1);
			return (memcmp(&a4->sin_addr, &b4->sin_addr,
			    sizeof(a4->sin_addr)));
		}
	case AF_CUST_QUIC6:
		{
			struct sockaddr_in6 *a6 = (void *)a, *b6 = (void *)b;
			if (a6->sin6_port != b6->sin6_port)
				return (-1);
			return (memcmp(&a6->sin6_addr, &b6->sin6_addr,
			    sizeof(a6->sin6_addr)));
		}
	default:
		return (-1);
	}

}

#define LI_MANDATORY_FLAGS	(LI_O_FOREIGN | LI_O_V6ONLY | LI_O_V4V6)
/* When binding the listeners, check if a socket has been sent to us by the
 * previous process that we could reuse, instead of creating a new one.
 */
static int quic_find_compatible_fd(struct listener *l)
{
	struct xfer_sock_list *xfer_sock = xfer_sock_list;
	int ret = -1;

	while (xfer_sock) {
		if (!compare_sockaddr(&xfer_sock->addr, &l->addr)) {
			if ((l->interface == NULL && xfer_sock->iface == NULL) ||
			    (l->interface != NULL && xfer_sock->iface != NULL &&
			     !strcmp(l->interface, xfer_sock->iface))) {
				if ((l->options & LI_MANDATORY_FLAGS) ==
				    (xfer_sock->options & LI_MANDATORY_FLAGS)) {
					if ((xfer_sock->namespace == NULL &&
					    l->netns == NULL)
#ifdef USE_NS
					    || (xfer_sock->namespace != NULL &&
					    l->netns != NULL &&
					    !strcmp(xfer_sock->namespace,
					    l->netns->node.key))
#endif
					   ) {
						break;
					}

				}
			}
		}
		xfer_sock = xfer_sock->next;
	}
	if (xfer_sock != NULL) {
		ret = xfer_sock->fd;
		if (xfer_sock == xfer_sock_list)
			xfer_sock_list = xfer_sock->next;
		if (xfer_sock->prev)
			xfer_sock->prev->next = xfer_sock->next;
		if (xfer_sock->next)
			xfer_sock->next->prev = xfer_sock->prev;
		free(xfer_sock->iface);
		free(xfer_sock->namespace);
		free(xfer_sock);
	}
	return ret;
}
#undef L1_MANDATORY_FLAGS

/* This function tries to bind a UDPv4/v6 listener. It may return a warning or
 * an error message in <errmsg> if the message is at most <errlen> bytes long
 * (including '\0'). Note that <errmsg> may be NULL if <errlen> is also zero.
 * The return value is composed from ERR_ABORT, ERR_WARN,
 * ERR_ALERT, ERR_RETRYABLE and ERR_FATAL. ERR_NONE indicates that everything
 * was alright and that no message was returned. ERR_RETRYABLE means that an
 * error occurred but that it may vanish after a retry (eg: port in use), and
 * ERR_FATAL indicates a non-fixable error. ERR_WARN and ERR_ALERT do not alter
 * the meaning of the error, but just indicate that a message is present which
 * should be displayed with the respective level. Last, ERR_ABORT indicates
 * that it's pointless to try to start other listeners. No error message is
 * returned if errlen is NULL.
 */
int quic_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	__label__ quic_return, quic_close_return;
	int fd, err;
	int ext;
	const char *msg = NULL;

	/* ensure we never return garbage */
	if (errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	err = ERR_NONE;

	if (listener->fd == -1)
		listener->fd = quic_find_compatible_fd(listener);

	/* if the listener already has an fd assigned, then we were offered the
	 * fd by an external process (most likely the parent), and we don't want
	 * to create a new socket. However we still want to set a few flags on
	 * the socket.
	 */
	fd = listener->fd;
	ext = (fd >= 0);

	if (!ext) {
		sa_family_t sa_family = listener->addr.ss_family == AF_CUST_QUIC ? AF_INET :
			                    listener->addr.ss_family == AF_CUST_QUIC6 ? AF_INET6 : -1;

		fd = my_socketat(listener->netns, sa_family, SOCK_DGRAM, IPPROTO_UDP);

		if (fd == -1) {
			err |= ERR_RETRYABLE | ERR_ALERT;
			msg = "cannot create listening socket";
			goto quic_return;
		}
	}

	if (fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ABORT | ERR_ALERT;
		msg = "not enough free sockets (raise '-n' parameter)";
		goto quic_close_return;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "cannot make socket non-blocking";
		goto quic_close_return;
	}

	if (!ext && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		/* not fatal but should be reported */
		msg = "cannot do so_reuseaddr";
		err |= ERR_ALERT;
	}

	if (listener->options & LI_O_NOLINGER)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &nolinger, sizeof(struct linger));
	else {
		struct linger tmplinger;
		socklen_t len = sizeof(tmplinger);
		if (getsockopt(fd, SOL_SOCKET, SO_LINGER, &tmplinger, &len) == 0 &&
		    (tmplinger.l_onoff == 1 || tmplinger.l_linger == 0)) {
			tmplinger.l_onoff = 0;
			tmplinger.l_linger = 0;
			setsockopt(fd, SOL_SOCKET, SO_LINGER, &tmplinger,
			    sizeof(tmplinger));
		}
	}

#ifdef SO_REUSEPORT
	/* OpenBSD and Linux 3.9 support this. As it's present in old libc versions of
	 * Linux, it might return an error that we will silently ignore.
	 */
	if (!ext && (global.tune.options & GTUNE_USE_REUSEPORT))
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

	if (!ext && (listener->options & LI_O_FOREIGN)) {
		switch (listener->addr.ss_family) {
		case AF_CUST_QUIC:
			if (1
#if defined(IP_TRANSPARENT)
			    && (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) == -1)
#endif
#if defined(IP_FREEBIND)
			    && (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == -1)
#endif
#if defined(IP_BINDANY)
			    && (setsockopt(fd, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) == -1)
#endif
#if defined(SO_BINDANY)
			    && (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == -1)
#endif
			    ) {
				msg = "cannot make listening socket transparent";
				err |= ERR_ALERT;
			}
		break;
		case AF_CUST_QUIC6:
			if (1
#if defined(IPV6_TRANSPARENT) && defined(SOL_IPV6)
			    && (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) == -1)
#endif
#if defined(IP_FREEBIND)
			    && (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) == -1)
#endif
#if defined(IPV6_BINDANY)
			    && (setsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) == -1)
#endif
#if defined(SO_BINDANY)
			    && (setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) == -1)
#endif
			    ) {
				msg = "cannot make listening socket transparent";
				err |= ERR_ALERT;
			}
		break;
		}
	}

#ifdef SO_BINDTODEVICE
	/* Note: this might fail if not CAP_NET_RAW */
	if (!ext && listener->interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       listener->interface, strlen(listener->interface) + 1) == -1) {
			msg = "cannot bind listener to device";
			err |= ERR_WARN;
		}
	}
#endif
#if defined(IPV6_V6ONLY)
	if (listener->options & LI_O_V6ONLY)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	else if (listener->options & LI_O_V4V6)
                setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
#endif

	if (!ext) {
		int ret;
		sa_family_t sa_family;

		sa_family = listener->addr.ss_family;
		listener->addr.ss_family = sa_family == AF_CUST_QUIC ? AF_INET :
			                       sa_family == AF_CUST_QUIC6 ? AF_INET6 : -1;
		ret = bind(fd, (struct sockaddr *)&listener->addr, listener->proto->sock_addrlen);
		listener->addr.ss_family = sa_family;
		if (ret == -1) {
			err |= ERR_RETRYABLE | ERR_ALERT;
			msg = "cannot bind socket";
			goto quic_close_return;
		}
	}

	/* the socket is ready */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	fd_insert(fd, listener, quic_fd_handler,
	          thread_mask(listener->bind_conf->bind_thread) & all_threads_mask);

 quic_return:
	if (msg && errlen) {
		char pn[INET6_ADDRSTRLEN];

		addr_to_str(&listener->addr, pn, sizeof(pn));
		snprintf(errmsg, errlen, "%s [%s:%d]", msg, pn, get_host_port(&listener->addr));
	}
	return err;

 quic_close_return:
	close(fd);
	goto quic_return;
}

/* This function creates all QUIC sockets bound to the protocol entry <proto>.
 * It is intended to be used as the protocol's bind_all() function.
 * The sockets will be registered but not added to any fd_set, in order not to
 * loose them across the fork(). A call to enable_all_listeners() is needed
 * to complete initialization. The return value is composed from ERR_*.
 */
static int quic_bind_listeners(struct protocol *proto, char *errmsg, int errlen)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= quic_bind_listener(listener, errmsg, errlen);
		if (err & ERR_ABORT)
			break;
	}

	return err;
}

/* Add <listener> to the list of quic4 listeners, on port <port>. The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 */
static void quic4_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_quic4;
	((struct sockaddr_in *)(&listener->addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_quic4.listeners, &listener->proto_list);
	proto_quic4.nb_listeners++;
}

/* Add <listener> to the list of quic6 listeners, on port <port>. The
 * listener's state is automatically updated from LI_INIT to LI_ASSIGNED.
 * The number of listeners for the protocol is updated.
 */
static void quic6_add_listener(struct listener *listener, int port)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_quic6;
	((struct sockaddr_in *)(&listener->addr))->sin_port = htons(port);
	LIST_ADDQ(&proto_quic6.listeners, &listener->proto_list);
	proto_quic6.nb_listeners++;
}

/* Pause a listener. Returns < 0 in case of failure, 0 if the listener
 * was totally stopped, or > 0 if correctly paused.
 */
int quic_pause_listener(struct listener *l)
{
	/* XXX TO DO XXX */
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
