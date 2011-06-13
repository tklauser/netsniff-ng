/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <netinet/tcp.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "die.h"
#include "strlcpy.h"
#include "netdev.h"
#include "ct_client.h"
#include "curvetun.h"
#include "compiler.h"

/* XXX: remove */
static const char *rport = "6666";
static const char *rhost = "localhost";
static const char *scope = "wlan0";

extern sig_atomic_t sigint;

int tun_open_or_die(char *name)
{
	int fd, ret;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		panic("Cannot open /dev/net/tun!\n");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (name)
		strlcpy(ifr.ifr_name, name, IFNAMSIZ);

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret < 0)
		panic("ioctl screwed up!\n");

	return fd;
}

int client_main(void)
{
	int fd = -1, fd_tun, err, ret, try = 1, i, one;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;
	struct pollfd fds[2];
	char buffer[1600]; //XXX

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	fd_tun = tun_open_or_die("curvetun");

	ret = getaddrinfo(rhost, rport, &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (ai->ai_family == PF_INET6) {
			saddr6 = (struct sockaddr_in6 *) ai->ai_addr;
			if (saddr6->sin6_scope_id == 0) {
				saddr6->sin6_scope_id = device_ifindex(scope);
				info("Scope set to %d!\n",
				     saddr6->sin6_scope_id);
			}
		}

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		errno = 0;
		ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			whine("Cannot connect to remote, try %d: %s!\n",
			      try++, strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

		one = 1;
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
		one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	}

	freeaddrinfo(ahead);
	if (fd < 0)
		panic("Cannot create socket!\n");

	system("ifconfig curvetun up");

	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;
	fds[1].fd = fd_tun;
	fds[0].events = POLLIN;
	fds[1].events = POLLIN;

	while (likely(!sigint)) {
		ret = poll(fds, 2, -1);
		info("got event!!\n");
		if (ret > 0) {
			for (i = 0; i < 2; ++i) {
				/* XXX: sendfile? or TCP_CORK */
				if (fds[i].fd == fd_tun) {
					ret = read(fd_tun, buffer, sizeof(buffer));
					if (ret <= 0)
						continue;
					err = write(fd, buffer, ret);
					if (err != ret)
						perror("tun -> net");
					info("tun -> net done!!!\n");
				} else if (fds[i].fd == fd) {
					ret = read(fd, buffer, sizeof(buffer));
					if (ret < 0)
						continue;
					if (ret == 0)
						break;
					err = write(fd_tun, buffer, ret);
					if (err != ret)
						perror("net -> tun");
					info("net -> tun done!!!\n");
				}
			}
		}
	}

	close(fd);
	close(fd_tun);

	return 0;
}

