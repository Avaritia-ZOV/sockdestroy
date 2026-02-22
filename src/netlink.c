#ifndef UNSUPPORTED_PLATFORM

#include "netlink.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

int netlink_open(netlink_sock_t *ns) {
    struct sockaddr_nl addr;

    ns->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (ns->fd < 0)
        return -errno;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (bind(ns->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        close(ns->fd);
        ns->fd = -1;
        return -err;
    }

    ns->seq = 0;
    return 0;
}

void netlink_close(netlink_sock_t *ns) {
    if (ns->fd >= 0) {
        close(ns->fd);
        ns->fd = -1;
    }
}

int netlink_send(netlink_sock_t *ns, struct nlmsghdr *nlh) {
    struct sockaddr_nl dst;
    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    struct msghdr msg = {
        .msg_name = &dst,
        .msg_namelen = sizeof(dst),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    /* nl_pid = 0 means kernel */

    nlh->nlmsg_seq = ++ns->seq;

    ssize_t sent;
    do {
        sent = sendmsg(ns->fd, &msg, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0)
        return -errno;
    return 0;
}

ssize_t netlink_recv(netlink_sock_t *ns, void *buf, size_t buflen) {
    struct sockaddr_nl src;
    struct iovec iov = { .iov_base = buf, .iov_len = buflen };
    struct msghdr msg = {
        .msg_name = &src,
        .msg_namelen = sizeof(src),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    /* MSG_PEEK | MSG_TRUNC: peek at the message without consuming it.
     * MSG_TRUNC makes recvmsg return the real message length even if
     * it exceeds the buffer, so we can detect truncation safely. */
    ssize_t len;
    do {
        len = recvmsg(ns->fd, &msg, MSG_PEEK | MSG_TRUNC);
    } while (len < 0 && errno == EINTR);
    if (len < 0)
        return -errno;

    if ((size_t)len > buflen) {
        /* Message is larger than buffer — still in the kernel queue
         * (MSG_PEEK did not consume it). Caller can realloc and retry. */
        return -EMSGSIZE;
    }

    /* Buffer is large enough — consume the message */
    iov.iov_base = buf;
    iov.iov_len = buflen;
    msg.msg_namelen = sizeof(src);
    msg.msg_flags = 0;
    do {
        len = recvmsg(ns->fd, &msg, 0);
    } while (len < 0 && errno == EINTR);
    if (len < 0)
        return -errno;

    return len;
}

ssize_t netlink_recv_expected(netlink_sock_t *ns, void *buf, size_t buflen, uint32_t expected_seq) {
    for (int attempts = 0; attempts < NETLINK_MAX_RECV_RETRIES; attempts++) {
        ssize_t len = netlink_recv(ns, buf, buflen);
        if (len < 0)
            return len;

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        if (NLMSG_OK(nlh, (int)len) && nlh->nlmsg_seq == expected_seq)
            return len;
        /* Wrong sequence — discard and retry */
    }
    /* Retry limit exceeded: sequence mismatch — protocol error, not a timeout */
    return -EPROTO;
}

#endif /* UNSUPPORTED_PLATFORM */
