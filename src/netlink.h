#ifndef SS_BINDING_NETLINK_H
#define SS_BINDING_NETLINK_H

#ifdef UNSUPPORTED_PLATFORM

/* Minimal stubs for non-Linux platforms — just enough for addon.c to compile.
 * The JS wrapper will throw before any native function is called on non-Linux. */
#include <stdint.h>
typedef struct { int fd; uint32_t seq; } netlink_sock_t;

#else /* Linux */

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* Netlink SOCK_DIAG protocol */
#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

/* Message types */
#define SOCK_DIAG_BY_FAMILY 20
#define SOCK_DESTROY_SOCK   21   /* avoid conflict with any existing SOCK_DESTROY macro */

/* Bytecode filter ops */
#define INET_DIAG_BC_NOP      0
#define INET_DIAG_BC_JMP      1
#define INET_DIAG_BC_S_COND   7
#define INET_DIAG_BC_D_COND   8

/* Inet diag request attribute types */
#define INET_DIAG_REQ_NONE      0
#define INET_DIAG_REQ_BYTECODE  1

/* TCP states bitmask — all states (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.) */
#define TCPF_ALL (~0U)

/* Address families */
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* IP protocol — use enum from <netinet/in.h> to avoid macro/enum conflict */
#include <netinet/in.h>

/* NLM flags - define only if not already defined */
#ifndef NLM_F_REQUEST
#define NLM_F_REQUEST 0x01
#endif
#ifndef NLM_F_ACK
#define NLM_F_ACK    0x04
#endif
#ifndef NLM_F_ROOT
#define NLM_F_ROOT   0x100
#endif
#ifndef NLM_F_MATCH
#define NLM_F_MATCH  0x200
#endif
#ifndef NLM_F_DUMP
#define NLM_F_DUMP   (NLM_F_ROOT | NLM_F_MATCH)
#endif

/* NLMSG types */
#ifndef NLMSG_DONE
#define NLMSG_DONE   3
#endif
#ifndef NLMSG_ERROR
#define NLMSG_ERROR  2
#endif

/* NLMSG alignment macros */
#ifndef NLMSG_ALIGNTO
#define NLMSG_ALIGNTO 4U
#endif
#ifndef NLMSG_ALIGN
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#endif
#ifndef NLMSG_HDRLEN
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#endif
#ifndef NLMSG_LENGTH
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#endif
#ifndef NLMSG_DATA
#define NLMSG_DATA(nlh) ((void*)(((char*)(nlh)) + NLMSG_HDRLEN))
#endif
#ifndef NLMSG_NEXT
#define NLMSG_NEXT(nlh, len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
    (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#endif
#ifndef NLMSG_OK
#define NLMSG_OK(nlh, len) ((len) >= (int)sizeof(struct nlmsghdr) && \
    (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
    (int)(nlh)->nlmsg_len <= (len) && \
    (nlh)->nlmsg_len <= (unsigned int)(len))
#endif

/* NLA (Netlink Attribute) macros */
#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

/* nlattr is provided by <linux/netlink.h> */

/* inet_diag_sockid — identifies a specific socket */
struct inet_diag_sockid {
    uint16_t idiag_sport;     /* source port (network byte order) */
    uint16_t idiag_dport;     /* destination port (network byte order) */
    uint32_t idiag_src[4];    /* source address */
    uint32_t idiag_dst[4];    /* destination address */
    uint32_t idiag_if;        /* interface index */
    uint32_t idiag_cookie[2]; /* socket cookie (kernel opaque) */
};

#define INET_DIAG_NOCOOKIE (~0U)

/* inet_diag_req_v2 — request structure for SOCK_DIAG_BY_FAMILY and SOCK_DESTROY */
struct inet_diag_req_v2 {
    uint8_t  sdiag_family;
    uint8_t  sdiag_protocol;
    uint8_t  idiag_ext;
    uint8_t  pad;
    uint32_t idiag_states;
    struct inet_diag_sockid id;
};

/* inet_diag_msg — response from kernel for each matched socket */
struct inet_diag_msg {
    uint8_t  idiag_family;
    uint8_t  idiag_state;
    uint8_t  idiag_timer;
    uint8_t  idiag_retrans;
    struct inet_diag_sockid id;
    uint32_t idiag_expires;
    uint32_t idiag_rqueue;
    uint32_t idiag_wqueue;
    uint32_t idiag_uid;
    uint32_t idiag_inode;
};

/* Bytecode filter operation */
struct inet_diag_bc_op {
    uint8_t  code;
    uint8_t  yes;
    uint16_t no;
};

/* Host condition for bytecode filter (S_COND / D_COND) */
struct inet_diag_hostcond {
    uint8_t  family;
    uint8_t  prefix_len;
    int      port;       /* -1 = any port */
    uint32_t addr[];     /* flexible array: 1 elem for IPv4, 4 for IPv6 */
};

/* nlmsgerr is provided by <linux/netlink.h> */

/* Netlink socket wrapper */
typedef struct {
    int fd;
    uint32_t seq;
} netlink_sock_t;

/* Open a NETLINK_SOCK_DIAG socket. Returns 0 on success, -errno on error. */
int netlink_open(netlink_sock_t *ns);

/* Close netlink socket */
void netlink_close(netlink_sock_t *ns);

/* Send a netlink message. Returns 0 on success, -errno on error. */
int netlink_send(netlink_sock_t *ns, struct nlmsghdr *nlh);

/* Receive into buffer. Returns bytes received, or -errno on error. */
ssize_t netlink_recv(netlink_sock_t *ns, void *buf, size_t buflen);

/* Receive a netlink message, validating the sequence number.
 * Discards messages that don't match the expected sequence.
 * Returns bytes received on success, -errno on error. */
ssize_t netlink_recv_expected(netlink_sock_t *ns, void *buf, size_t buflen, uint32_t expected_seq);

#endif /* UNSUPPORTED_PLATFORM */
#endif /* SS_BINDING_NETLINK_H */
