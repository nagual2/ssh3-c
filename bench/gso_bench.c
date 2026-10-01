/*
 * Copyright (C) 2026 the ssh3-c authors
 */

/*
 * UDP GSO microbenchmark for ssh3-c.
 *
 * Measures the loopback throughput of plain sendmsg() (one datagram per
 * call) versus segmented sendmsg() with the UDP_SEGMENT cmsg (GSO: many
 * segments per call) over two connected UDP sockets.
 *
 * usage: s3gso_bench [--pkt N] [--total N] [--runs N]
 *     --pkt    datagram (GSO segment) size in bytes, default 1350
 *     --total  total bytes per run in MiB, default 256
 *     --runs   runs per mode, default 3 (the median is reported)
 */

/* recvmmsg() and struct mmsghdr are GNU extensions */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* NOLINT(cert-dcl37-c,cert-dcl51-cpp) */
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/udp.h> /* UDP_SEGMENT; conflicts with netinet/udp.h */

#define S3_BENCH_DEFAULT_PKT       1350
#define S3_BENCH_DEFAULT_TOTAL_MIB 256
#define S3_BENCH_DEFAULT_RUNS      3

#define S3_BENCH_MAX_DGRAM 65507 /* the maximum udp datagram size */

#define S3_BENCH_RCVBUF (4 * 1024 * 1024)

#define S3_BENCH_MAX_IDLE 20000000 /* spin iterations without data */

#define S3_BENCH_BATCH 64 /* datagrams per recvmmsg() call */

/*
 * the sender keeps the in-flight bytes below this window, so the receive
 * buffer of the receiver can never overflow (loopback drops datagrams
 * silently, there is no backpressure in udp)
 */
#define S3_BENCH_WINDOW 65536

typedef struct {
    int           fd;
    size_t        total;
    size_t        dgram_max;
    atomic_size_t received;
    atomic_int    started; /* the receiver is in its receive loop */
    int           failed;
} s3_bench_receiver_t;

static void *s3_bench_receiver(void *data);
static int s3_bench_run(int snd_fd, int rcv_fd, size_t total, int gso, size_t pkt, size_t segments,
                        unsigned char *buf, double *mbs);
static double s3_bench_median(double *values, size_t n);
static long   s3_bench_arg(const char *name, const char *value, long max);

static void *
s3_bench_receiver(void *data)
{
    s3_bench_receiver_t *rc = data;
    struct mmsghdr       mmsg[S3_BENCH_BATCH];
    struct iovec         iov[S3_BENCH_BATCH];
    unsigned char       *buf;
    ssize_t              n;
    int                  i, idle;

    buf = malloc(rc->dgram_max * S3_BENCH_BATCH);

    if (buf == NULL) {
        rc->failed = 1;
        return NULL;
    }

    for (i = 0; i < S3_BENCH_BATCH; i++) {
        iov[i].iov_base = buf + (size_t)i * rc->dgram_max;
        iov[i].iov_len = rc->dgram_max;

        memset(&mmsg[i], 0, sizeof(mmsg[i]));
        mmsg[i].msg_hdr.msg_iov = &iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }

    idle = 0;

    atomic_store(&rc->started, 1);

    /*
     * the receive loop spins without sleeping: a sleeping receiver turns
     * every wakeup into a pipeline stall and hides the difference between
     * the send paths being measured
     */

    while (rc->received < rc->total) {

        n = recvmmsg(rc->fd, mmsg, S3_BENCH_BATCH, MSG_DONTWAIT, NULL);

        if (n == -1) {

            if (errno == EAGAIN || errno == EINTR) {
                if (++idle > S3_BENCH_MAX_IDLE) {
                    rc->failed = 1;
                    break;
                }

                continue;
            }

            rc->failed = 1;
            break;
        }

        idle = 0;

        for (i = 0; i < n; i++) {
            rc->received += (size_t)mmsg[i].msg_len;
        }
    }

    free(buf);

    return NULL;
}

static int
s3_bench_run(int snd_fd, int rcv_fd, size_t total, int gso, size_t pkt, size_t segments,
             unsigned char *buf, double *mbs)
{
    struct timespec t0, t1;
    struct iovec    iov;
    struct msghdr   msg;
#ifdef UDP_SEGMENT
    struct cmsghdr *cmsg;
#endif
    char                ctrl[CMSG_SPACE(sizeof(uint16_t))];
    pthread_t           th;
    s3_bench_receiver_t rc;
    double              sec;
    size_t              len, chunk, sent;
    ssize_t             n;

    len = segments * pkt;

    memset(&rc, 0, sizeof(rc));
    rc.fd = rcv_fd;
    rc.total = total;
    rc.dgram_max = pkt;

    if (pthread_create(&th, NULL, s3_bench_receiver, &rc) != 0) {
        printf("pthread_create() failed\n");
        return 1;
    }

    /* wait until the receiver is in its receive loop: the loopback path
       drops datagrams silently once the receive buffer overflows */

    while (!atomic_load(&rc.started)) {
        sched_yield();
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);

    sent = 0;

    while (sent < total) {

        memset(&msg, 0, sizeof(msg));
        memset(ctrl, 0, sizeof(ctrl));

        if (gso && total - sent >= len) {

            /* one sendmsg() carries "segments" datagrams of pkt bytes */

            iov.iov_base = buf;
            iov.iov_len = len;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl;
            msg.msg_controllen = sizeof(ctrl);

#ifdef UDP_SEGMENT
            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = IPPROTO_UDP;
            cmsg->cmsg_type = UDP_SEGMENT;
            cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
            *(uint16_t *)CMSG_DATA(cmsg) = (uint16_t)pkt;
#endif

            n = sendmsg(snd_fd, &msg, 0);

        } else {
            chunk = (total - sent < pkt) ? total - sent : pkt;

            n = send(snd_fd, buf, chunk, 0);
        }

        if (n == -1) {

            if (errno == EINTR) {
                continue;
            }

            if (gso && (errno == EINVAL || errno == EOPNOTSUPP || errno == ENOTSUP)) {
                printf("GSO unsupported\n");
                return 2;
            }

            printf("send failed: %s\n", strerror(errno));
            return 1;
        }

        sent += (size_t)n;

        /*
         * flow control: wait while the bytes the receiver has not seen
         * yet exceed the window; without this the receive buffer
         * overflows and loopback drops datagrams silently
         */

        while (sent - (size_t)rc.received > S3_BENCH_WINDOW) {
            sched_yield();
        }
    }

    if (pthread_join(th, NULL) != 0) {
        printf("pthread_join() failed\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (rc.failed || rc.received != rc.total) {
        printf("receiver failed: %zu of %zu bytes\n", rc.received, rc.total);
        return 1;
    }

    sec = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    *mbs = (double)total / (1024.0 * 1024.0) / sec;

    return 0;
}

static double
s3_bench_median(double *values, size_t n)
{
    size_t i, j;
    double tmp;

    for (i = 1; i < n; i++) {
        tmp = values[i];

        for (j = i; j > 0 && values[j - 1] > tmp; j--) {
            values[j] = values[j - 1];
        }

        values[j] = tmp;
    }

    return values[n / 2];
}

static long
s3_bench_arg(const char *name, const char *value, long max)
{
    char *end;
    long  num;

    num = strtol(value, &end, 10);

    if (end == value || *end != '\0' || num <= 0 || num > max) {
        printf("invalid %s: %s\n", name, value);
        exit(1);
    }

    return num;
}

int
main(int argc, char *argv[])
{
    int                i, ret, rcv_fd = -1, snd_fd = -1;
    unsigned char     *buf = NULL;
    size_t             pkt, segments, total, runs, r, size;
    double             plain[64], gso[64], med_plain, med_gso;
    struct sockaddr_in sa;
    socklen_t          salen;
    int                opt_rcvbuf;

    pkt = S3_BENCH_DEFAULT_PKT;
    total = (size_t)S3_BENCH_DEFAULT_TOTAL_MIB * 1024 * 1024;
    runs = S3_BENCH_DEFAULT_RUNS;

    for (i = 1; i < argc; i += 2) {

        if (i + 1 >= argc) {
            printf("missing value for %s\n", argv[i]);
            return 1;
        }

        if (strcmp(argv[i], "--pkt") == 0) {
            pkt = (size_t)s3_bench_arg("--pkt", argv[i + 1], S3_BENCH_MAX_DGRAM);

        } else if (strcmp(argv[i], "--total") == 0) {
            total = (size_t)s3_bench_arg("--total", argv[i + 1], 65536) * 1024 * 1024;

        } else if (strcmp(argv[i], "--runs") == 0) {
            runs = (size_t)s3_bench_arg("--runs", argv[i + 1], 64);

        } else {
            printf("unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (runs > 64) {
        runs = 64;
    }

    segments = S3_BENCH_MAX_DGRAM / pkt;

    if (segments < 1) {
        printf("packet size %zu is too large\n", pkt);
        return 1;
    }

    size = segments * pkt;

    buf = malloc(size);

    if (buf == NULL) {
        printf("malloc(%zu) failed\n", size);
        return 1;
    }

    memset(buf, 0xAB, size);

    rcv_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (rcv_fd == -1) {
        printf("socket() failed: %s\n", strerror(errno));
        ret = 1;
        goto done;
    }

    opt_rcvbuf = S3_BENCH_RCVBUF;

    (void)setsockopt(rcv_fd, SOL_SOCKET, SO_RCVBUF, &opt_rcvbuf, sizeof(opt_rcvbuf));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    if (bind(rcv_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        printf("bind() failed: %s\n", strerror(errno));
        ret = 1;
        goto done;
    }

    salen = sizeof(sa);

    if (getsockname(rcv_fd, (struct sockaddr *)&sa, &salen) == -1) {
        printf("getsockname() failed: %s\n", strerror(errno));
        ret = 1;
        goto done;
    }

    snd_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (snd_fd == -1) {
        printf("socket() failed: %s\n", strerror(errno));
        ret = 1;
        goto done;
    }

    if (connect(snd_fd, (struct sockaddr *)&sa, salen) == -1) {
        printf("connect() failed: %s\n", strerror(errno));
        ret = 1;
        goto done;
    }

    printf("s3gso_bench: pkt=%zu segments=%zu total=%zu MiB runs=%zu\n", pkt, segments,
           total / (1024UL * 1024UL), runs);

    for (r = 0; r < runs; r++) {
        ret = s3_bench_run(snd_fd, rcv_fd, total, 0, pkt, segments, buf, &plain[r]);

        if (ret != 0) {
            goto done;
        }
    }

#ifndef UDP_SEGMENT
    printf("GSO unsupported\n");
    ret = 2;
    goto done;
#endif

    for (r = 0; r < runs; r++) {
        ret = s3_bench_run(snd_fd, rcv_fd, total, 1, pkt, segments, buf, &gso[r]);

        if (ret != 0) {
            goto done;
        }
    }

    med_plain = s3_bench_median(plain, runs);
    med_gso = s3_bench_median(gso, runs);

    printf("plain: median %.1f MB/s (runs:", med_plain);

    for (r = 0; r < runs; r++) {
        printf(" %.1f", plain[r]);
    }

    printf(")\n");

    printf("gso:   median %.1f MB/s (runs:", med_gso);

    for (r = 0; r < runs; r++) {
        printf(" %.1f", gso[r]);
    }

    printf(")\n");

    printf("ratio gso/plain: %.2fx\n", med_gso / med_plain);

    ret = 0;

done:

    if (snd_fd != -1) {
        (void)close(snd_fd);
    }

    if (rcv_fd != -1) {
        (void)close(rcv_fd);
    }

    free(buf);

    return ret;
}
