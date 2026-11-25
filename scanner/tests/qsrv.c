/* kit-c test QUIC server (TEST ONLY; built by tests/test_kit.py into the tmpfs work directory, never shipped as a binary).
 * Derived from lab-B11 scripts/qsrv.c (minimal OpenSSL >= 3.5 QUIC server: SSL_new_listener / SSL_accept_connection).
 * Changes for kit-c: the server never sends or reads application data and never closes first while the client is
 * alive; it ACCEPTS every stream the client opens and logs it (id, direction, bytes, FIN/reset), waits until the
 * client closes the connection (or WAIT seconds), and logs the client's CONNECTION_CLOSE (error code, reason, whether
 * it was a transport or an application close). QSRV_TRACE=FILE writes SSL_trace (TLS messages and QUIC packets and
 * frames as the server sees them) to FILE. These logs are what tests q01-q02 assert on.
 * usage: qsrv PORT CERT KEY [GROUPS|-] [validate|novalidate] [WAIT] [ADDR]
 *   GROUPS "-" = library default (SSL_CTX_set1_groups_list is not called). ALPN accepted: h3.
 *   validate (default) = QUIC address validation (Retry); novalidate = SSL_LISTENER_FLAG_NO_VALIDATE.
 *   WAIT = seconds to wait for the client's close after the handshake (default 3).
 *   ADDR = local IPv4 or IPv6 address to bind (default 127.0.0.1). One connection at a time, blocking accept. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/err.h>

static double since(const struct timespec *t0)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) + (t.tv_nsec - t0->tv_nsec) / 1e9;
}

static int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char srv[] = "\x02h3";
    (void)s; (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, srv, sizeof(srv) - 1, in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#define MAXS 16
struct st { SSL *s; uint64_t id; int type; size_t bytes; int end; };

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: qsrv PORT CERT KEY [GROUPS|-] [validate|novalidate] [WAIT] [ADDR]\n"); return 2; }
    int port = atoi(argv[1]);
    const char *groups = argc > 4 ? argv[4] : "-";
    uint64_t lflags = (argc > 5 && strcmp(argv[5], "novalidate") == 0) ? SSL_LISTENER_FLAG_NO_VALIDATE : 0;
    double wait = argc > 6 ? atof(argv[6]) : 3.0;
    const char *addr = argc > 7 ? argv[7] : "127.0.0.1";
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("qsrv: %s, groups=%s, listener flags=%llu, wait=%.1f\n", OpenSSL_version(OPENSSL_VERSION), groups,
           (unsigned long long)lflags, wait);

    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL || SSL_CTX_use_certificate_chain_file(ctx, argv[2]) <= 0
        || SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); return 1;
    }
    if (strcmp(groups, "-") != 0 && !SSL_CTX_set1_groups_list(ctx, groups)) {
        fprintf(stderr, "qsrv: cannot set groups %s\n", groups); ERR_print_errors_fp(stderr); return 1;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, NULL);
    const char *tr = getenv("QSRV_TRACE");
    BIO *tb = NULL;
    if (tr != NULL) {
        tb = BIO_new_file(tr, "a");
        if (tb == NULL) { fprintf(stderr, "qsrv: cannot open %s\n", tr); return 1; }
        SSL_CTX_set_msg_callback(ctx, SSL_trace);
        SSL_CTX_set_msg_callback_arg(ctx, tb);
    }

    struct sockaddr_storage ss_; memset(&ss_, 0, sizeof(ss_));
    struct sockaddr_in *s4 = (struct sockaddr_in *)&ss_; struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss_;
    socklen_t sl;
    if (inet_pton(AF_INET, addr, &s4->sin_addr) == 1) { s4->sin_family = AF_INET; s4->sin_port = htons(port); sl = sizeof(*s4); }
    else if (inet_pton(AF_INET6, addr, &s6->sin6_addr) == 1) { s6->sin6_family = AF_INET6; s6->sin6_port = htons(port); sl = sizeof(*s6); }
    else { fprintf(stderr, "qsrv: bad address %s\n", addr); return 2; }
    int fd = socket(ss_.ss_family, SOCK_DGRAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&ss_, sl) < 0) { perror("bind"); return 1; }
    SSL *ln = SSL_new_listener(ctx, lflags);
    if (ln == NULL || !SSL_set_fd(ln, fd) || !SSL_listen(ln)) { ERR_print_errors_fp(stderr); return 1; }
    printf("qsrv: listening udp %s port %d\n", addr, port);

    for (unsigned n = 1;; n++) {
        SSL *c = SSL_accept_connection(ln, 0);
        if (c == NULL) { printf("qsrv: accept failed\n"); ERR_print_errors_fp(stdout); continue; }
        struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
        int dm = SSL_set_default_stream_mode(c, SSL_DEFAULT_STREAM_MODE_NONE);
        int ip = SSL_set_incoming_stream_policy(c, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
        int hs = SSL_do_handshake(c);
        const unsigned char *alpn = NULL; unsigned int alen = 0;
        SSL_get0_alpn_selected(c, &alpn, &alen);
        int g = SSL_get_negotiated_group(c);
        const char *gn = SSL_group_to_name(c, g);
        printf("qsrv: conn %u handshake=%d version=%s group=%s alpn=%.*s (default_stream_mode_none=%d accept_policy=%d)\n",
               n, hs, SSL_get_version(c), gn ? gn : "?", (int)alen, alpn ? (const char *)alpn : "", dm, ip);
        if (hs != 1) ERR_print_errors_fp(stdout);
        ERR_clear_error();
        SSL_set_blocking_mode(c, 0);
        struct st ss[MAXS]; int ns = 0;
        SSL_CONN_CLOSE_INFO ci; memset(&ci, 0, sizeof(ci));
        int closed = 0;
        while (since(&t0) < wait) {
            SSL_handle_events(c);
            SSL *s;
            while (ns < MAXS && (s = SSL_accept_stream(c, SSL_ACCEPT_STREAM_NO_BLOCK)) != NULL) {
                SSL_set_blocking_mode(s, 0);
                ss[ns].s = s; ss[ns].id = SSL_get_stream_id(s); ss[ns].type = SSL_get_stream_type(s);
                ss[ns].bytes = 0; ss[ns].end = 0;
                printf("qsrv: conn %u client opened stream id=%llu type=%d at %.3f s\n", n,
                       (unsigned long long)ss[ns].id, ss[ns].type, since(&t0));
                ns++;
            }
            for (int i = 0; i < ns; i++) {
                if (ss[i].end) continue;
                char buf[4096]; size_t nr;
                while (SSL_read_ex(ss[i].s, buf, sizeof(buf), &nr)) ss[i].bytes += nr;
                int rs = SSL_get_stream_read_state(ss[i].s);
                if (rs == SSL_STREAM_STATE_FINISHED || rs == SSL_STREAM_STATE_RESET_REMOTE || rs == SSL_STREAM_STATE_CONN_CLOSED)
                    ss[i].end = rs;
                ERR_clear_error();
            }
            if (SSL_get_conn_close_info(c, &ci, sizeof(ci))) { closed = 1; break; }
            usleep(1000);
        }
        for (int i = 0; i < ns; i++) {
            printf("qsrv: conn %u stream id=%llu type=%d bytes=%zu end_state=%d\n", n, (unsigned long long)ss[i].id,
                   ss[i].type, ss[i].bytes, ss[i].end);
            SSL_free(ss[i].s);
        }
        if (closed)
            printf("qsrv: conn %u closed_by=%s %s error=0x%llx reason=%.*s streams=%d after %.3f s\n", n,
                   (ci.flags & SSL_CONN_CLOSE_FLAG_LOCAL) ? "server" : "client",
                   (ci.flags & SSL_CONN_CLOSE_FLAG_TRANSPORT) ? "transport" : "application",
                   (unsigned long long)ci.error_code, (int)ci.reason_len, ci.reason ? ci.reason : "", ns, since(&t0));
        else
            printf("qsrv: conn %u not closed by the client within %.1f s; streams=%d\n", n, wait, ns);
        if (!closed) {
            SSL_SHUTDOWN_EX_ARGS a; memset(&a, 0, sizeof(a));
            a.quic_error_code = 0x100; a.quic_reason = "kit-c qsrv done";
            struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
            while (SSL_shutdown_ex(c, 0, &a, sizeof(a)) == 0 && since(&t1) < 2.0) { SSL_handle_events(c); usleep(1000); }
        }
        /* keep the connection alive briefly so a final CONNECTION_CLOSE is transmitted before SSL_free */
        struct timespec t2; clock_gettime(CLOCK_MONOTONIC, &t2);
        while (since(&t2) < 0.3) { SSL_handle_events(c); SSL_handle_events(ln); usleep(1000); }
        printf("qsrv: conn %u done\n", n);
        if (tb) (void)BIO_flush(tb);
        ERR_clear_error();
        SSL_free(c);
    }
}
