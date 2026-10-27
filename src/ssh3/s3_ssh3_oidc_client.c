/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the client OIDC flow: the loopback redirect listener, the PKCE
 * S256 challenge, the authorization code exchange at the token
 * endpoint and the local id_token verification (the reference
 * auth/oidc/openid_connect.go Connect() shape, one blocking pass)
 */

/* the loopback sockets: the winsock twins ride the S3_WIN32 define
 * (the LEAN build pulls no net headers on its own) */

#if (S3_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

#include <s3_https_fetch.h>
#include <s3_ssh3_oidc_client.h>

/* the fd closer and the setsockopt optval of the loopback sockets */

#if (S3_WIN32)
#define s3_oidc_close(fd)      closesocket(fd)
#define s3_oidc_sockopt_val(p) ((const char *)(p))
#else
#define s3_oidc_close(fd)      close(fd)
#define s3_oidc_sockopt_val(p) (p)
#endif

/* the redirect answer of the reference callback */

#define S3_SSH3_OIDC_CLI_ANSWER "you can now close this tab"

/* the blocking waits of the flow (the human at the browser tab) */

#define S3_SSH3_OIDC_CLI_TIMEOUT_SEC 300

static void
s3_cli_hex(const u_char *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";

    size_t i;

    for (i = 0; i < len; i++) {
        out[2 * i] = digits[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = digits[in[i] & 0xf];
    }

    out[2 * len] = '\0';
}

/* the query-value percent-encoding: the conversation nonce is the
 * base64 std form, its +/ and = ride the query only escaped */

static size_t
s3_cli_url_encode(const char *in, char *out, size_t out_max)
{
    static const char hex[] = "0123456789ABCDEF";

    const u_char *p = (const u_char *)in;
    size_t        n = 0;

    while (*p != '\0') {

        u_char c = *p++;

        int safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '-' || c == '.' || c == '_' || c == '~';

        if (out_max < n + 4) {
            return 0;
        }

        if (safe) {
            out[n++] = (char)c;

        } else {
            out[n++] = '%';
            out[n++] = hex[(c >> 4) & 0xf];
            out[n++] = hex[c & 0xf];
        }
    }

    out[n] = '\0';

    return n;
}

s3_int_t
s3_ssh3_oidc_flow_init(s3_ssh3_oidc_flow_t *f, const char *authorization_endpoint,
                       const char *client_id, const char *nonce)
{
    struct sockaddr_in sa;
    u_char             raw[32];
    u_char             challenge[EVP_MAX_MD_SIZE], challenge_b64[64];
    char               nonce_enc[192];
    unsigned           md_len;
    size_t             n;
    int                url_n, yes = 1;

    s3_memzero(f, sizeof(*f));

    if (s3_strlen(nonce) + 1 > sizeof(f->nonce)) {
        return S3_ERROR;
    }

    s3_memcpy(f->nonce, nonce, s3_strlen(nonce) + 1);

    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return S3_ERROR;
    }

    s3_cli_hex(raw, sizeof(raw), f->state);

    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_b64url_encode(raw, sizeof(raw), (u_char *)f->verifier) != 43) {
        return S3_ERROR;
    }

    f->verifier[43] = '\0';

    /* the S256 challenge: base64url(sha256(verifier)) */

    if (EVP_Digest(f->verifier, s3_strlen(f->verifier), challenge, &md_len, EVP_sha256(), NULL) !=
        1) {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_b64url_encode(challenge, md_len, challenge_b64) != 43) {
        return S3_ERROR;
    }

    challenge_b64[43] = '\0';

    /* the nonce rides the query percent-encoded (the base64 std
     * alphabet carries + and =), the endpoint decodes it back */

    if (s3_cli_url_encode(f->nonce, nonce_enc, sizeof(nonce_enc)) == 0) {
        s3_oidc_close(f->listen_fd);
        f->listen_fd = -1;
        return S3_ERROR;
    }

    /* the loopback redirect listener, the kernel port like the
     * reference net.Listen("tcp", ":0") */

    f->listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (f->listen_fd < 0) {
        return S3_ERROR;
    }

    (void)setsockopt(f->listen_fd, SOL_SOCKET, SO_REUSEADDR, s3_oidc_sockopt_val(&yes),
                     sizeof(yes));

    s3_memzero(&sa, sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    if (bind(f->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(f->listen_fd, 1) != 0) {
        s3_oidc_close(f->listen_fd);
        f->listen_fd = -1;
        return S3_ERROR;
    }

    {
        struct sockaddr_in bound;
        socklen_t          blen = sizeof(bound);

        if (getsockname(f->listen_fd, (struct sockaddr *)&bound, &blen) != 0) {
            s3_oidc_close(f->listen_fd);
            f->listen_fd = -1;
            return S3_ERROR;
        }

        f->port = ntohs(bound.sin_port);
    }

    n = snprintf(f->redirect_uri, sizeof(f->redirect_uri), "http://127.0.0.1:%d/ssh", f->port);

    if (n >= sizeof(f->redirect_uri)) {
        s3_oidc_close(f->listen_fd);
        f->listen_fd = -1;
        return S3_ERROR;
    }

    /* the endpoint may carry its own query (the providers do) */

    url_n =
        snprintf(f->authorize_url, sizeof(f->authorize_url),
                 "%s%sresponse_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=%s"
                 "&nonce=%s&code_challenge=%s&code_challenge_method=S256",
                 authorization_endpoint, (strchr(authorization_endpoint, '?') != NULL) ? "&" : "?",
                 client_id, f->redirect_uri, f->state, nonce_enc, challenge_b64);

    if (url_n <= 0 || (size_t)url_n >= sizeof(f->authorize_url)) {
        s3_oidc_close(f->listen_fd);
        f->listen_fd = -1;
        return S3_ERROR;
    }

    return S3_OK;
}

/* the query parameter of the request line: "?name=value&" */

static s3_int_t
s3_cli_query_param(const char *target, const char *name, char *buf, size_t buf_max)
{
    const char *q, *p, *amp, *vend;
    size_t      nlen, n;

    nlen = s3_strlen(name);

    q = strchr(target, '?');

    if (q == NULL) {
        return S3_DECLINED;
    }

    p = q + 1;
    vend = target + s3_strlen(target);

    while (p < vend) {

        if (s3_strncmp(p, name, nlen) == 0 && p[nlen] == '=') {

            p += nlen + 1;

            amp = strchr(p, '&');

            vend = (amp != NULL) ? amp : target + s3_strlen(target);

            n = (size_t)(vend - p);

            if (n == 0 || n + 1 > buf_max) {
                return S3_DECLINED;
            }

            s3_memcpy(buf, p, n);
            buf[n] = '\0';

            return S3_OK;
        }

        amp = strchr(p, '&');

        if (amp == NULL) {
            /* the last segment sits behind this amp */
            break;
        }

        p = amp + 1;
    }

    return S3_DECLINED;
}

s3_int_t
s3_ssh3_oidc_flow_wait_code(s3_ssh3_oidc_flow_t *f, char *code, size_t code_max)
{
    struct timeval tv;
    char           req[8192], target[2048], got_state[65];
    const char    *sp;
    size_t         n;
    ssize_t        got;
    int            conn, ok;
    s3_int_t       rc;

    tv.tv_sec = S3_SSH3_OIDC_CLI_TIMEOUT_SEC;
    tv.tv_usec = 0;

    (void)setsockopt(f->listen_fd, SOL_SOCKET, SO_RCVTIMEO, s3_oidc_sockopt_val(&tv), sizeof(tv));

    conn = accept(f->listen_fd, NULL, NULL);

    s3_oidc_close(f->listen_fd);
    f->listen_fd = -1;

    if (conn < 0) {
        return S3_ERROR;
    }

    (void)setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, s3_oidc_sockopt_val(&tv), sizeof(tv));

    /* one request line carries the redirect, the rest is drained by
     * the close (the browsers pipeline nothing before the response) */

    n = 0;

    while (n + 1 < sizeof(req)) {

        got = recv(conn, req + n, 1, 0);

        if (got <= 0) {
            s3_oidc_close(conn);
            return S3_ERROR;
        }

        if (req[n] == '\n') {
            break;
        }

        n++;
    }

    req[n] = '\0';

    /* "GET <target> HTTP/1.x" */

    ok = (s3_strncmp(req, "GET ", 4) == 0);

    if (ok) {

        sp = req + 4;

        {
            const char *eol = strchr(sp, ' ');

            if (eol == NULL || (size_t)(eol - sp) + 1 > sizeof(target)) {
                ok = 0;

            } else {

                s3_memcpy(target, sp, (size_t)(eol - sp));
                target[eol - sp] = '\0';
            }
        }
    }

    if (!ok) {
        s3_oidc_close(conn);
        return S3_ERROR;
    }

    rc = s3_cli_query_param(target, "state", got_state, sizeof(got_state));

    if (rc != S3_OK || s3_strcmp(got_state, f->state) != 0) {

        /* the state mismatch answers the 400 like the reference */

        (void)send(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", 47, 0);
        s3_oidc_close(conn);

        return S3_DECLINED;
    }

    rc = s3_cli_query_param(target, "code", code, code_max);

    if (rc != S3_OK) {
        s3_oidc_close(conn);
        return S3_ERROR;
    }

    /* the reference answer body */

    {
        char resp[160];

        n = (size_t)snprintf(resp, sizeof(resp),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: %zu\r\n"
                             "\r\n"
                             "%s",
                             sizeof(S3_SSH3_OIDC_CLI_ANSWER) - 1, S3_SSH3_OIDC_CLI_ANSWER);

        (void)send(conn, resp, n, 0);
    }

    s3_oidc_close(conn);

    return S3_OK;
}

s3_int_t
s3_ssh3_oidc_client_token(const char *issuer_url, const char *client_id, const char *ca_file,
                          const s3_ssh3_oidc_flow_t *f, const char *code, char *token,
                          size_t token_max)
{
    char                    form[2048];
    s3_str_t                body, resp, doc;
    unsigned                status;
    size_t                  n;
    s3_int_t                rc;
    s3_ssh3_oidc_provider_t provider;
    s3_ssh3_oidc_verifier_t v;

    if (f->nonce[0] == '\0' || s3_strlen(f->verifier) != 43) {
        return S3_ERROR;
    }

    if (s3_ssh3_oidc_discover(issuer_url, ca_file, &provider) != S3_OK) {
        return S3_ERROR;
    }

    /* the token form: the code, the redirect and the PKCE verifier */

    n = (size_t)snprintf(form, sizeof(form),
                         "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s"
                         "&code_verifier=%s",
                         code, f->redirect_uri, client_id, f->verifier);

    if (n >= sizeof(form)) {
        return S3_ERROR;
    }

    body.data = (u_char *)form;
    body.len = n;

    if (s3_https_fetch(provider.token_endpoint, "POST", &body, NULL, ca_file, &status, &resp) !=
        S3_OK) {
        return S3_ERROR;
    }

    if (status != 200) {
        s3_free(resp.data);
        return S3_ERROR;
    }

    doc.data = resp.data;
    doc.len = resp.len;

    rc = s3_ssh3_oidc_json_string(&doc, "id_token", token, token_max);

    s3_free(resp.data);

    if (rc != S3_OK) {
        return S3_ERROR;
    }

    /* the local verification the reference runs on the callback; the
     * discovered provider rides the verifier (no second discovery) */

    if (s3_ssh3_oidc_verifier_init(&v, issuer_url, ca_file) != S3_OK) {
        return S3_ERROR;
    }

    v.provider = provider;
    v.provider_ready = 1;

    if (s3_ssh3_oidc_jwks_fetch(&v.provider, ca_file, &v.jwks) != S3_OK) {
        s3_ssh3_oidc_verifier_clear(&v);
        return S3_ERROR;
    }

    rc = s3_ssh3_oidc_verifier_verify(&v, client_id, token, f->nonce, time(NULL));

    s3_ssh3_oidc_verifier_clear(&v);

    return rc;
}
