/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the server auth verifiers of the reference server_auth/ chain
 * (docs/P4-WIRE.md 7), the wire-level shape: the Basic credentials of
 * the authorization header, the username of the CONNECT target, the
 * default identities chain of the session user, the harness password
 * file (the plaintext fixture form standing in for the unix shadow
 * check) and the sshd authorized_keys iterator; the wiring picks the
 * checks it speaks
 */

#include <s3_core.h>

#include <pwd.h>
#include <stdio.h>

#include <s3_ssh3_auth_srv.h>

/* the file fixture cap, a bigger file is a wiring mistake */

#define S3_SSH3_AUTH_FILE_MAX (1024 * 1024)

/*
 * the strict standard base64 of the Basic scheme (+/,=): the padding
 * ends the final quantum only, the unpadded full quanta decode like
 * base64.StdEncoding does; the result lands in place, the output
 * never overruns the input position
 */

static s3_int_t
s3_ssh3_auth_b64_sextet(u_char c, s3_uint_t *value)
{
    if (c >= 'A' && c <= 'Z') {
        *value = (s3_uint_t)(c - 'A');
        return S3_OK;
    }

    if (c >= 'a' && c <= 'z') {
        *value = (s3_uint_t)(c - 'a') + 26;
        return S3_OK;
    }

    if (c >= '0' && c <= '9') {
        *value = (s3_uint_t)(c - '0') + 52;
        return S3_OK;
    }

    if (c == '+') {
        *value = 62;
        return S3_OK;
    }

    if (c == '/') {
        *value = 63;
        return S3_OK;
    }

    return S3_ERROR;
}

static s3_int_t
s3_ssh3_auth_b64_decode(u_char *data, size_t len, size_t *dlen)
{
    s3_uint_t v[4];
    size_t    n, i, out, pad;
    u_char    c;

    /* the quantum shape: the ragged payload is garbage */

    if (len == 0 || len % 4 != 0) {
        return S3_ERROR;
    }

    out = 0;

    for (n = 0; n < len; n += 4) {

        pad = 0;

        for (i = 0; i < 4; i++) {

            c = data[n + i];

            if (c == '=') {

                /* the padding lives at the tail of the final quantum */

                if (n + 4 != len || i < 2) {
                    return S3_ERROR;
                }

                pad++;
                v[i] = 0;

                continue;
            }

            if (pad > 0) {
                /* the data behind the padding */
                return S3_ERROR;
            }

            if (s3_ssh3_auth_b64_sextet(c, &v[i]) != S3_OK) {
                return S3_ERROR;
            }
        }

        data[out++] = (u_char)((v[0] << 2) | (v[1] >> 4));

        if (pad < 2) {
            data[out++] = (u_char)(((v[1] & 0xf) << 4) | (v[2] >> 2));
        }

        if (pad < 1) {
            data[out++] = (u_char)(((v[2] & 0x3) << 6) | v[3]);
        }
    }

    *dlen = out;

    return S3_OK;
}

s3_int_t
s3_ssh3_auth_basic_decode(const s3_str_t *header, s3_str_t *user, s3_str_t *pass)
{
    static const s3_str_t scheme = s3_string("Basic");

    const u_char *space, *colon;
    u_char       *base;
    size_t        dlen;
    s3_int_t      rc;

    s3_str_null(user);
    s3_str_null(pass);

    /* the exact-case scheme token, one space, like the client sends */

    space = memchr(header->data, ' ', header->len);

    if (space == NULL) {

        if (header->len != scheme.len || s3_memcmp(header->data, scheme.data, scheme.len) != 0) {
            return S3_DECLINED;
        }

        /* "Basic" alone: the scheme is ours, the payload is missing */

        return S3_ERROR;
    }

    if ((size_t)(space - header->data) != scheme.len ||
        s3_memcmp(header->data, scheme.data, scheme.len) != 0) {
        return S3_DECLINED;
    }

    base = (u_char *)space + 1;
    dlen = header->len - (size_t)(space - header->data) - 1;

    rc = s3_ssh3_auth_b64_decode(base, dlen, &dlen);

    if (rc != S3_OK) {
        return S3_ERROR;
    }

    /* the views split on the first colon of the decoded region */

    colon = memchr(base, ':', dlen);

    if (colon == NULL) {
        return S3_ERROR;
    }

    user->data = base;
    user->len = (size_t)(colon - base);

    pass->data = (u_char *)colon + 1;
    pass->len = dlen - user->len - 1;

    if (user->len == 0 || pass->len == 0) {
        s3_str_null(user);
        s3_str_null(pass);
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_auth_user_from_path(const s3_str_t *path, s3_str_t *user)
{
    static const s3_str_t param = s3_string("user=");

    const u_char *p, *end, *amp, *value;
    size_t        vlen;

    s3_str_null(user);

    /* the query begins at the '?', the parameters split on '&' */

    p = memchr(path->data, '?', path->len);

    if (p == NULL) {
        return S3_DECLINED;
    }

    p++;
    end = path->data + path->len;

    while (p < end) {

        /* the parameter name must match whole, the value stays raw */

        if ((size_t)(end - p) > param.len && s3_memcmp(p, param.data, param.len) == 0) {

            value = p + param.len;

            amp = memchr(value, '&', (size_t)(end - value));
            vlen = (amp != NULL) ? (size_t)(amp - value) : (size_t)(end - value);

            /* the first user parameter decides, the empty is absent */

            if (vlen == 0) {
                return S3_DECLINED;
            }

            user->data = (u_char *)value;
            user->len = vlen;

            return S3_OK;
        }

        amp = memchr(p, '&', (size_t)(end - p));

        if (amp == NULL) {
            break;
        }

        p = amp + 1;
    }

    return S3_DECLINED;
}

/*
 * the plain session names only: the same charset the -K %u expansion
 * guards (no leading dot, no separator) - a username is never a path
 * fragment
 */

static s3_int_t
s3_ssh3_auth_plain_name(const s3_str_t *user)
{
    size_t i;

    if (user->len == 0 || user->len > 255 || user->data[0] == '.') {
        return S3_ERROR;
    }

    for (i = 0; i < user->len; i++) {

        u_char c = user->data[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return S3_ERROR;
        }
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_auth_default_chain(const s3_str_t *user, char *buf, size_t size,
                           const char *paths[S3_SSH3_AUTH_CHAIN_MAX], unsigned *n)
{
    static const char *suffix[S3_SSH3_AUTH_CHAIN_MAX] = {"/.ssh3/authorized_identities",
                                                         "/.ssh/authorized_keys"};

    char           name[256];
    struct passwd *pw;
    size_t         left = size;
    unsigned       i;

    *n = 0;

    if (s3_ssh3_auth_plain_name(user) != S3_OK) {
        return S3_ERROR;
    }

    s3_memcpy(name, user->data, user->len);
    name[user->len] = '\0';

    pw = getpwnam(name);

    /* the unknown user, or a home-less one: the CWD-relative read the
     * reference's path.Join() would produce with an empty home is not
     * reproduced here */

    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] == '\0') {
        return S3_ERROR;
    }

    for (i = 0; i < S3_SSH3_AUTH_CHAIN_MAX; i++) {

        int m;

        if (left == 0) {
            return S3_ERROR;
        }

        m = snprintf(buf, left, "%s%s", pw->pw_dir, suffix[i]);

        if (m < 0 || (size_t)m >= left) {
            return S3_ERROR;
        }

        paths[i] = buf;
        buf += (size_t)m + 1;
        left -= (size_t)m + 1;
    }

    *n = S3_SSH3_AUTH_CHAIN_MAX;

    return S3_OK;
}

s3_int_t
s3_ssh3_auth_password_file_check(const char *path, const s3_str_t *user, const s3_str_t *pass)
{
    u_char  *buf, *p, *end, *nl, *line_end, *colon;
    size_t   n;
    long     size;
    FILE    *f;
    s3_int_t rc;

    f = fopen(path, "rb");

    if (f == NULL) {
        return S3_ERROR;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return S3_ERROR;
    }

    size = ftell(f);

    if (size < 0 || size > S3_SSH3_AUTH_FILE_MAX) {
        fclose(f);
        return S3_ERROR;
    }

    rewind(f);

    buf = s3_alloc((size_t)size + 1, NULL);

    if (buf == NULL) {
        fclose(f);
        return S3_ERROR;
    }

    if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        s3_free(buf);
        fclose(f);
        return S3_ERROR;
    }

    fclose(f);

    p = buf;
    end = buf + size;

    rc = S3_DECLINED;

    while (p < end) {

        nl = memchr(p, '\n', (size_t)(end - p));

        line_end = (nl != NULL) ? nl : end;

        /* CRLF: the carriage return dies with the line end */

        if (line_end > p && line_end[-1] == '\r') {
            line_end--;
        }

        if (line_end > p && *p != '#') {

            colon = memchr(p, ':', (size_t)(line_end - p));

            if (colon != NULL) {

                /*
                 * the first line with the matching user decides, the
                 * later duplicates never resurrect the verdict
                 */

                if ((size_t)(colon - p) == user->len && s3_memcmp(p, user->data, user->len) == 0) {
                    n = (size_t)(line_end - colon) - 1;

                    rc = (n == pass->len && s3_memcmp(colon + 1, pass->data, pass->len) == 0)
                             ? S3_OK
                             : S3_DECLINED;

                    break;
                }
            }
        }

        p = (nl != NULL) ? nl + 1 : end;
    }

    s3_free(buf);

    return rc;
}

/*
 * the sshd authorized_keys iterator.  The first token decides between
 * the options and the keytype: a token with ',' or '=' or without the
 * ssh-/ecdsa-/sk- stem is an options prefix, skipped wholesale to the
 * first space outside the quotes (the quoted values ride the scan
 * unparsed - the documented simplification against the full sshd
 * option grammar, an unterminated quote is S3_ERROR); behind the
 * keytype sits the base64 blob, the comment to the line end is
 * ignored
 */

s3_int_t
s3_ssh3_auth_authorized_keys_next(const u_char **pos, const u_char *end, s3_str_t *keytype,
                                  s3_str_t *b64)
{
    const u_char *p, *nl, *next, *line_end, *tok, *tok_end, *q;
    size_t        tlen;
    unsigned      in_quote, is_options, stem;

    p = *pos;

    while (p < end) {

        nl = memchr(p, '\n', (size_t)(end - p));

        next = (nl != NULL) ? nl + 1 : end;
        line_end = (nl != NULL) ? nl : end;

        /* CRLF: the carriage return dies with the line end */

        if (line_end > p && line_end[-1] == '\r') {
            line_end--;
        }

        if (line_end == p || *p == '#') {
            /* the empty lines and the comments skip */
            p = next;
            continue;
        }

        /* the first token (to the first space) is the shape detector */

        tok_end = p;

        while (tok_end < line_end && *tok_end != ' ') {
            tok_end++;
        }

        tlen = (size_t)(tok_end - p);

        is_options = (memchr(p, ',', tlen) != NULL || memchr(p, '=', tlen) != NULL);

        if (!is_options) {

            stem = ((tlen >= 4 && s3_memcmp(p, "ssh-", 4) == 0) ||
                    (tlen >= 6 && s3_memcmp(p, "ecdsa-", 6) == 0) ||
                    (tlen >= 3 && s3_memcmp(p, "sk-", 3) == 0));

            is_options = !stem;
        }

        if (is_options) {

            /* the prefix runs to the first space outside the quotes */

            q = p;
            in_quote = 0;

            while (q < line_end) {

                if (*q == '"') {
                    in_quote = !in_quote;

                } else if (*q == ' ' && !in_quote) {
                    break;
                }

                q++;
            }

            if (in_quote) {
                /* the quote of the options prefix never closed */
                return S3_ERROR;
            }

            p = q;
        }

        /* the keytype token */

        while (p < line_end && *p == ' ') {
            p++;
        }

        tok = p;

        while (p < line_end && *p != ' ') {
            p++;
        }

        if (p == tok) {
            /* nothing behind the options prefix */
            return S3_ERROR;
        }

        keytype->data = (u_char *)tok;
        keytype->len = (size_t)(p - tok);

        /* the base64 blob, the comment behind it is ignored */

        while (p < line_end && *p == ' ') {
            p++;
        }

        tok = p;

        while (p < line_end && *p != ' ') {
            p++;
        }

        if (p == tok) {
            /* the keytype without the blob */
            return S3_ERROR;
        }

        b64->data = (u_char *)tok;
        b64->len = (size_t)(p - tok);

        *pos = next;

        return S3_OK;
    }

    *pos = p;

    return S3_DONE;
}
