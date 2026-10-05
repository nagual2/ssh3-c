/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the libFuzzer harness of the sftp v3 codec: the frame layer eats
 * the whole input frame by frame, every parsed packet runs through
 * the strict body decoders of its type and through the generic
 * scalar readers; the strict-decoder contract is truncation to
 * S3_ERROR, never an out-of-bounds access
 */

#include <stddef.h>
#include <stdint.h>

#include <s3_core.h>

#include <s3_ssh3_sftp_codec.h>

#include "s3_fuzz.h"

static void
s3_fuzz_body_by_type(const s3_ssh3_sftp_pkt_t *pkt)
{
    const s3_str_t      *body = &pkt->body;
    const u_char        *pos, *end;
    s3_str_t             a, b, data;
    s3_ssh3_sftp_attrs_t attrs;
    uint32_t             code, count, i, pflags, len;
    uint64_t             offset;
    s3_int_t             rc;

    switch (pkt->type) {

    case S3_SSH3_SFTP_OPEN:

        if (s3_ssh3_sftp_parse_open_body(body, &a, &pflags, &attrs) == S3_OK) {
            s3_fuzz_sink(a.len + pflags + attrs.flags);
        }

        return;

    case S3_SSH3_SFTP_READ:

        if (s3_ssh3_sftp_parse_read_body(body, &a, &offset, &len) == S3_OK) {
            s3_fuzz_sink(a.len + offset + len);
        }

        return;

    case S3_SSH3_SFTP_WRITE:

        if (s3_ssh3_sftp_parse_write_body(body, &a, &offset, &data) == S3_OK) {
            s3_fuzz_sink(a.len + offset + data.len);
        }

        return;

    case S3_SSH3_SFTP_SETSTAT:
    case S3_SSH3_SFTP_FSETSTAT:
    case S3_SSH3_SFTP_MKDIR:

        /* the string plus the attribute block */

        pos = body->data;
        end = body->data + body->len;

        if (s3_ssh3_sftp_parse_string(&pos, end, &a) == S3_OK &&
            s3_ssh3_sftp_parse_attrs(&pos, end, &attrs) == S3_OK) {
            s3_fuzz_sink(a.len + attrs.flags);
        }

        return;

    case S3_SSH3_SFTP_RENAME:
    case S3_SSH3_SFTP_SYMLINK:

        if (s3_ssh3_sftp_parse_rename_body(body, &a, &b) == S3_OK) {
            s3_fuzz_sink(a.len + b.len);
        }

        return;

    case S3_SSH3_SFTP_NAME:

        pos = body->data;
        end = body->data + body->len;

        if (s3_ssh3_sftp_parse_u32(&pos, end, &count) != S3_OK) {
            return;
        }

        /* every entry costs at least two 4-byte lengths and the
         * 4-byte attribute flags, so a count above that is
         * malformed and the parse below would refuse anyway; the
         * bound keeps a hostile count from spinning the loop */

        if (count > (uint32_t)(body->len / 12)) {
            return;
        }

        rc = S3_OK;

        for (i = 0; i < count && rc == S3_OK; i++) {
            rc = s3_ssh3_sftp_parse_string(&pos, end, &a);

            if (rc == S3_OK) {
                rc = s3_ssh3_sftp_parse_string(&pos, end, &b);
            }

            if (rc == S3_OK) {
                rc = s3_ssh3_sftp_parse_attrs(&pos, end, &attrs);
            }

            if (rc == S3_OK) {
                s3_fuzz_sink(a.len + b.len);
            }
        }

        return;

    case S3_SSH3_SFTP_EXTENDED:

        /* the request carries the name string, the rest is the data
         * view; the reply mirrors the shape */

        pos = body->data;
        end = body->data + body->len;

        if (s3_ssh3_sftp_parse_string(&pos, end, &a) == S3_OK) {
            s3_fuzz_sink(a.len + (size_t)(end - pos));
        }

        return;

    case S3_SSH3_SFTP_STATUS:

        /* the code, the message string, the language string */

        pos = body->data;
        end = body->data + body->len;

        if (s3_ssh3_sftp_parse_u32(&pos, end, &code) != S3_OK) {
            return;
        }

        s3_fuzz_sink(code);

        if (s3_ssh3_sftp_parse_string(&pos, end, &a) == S3_OK &&
            s3_ssh3_sftp_parse_string(&pos, end, &b) == S3_OK) {
            s3_fuzz_sink(a.len + b.len);
        }

        return;

    default:
        break;
    }

    /* the remaining types ride one string with the exact end: the
     * path bodies (LSTAT, STAT, REALPATH, OPENDIR, RMDIR, REMOVE,
     * READLINK) and the handle bodies (CLOSE, READDIR, FSTAT, the
     * HANDLE and DATA replies keep the view whole) */

    if (s3_ssh3_sftp_parse_path_body(body, &a) == S3_OK) {
        s3_fuzz_sink(a.len);

    } else if (s3_ssh3_sftp_parse_handle_body(body, &a) == S3_OK) {
        s3_fuzz_sink(a.len);
    }
}

static void
s3_fuzz_body_generic(const s3_str_t *body)
{
    const u_char        *pos, *end;
    s3_str_t             s;
    s3_ssh3_sftp_attrs_t attrs;
    uint32_t             u32;
    uint64_t             u64;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_u32(&pos, end, &u32) == S3_OK) {
        s3_fuzz_sink(u32);
    }

    pos = body->data;

    if (s3_ssh3_sftp_parse_u64(&pos, end, &u64) == S3_OK) {
        s3_fuzz_sink(u64);
    }

    pos = body->data;

    if (s3_ssh3_sftp_parse_string(&pos, end, &s) == S3_OK) {
        s3_fuzz_sink(s.len);
    }

    pos = body->data;

    if (s3_ssh3_sftp_parse_attrs(&pos, end, &attrs) == S3_OK) {
        s3_fuzz_sink(attrs.flags);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const u_char      *pos, *end;
    s3_ssh3_sftp_pkt_t pkt;
    s3_int_t           rc;

    pos = (const u_char *)data;
    end = pos + size;

    for (;;) {
        rc = s3_ssh3_sftp_codec_frame(&pos, end, &pkt);

        if (rc != S3_OK) {
            break;
        }

        s3_fuzz_sink(pkt.body.len);
        s3_fuzz_sink(pkt.request_id);
        s3_fuzz_sink(pkt.type);

        s3_fuzz_body_by_type(&pkt);
        s3_fuzz_body_generic(&pkt.body);
    }

    /* the bytes the frame layer consumed */

    s3_fuzz_sink((size_t)(pos - (const u_char *)data));

    return 0;
}
