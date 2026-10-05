/*
 * Copyright (C) 2026 the ssh3-c authors
 *
 * the sftp v3 wire codec (draft-ietf-secsh-filexfer-02): the frame
 * layer, the zero-copy strict parsers and the measure-mode encoders;
 * nothing is allocated here, the parsed strings stay views into the
 * receive buffer and the encoders write into the buffer of the caller
 */

#include <s3_core.h>

#include <s3_ssh3_sftp_codec.h>

static uintptr_t s3_ssh3_sftp_attrs_size(const s3_ssh3_sftp_attrs_t *a);
static u_char   *s3_ssh3_sftp_put_attrs(u_char *p, const s3_ssh3_sftp_attrs_t *a);
static u_char   *s3_ssh3_sftp_put_head(u_char *p, uint8_t type, uint32_t id, uintptr_t body_len);
static u_char   *s3_ssh3_sftp_put_string(u_char *p, const s3_str_t *s);
static uintptr_t s3_ssh3_sftp_string_size(const s3_str_t *s);
static uintptr_t s3_ssh3_sftp_encode_id_string(u_char *p, uint8_t type, uint32_t id,
                                               const s3_str_t *s);

/* the big-endian scalars: the wire order of sftp is big-endian everywhere */

static s3_inline uint32_t
s3_ssh3_sftp_get_u32(const u_char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static s3_inline uint64_t
s3_ssh3_sftp_get_u64(const u_char *p)
{
    return ((uint64_t)s3_ssh3_sftp_get_u32(p) << 32) | (uint64_t)s3_ssh3_sftp_get_u32(p + 4);
}

static s3_inline u_char *
s3_ssh3_sftp_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char)(v >> 24);
    p[1] = (u_char)(v >> 16);
    p[2] = (u_char)(v >> 8);
    p[3] = (u_char)v;

    return p + 4;
}

static s3_inline u_char *
s3_ssh3_sftp_put_u64(u_char *p, uint64_t v)
{
    p = s3_ssh3_sftp_put_u32(p, (uint32_t)(v >> 32));

    return s3_ssh3_sftp_put_u32(p, (uint32_t)v);
}

static uintptr_t
s3_ssh3_sftp_string_size(const s3_str_t *s)
{
    return 4 + s->len;
}

static u_char *
s3_ssh3_sftp_put_string(u_char *p, const s3_str_t *s)
{
    p = s3_ssh3_sftp_put_u32(p, (uint32_t)s->len);

    if (s->len != 0) {
        p = s3_cpymem(p, s->data, s->len);
    }

    return p;
}

static u_char *
s3_ssh3_sftp_put_head(u_char *p, uint8_t type, uint32_t id, uintptr_t body_len)
{
    /* the length prefix covers the type byte, the id and the body */

    p = s3_ssh3_sftp_put_u32(p, (uint32_t)(5 + body_len));
    *p++ = type;

    return s3_ssh3_sftp_put_u32(p, id);
}

static uintptr_t
s3_ssh3_sftp_attrs_size(const s3_ssh3_sftp_attrs_t *a)
{
    uintptr_t size;

    size = 4;

    if (a->flags & S3_SSH3_SFTP_ATTR_SIZE) {
        size += 8;
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_UIDGID) {
        size += 8;
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_PERMISSION) {
        size += 4;
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_ACMODTIME) {
        size += 8;
    }

    /* the raw view already carries the count field of the pairs */

    if (a->flags & S3_SSH3_SFTP_ATTR_EXTENDED) {
        size += a->extended.len;
    }

    return size;
}

static u_char *
s3_ssh3_sftp_put_attrs(u_char *p, const s3_ssh3_sftp_attrs_t *a)
{
    p = s3_ssh3_sftp_put_u32(p, a->flags);

    if (a->flags & S3_SSH3_SFTP_ATTR_SIZE) {
        p = s3_ssh3_sftp_put_u64(p, a->size);
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_UIDGID) {
        p = s3_ssh3_sftp_put_u32(p, a->uid);
        p = s3_ssh3_sftp_put_u32(p, a->gid);
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_PERMISSION) {
        p = s3_ssh3_sftp_put_u32(p, a->perms);
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_ACMODTIME) {
        p = s3_ssh3_sftp_put_u32(p, a->atime);
        p = s3_ssh3_sftp_put_u32(p, a->mtime);
    }

    if ((a->flags & S3_SSH3_SFTP_ATTR_EXTENDED) && a->extended.len != 0) {
        p = s3_cpymem(p, a->extended.data, a->extended.len);
    }

    return p;
}

static uintptr_t
s3_ssh3_sftp_encode_id_string(u_char *p, uint8_t type, uint32_t id, const s3_str_t *s)
{
    uintptr_t size;

    size = 4 + 1 + 4 + s3_ssh3_sftp_string_size(s);

    if (p == NULL) {
        return size;
    }

    p = s3_ssh3_sftp_put_head(p, type, id, size - 9);

    return (uintptr_t)s3_ssh3_sftp_put_string(p, s);
}

s3_int_t
s3_ssh3_sftp_codec_frame(const u_char **pos, const u_char *end, s3_ssh3_sftp_pkt_t *pkt)
{
    const u_char *p;
    size_t        avail, body_len;
    uint32_t      length;
    uint8_t       type;

    p = *pos;
    avail = end - p;

    if (avail < 4) {
        return S3_AGAIN;
    }

    length = s3_ssh3_sftp_get_u32(p);

    /* the zero length has no type byte, the cap bounds a hostile peer */

    if (length < 1 || length > S3_SSH3_SFTP_MAX_FRAME) {
        return S3_ERROR;
    }

    if (avail < 4 + (size_t)length) {
        return S3_AGAIN;
    }

    type = p[4];

    pkt->type = type;

    /* every type but INIT and VERSION carries the request id */

    if (type != S3_SSH3_SFTP_INIT && type != S3_SSH3_SFTP_VERSION) {
        if (length < 5) {
            return S3_ERROR;
        }

        pkt->has_id = 1;
        pkt->request_id = s3_ssh3_sftp_get_u32(p + 5);

        body_len = length - 5;
        pkt->body.data = (u_char *)p + 9;

    } else {
        pkt->has_id = 0;
        pkt->request_id = 0;

        body_len = length - 1;
        pkt->body.data = (u_char *)p + 5;
    }

    pkt->body.len = body_len;

    *pos = p + 4 + length;

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_u32(const u_char **pos, const u_char *end, uint32_t *v)
{
    if (end - *pos < 4) {
        return S3_ERROR;
    }

    *v = s3_ssh3_sftp_get_u32(*pos);
    *pos += 4;

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_u64(const u_char **pos, const u_char *end, uint64_t *v)
{
    if (end - *pos < 8) {
        return S3_ERROR;
    }

    *v = s3_ssh3_sftp_get_u64(*pos);
    *pos += 8;

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_string(const u_char **pos, const u_char *end, s3_str_t *s)
{
    uint32_t len;

    if (end - *pos < 4) {
        return S3_ERROR;
    }

    len = s3_ssh3_sftp_get_u32(*pos);

    if ((size_t)(end - *pos - 4) < len) {
        return S3_ERROR;
    }

    s->len = len;
    s->data = (u_char *)*pos + 4;
    *pos += 4 + len;

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_attrs(const u_char **pos, const u_char *end, s3_ssh3_sftp_attrs_t *a)
{
    const u_char *p, *ext;
    s3_str_t      skip;
    uint32_t      count, i;

    p = *pos;

    s3_memzero(a, sizeof(*a));

    if (s3_ssh3_sftp_parse_u32(&p, end, &a->flags) != S3_OK) {
        return S3_ERROR;
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_SIZE) {
        if (s3_ssh3_sftp_parse_u64(&p, end, &a->size) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_UIDGID) {
        if (s3_ssh3_sftp_parse_u32(&p, end, &a->uid) != S3_OK) {
            return S3_ERROR;
        }

        if (s3_ssh3_sftp_parse_u32(&p, end, &a->gid) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_PERMISSION) {
        if (s3_ssh3_sftp_parse_u32(&p, end, &a->perms) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_ACMODTIME) {
        if (s3_ssh3_sftp_parse_u32(&p, end, &a->atime) != S3_OK) {
            return S3_ERROR;
        }

        if (s3_ssh3_sftp_parse_u32(&p, end, &a->mtime) != S3_OK) {
            return S3_ERROR;
        }
    }

    if (a->flags & S3_SSH3_SFTP_ATTR_EXTENDED) {
        /* the raw view starts at the count field, the pairs ride in it
         * verbatim; they are parsed only to find the end of the block */

        ext = p;

        if (s3_ssh3_sftp_parse_u32(&p, end, &count) != S3_OK) {
            return S3_ERROR;
        }

        for (i = 0; i < count; i++) {
            if (s3_ssh3_sftp_parse_string(&p, end, &skip) != S3_OK ||
                s3_ssh3_sftp_parse_string(&p, end, &skip) != S3_OK) {
                return S3_ERROR;
            }
        }

        a->extended.data = (u_char *)ext;
        a->extended.len = p - ext;
    }

    *pos = p;

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_path_body(const s3_str_t *body, s3_str_t *path)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, path) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_open_body(const s3_str_t *body, s3_str_t *path, uint32_t *pflags,
                             s3_ssh3_sftp_attrs_t *attrs)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, path) != S3_OK ||
        s3_ssh3_sftp_parse_u32(&pos, end, pflags) != S3_OK ||
        s3_ssh3_sftp_parse_attrs(&pos, end, attrs) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_read_body(const s3_str_t *body, s3_str_t *handle, uint64_t *offset,
                             uint32_t *len)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, handle) != S3_OK ||
        s3_ssh3_sftp_parse_u64(&pos, end, offset) != S3_OK ||
        s3_ssh3_sftp_parse_u32(&pos, end, len) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_write_body(const s3_str_t *body, s3_str_t *handle, uint64_t *offset,
                              s3_str_t *data)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, handle) != S3_OK ||
        s3_ssh3_sftp_parse_u64(&pos, end, offset) != S3_OK ||
        s3_ssh3_sftp_parse_string(&pos, end, data) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_handle_body(const s3_str_t *body, s3_str_t *handle)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, handle) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_setstat_body(const s3_str_t *body, s3_str_t *path, s3_ssh3_sftp_attrs_t *attrs)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, path) != S3_OK ||
        s3_ssh3_sftp_parse_attrs(&pos, end, attrs) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

s3_int_t
s3_ssh3_sftp_parse_rename_body(const s3_str_t *body, s3_str_t *old_path, s3_str_t *new_path)
{
    const u_char *pos, *end;

    pos = body->data;
    end = body->data + body->len;

    if (s3_ssh3_sftp_parse_string(&pos, end, old_path) != S3_OK ||
        s3_ssh3_sftp_parse_string(&pos, end, new_path) != S3_OK) {
        return S3_ERROR;
    }

    if (pos != end) {
        return S3_ERROR;
    }

    return S3_OK;
}

uintptr_t
s3_ssh3_sftp_encode_init(u_char *p, uint32_t version)
{
    if (p == NULL) {
        return 4 + 1 + 4;
    }

    p = s3_ssh3_sftp_put_u32(p, 5);
    *p++ = S3_SSH3_SFTP_INIT;

    return (uintptr_t)s3_ssh3_sftp_put_u32(p, version);
}

uintptr_t
s3_ssh3_sftp_encode_version(u_char *p, uint32_t version)
{
    if (p == NULL) {
        return 4 + 1 + 4;
    }

    p = s3_ssh3_sftp_put_u32(p, 5);
    *p++ = S3_SSH3_SFTP_VERSION;

    return (uintptr_t)s3_ssh3_sftp_put_u32(p, version);
}

uintptr_t
s3_ssh3_sftp_encode_status(u_char *p, uint32_t id, uint32_t code, const s3_str_t *msg)
{
    size_t    msg_len;
    uintptr_t body;

    msg_len = (msg != NULL) ? msg->len : 0;

    /* the code, the message and the empty language tag */

    body = 4 + 4 + msg_len + 4;

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_STATUS, id, body);
    p = s3_ssh3_sftp_put_u32(p, code);

    if (msg != NULL) {
        p = s3_ssh3_sftp_put_string(p, msg);

    } else {
        p = s3_ssh3_sftp_put_u32(p, 0);
    }

    return (uintptr_t)s3_ssh3_sftp_put_u32(p, 0);
}

uintptr_t
s3_ssh3_sftp_encode_status_ok(u_char *p, uint32_t id)
{
    return s3_ssh3_sftp_encode_status(p, id, S3_SSH3_SFTP_FX_OK, NULL);
}

uintptr_t
s3_ssh3_sftp_encode_handle(u_char *p, uint32_t id, const s3_str_t *handle)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_HANDLE, id, handle);
}

uintptr_t
s3_ssh3_sftp_encode_data(u_char *p, uint32_t id, const s3_str_t *data)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_DATA, id, data);
}

uintptr_t
s3_ssh3_sftp_encode_name(u_char *p, uint32_t id, const s3_ssh3_sftp_name_t *names, uint32_t count)
{
    uintptr_t size;
    uint32_t  i;

    size = 4 + 1 + 4 + 4;

    for (i = 0; i < count; i++) {
        size += s3_ssh3_sftp_string_size(&names[i].filename) +
                s3_ssh3_sftp_string_size(&names[i].longname) +
                s3_ssh3_sftp_attrs_size(&names[i].attrs);
    }

    if (p == NULL) {
        return size;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_NAME, id, size - 9);
    p = s3_ssh3_sftp_put_u32(p, count);

    for (i = 0; i < count; i++) {
        p = s3_ssh3_sftp_put_string(p, &names[i].filename);
        p = s3_ssh3_sftp_put_string(p, &names[i].longname);
        p = s3_ssh3_sftp_put_attrs(p, &names[i].attrs);
    }

    return (uintptr_t)p;
}

uintptr_t
s3_ssh3_sftp_encode_attrs(u_char *p, uint32_t id, const s3_ssh3_sftp_attrs_t *a)
{
    uintptr_t body;

    body = s3_ssh3_sftp_attrs_size(a);

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_ATTRS, id, body);

    return (uintptr_t)s3_ssh3_sftp_put_attrs(p, a);
}

uintptr_t
s3_ssh3_sftp_encode_realpath(u_char *p, uint32_t id, const s3_str_t *path)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_REALPATH, id, path);
}

uintptr_t
s3_ssh3_sftp_encode_stat(u_char *p, uint32_t id, const s3_str_t *path)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_STAT, id, path);
}

uintptr_t
s3_ssh3_sftp_encode_open(u_char *p, uint32_t id, const s3_str_t *path, uint32_t pflags,
                         const s3_ssh3_sftp_attrs_t *attrs)
{
    uintptr_t body;

    body = s3_ssh3_sftp_string_size(path) + 4 + s3_ssh3_sftp_attrs_size(attrs);

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_OPEN, id, body);
    p = s3_ssh3_sftp_put_string(p, path);
    p = s3_ssh3_sftp_put_u32(p, pflags);

    return (uintptr_t)s3_ssh3_sftp_put_attrs(p, attrs);
}

uintptr_t
s3_ssh3_sftp_encode_close(u_char *p, uint32_t id, const s3_str_t *handle)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_CLOSE, id, handle);
}

uintptr_t
s3_ssh3_sftp_encode_read(u_char *p, uint32_t id, const s3_str_t *handle, uint64_t offset,
                         uint32_t len)
{
    uintptr_t body;

    body = s3_ssh3_sftp_string_size(handle) + 8 + 4;

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_READ, id, body);
    p = s3_ssh3_sftp_put_string(p, handle);
    p = s3_ssh3_sftp_put_u64(p, offset);

    return (uintptr_t)s3_ssh3_sftp_put_u32(p, len);
}

uintptr_t
s3_ssh3_sftp_encode_write(u_char *p, uint32_t id, const s3_str_t *handle, uint64_t offset,
                          const s3_str_t *data)
{
    uintptr_t body;

    body = s3_ssh3_sftp_string_size(handle) + 8 + s3_ssh3_sftp_string_size(data);

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_WRITE, id, body);
    p = s3_ssh3_sftp_put_string(p, handle);
    p = s3_ssh3_sftp_put_u64(p, offset);

    return (uintptr_t)s3_ssh3_sftp_put_string(p, data);
}

uintptr_t
s3_ssh3_sftp_encode_opendir(u_char *p, uint32_t id, const s3_str_t *path)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_OPENDIR, id, path);
}

uintptr_t
s3_ssh3_sftp_encode_readdir(u_char *p, uint32_t id, const s3_str_t *handle)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_READDIR, id, handle);
}

uintptr_t
s3_ssh3_sftp_encode_mkdir(u_char *p, uint32_t id, const s3_str_t *path,
                          const s3_ssh3_sftp_attrs_t *attrs)
{
    uintptr_t body;

    body = s3_ssh3_sftp_string_size(path) + s3_ssh3_sftp_attrs_size(attrs);

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_MKDIR, id, body);
    p = s3_ssh3_sftp_put_string(p, path);

    return (uintptr_t)s3_ssh3_sftp_put_attrs(p, attrs);
}

uintptr_t
s3_ssh3_sftp_encode_rmdir(u_char *p, uint32_t id, const s3_str_t *path)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_RMDIR, id, path);
}

uintptr_t
s3_ssh3_sftp_encode_remove(u_char *p, uint32_t id, const s3_str_t *path)
{
    return s3_ssh3_sftp_encode_id_string(p, S3_SSH3_SFTP_REMOVE, id, path);
}

uintptr_t
s3_ssh3_sftp_encode_rename(u_char *p, uint32_t id, const s3_str_t *old_path,
                           const s3_str_t *new_path)
{
    uintptr_t body;

    body = s3_ssh3_sftp_string_size(old_path) + s3_ssh3_sftp_string_size(new_path);

    if (p == NULL) {
        return 9 + body;
    }

    p = s3_ssh3_sftp_put_head(p, S3_SSH3_SFTP_RENAME, id, body);
    p = s3_ssh3_sftp_put_string(p, old_path);

    return (uintptr_t)s3_ssh3_sftp_put_string(p, new_path);
}
