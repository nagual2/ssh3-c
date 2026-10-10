/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SFTP_CODEC_H_INCLUDED_
#define _S3_SSH3_SFTP_CODEC_H_INCLUDED_

#include <s3_base.h>

#include <s3_ssh3_sftp.h>

/*
 * the SFTP v3 wire codec: the frame layer (the 4-byte big-endian
 * length plus the type byte, the reference pkg/sftp framing.rs of
 * the channel byte stream) and the measure-mode encoders with the
 * zero-copy parsers of the bodies; the parsed strings are views into
 * the receive buffer, every parse is strict like the rest of the
 * port
 *
 * the scalar order of the wire is big-endian everywhere, the varint
 * of QUIC does not exist below this line
 */

typedef struct {
    uint8_t  type;
    uint32_t request_id; /* valid when has_id */
    unsigned has_id : 1;
    s3_str_t body; /* the view after the type (and the id) */
} s3_ssh3_sftp_pkt_t;

/*
 * extracts one frame at *pos against end: on S3_OK the type, the id
 * (when the type carries one: everything but INIT and VERSION) and
 * the body view are filled and *pos advances past the frame;
 * S3_AGAIN when the buffer ends inside a frame (the caller feeds the
 * continuation and retries), S3_ERROR on a length prefix above
 * S3_SSH3_SFTP_MAX_FRAME
 */

s3_int_t s3_ssh3_sftp_codec_frame(const u_char **pos, const u_char *end, s3_ssh3_sftp_pkt_t *pkt);

/* the strict scalar readers of a body (S3_ERROR past end) */

s3_int_t s3_ssh3_sftp_parse_u32(const u_char **pos, const u_char *end, uint32_t *v);

s3_int_t s3_ssh3_sftp_parse_u64(const u_char **pos, const u_char *end, uint64_t *v);

/*
 * the SSHString: on S3_OK the view points into the receive buffer
 * and *pos advances past it
 */

s3_int_t s3_ssh3_sftp_parse_string(const u_char **pos, const u_char *end, s3_str_t *s);

/*
 * the attribute block; the extended pairs ride in the raw view
 * (s3_ssh3_sftp.h); a truncated block is S3_ERROR
 */

s3_int_t s3_ssh3_sftp_parse_attrs(const u_char **pos, const u_char *end, s3_ssh3_sftp_attrs_t *a);

/*
 * the request bodies of the server side: each takes the pkt body
 * (after the type and the id), the out-strings are views; the
 * trailing garbage is S3_ERROR except where noted
 */

s3_int_t s3_ssh3_sftp_parse_path_body(const s3_str_t *body, s3_str_t *path);

s3_int_t s3_ssh3_sftp_parse_open_body(const s3_str_t *body, s3_str_t *path, uint32_t *pflags,
                                      s3_ssh3_sftp_attrs_t *attrs);

s3_int_t s3_ssh3_sftp_parse_read_body(const s3_str_t *body, s3_str_t *handle, uint64_t *offset,
                                      uint32_t *len);

s3_int_t s3_ssh3_sftp_parse_write_body(const s3_str_t *body, s3_str_t *handle, uint64_t *offset,
                                       s3_str_t *data);

s3_int_t s3_ssh3_sftp_parse_handle_body(const s3_str_t *body, s3_str_t *handle);

s3_int_t s3_ssh3_sftp_parse_setstat_body(const s3_str_t *body, s3_str_t *path,
                                         s3_ssh3_sftp_attrs_t *attrs);

s3_int_t s3_ssh3_sftp_parse_rename_body(const s3_str_t *body, s3_str_t *old_path,
                                        s3_str_t *new_path);

/*
 * the encoders: written at p, the past-the-end pointer returned, or
 * the encoded size when p is NULL (the measure mode); each writes
 * the full packet - the length prefix, the type byte, the id when
 * the type carries one and the body
 */

uintptr_t s3_ssh3_sftp_encode_init(u_char *p, uint32_t version);

uintptr_t s3_ssh3_sftp_encode_version(u_char *p, uint32_t version);

uintptr_t s3_ssh3_sftp_encode_status(u_char *p, uint32_t id, uint32_t code, const s3_str_t *msg);

/* the empty error message, the common shape */

uintptr_t s3_ssh3_sftp_encode_status_ok(u_char *p, uint32_t id);

uintptr_t s3_ssh3_sftp_encode_handle(u_char *p, uint32_t id, const s3_str_t *handle);

uintptr_t s3_ssh3_sftp_encode_data(u_char *p, uint32_t id, const s3_str_t *data);

/* count entries of names, the arrays of the NAME reply */

uintptr_t s3_ssh3_sftp_encode_name(u_char *p, uint32_t id, const s3_ssh3_sftp_name_t *names,
                                   uint32_t count);

uintptr_t s3_ssh3_sftp_encode_attrs(u_char *p, uint32_t id, const s3_ssh3_sftp_attrs_t *a);

/* the request encoders of the client side (the id goes first) */

uintptr_t s3_ssh3_sftp_encode_realpath(u_char *p, uint32_t id, const s3_str_t *path);

uintptr_t s3_ssh3_sftp_encode_stat(u_char *p, uint32_t id, const s3_str_t *path);

uintptr_t s3_ssh3_sftp_encode_open(u_char *p, uint32_t id, const s3_str_t *path, uint32_t pflags,
                                   const s3_ssh3_sftp_attrs_t *attrs);

uintptr_t s3_ssh3_sftp_encode_close(u_char *p, uint32_t id, const s3_str_t *handle);

uintptr_t s3_ssh3_sftp_encode_read(u_char *p, uint32_t id, const s3_str_t *handle, uint64_t offset,
                                   uint32_t len);

uintptr_t s3_ssh3_sftp_encode_write(u_char *p, uint32_t id, const s3_str_t *handle, uint64_t offset,
                                    const s3_str_t *data);

uintptr_t s3_ssh3_sftp_encode_opendir(u_char *p, uint32_t id, const s3_str_t *path);

uintptr_t s3_ssh3_sftp_encode_readdir(u_char *p, uint32_t id, const s3_str_t *handle);

uintptr_t s3_ssh3_sftp_encode_mkdir(u_char *p, uint32_t id, const s3_str_t *path,
                                    const s3_ssh3_sftp_attrs_t *attrs);

uintptr_t s3_ssh3_sftp_encode_setstat(u_char *p, uint32_t id, const s3_str_t *path,
                                      const s3_ssh3_sftp_attrs_t *attrs);

uintptr_t s3_ssh3_sftp_encode_rmdir(u_char *p, uint32_t id, const s3_str_t *path);

uintptr_t s3_ssh3_sftp_encode_remove(u_char *p, uint32_t id, const s3_str_t *path);

uintptr_t s3_ssh3_sftp_encode_rename(u_char *p, uint32_t id, const s3_str_t *old_path,
                                     const s3_str_t *new_path);

#endif /* _S3_SSH3_SFTP_CODEC_H_INCLUDED_ */
