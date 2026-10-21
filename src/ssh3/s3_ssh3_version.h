/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_VERSION_H_INCLUDED_
#define _S3_SSH3_VERSION_H_INCLUDED_

#include <s3_base.h>

/*
 * the ssh3 version negotiation, the port of the reference version.go
 * (project/ssh3): the CONNECT announces the endpoint version in the
 * User-Agent field, the server answers 403 unless the string parses
 * and is supported
 *
 * the format (whitespace-separated):
 *
 *     <protocol-name> <protocol-major>.<protocol-minor>
 *     <implementation-name> <software-major>.<software-minor>.<software-patch>
 *     [experimental_spec_version=<spec>] [other key=value extras are skipped]
 *
 * the spec version may also ride inside the protocol field as
 * "major.minor_<spec>", like in the reference ParseProtocolVersion()
 */

#define S3_SSH3_PROTOCOL_NAME "SSH"

#define S3_SSH3_PROTOCOL_MAJOR 3
#define S3_SSH3_PROTOCOL_MINOR 0

/* this implementation announces the reference experimental spec version */
#define S3_SSH3_SPEC_VERSION "alpha-00"

#define S3_SSH3_IMPLEMENTATION_NAME "ssh3-c"
#define S3_SSH3_SOFTWARE_MAJOR      0
#define S3_SSH3_SOFTWARE_MINOR      5
#define S3_SSH3_SOFTWARE_PATCH      2

#define S3_SSH3_VERSION_STRING                                                                     \
    S3_SSH3_PROTOCOL_NAME " 3.0 " S3_SSH3_IMPLEMENTATION_NAME                                      \
                          " 0.5.2 experimental_spec_version=" S3_SSH3_SPEC_VERSION

/*
 * the parsed view of a version string; the strings are zero-copy
 * slices of the input buffer, valid while it lives
 */
typedef struct {
    s3_str_t implementation;
    s3_str_t spec_version; /* empty when the request carries none */

    unsigned protocol_major;
    unsigned protocol_minor;

    unsigned software_major;
    unsigned software_minor;
    unsigned software_patch;

    /*
     * the compression capability of the peer (PLAN.md 9, B8): the mask
     * of the algorithms the peer announced in the "compress=" field of
     * the version string, zero when the peer announced nothing (every
     * peer before the extension)
     */

    uint32_t compress_mask;
} s3_ssh3_version_t;

/*
 * parses the version string; S3_OK, or S3_ERROR on a malformed one
 * (fewer than the four mandatory fields, a non-numeric component, a
 * wrong component count)
 */
s3_int_t s3_ssh3_version_parse(const u_char *data, size_t len, s3_ssh3_version_t *v);

/*
 * the reference IsVersionSupported(): the protocol version must be
 * ours (3.0); a request without a spec version passes only for the
 * legacy reference implementations 0.1.3..0.1.5; anything else needs
 * the experimental spec version we speak (alpha-00)
 */
s3_int_t s3_ssh3_version_supported(const s3_ssh3_version_t *v);

/*
 * writes the version string of this build into buf and returns the
 * length: the base string plus the "compress=<list>" capability field
 * when the build has a codec (the runtime form, the capability depends
 * on the compiled-in codecs)
 */

size_t s3_ssh3_version_string(u_char *buf, size_t cap);

#endif /* _S3_SSH3_VERSION_H_INCLUDED_ */
