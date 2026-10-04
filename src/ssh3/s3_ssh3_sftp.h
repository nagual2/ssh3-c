/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_SFTP_H_INCLUDED_
#define _S3_SSH3_SFTP_H_INCLUDED_

#include <s3_base.h>

/*
 * the SFTP v3 constants shared by the codec, the server and the
 * client driver (draft-ietf-secsh-filexfer-02, the dialect of
 * OpenSSH and pkg/sftp); the numbers live in one place, the modules
 * never hardcode them
 */

#define S3_SSH3_SFTP_PROTOCOL_VERSION 3
#define S3_SSH3_CHANNEL_TYPE_SFTP     "sftp"

/*
 * the hard cap of one frame: the 4-byte length prefix above it is a
 * protocol error (the channel maxPacketSize caps the carrier chunks
 * far below, the cap only bounds a hostile peer)
 */

#define S3_SSH3_SFTP_MAX_FRAME (256 * 1024)

/* the packet types */

#define S3_SSH3_SFTP_INIT           1
#define S3_SSH3_SFTP_VERSION        2
#define S3_SSH3_SFTP_OPEN           3
#define S3_SSH3_SFTP_CLOSE          8
#define S3_SSH3_SFTP_READ           5
#define S3_SSH3_SFTP_WRITE          6
#define S3_SSH3_SFTP_LSTAT          7
#define S3_SSH3_SFTP_FSTAT          8
#define S3_SSH3_SFTP_SETSTAT        9
#define S3_SSH3_SFTP_FSETSTAT       10
#define S3_SSH3_SFTP_OPENDIR        11
#define S3_SSH3_SFTP_READDIR        12
#define S3_SSH3_SFTP_REMOVE         13
#define S3_SSH3_SFTP_MKDIR          14
#define S3_SSH3_SFTP_RMDIR          15
#define S3_SSH3_SFTP_REALPATH       16
#define S3_SSH3_SFTP_STAT           17
#define S3_SSH3_SFTP_RENAME         18
#define S3_SSH3_SFTP_READLINK       19
#define S3_SSH3_SFTP_STATUS         101
#define S3_SSH3_SFTP_HANDLE         102
#define S3_SSH3_SFTP_DATA           103
#define S3_SSH3_SFTP_NAME           104
#define S3_SSH3_SFTP_ATTRS          105
#define S3_SSH3_SFTP_EXTENDED       200
#define S3_SSH3_SFTP_EXTENDED_REPLY 201

/* the status codes of the STATUS reply */

#define S3_SSH3_SFTP_FX_OK               0
#define S3_SSH3_SFTP_FX_EOF              1
#define S3_SSH3_SFTP_FX_NO_SUCH_FILE     2
#define S3_SSH3_SFTP_FX_PERMISSION_DENIED 3
#define S3_SSH3_SFTP_FX_FAILURE          4
#define S3_SSH3_SFTP_FX_BAD_MESSAGE      5
#define S3_SSH3_SFTP_FX_OP_UNSUPPORTED   8

/* the pflags of OPEN */

#define S3_SSH3_SFTP_FXF_READ   0x00000001
#define S3_SSH3_SFTP_FXF_WRITE  0x00000002
#define S3_SSH3_SFTP_FXF_APPEND 0x00000004
#define S3_SSH3_SFTP_FXF_CREAT  0x00000008
#define S3_SSH3_SFTP_FXF_TRUNC  0x00000010
#define S3_SSH3_SFTP_FXF_EXCL   0x00000020

/* the attribute flags (the present-fields mask of ATTRS) */

#define S3_SSH3_SFTP_ATTR_SIZE       0x00000001
#define S3_SSH3_SFTP_ATTR_UIDGID     0x00000002
#define S3_SSH3_SFTP_ATTR_PERMISSION 0x00000004
#define S3_SSH3_SFTP_ATTR_ACMODTIME  0x00000008
#define S3_SSH3_SFTP_ATTR_EXTENDED   0x80000000

/*
 * the attribute block; the extended pairs, when the flag is set, are
 * kept as the raw view of the remaining bytes (the v3 dialect of
 * pkg/sftp sends none, the server and the client skip them verbatim)
 */

typedef struct {
    uint32_t flags;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint32_t perms;
    uint32_t atime;
    uint32_t mtime;
    s3_str_t extended; /* the raw view, empty unless EXTENDED */
} s3_ssh3_sftp_attrs_t;

/* one entry of the NAME reply */

typedef struct {
    s3_str_t             filename;
    s3_str_t             longname;
    s3_ssh3_sftp_attrs_t attrs;
} s3_ssh3_sftp_name_t;

#endif /* _S3_SSH3_SFTP_H_INCLUDED_ */
