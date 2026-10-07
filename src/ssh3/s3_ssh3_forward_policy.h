/*
 * Copyright (C) 2026 the ssh3-c authors
 */

#ifndef _S3_SSH3_FORWARD_POLICY_H_INCLUDED_
#define _S3_SSH3_FORWARD_POLICY_H_INCLUDED_

#include <s3_base.h>

/*
 * the forward target policy, the PermitOpen analog (F-05, the
 * reference cmd/forward_policy.go): server-side direct-tcp and
 * direct-udp dials used to reach any client-chosen target with the
 * process privileges, the sshd_config PermitOpen spec bounds them
 *
 * the spec is the comma/space-separated host:port entries:
 *
 *   host:port            the exact host and port
 *   *.example.org:443    the wildcard host suffix
 *   host:*               any port
 *   [2001:db8::1]:443    the bracketed ipv6 literal
 *   !host:port           the negated entry
 *
 * the host patterns fold to the lowercase at the parse, "*" matches
 * every host, the "*.suffix" form matches the subdomains but not the
 * suffix domain itself (the sshd_config PATTERNS shape); a negated
 * entry matching the target denies on its own, an unmatched target
 * stays allowed only while the policy carries no allow entry at all
 * (the negation-only shape); the empty spec keeps the historical
 * unrestricted dial
 */

#define S3_SSH3_FORWARD_POLICY_SPEC_MAX 4096
#define S3_SSH3_FORWARD_POLICY_MAX      64
#define S3_SSH3_FORWARD_POLICY_HOST_MAX 255

typedef struct {
    u_char   host[S3_SSH3_FORWARD_POLICY_HOST_MAX + 1]; /* the lowercase pattern */
    size_t   host_len;
    uint16_t port;         /* the exact port while port_any is clear */
    unsigned port_any : 1; /* the "*" port */
    unsigned negated : 1;  /* the "!" prefix */
} s3_ssh3_forward_policy_entry_t;

typedef struct {
    s3_ssh3_forward_policy_entry_t entries[S3_SSH3_FORWARD_POLICY_MAX];
    unsigned                       n; /* zero entries = unrestricted, the empty spec */
} s3_ssh3_forward_policy_t;

/*
 * resets the policy to the unrestricted zero state (the zero policy
 * short-circuits the check, like the nil policy of the reference)
 */

void s3_ssh3_forward_policy_init(s3_ssh3_forward_policy_t *p);

/*
 * parses the comma/space-separated spec; an empty or separator-only
 * spec parses into the unrestricted zero policy; a malformed entry
 * (no colon, an empty host or port, a port out of the uint16 range,
 * a host or the spec itself over the bound, too many entries)
 * returns S3_ERROR, the policy content stays unspecified then and the
 * caller must not use it
 */

s3_int_t s3_ssh3_forward_policy_parse(s3_ssh3_forward_policy_t *p, const char *spec);

/*
 * reports whether the dial to host:port may proceed: S3_OK allows,
 * S3_DECLINED denies; the nil or zero policy stays unrestricted; the
 * host is the canonical lowercase text of the target (the inet_ntop
 * output of the raw wire ip, the dial as the client spelled it)
 */

s3_int_t s3_ssh3_forward_policy_check(const s3_ssh3_forward_policy_t *p, const char *host,
                                      uint16_t port);

#endif /* _S3_SSH3_FORWARD_POLICY_H_INCLUDED_ */
