# packaging - distribution packages for ssh3-server

Assembles the distribution packages for the `ssh3-server` daemon from the
`build/linux-release/ssh3-server` binary (built on demand via the
`linux-release` preset when missing).

## Layout

| Path | Contents |
|------|----------|
| `build.sh` | the orchestrator: `bash packaging/build.sh [deb\|rpm\|apk\|all]` |
| `deb/` | debian control, postinst, copyright payloads |
| `rpm/` | rpm spec template (`@VERSION@` substituted from the binary) |
| `apk/` | apk-tools v2 `.PKGINFO` template |
| `openwrt/` | openwrt feed makefile (built inside the openwrt SDK, not here) |
| `_build/` | final packages (gitignored, never committed) |

## Usage

```
bash packaging/build.sh          # deb + rpm + apk
bash packaging/build.sh deb      # one format at a time
```

Staging happens under `/tmp` and is cleaned up automatically: dpkg-deb and
rpm enforce real POSIX file modes, which a windows drvfs checkout (`/mnt/c`,
everything 0777) cannot provide. Only the final packages land in
`packaging/_build/`.

The package version is parsed from the daemon itself (`ssh3-server -V`);
`deb/control` carries the version literally and `build.sh` cross-checks it
against the binary. The rpm/apk templates are substituted at build time.

## Target matrix (OpenSSL >= 3.5 with the QUIC TLS API)

| Target | OpenSSL 3.5 in the base repo | Library package | Notes |
|--------|------------------------------|-----------------|-------|
| Debian 13 (trixie) | yes (3.5.x) | `libssl3t64` | primary deb target |
| Alpine 3.22 | yes | `libssl3` (apk `so:libssl.so.3`) | apk needs a musl build |
| Fedora | <= 42: no (3.0/3.2), 43+: yes | `openssl-libs` | rpm requires >= 3.5 |
| Ubuntu 24.04 | no (3.0.13) | `libssl3t64` | needs a custom OpenSSL 3.5 |

The deb dependency is `libssl3t64 (>= 3.5) | libssl3 (>= 3.5)`: trixie
renamed the library package during the 64-bit time_t transition and kept
the `t64` name on all architectures, and a versioned dependency cannot be
satisfied by a versioned `Provides`, so the plain `libssl3` name would
never resolve on the primary target.

## Known limitations

1. The build-tree binary links the developer OpenSSL 3.5 (`~/opt/openssl-3.5`)
   and carries its RUNPATH; `build.sh` strips the RUNPATH from the packaged
   copy (patchelf, falling back to chrpath; without either a warning is
   printed), so the shipped binary resolves the system `libssl.so.3`/
   `libcrypto.so.3` - which must be 3.5+ on the target.
2. The apk package is assembled by hand (two concatenated tar.gz streams,
   apk-tools v2); a real alpine package must be built against musl inside
   an alpine environment - the shipped binary is glibc-linked.
3. Neither the apk nor the rpm is signed (no signing key in the tree);
   unsigned apk packages install with `apk add --allow-untrusted`.
4. The openwrt ipk is a feed makefile stub: it needs the openwrt SDK with
   an OpenSSL >= 3.5 (openwrt main; the 24.10/23.05 branches carry 3.0.x).
5. The systemd unit wiring (deb postinst integration block) lands at the
   integration step, sourced from `packaging/systemd/`.
