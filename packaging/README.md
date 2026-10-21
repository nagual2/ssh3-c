# packaging - distribution packages for ssh3
> Languages: EN (this file) · [RU](README.ru.md) · [DE](README.de.md)

Assembles the distribution packages for the `ssh3-server` daemon and the
`ssh3` client from the `build/linux-release/` binaries (built on demand
via the `linux-release` preset when missing).

## Layout

| Path | Contents |
|------|----------|
| `build.sh` | the orchestrator: `bash packaging/build.sh [deb\|rpm\|apk\|all]` |
| `deb/` | debian control, postinst, copyright payloads |
| `rpm/` | rpm spec template: the `ssh3-server` and the `ssh3-client` packages (`@VERSION@` substituted from the binary) |
| `apk/` | apk-tools v2 `.PKGINFO` templates: `PKGINFO.in` (the server) and `PKGINFO-client.in` (the client) |
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
The client half is cross-checked too: `ssh3 -V` announces its own version
(`ssh3 version SSH 3.0 ssh3-c X.Y.Z ...`) and `build.sh` refuses to pack a
client whose version differs from the daemon's - the two halves ship as one
release.

## The packages

The split follows the openssh canon and the debian source package
(`debian/control`): the daemon and the CLI are two packages of the same
version, the client of a serverless host needs no daemon and the daemon
needs no client.

| Format | Packages | Payload of the client half |
|--------|----------|---------------------------|
| deb | `ssh3-server`, `ssh3-client`, `ssh3c-libssl3` | `/usr/bin/ssh3`, `ssh3(1)` |
| rpm | `ssh3-server`, `ssh3-client` (one spec, two packages) | `/usr/bin/ssh3`, `/usr/share/man/man1/ssh3.1.gz` |
| apk | `ssh3-server`, `ssh3-client` (two `.PKGINFO` templates) | `/usr/bin/ssh3`, `/usr/share/man/man1/ssh3.1.gz` |

The rpm spec builds both packages in one `rpmbuild` run: the daemon is the
main package (`%{_sbindir}/ssh3-server`), the client is the subpackage
`%package -n ssh3-client` (`%{_bindir}/ssh3` plus the man page). The
drop-in dance against the go fork follows the deb side: the client
conflicts with (and obsoletes) `ssh3-go-client`, the daemon with both
`ssh3-go-client` and `ssh3-go-server`.

The client man page is the same file the debian source package installs:
`debian/ssh3.1` (mdoc). The apk side has no separate template for it -
the page is gzipped into the package payload.

The architecture of the rpm and the apk follows the `ARCH` switch of
`build.sh` (`amd64` -> x86_64, `arm64` -> aarch64); the arm64 binaries
themselves are the B7 item of the plan.

## The apk package (APKv2)

The apk package is two concatenated gzip streams: the control segment
(`.PKGINFO`) and the data segment (the payload). Two details are not
obvious and were verified against the real apk-tools (2.14, an alpine 3.22
container):

1. the tar of both segments is the POSIX ustar (`tar --format=ustar`):
   apk-tools has its own tar parser and rejects the GNU format (the
   `ustar  ` magic) with "BAD archive";
2. the control segment must NOT carry the tar end-of-archive marker (the
   two empty headers): apk-tools v2 mis-parses a control segment with the
   marker and rejects the whole package with "BAD archive" - the alpine
   packages have the marker cut off the same way, their segment ends right
   after the `.PKGINFO` entry. `build.sh` cuts it off with `truncate`.

The data segment keeps the marker (apk tolerates it there). The control
template also carries the `@APKARCH@` placeholder - substituted from the
same `ARCH` switch as the rpm.

## Target matrix (OpenSSL >= 3.5 with the QUIC TLS API)

| Target | OpenSSL 3.5 in the base repo | Bundled? | Notes |
|--------|------------------------------|----------|-------|
| Debian 13 (trixie) | yes (3.5.x) | deb ships it | primary deb target; the bundle loads even here (RUNPATH wins) |
| Mint 22.x / Ubuntu 24.04 | no (3.0.13) | deb ships it | the bundle is the point - the deb installs as-is |
| Alpine 3.22 | yes | no | apk needs a musl build; bundle port is backlog |
| Fedora | <= 42: no (3.0/3.2), 43+: yes | no | rpm keeps the system-openssl scheme; bundle port is backlog |

## The bundled OpenSSL (deb)

The daemon speaks the OpenSSL 3.5 QUIC TLS API, but mint 22.x and
ubuntu 24.04 (the deb install targets) still ship 3.0.x. The package
therefore embeds the shared-library pair:

- the source is the official Debian 13 (trixie) `libssl3t64` package
  (3.5.7 at the time of writing, the URL is pinned in `build.sh`),
  fetched with curl/wget and unpacked with `dpkg-deb -x`, cached under
  `packaging/_build/cache/`;
- the two libraries (`libssl.so.3`, `libcrypto.so.3`, mode 0644, root)
  are staged into the private `/usr/lib/ssh3-c/lib/` - unmodified; the
  system `libssl` is neither required nor touched;
- the staged binary carries `RUNPATH=/usr/lib/ssh3-c/lib` (patchelf,
  mandatory): RUNPATH resolves before the default paths, so the bundle
  wins for this binary only. Nothing leaks into the global linker
  paths and no other binary can pick the private pair.

Resolution order of the bundle source (the fetch-bundle step):

1. `LIBSSL_SRC` - a path to a `.deb` file, a deb URL, or a directory
   with a local OpenSSL build (the dir itself, `lib/`, `lib64/` are
   searched for `libssl.so.3`/`libcrypto.so.3`);
2. `LOCAL_OPENSSL_DIR` - the same directory override, spelled the old
   way (kept as the no-network fallback);
3. the cache (`packaging/_build/cache/`), then the pinned
   deb.debian.org URL.

A failed fetch is fatal, with instructions in the message. Without
network pass `LIBSSL_SRC=<local deb, url or build dir>` (or
`LOCAL_OPENSSL_DIR=<build dir>`). When the override is a local build,
the libraries are not Debian-built - their version and build options
are then the caller's responsibility (the daemon needs the 3.5 QUIC
TLS API).

Why a bundle and not static linking or a system dependency:

- static linking was rejected by the design owner (a bigger diff/rebuild
  surface per release; the NSS module story stays untouched in both
  schemes, the bundle is simply simpler);
- a system dependency (`libssl3t64 (>= 3.5)`) cannot express "trixie
  has it, noble does not" in a single `Depends` line without hosting an
  apt repo - the bundle does it with zero repositories.

Note: when the system already has OpenSSL 3.5 (Debian 13), the bundle
still loads (RUNPATH beats the default paths). That is deliberate - the
shipped pair is a tested, known-good 3.5.x.

The deb `Depends` mirrors the NEEDED list of the bundle pair:
`libc6, zlib1g, libzstd1, adduser` (libcrypto needs zlib and zstd;
libcrypt comes with libc6). The system `libssl3t64`/`libssl3` is no
longer referenced.

Backlog: porting the same scheme (private dir + RUNPATH) to the rpm and
apk payloads is tracked separately; both still strip the build RUNPATH
and expect the system OpenSSL 3.5.

## Debian source package (RFS, `debian/`)

`packaging/debian/` holds the Debian packaging for the Debian 13
(trixie) source package: format `3.0 (quilt)`, `ssh3-c (0.3.0-1)`
unstable, binary package `ssh3-server` (amd64).  It targets the Debian
archive (mentors.debian.net upload) and **builds from source** against
the **system** `libssl3t64 (>= 3.5)` - trixie ships 3.5.x with the QUIC
TLS API, so no bundle is needed here.

### Coexistence with the build.sh deb

The two deb variants stay side by side, each with its own niche:

| № | Difference | build.sh deb (`packaging/deb/`) | debian/ source package |
|---|------------|--------------------------------|------------------------|
| 1 | OpenSSL | bundles the Debian 13 libssl3t64 pair in the private `/usr/lib/ssh3-c/lib` (RUNPATH-pinned) | system `libssl3t64 (>= 3.5)` (`Depends`) |
| 2 | Payload | prebuilt binary staged by `build.sh` | compiled from the orig tree (cmake+ninja, `hardening=+all`) |
| 3 | Binary path | `/usr/sbin/ssh3-server` | `/usr/bin/ssh3-server` |
| 4 | Env config | none (env/CLI only) | conffile `/etc/ssh3/ssh3-server.env` (template `debian/ssh3-server.env`, read via `EnvironmentFile` in the service unit) |
| 5 | Unit enable | hand-rolled postinst block | `dh_installsystemd`: the socket carries `[Install]` and gets enabled, the service stays static (socket-activated, no direct `systemctl` calls) |
| 6 | Target | arbitrary hosts incl. OpenSSL 3.0.x (mint 22.x, ubuntu 24.04) | Debian 13 archive (RFS upload) |

`build.sh` and `packaging/deb/` are untouched by the debian/ variant;
the `packaging/systemd/` units stay the canonical source - the
`packaging/debian/ssh3-server.{socket,service}` copies differ only in
the binary path (`/usr/bin`), the `EnvironmentFile` line and nothing
else (the service has no `[Install]` section, so it remains static and
`dh_installsystemd` enables the socket only).

### Build (docker debian:trixie)

The local WSL is ubuntu 24.04 (OpenSSL 3.0), so the build runs in a
`debian:trixie` container with the WSL clone mounted:

```
git archive --format=tar --prefix=ssh3-c-0.3.0/ pkg/debian-rfs | tar -x -C /tmp/deb
rm -rf /tmp/deb/ssh3-c-0.3.0/packaging/debian   # the orig carries no debian/ sub-tree
tar -C /tmp/deb -czf ssh3-c_0.3.0.orig.tar.gz ssh3-c-0.3.0
cp -r packaging/debian /tmp/deb/ssh3-c-0.3.0/debian
cd /tmp/deb/ssh3-c-0.3.0
dpkg-buildpackage -us -uc -S                    # source (.dsc + orig + debian.tar)
dpkg-buildpackage -us -uc -b                    # binary (.deb + .changes)
```

Artifacts land in `packaging/_debian/` (gitignored, like `_build/`).
Notes: the rules build the single `ssh3-server` ninja target (the
client, the bench and the interop runners of the default ALL stay out);
the upstream unit test suite is not wired into this packaging build
(it is exercised by the linux-release CI preset); `dh_auto_install` is
a no-op (no `install()` rules in the upstream CMakeLists) - the
`ssh3-server.install` lines pick the daemon, the man page and the env
template straight from the source/build tree.

## Known limitations

1. The build-tree binary links the developer OpenSSL 3.5
   (`~/opt/openssl-3.5`) and carries its RUNPATH. The deb replaces that
   RUNPATH with the private bundle path (patchelf, mandatory) and ships
   the bundle pair - see "The bundled OpenSSL (deb)"; the rpm and the
   apk still strip the RUNPATH and require the system OpenSSL 3.5.
2. The apk package is assembled by hand (two concatenated tar.gz streams,
   apk-tools v2); a real alpine package must be built against musl inside
   an alpine environment - the shipped binary is glibc-linked. The format
   itself is verified: `apk verify` accepts both packages and `apk add
   --allow-untrusted` installs them (the files land in place); the
   `so:libssl.so.3` dependency is not resolvable in a plain alpine
   container (alpine 3.22 splits the library into `libssl3`/`libcrypto3`),
   so apk counts one unresolved dependency per package - the same for the
   old server package.
3. Neither the apk nor the rpm is signed (no signing key in the tree);
   unsigned apk packages install with `apk add --allow-untrusted`.
4. The openwrt ipk is a feed makefile stub: it needs the openwrt SDK with
   an OpenSSL >= 3.5 (openwrt main; the 24.10/23.05 branches carry 3.0.x).
5. The systemd unit wiring (deb postinst integration block) lands at the
   integration step, sourced from `packaging/systemd/`.
