#!/usr/bin/env bash
# build.sh - assemble the ssh3-server distribution packages (deb/rpm/apk).
#
# usage: bash packaging/build.sh [deb|rpm|apk|all]      (default: all)
#
# the payload is build/linux-release/ssh3-server; when the binary is
# missing, the script configures and builds the linux-release preset
# itself. staging happens under /tmp (dpkg-deb and rpm enforce real
# POSIX file modes, which a windows drvfs checkout cannot provide);
# the final packages are copied into packaging/_build/ (gitignored).
# the package sources stay in packaging/{deb,rpm,apk,openwrt}/.
#
# the deb embeds the OpenSSL 3.5 bundle: fetch-bundle pulls the unmodified
# libssl3t64 shared libraries of Debian 13 (3.5.x, cached under
# _build/cache/), stage-bundle puts them into the private
# /usr/lib/ssh3-c/lib/ and set-rpath pins the staged binary there
# (patchelf). this is what makes the deb installable on the OpenSSL
# 3.0.x targets (mint 22.x, ubuntu 24.04) without touching the system
# libssl. overrides: LIBSSL_SRC=<deb file|deb url|openssl build dir>,
# LOCAL_OPENSSL_DIR=<openssl build dir>.
#
# not built here:
#   - the openwrt ipk needs the openwrt SDK - see packaging/openwrt/Makefile;
#   - the rpm build needs rpmbuild (apt-get install rpm on a debian/ubuntu
#     build host).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

# the target architecture of the channel: amd64 (the default) or arm64
# (the F3/B7 wave: the arm rollout of the hosting - Graviton/Ampere).
# the deb architecture, the rpm architecture, the Debian multiarch
# triple and the build directory of the binary follow from it
ARCH=${ARCH:-amd64}
case "$ARCH" in
    amd64)
        DEB_ARCH=amd64
        RPM_ARCH=x86_64
        MULTIARCH=x86_64-linux-gnu
        BUILD_DIR=linux-release
        STRIP_CMD=strip
        ;;
    arm64)
        DEB_ARCH=arm64
        RPM_ARCH=aarch64
        MULTIARCH=aarch64-linux-gnu
        BUILD_DIR=linux-arm64
        STRIP_CMD=aarch64-linux-gnu-strip
        ;;
    *)
        echo "build.sh: unknown ARCH=$ARCH (amd64|arm64)" >&2
        exit 1
        ;;
esac

BIN_DIR="$REPO_DIR/build/$BUILD_DIR"
BIN="$BIN_DIR/ssh3-server"
OUT_DIR="$SCRIPT_DIR/_build"
mkdir -p "$OUT_DIR"
STAGE_ROOT=$(mktemp -d /tmp/ssh3-pkg.XXXXXX)
PKG_RELEASE=1
trap 'rm -rf "$STAGE_ROOT"' EXIT

log() { printf '==> %s\n' "$1"; }
die() { printf 'build.sh: %s\n' "$1"; exit 1; }

# the bundled OpenSSL (deb): the daemon speaks the OpenSSL 3.5 QUIC TLS
# API, while mint 22.x/ubuntu 24.04 ship 3.0.x. the deb ships the
# UNMODIFIED Debian 13 (trixie) libssl3t64 shared libraries in the
# private /usr/lib/ssh3-c/lib/ and pins the staged binary RUNPATH to it:
# the system libssl (any version) is left alone, nothing leaks into the
# global linker paths, and the RUNPATH resolves before the default
# paths, so the bundle wins for this binary only. the deb Depends line
# mirrors the NEEDED of the bundle pair (libc6, zlib1g, libzstd1) - the
# system libssl3t64/libssl3 is no longer required at all.
BUNDLE_LIB_DIR=/usr/lib/ssh3-c/lib
LIBSSL3T64_URL="https://deb.debian.org/debian/pool/main/o/openssl/libssl3t64_3.5.7-1~deb13u3_${DEB_ARCH}.deb"
BUNDLE_CACHE="$OUT_DIR/cache"
BUNDLE_STAGE="$STAGE_ROOT/bundle"
BUNDLE_DEB_ROOT="$BUNDLE_STAGE/root"

# curl or wget, whatever the build host has
fetch_url() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 2 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$out" "$url"
    else
        die "neither curl nor wget found - cannot fetch $url"
    fi
}

# copy the shared-library pair out of a local OpenSSL build tree
# (LIBSSL_SRC/LOCAL_OPENSSL_DIR); returns 1 when either is missing
bundle_from_dir() {
    local dir="$1" lib cand found
    mkdir -p "$BUNDLE_STAGE"
    for lib in libssl.so.3 libcrypto.so.3; do
        found=""
        for cand in "$dir" "$dir/lib" "$dir/lib64"; do
            if [ -e "$cand/$lib" ]; then
                found="$cand/$lib"
                break
            fi
        done
        [ -n "$found" ] || return 1
        cp -L "$found" "$BUNDLE_STAGE/$lib"
    done
    log "bundle source: $dir (local build)"
    return 0
}

# resolve the bundle libraries into $BUNDLE_STAGE (libssl.so.3,
# libcrypto.so.3, plus the openssl copyright when the source is the
# Debian deb): LIBSSL_SRC first, then LOCAL_OPENSSL_DIR, then the
# cached/fetched Debian 13 libssl3t64 deb
fetch_bundle() {
    local deb="" lib
    rm -rf "$BUNDLE_STAGE"
    if [ -n "${LIBSSL_SRC:-}" ]; then
        case "$LIBSSL_SRC" in
            *.deb) deb="$LIBSSL_SRC" ;;
            http://* | https://* | file://*)
                mkdir -p "$BUNDLE_CACHE"
                deb="$BUNDLE_CACHE/$(basename "$LIBSSL_SRC")"
                log "fetching the bundle source: $LIBSSL_SRC"
                fetch_url "$LIBSSL_SRC" "$deb" \
                    || die "cannot fetch LIBSSL_SRC=$LIBSSL_SRC"
                ;;
            *)
                bundle_from_dir "$LIBSSL_SRC" \
                    || die "LIBSSL_SRC=$LIBSSL_SRC: libssl.so.3/libcrypto.so.3 not found (searched the dir, lib/, lib64/)"
                return 0
                ;;
        esac
    elif [ -n "${LOCAL_OPENSSL_DIR:-}" ]; then
        bundle_from_dir "$LOCAL_OPENSSL_DIR" \
            || die "LOCAL_OPENSSL_DIR=$LOCAL_OPENSSL_DIR: libssl.so.3/libcrypto.so.3 not found (searched the dir, lib/, lib64/)"
        return 0
    else
        mkdir -p "$BUNDLE_CACHE"
        deb="$BUNDLE_CACHE/$(basename "$LIBSSL3T64_URL")"
        if [ ! -e "$deb" ]; then
            log "fetching the bundle source: $(basename "$deb")"
            fetch_url "$LIBSSL3T64_URL" "$deb" \
                || die "cannot fetch $LIBSSL3T64_URL (no network?) - provide LIBSSL_SRC=<deb|url|dir> or LOCAL_OPENSSL_DIR=<dir with a local OpenSSL 3.5 build>"
        fi
    fi

    # the Debian deb layout: the multiarch directory + the copyright
    mkdir -p "$BUNDLE_DEB_ROOT"
    dpkg-deb -x "$deb" "$BUNDLE_DEB_ROOT" \
        || die "cannot extract $deb"
    mkdir -p "$BUNDLE_STAGE"
    for lib in libssl.so.3 libcrypto.so.3; do
        [ -e "$BUNDLE_DEB_ROOT/usr/lib/$MULTIARCH/$lib" ] \
            || die "$deb: $lib not found under usr/lib/$MULTIARCH - unexpected deb layout"
        cp -L "$BUNDLE_DEB_ROOT/usr/lib/$MULTIARCH/$lib" "$BUNDLE_STAGE/$lib"
    done
    if [ -e "$BUNDLE_DEB_ROOT/usr/share/doc/libssl3t64/copyright" ]; then
        cp "$BUNDLE_DEB_ROOT/usr/share/doc/libssl3t64/copyright" \
            "$BUNDLE_STAGE/openssl-copyright"
    else
        log "WARNING: $deb has no libssl3t64 copyright - the OpenSSL license text is not staged"
    fi
    log "bundle source: $(basename "$deb") (unmodified Debian 13 libssl3t64)"
}

# on-screen proof the staged pair is really OpenSSL 3.5.x
bundle_report() {
    local ver=""
    if command -v strings >/dev/null 2>&1; then
        ver=$(strings "$BUNDLE_STAGE/libcrypto.so.3" \
            | grep "^OpenSSL 3\." | head -n 1 || true)
    fi
    log "bundle: $BUNDLE_LIB_DIR/lib{ssl,crypto}.so.3 ${ver:+($ver)}"
}

# the build-tree binary carries the developer OpenSSL RUNPATH (the custom
# ~/opt/openssl-3.5 of the build host); a shipped binary must resolve the
# SYSTEM libssl.so.3/libcrypto.so.3 (3.5+) on the target instead. this
# strips the staged copy only - the build tree keeps its RUNPATH for ctest.
strip_runpath() {
    local bin="$1"
    if command -v patchelf >/dev/null 2>&1; then
        patchelf --remove-rpath "$bin"
    elif command -v chrpath >/dev/null 2>&1; then
        chrpath -d "$bin"
    else
        log "WARNING: patchelf/chrpath missing, the package keeps the build RUNPATH"
    fi
}

# the deb pins the staged binary to the private bundle directory: the
# RUNPATH resolves before the default paths (after LD_LIBRARY_PATH), so
# the bundle wins for this binary only - the system libssl serves
# everything else. patchelf is mandatory here: without the RUNPATH the
# binary is dead on the 3.0.x targets the bundle exists for. the fixed
# absolute private path is deliberate - no $ORIGIN games
set_runpath() {
    local bin="$1"
    command -v patchelf >/dev/null 2>&1 \
        || die "patchelf not found (apt-get install patchelf) - the bundled-OpenSSL scheme needs it"
    patchelf --set-rpath "$BUNDLE_LIB_DIR" "$bin"
}

# the version comes from the daemon itself: -V prints "ssh3-server version X.Y.Z"
ensure_bin() {
    if [ ! -x "$BIN" ]; then
        log "no prebuilt binary, running the linux-release preset"
        (cd "$REPO_DIR" && cmake --preset linux-release)
        (cd "$REPO_DIR" && cmake --build --preset linux-release)
    fi
    VERSION=$("$BIN" -V | awk '{print $3}')
    [ -n "$VERSION" ] || die "cannot parse the version from '$BIN -V'"
    log "packaging ssh3-server $VERSION"
}

build_deb() {
    log "building the deb package"
    local stage="$STAGE_ROOT/deb/pkg"
    local debver
    debver=$(sed -n 's/^Version: //p' "$SCRIPT_DIR/deb/control" | head -n 1)
    [ "${debver%%-*}" = "$VERSION" ] \
        || die "deb/control Version ($debver) does not match the binary ($VERSION)"
    fetch_bundle
    mkdir -p "$stage/DEBIAN" "$stage/usr/sbin" "$stage/usr/share/doc/ssh3-server"
    mkdir -p "$stage/usr/lib/systemd/system"
    chmod 0755 "$STAGE_ROOT/deb" "$stage" "$stage/usr" "$stage/DEBIAN"
    install -m 0755 "$BIN" "$stage/usr/sbin/ssh3-server"
    set_runpath "$stage/usr/sbin/ssh3-server"
    sed "s/@ARCH@/$DEB_ARCH/" "$SCRIPT_DIR/deb/control" \
        > "$stage/DEBIAN/control"
    install -m 0755 "$SCRIPT_DIR/deb/postinst" "$stage/DEBIAN/postinst"
    install -m 0644 "$SCRIPT_DIR/deb/copyright" "$stage/usr/share/doc/ssh3-server/copyright"
    install -m 0644 "$REPO_DIR/THIRD-PARTY-NOTICES.md" \
        "$stage/usr/share/doc/ssh3-server/THIRD-PARTY-NOTICES"
    if [ -e "$BUNDLE_STAGE/openssl-copyright" ]; then
        install -m 0644 "$BUNDLE_STAGE/openssl-copyright" \
            "$stage/usr/share/doc/ssh3-server/openssl-copyright"
    fi
    install -m 0644 "$SCRIPT_DIR/systemd/ssh3-server.socket" \
        "$stage/usr/lib/systemd/system/ssh3-server.socket"
    install -m 0644 "$SCRIPT_DIR/systemd/ssh3-server.service" \
        "$stage/usr/lib/systemd/system/ssh3-server.service"
    bundle_report
    dpkg-deb --root-owner-group --build "$stage" \
        "$OUT_DIR/ssh3-server_${debver}_${DEB_ARCH}.deb"
}

# the bundled OpenSSL 3.5 of the deb channel is a package of its own
# (ssh3c-libssl3): the server and the client debs depend on it, the
# path stays /usr/lib/ssh3-c/lib - the client of a serverless host
# rides the same bundle
build_deb_libs() {
    log "building the bundled-libs deb package"
    local stage="$STAGE_ROOT/deb/libs"
    local debver
    debver=$(sed -n 's/^Version: //p' "$SCRIPT_DIR/deb/control" | head -n 1)
    [ "${debver%%-*}" = "$VERSION" ] \
        || die "deb/control Version ($debver) does not match the binary ($VERSION)"
    fetch_bundle
    mkdir -p "$stage/DEBIAN" "$stage/usr/lib/ssh3-c/lib"
    chmod 0755 "$STAGE_ROOT/deb" "$stage" "$stage/usr" "$stage/DEBIAN" \
        "$stage/usr/lib/ssh3-c" "$stage/usr/lib/ssh3-c/lib"
    install -m 0644 "$BUNDLE_STAGE/libssl.so.3" \
        "$stage/usr/lib/ssh3-c/lib/libssl.so.3"
    install -m 0644 "$BUNDLE_STAGE/libcrypto.so.3" \
        "$stage/usr/lib/ssh3-c/lib/libcrypto.so.3"
    sed -e "s/@VERSION@/$debver/" -e "s/@ARCH@/$DEB_ARCH/" \
        "$SCRIPT_DIR/deb/libssl3-control" \
        > "$stage/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$stage" \
        "$OUT_DIR/ssh3c-libssl3_${debver}_${DEB_ARCH}.deb"
}

# the client deb: /usr/bin/ssh3 with the RUNPATH into the private
# bundle directory, the man page, and the postinst compatibility link
# /usr/local/bin/ssh3 -> /usr/bin/ssh3 (the admin's own file wins)
build_deb_client() {
    log "building the client deb package"
    local stage="$STAGE_ROOT/deb/client"
    local client="$BIN_DIR/ssh3"
    [ -x "$client" ] || die "no client binary at '$client' (cmake --build --preset linux-release)"
    local debver
    debver=$(sed -n 's/^Version: //p' "$SCRIPT_DIR/deb/control" | head -n 1)
    [ "${debver%%-*}" = "$VERSION" ] \
        || die "deb/control Version ($debver) does not match the binary ($VERSION)"
    mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/man/man1"
    chmod 0755 "$STAGE_ROOT/deb" "$stage" "$stage/usr" "$stage/DEBIAN" \
        "$stage/usr/bin"
    install -m 0755 "$client" "$stage/usr/bin/ssh3"
    set_runpath "$stage/usr/bin/ssh3"
    gzip -c "$SCRIPT_DIR/debian/ssh3.1" > "$stage/usr/share/man/man1/ssh3.1.gz"
    install -m 0755 "$SCRIPT_DIR/deb/client-postinst" "$stage/DEBIAN/postinst"
    sed -e "s/@VERSION@/$debver/" -e "s/@ARCH@/$DEB_ARCH/" \
        "$SCRIPT_DIR/deb/client-control" \
        > "$stage/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$stage" \
        "$OUT_DIR/ssh3-client_${debver}_${DEB_ARCH}.deb"
}

build_rpm() {
    log "building the rpm package"
    command -v rpmbuild >/dev/null 2>&1 || die "rpmbuild not found (apt-get install rpm)"
    local top="$STAGE_ROOT/rpm/rpmbuild"
    mkdir -p "$top/BUILD" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"
    install -m 0755 "$BIN" "$top/SOURCES/ssh3-server"
    strip_runpath "$top/SOURCES/ssh3-server"
    install -m 0644 "$REPO_DIR/LICENSE" "$top/SOURCES/LICENSE"
    install -m 0644 "$REPO_DIR/THIRD-PARTY-NOTICES.md" "$top/SOURCES/THIRD-PARTY-NOTICES.md"
    install -m 0644 "$REPO_DIR/README.md" "$top/SOURCES/README.md"
    # @VERSION@ in the spec template is substituted here, so the package and
    # the binary always carry the same version; @RPMARCH@ is the build
    # architecture of the spec (the rpm of a foreign architecture needs a
    # cross toolchain the host does not have - that build stays refused)
    sed -e "s/@VERSION@/$VERSION/" -e "s/@RPMARCH@/$RPM_ARCH/" \
        "$SCRIPT_DIR/rpm/ssh3-server.spec" > "$top/SPECS/ssh3-server.spec"
    rpmbuild -bb --define "_topdir $top" \
        "$top/SPECS/ssh3-server.spec"
    mv "$top"/RPMS/$RPM_ARCH/ssh3-server-*.rpm "$OUT_DIR/"
}

build_apk() {
    log "building the apk package (apk-tools v2: control.tar.gz + data.tar.gz)"
    local stage="$STAGE_ROOT/apk"
    mkdir -p "$stage/control" "$stage/data/usr/sbin"
    install -m 0755 "$BIN" "$stage/data/usr/sbin/ssh3-server"
    strip_runpath "$stage/data/usr/sbin/ssh3-server"
    sed -e "s/@VERSION@/$VERSION/" \
        -e "s/@BUILDDATE@/$(date +%s)/" \
        -e "s/@SIZE@/$(du -sb "$stage/data" | cut -f1)/" \
        "$SCRIPT_DIR/apk/PKGINFO.in" > "$stage/control/.PKGINFO"
    tar --owner=0 --group=0 --numeric-owner \
        -czf "$stage/control.tar.gz" -C "$stage/control" .PKGINFO
    tar --owner=0 --group=0 --numeric-owner \
        -czf "$stage/data.tar.gz" -C "$stage/data" usr
    cat "$stage/control.tar.gz" "$stage/data.tar.gz" \
        > "$OUT_DIR/ssh3-server_${VERSION}-r0.apk"
}

FMT="${1:-all}"
case "$FMT" in
    deb) ensure_bin; build_deb ;;
    deb-libs) ensure_bin; fetch_bundle; build_deb_libs ;;
    deb-client) ensure_bin; build_deb_client ;;
    rpm) ensure_bin; build_rpm ;;
    apk) ensure_bin; build_apk ;;
    all) ensure_bin; build_deb; build_deb_libs; build_deb_client; build_rpm; build_apk ;;
    *) die "usage: bash packaging/build.sh [deb|rpm|apk|all]" ;;
esac

log "artifacts:"
for f in "$OUT_DIR"/*.deb "$OUT_DIR"/*.rpm "$OUT_DIR"/*.apk; do
    if [ -e "$f" ]; then ls -l "$f"; fi
done
