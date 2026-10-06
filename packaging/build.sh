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
# not built here:
#   - the openwrt ipk needs the openwrt SDK - see packaging/openwrt/Makefile;
#   - the rpm build needs rpmbuild (apt-get install rpm on a debian/ubuntu
#     build host).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BIN_DIR="$REPO_DIR/build/linux-release"
BIN="$BIN_DIR/ssh3-server"
OUT_DIR="$SCRIPT_DIR/_build"
STAGE_ROOT=$(mktemp -d /tmp/ssh3-pkg.XXXXXX)
PKG_RELEASE=1
trap 'rm -rf "$STAGE_ROOT"' EXIT

log() { printf '==> %s\n' "$1"; }
die() { printf 'build.sh: %s\n' "$1"; exit 1; }

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
    mkdir -p "$stage/DEBIAN" "$stage/usr/sbin" "$stage/usr/share/doc/ssh3-server"
    chmod 0755 "$STAGE_ROOT/deb" "$stage" "$stage/usr" "$stage/DEBIAN"
    install -m 0755 "$BIN" "$stage/usr/sbin/ssh3-server"
    strip_runpath "$stage/usr/sbin/ssh3-server"
    install -m 0644 "$SCRIPT_DIR/deb/control" "$stage/DEBIAN/control"
    install -m 0755 "$SCRIPT_DIR/deb/postinst" "$stage/DEBIAN/postinst"
    install -m 0644 "$SCRIPT_DIR/deb/copyright" "$stage/usr/share/doc/ssh3-server/copyright"
    install -m 0644 "$REPO_DIR/THIRD-PARTY-NOTICES.md" \
        "$stage/usr/share/doc/ssh3-server/THIRD-PARTY-NOTICES"
    dpkg-deb --root-owner-group --build "$stage" \
        "$OUT_DIR/ssh3-server_${debver}_amd64.deb"
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
    # the binary always carry the same version
    sed -e "s/@VERSION@/$VERSION/" \
        "$SCRIPT_DIR/rpm/ssh3-server.spec" > "$top/SPECS/ssh3-server.spec"
    rpmbuild -bb --define "_topdir $top" "$top/SPECS/ssh3-server.spec"
    mv "$top"/RPMS/x86_64/ssh3-server-*.rpm "$OUT_DIR/"
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
    rpm) ensure_bin; build_rpm ;;
    apk) ensure_bin; build_apk ;;
    all) ensure_bin; build_deb; build_rpm; build_apk ;;
    *) die "usage: bash packaging/build.sh [deb|rpm|apk|all]" ;;
esac

log "artifacts:"
for f in "$OUT_DIR"/*.deb "$OUT_DIR"/*.rpm "$OUT_DIR"/*.apk; do
    if [ -e "$f" ]; then ls -l "$f"; fi
done
