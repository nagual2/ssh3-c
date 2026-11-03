# OpenWrt feed makefile for ssh3-server (P8(2): install-able through the
# SDK).
#
# drop this directory into a package feed (e.g. package/ssh3/ of a custom
# feed) and run "make package/ssh3-server/compile V=s" inside the openwrt
# SDK/buildroot. NOT built by packaging/build.sh: that needs the SDK.
#
# dependency note: libopenssl must provide the QUIC TLS API (OpenSSL 3.5+).
# openwrt main carries 3.5.x since the 2025 bump; the 24.10/23.05 stable
# branches ship 3.0.x and cannot run this daemon - the cmake configure
# refuses (find_package(OpenSSL 3.5 REQUIRED)). the target stack of the
# owner is 25.12.x; the tests pin to the openwrt-dev VM (the owner's
# decision 2026-10-29: nothing installs onto the routers from here).
#
# the codecs ride the feeds: zlib and zstd ship everywhere, liblz4 too -
# without one of them the channel body rides the remaining codecs (the
# B8 gate is the intersection of the peer mask).

# the package variables ride BEFORE the includes: the stamps of
# package.mk (STAMP_BUILT) freeze PKG_BUILD_DIR at the include time,
# the variables after the include freeze empty (the git proto of the
# stub masked it with its own download fields)

PKG_NAME:=ssh3-server
PKG_VERSION:=0.5.8
PKG_RELEASE:=1

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
# the SDK build rides the tarball of the release tag placed into the
# SDK dl/ directory by hand (the release script builds it with git
# archive); the Download machinery is bypassed - the prepare unpacks
# the tarball straight into the build dir (the file:// self-download
# of the SDK overwrote the mirror copy)
PKG_MAINTAINER:=ssh3-c maintainers <maintainers@example.com>
PKG_LICENSE:=BSD-2-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
export PKG_BUILD_DIR

define Package/ssh3-server
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=SSH
  TITLE:=SSH3 server (SSH over QUIC/HTTP3)
  URL:=https://github.com/nagual2/ssh3-c
  DEPENDS:=+libopenssl +zlib +libzstd +liblz4 +openssl-util
  USERID:=ssh3=370
endef

define Package/ssh3-server/description
  SSH3 server daemon: the SSH3 protocol carried over HTTP/3 (QUIC),
  implemented in C in the nginx style on top of the OpenSSL QUIC TLS
  API (OpenSSL >= 3.5). Configured through /etc/config/ssh3 (the uci
  core section, procd init); the per-session setuid drops every
  authenticated session onto its system identity (the sshd shape),
  the daemon itself keeps a minimal bounding set.
  Coexistence: a peer of OpenSSH (tcp/22) and a drop-in replacement
  of the go fork (the same binary names); see docs/COEXISTENCE.md.
endef

define Package/ssh3-server/conffiles
/etc/config/ssh3
/etc/ssh3/authorized_keys
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(TAR) -xzf $(TOPDIR)/dl/ssh3-c-$(PKG_VERSION).tar.gz -C $(PKG_BUILD_DIR)
endef

# build only the daemon target, not the bench/interop/test binaries
define Build/Compile
	$(call Build/Compile/Default,ssh3-server)
endef

# the cmake tree carries no install rules: the daemon binary copies
# into the ipkg-install dir by hand (the Build/Install/Default ninja
# install target does not exist)

define Build/Install
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ssh3-server $(PKG_INSTALL_DIR)/usr/sbin/
endef

define Package/ssh3-server/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ssh3-server $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/ssh3-server $(1)/etc/init.d/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/ssh3 $(1)/etc/config/

	$(INSTALL_DIR) $(1)/etc/ssh3
	$(INSTALL_CONF) ./files/etc/ssh3/authorized_keys $(1)/etc/ssh3/authorized_keys

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-ssh3-server-cert $(1)/etc/uci-defaults/
endef

$(eval $(call BuildPackage,ssh3-server))
