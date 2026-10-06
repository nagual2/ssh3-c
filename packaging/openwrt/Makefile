# OpenWrt feed makefile for ssh3-server (P7 packaging stub).
#
# drop this directory into a package feed (e.g. package/ssh3/ of a custom
# feed) and run "make package/ssh3-server/compile V=s" inside the openwrt
# SDK/buildroot. NOT built by packaging/build.sh: that needs the SDK.
#
# dependency note: libopenssl must provide the QUIC TLS API (OpenSSL 3.5+).
# openwrt main carries 3.5.x since the 2025 bump; the 24.10/23.05 stable
# branches ship 3.0.x and cannot run this daemon. the ipk produced by the
# SDK on musl/mipsel-class targets is the real deliverable; this makefile
# only describes the build.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

PKG_NAME:=ssh3-server
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_SOURCE_PROTO:=git
# set to the release repository (or a file:// tarball source) of the tree
PKG_SOURCE_URL:=https://git.example/ssh3-c.git
PKG_SOURCE_VERSION:=v0.1.0
PKG_MIRROR_HASH:=skip
PKG_MAINTAINER:=ssh3-c maintainers <maintainers@example.com>
PKG_LICENSE:=BSD-2-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1
CMAKE_INSTALL:=1

define Package/ssh3-server
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=SSH
  TITLE:=SSH3 server (SSH over QUIC/HTTP3)
  DEPENDS:=+libopenssl
endef

define Package/ssh3-server/description
  SSH3 server daemon: the SSH3 protocol carried over HTTP/3 (QUIC),
  implemented in C in the nginx style on top of the OpenSSL QUIC TLS
  API (OpenSSL >= 3.5). Configured through environment variables
  (SSH3_LOG_LEVEL, SSH3_LOG_FILE, SSH3_SHUTDOWN_DRAIN) and command-line
  flags.
endef

# build only the daemon target, not the bench/interop/test binaries
define Build/Compile
	$(call Build/Compile/Default,ssh3-server)
endef

define Package/ssh3-server/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ssh3-server $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,ssh3-server))
