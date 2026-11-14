# the OpenWrt x86/64 cross toolchain (the official SDK gcc-14.3 musl)
# against the system libraries of the OpenWrt VM: the apk packages of
# the 25.12.6 release (libopenssl3 3.5.9, zlib 1.3.1, zstd 1.5.7) ride
# byte-exact - the .so files came off the VM, no library is rebuilt
# for the cross stage - and the include trees are the upstream headers
# of the same versions (the apk -dev split carries them where the
# release has it, the upstream tarball where it does not)
#
# the env contract: OPENWRT_TOOLCHAIN_BIN (the SDK toolchain bin) and
# OPENWRT_SYS_STAGE (the system stage: usr/include + usr/lib)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(OPENWRT_TOOLCHAIN_BIN "$ENV{OPENWRT_TOOLCHAIN_BIN}" CACHE PATH
    "the SDK toolchain bin")
set(OPENWRT_SYS_STAGE "$ENV{OPENWRT_SYS_STAGE}" CACHE PATH
    "the system stage (usr/include + usr/lib of the VM packages)")

if(NOT OPENWRT_TOOLCHAIN_BIN OR NOT OPENWRT_SYS_STAGE)
    message(FATAL_ERROR
        "the OpenWrt cross env is not set: OPENWRT_TOOLCHAIN_BIN, OPENWRT_SYS_STAGE")
endif()

set(CMAKE_C_COMPILER "${OPENWRT_TOOLCHAIN_BIN}/x86_64-openwrt-linux-gcc")
set(CMAKE_CXX_COMPILER "${OPENWRT_TOOLCHAIN_BIN}/x86_64-openwrt-linux-g++")

# the include and link roots point at the system stage, the host
# paths are hidden (the cross build cannot pick a host library)

set(CMAKE_FIND_ROOT_PATH "${OPENWRT_SYS_STAGE}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# the OpenSSL of the system (libopenssl3 3.5.9, the runtime .so of the
# VM); the .so.3 suffix has no unversioned link, the files are named

set(OPENSSL_ROOT_DIR "${OPENWRT_SYS_STAGE}/usr" CACHE PATH
    "the system OpenSSL root")
set(OPENSSL_INCLUDE_DIR "${OPENWRT_SYS_STAGE}/usr/include" CACHE PATH
    "the OpenSSL 3.5.9 headers")
set(OPENSSL_CRYPTO_LIBRARY
    "${OPENWRT_SYS_STAGE}/usr/lib/libcrypto.so.3" CACHE FILEPATH
    "the system libcrypto")
set(OPENSSL_SSL_LIBRARY
    "${OPENWRT_SYS_STAGE}/usr/lib/libssl.so.3" CACHE FILEPATH
    "the system libssl")

# the zlib and zstd of the system (the runtime .so of the VM, the
# headers of the same upstream versions)

set(ZLIB_INCLUDE_DIR "${OPENWRT_SYS_STAGE}/usr/include" CACHE PATH
    "the zlib 1.3.1 headers")
set(ZLIB_LIBRARY
    "${OPENWRT_SYS_STAGE}/usr/lib/libz.so.1" CACHE FILEPATH
    "the system libz")

set(S3_ZSTD_INCLUDE_DIR "${OPENWRT_SYS_STAGE}/usr/include" CACHE PATH
    "the zstd 1.5.7 headers")
set(S3_ZSTD_LIBRARY
    "${OPENWRT_SYS_STAGE}/usr/lib/libzstd.so.1" CACHE FILEPATH
    "the system libzstd")
