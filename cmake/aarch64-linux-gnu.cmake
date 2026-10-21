# the aarch64-linux-gnu cross toolchain (the F3/B7 wave: the arm
# rollout of the hosting - Graviton/Ampere).
#
# the OpenSSL 3.5 comes from the arm64 Debian 13 packages (the same
# version the x86-64 bundle ships): libssl-dev for the headers and
# the link, libssl3t64 for the runtime pair.  the staged prefix is
# /opt/ssl-arm64, unpacked with dpkg-deb -x - the find root hides the
# host's 3.0.x, so the cross build cannot pick it up by accident.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

# the staged OpenSSL 3.5 (the arm64 deb packages)
set(S3_OPENSSL_ARM64_ROOT "/opt/ssl-arm64" CACHE PATH
    "the staged arm64 OpenSSL 3.5 root (the deb packages unpacked)")

set(CMAKE_FIND_ROOT_PATH ${S3_OPENSSL_ARM64_ROOT})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(OPENSSL_ROOT_DIR ${S3_OPENSSL_ARM64_ROOT}/usr)
set(OPENSSL_USE_STATIC_LIBS OFF)

# the staged libraries are named by the multiarch triple of the
# Debian arm64 packages; the find_library of the cross build does not
# always reach the triple subdirectory, so the paths are named here
set(S3_ARM64_LIBDIR "aarch64-linux-gnu" CACHE STRING
    "the multiarch triple of the Debian arm64 packages")

set(OPENSSL_CRYPTO_LIBRARY
    "${S3_OPENSSL_ARM64_ROOT}/usr/lib/${S3_ARM64_LIBDIR}/libcrypto.so"
    CACHE FILEPATH "the staged arm64 libcrypto")
set(OPENSSL_SSL_LIBRARY
    "${S3_OPENSSL_ARM64_ROOT}/usr/lib/${S3_ARM64_LIBDIR}/libssl.so"
    CACHE FILEPATH "the staged arm64 libssl")
set(OPENSSL_INCLUDE_DIR "${S3_OPENSSL_ARM64_ROOT}/usr/include"
    CACHE PATH "the staged arm64 OpenSSL headers")

# the cross linker must not take the host's libraries
set(CMAKE_C_FLAGS_INIT "-Wl,--sysroot=${CMAKE_SYSROOT}")

# the arch-specific opensslconf.h of the Debian packages lives in the
# multiarch include directory, next to the generic headers
set(CMAKE_C_FLAGS_INIT
    "${CMAKE_C_FLAGS_INIT} -I${S3_OPENSSL_ARM64_ROOT}/usr/include/${S3_ARM64_LIBDIR}")
