cmake_minimum_required(VERSION 3.20)

project(ssh3-c LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# XSI strerror_r (int return), posix_memalign, sysconf, STDERR_FILENO.
add_compile_definitions(_POSIX_C_SOURCE=200809L)

include(CheckCSourceCompiles)

# the UDP GSO (man 7 udp UDP_SEGMENT) support, like NGX_HAVE_UDP_SEGMENT
check_c_source_compiles(
    "
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/udp.h>
    int main(void) {
        struct cmsghdr *cmsg = 0;
        (void) cmsg->cmsg_level = SOL_UDP;
        (void) cmsg->cmsg_type = UDP_SEGMENT;
        return 0;
    }
    "
    S3_HAVE_UDP_SEGMENT)

# the local address ancillary data, like NGX_HAVE_ADDRINFO_CMSG
check_c_source_compiles(
    "
    #include <sys/socket.h>
    #include <netinet/in.h>
    int main(void) {
        struct cmsghdr *cmsg = 0;
        (void) cmsg->cmsg_level = SOL_IP;
        (void) cmsg->cmsg_type = IP_PKTINFO;
#ifdef IPV6_RECVPKTINFO
        return 0;
#else
        return 1;
#endif
    }
    "
    S3_HAVE_ADDRINFO_CMSG)

set(S3_CORE_SOURCES
    src/core/s3_string.c
    src/core/s3_palloc.c
    src/core/s3_buf.c
    src/core/s3_rbtree.c
    src/core/s3_log.c
    src/core/s3_crc32.c
    src/os/unix/s3_errno.c
    src/os/unix/s3_cmsg.c
    src/event/s3_event.c
    src/event/s3_event_posted.c
    src/event/s3_event_timer.c
    src/event/s3_connection.c
    src/event/s3_event_udp.c
    src/event/modules/s3_epoll_module.c
    src/os/unix/s3_udp_sendmsg_chain.c
    src/os/unix/s3_udp_recv.c
    src/event/quic/s3_quic_transport.c
    src/event/quic/s3_quic_frames.c
    src/event/quic/s3_quic_protection.c
    src/event/quic/s3_quic_tokens.c
    src/event/quic/s3_quic_connid.c
    src/event/quic/s3_ssl.c
    src/event/quic/s3_quic_ssl.c
    src/event/quic/s3_quic.c
    src/event/quic/s3_quic_output.c
    src/event/quic/s3_quic_ack.c
)

add_library(s3core STATIC ${S3_CORE_SOURCES})

target_include_directories(s3core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/event
        ${CMAKE_CURRENT_SOURCE_DIR}/src/event/quic
        ${CMAKE_CURRENT_SOURCE_DIR}/src/os/unix
)

if(S3_HAVE_UDP_SEGMENT)
    target_compile_definitions(s3core PUBLIC S3_HAVE_UDP_SEGMENT=1)
endif()

if(S3_HAVE_ADDRINFO_CMSG)
    target_compile_definitions(s3core PUBLIC S3_HAVE_ADDRINFO_CMSG=1)
endif()

target_compile_options(s3core PRIVATE -Wall -Wextra -Werror)

# the QUIC crypto layer (HKDF/AEAD) requires OpenSSL 3.5+
if(EXISTS $ENV{HOME}/opt/openssl-3.5)
    list(PREPEND CMAKE_PREFIX_PATH $ENV{HOME}/opt/openssl-3.5)
endif()

find_package(OpenSSL 3.5 REQUIRED)

message(STATUS "OpenSSL ${OPENSSL_VERSION} (crypto: ${OPENSSL_CRYPTO_LIBRARY})")

# the QUIC modules link libcrypto and libssl through s3core;
# the QUIC TLS API (SSL_set_quic_tls_cbs) lives in libssl
target_link_libraries(s3core PUBLIC OpenSSL::Crypto OpenSSL::SSL)

find_package(Threads REQUIRED)

add_executable(s3gso_bench bench/gso_bench.c)
target_compile_options(s3gso_bench PRIVATE -Wall -Wextra -Werror)
target_link_libraries(s3gso_bench PRIVATE Threads::Threads)

# the interop runners over real UDP (the quic-go harness, later the Go fork)
foreach(S3_INTEROP interop_server interop_client)
    add_executable(s3${S3_INTEROP} interop/${S3_INTEROP}.c)
    target_compile_options(s3${S3_INTEROP} PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(s3${S3_INTEROP} PRIVATE s3core Threads::Threads)
endforeach()

set(S3_TESTS
    test_pool
    test_buf
    test_rbtree
    test_queue
    test_string
    test_log
    test_event
    test_udp
    test_quic_transport
    test_quic_frames
    test_quic_protection
    test_quic_tokens
    test_quic_ssl
    test_quic_core
    test_quic_output
    test_quic_ack
    test_quic_e2e
)

enable_testing()

foreach(S3_TEST ${S3_TESTS})
    add_executable(${S3_TEST} tests/${S3_TEST}.c)
    target_link_libraries(${S3_TEST} PRIVATE s3core)
    target_include_directories(${S3_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_compile_options(${S3_TEST} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${S3_TEST} COMMAND ${S3_TEST})
endforeach()
