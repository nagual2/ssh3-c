cmake_minimum_required(VERSION 3.20)

project(ssh3-c LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# XSI strerror_r (int return), posix_memalign, sysconf, STDERR_FILENO.
#
# the feature checks below must compile under the same feature macros as the
# build, otherwise they answer a question nobody asked: CMake runs
# check_c_source_compiles in a separate project that does not inherit
# add_compile_definitions
set(S3_FEATURE_DEFINITIONS -D_POSIX_C_SOURCE=200809L)

add_compile_definitions(${S3_FEATURE_DEFINITIONS})

include(CheckCSourceCompiles)

set(CMAKE_REQUIRED_DEFINITIONS ${S3_FEATURE_DEFINITIONS})

# the UDP GSO (man 7 udp UDP_SEGMENT) support, like NGX_HAVE_UDP_SEGMENT
check_c_source_compiles(
    "
    #include <sys/socket.h>
    #include <netinet/udp.h>
    int main(void) {
        struct cmsghdr cmsg;
        cmsg.cmsg_level = SOL_UDP;
        cmsg.cmsg_type = UDP_SEGMENT;
        return 0;
    }
    "
    S3_HAVE_UDP_SEGMENT)

# the local address ancillary data, like NGX_HAVE_ADDRINFO_CMSG.
#
# the code sizes cmsghdr payload with the two packet info structs, so the
# check must complete them -- IP_PKTINFO and IPV6_RECVPKTINFO are plain
# constants that survive on hosts where the structs are not declared.
# struct in6_pktinfo is behind __USE_GNU, in_pktinfo behind __USE_MISC
check_c_source_compiles(
    "
    #include <sys/socket.h>
    #include <netinet/in.h>
    int main(void) {
        struct cmsghdr cmsg;
        cmsg.cmsg_level = SOL_IP;
        cmsg.cmsg_type = IP_PKTINFO;
        return (int) (sizeof(struct in_pktinfo) + sizeof(struct in6_pktinfo)) & 0;
    }
    "
    S3_HAVE_ADDRINFO_CMSG)

unset(CMAKE_REQUIRED_DEFINITIONS)

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
    src/os/unix/s3_nonblocking.c
    src/os/unix/s3_sock_ntop.c
    src/os/unix/s3_https_fetch.c
    src/event/quic/s3_quic_transport.c
    src/event/quic/s3_quic_frames.c
    src/event/quic/s3_quic_protection.c
    src/event/quic/s3_quic_tokens.c
    src/event/quic/s3_quic_connid.c
    src/event/quic/s3_ssl.c
    src/event/quic/s3_quic_ssl.c
    src/event/quic/s3_quic.c
    src/event/quic/s3_quic_migration.c
    src/event/quic/s3_quic_output.c
    src/event/quic/s3_quic_ack.c
    src/event/quic/s3_quic_streams.c
    src/h3/s3_h3_encode.c
    src/h3/s3_h3_table.c
    src/h3/s3_h3_parse.c
    src/h3/s3_h3_uni.c
    src/ssh3/s3_ssh3_version.c
    src/ssh3/s3_ssh3_wire.c
    src/ssh3/s3_ssh3_message.c
    src/ssh3/s3_ssh3_request.c
    src/ssh3/s3_ssh3_channel.c
    src/ssh3/s3_ssh3_conversation.c
    src/ssh3/s3_ssh3_dgram.c
    src/ssh3/s3_ssh3_session_srv.c
    src/ssh3/s3_ssh3_auth_srv.c
    src/ssh3/s3_ssh3_oidc.c
    src/ssh3/s3_ssh3_oidc_client.c
    src/ssh3/s3_ssh3_session_cli.c
    src/ssh3/s3_ssh3_forward.c
    src/ssh3/s3_ssh3_agent.c
    src/ssh3/s3_ssh3_sftp_codec.c
    src/ssh3/s3_ssh3_sftp_srv.c
    src/ssh3/s3_ssh3_sftp_cli.c
    src/ssh3/s3_ssh3_cm.c
)

add_library(s3core STATIC ${S3_CORE_SOURCES})

target_include_directories(s3core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/event
        ${CMAKE_CURRENT_SOURCE_DIR}/src/h3
        ${CMAKE_CURRENT_SOURCE_DIR}/src/event/quic
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ssh3
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

# the libFuzzer parser-fuzzing harnesses (tests/fuzz/); the fuzz
# preset turns this on and skips the bench, the interop runners and
# the unit tests, the plain presets keep building everything

option(S3_BUILD_FUZZ "Build the libFuzzer parser-fuzzing harnesses" OFF)

if(NOT S3_BUILD_FUZZ)
    add_executable(s3gso_bench bench/gso_bench.c)
    target_compile_options(s3gso_bench PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(s3gso_bench PRIVATE Threads::Threads)

    # the interop runners over real UDP (the quic-go harness, later the Go fork)
    foreach(S3_INTEROP interop_server interop_client)
        add_executable(s3${S3_INTEROP} interop/${S3_INTEROP}.c)
        target_compile_options(s3${S3_INTEROP} PRIVATE -Wall -Wextra -Werror)
        target_link_libraries(s3${S3_INTEROP} PRIVATE s3core Threads::Threads)
    endforeach()

    # the production daemon (P6.5): the ssh3 route only, SIGTERM/SIGINT
    # drain, journald-friendly logging (the wiring is the harness one
    # by design, interop/interop_server.c stays the matrix peer)
    add_executable(ssh3-server app/ssh3_server.c)
    target_compile_options(ssh3-server PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ssh3-server PRIVATE s3core Threads::Threads)
endif()

# the fuzz harnesses link the libFuzzer runtime through their own
# link options, the global linker flags stay fuzz-free so the CMake
# compiler checks keep linking their own main()

if(S3_BUILD_FUZZ)
    foreach(S3_FUZZ fuzz_sftp_frame fuzz_cm_frame fuzz_forward_target fuzz_wire fuzz_message)
        add_executable(${S3_FUZZ} tests/fuzz/${S3_FUZZ}.c)
        target_compile_options(${S3_FUZZ} PRIVATE -Wall -Wextra -Werror)
        target_link_options(${S3_FUZZ} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${S3_FUZZ} PRIVATE s3core)
        set_target_properties(${S3_FUZZ} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests/fuzz)
    endforeach()

    add_executable(s3_fuzz_gen_seeds tests/fuzz/gen_seeds.c)
    target_compile_options(s3_fuzz_gen_seeds PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(s3_fuzz_gen_seeds PRIVATE s3core)
    set_target_properties(s3_fuzz_gen_seeds PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests/fuzz)

    add_custom_target(fuzz_seeds ALL
        COMMAND ${CMAKE_BINARY_DIR}/tests/fuzz/s3_fuzz_gen_seeds
                ${CMAKE_BINARY_DIR}/tests/fuzz/seeds
        DEPENDS s3_fuzz_gen_seeds
        COMMENT "generating the fuzz seed corpora")
endif()

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
    test_h3_qpack
    test_h3_parse
    test_h3_uni
    test_ssh3_version
    test_ssh3_wire
    test_ssh3_message
    test_ssh3_request
    test_ssh3_channel
    test_ssh3_conversation
    test_ssh3_dgram
    test_ssh3_session_srv
    test_ssh3_auth_srv
    test_ssh3_oidc
    test_ssh3_session_cli
    test_ssh3_forward
    test_ssh3_agent
    test_ssh3_sftp_codec
    test_ssh3_sftp_srv
    test_ssh3_sftp_cli
    test_ssh3_cm
)

enable_testing()

if(NOT S3_BUILD_FUZZ)
    foreach(S3_TEST ${S3_TESTS})
        add_executable(${S3_TEST} tests/${S3_TEST}.c)
        target_link_libraries(${S3_TEST} PRIVATE s3core)
        target_include_directories(${S3_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        target_compile_options(${S3_TEST} PRIVATE -Wall -Wextra -Werror)
        add_test(NAME ${S3_TEST} COMMAND ${S3_TEST})
    endforeach()
endif()
