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
#
# _GNU_SOURCE is the feature set of the reference on Linux (auto/os/linux):
# the BSD structures of the local address ancillary data (struct in_pktinfo,
# struct in6_pktinfo) live behind __USE_MISC, and the strict POSIX mode
# hides them — with the POSIX mode alone the S3_HAVE_ADDRINFO_CMSG check
# below can never pass and the whole local address path stays compiled out
set(S3_FEATURE_DEFINITIONS -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L)

add_compile_definitions(${S3_FEATURE_DEFINITIONS})

# the Windows beachhead (P9 wave 1, docs/PLAN.md): cross-built with
# mingw-w64 (preset windows-core, from WSL).  platform-free core,
# codecs and the os/win layer only -- the event/quic layers land with
# the select module (P9 wave 2+).  the unix path below is untouched
if(WIN32)

    # the event backend: exactly one s3_event_actions provider is
    # compiled in, the select module by default and the iocp port of
    # ngx_iocp_module behind S3_USE_IOCP (the overlapped udp receive)
    option(S3_USE_IOCP "IOCP event backend" OFF)

    if(S3_USE_IOCP)
        set(S3_EVENT_MODULE src/event/modules/s3_iocp_module.c)

    else()
        set(S3_EVENT_MODULE src/event/modules/s3_select_module.c)
    endif()

    add_library(s3core STATIC
        src/core/s3_string.c
        src/core/s3_palloc.c
        src/core/s3_buf.c
        src/core/s3_rbtree.c
        src/core/s3_log.c
        src/core/s3_crc32.c
        src/os/win/s3_errno.c
        src/os/win/s3_nonblocking.c
        src/os/win/s3_sock_ntop.c
        src/os/win/s3_os_init.c
        src/os/win/s3_udp_recv.c
        src/os/win/s3_udp_sendmsg_chain.c
        src/os/win/s3_udp_msg.c
        src/event/s3_event.c
        src/event/s3_event_posted.c
        src/event/s3_event_timer.c
        src/event/s3_connection.c
        src/event/s3_event_udp.c
        ${S3_EVENT_MODULE}
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
        src/ssh3/s3_ssh3_forward.c
        src/ssh3/s3_ssh3_forward_policy.c
        src/ssh3/s3_ssh3_reverse.c
        src/ssh3/s3_ssh3_dos_guard.c
        src/ssh3/s3_ssh3_sftp_codec.c
        src/ssh3/s3_ssh3_sftp_cli.c
        src/ssh3/s3_ssh3_cm.c
        src/ssh3/s3_ssh3_session_cli.c
    )

    target_include_directories(s3core
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/src/core
            ${CMAKE_CURRENT_SOURCE_DIR}/src/event
            ${CMAKE_CURRENT_SOURCE_DIR}/src/event/quic
            ${CMAKE_CURRENT_SOURCE_DIR}/src/h3
            ${CMAKE_CURRENT_SOURCE_DIR}/src/ssh3
            ${CMAKE_CURRENT_SOURCE_DIR}/src/os/win
        )

    target_compile_definitions(s3core PUBLIC S3_WIN32=1)

    # the quic branch of the udp event path; the quic layer rides the
    # cross-built OpenSSL like the unix build below
    target_compile_definitions(s3core PUBLIC S3_HAVE_QUIC=1)

    # the iocp event backend, visible to the tests and the app so the
    # seam headers see the same switches as s3core
    if(S3_USE_IOCP)
        target_compile_definitions(s3core PUBLIC S3_USE_IOCP=1)
    endif()

    target_link_libraries(s3core PUBLIC ws2_32)
    target_compile_options(s3core PRIVATE -Wall -Wextra -Werror)

    # the QUIC crypto layer (HKDF/AEAD, the OpenSSL QUIC TLS API); the
    # cross-built OpenSSL, the same ~/opt layout as the unix build
    if(EXISTS $ENV{HOME}/opt/openssl-3.5-mingw)
        list(PREPEND CMAKE_PREFIX_PATH $ENV{HOME}/opt/openssl-3.5-mingw)
    endif()

    find_package(OpenSSL 3.5 REQUIRED)

    message(STATUS "OpenSSL ${OPENSSL_VERSION} (crypto: ${OPENSSL_CRYPTO_LIBRARY})")

    target_link_libraries(s3core PUBLIC OpenSSL::Crypto OpenSSL::SSL)

    set(S3_WIN_TESTS
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
        test_h3_parse
        test_h3_qpack
        test_h3_uni
        test_ssh3_version
        test_ssh3_wire
        test_ssh3_message
        test_ssh3_request
        test_ssh3_channel
        test_ssh3_conversation
        test_ssh3_dgram
        test_ssh3_forward
        test_ssh3_forward_policy
        test_ssh3_dos_guard
        test_ssh3_sftp_codec
        test_ssh3_cm
        test_ssh3_reverse
        test_os_win
    )

    enable_testing()

    foreach(S3_TEST ${S3_WIN_TESTS})
        add_executable(${S3_TEST} tests/${S3_TEST}.c)
        target_link_libraries(${S3_TEST} PRIVATE s3core)
        target_include_directories(${S3_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        target_compile_options(${S3_TEST} PRIVATE -Wall -Wextra -Werror)
        add_test(NAME ${S3_TEST} COMMAND ${S3_TEST})
    endforeach()

    # the product client (P9 wave 3, stage A): the exec and the
    # interactive console session over the proved client modules;
    # the win shape of the shared app body (the unix shape builds in
    # the branch below, docs/PLAN.md 8.1)
    add_executable(ssh3 app/ssh3_client.c)
    target_compile_options(ssh3 PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ssh3 PRIVATE s3core)

    # the icon + VERSIONINFO object (go-winres, app/winres/): linked
    # as an external COFF object, regenerate on a version bump
    set_source_files_properties(app/winres/rsrc_windows_amd64.syso
        PROPERTIES EXTERNAL_OBJECT TRUE LANGUAGE C)
    target_sources(ssh3 PRIVATE app/winres/rsrc_windows_amd64.syso)

    return()
endif()

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

# the permanent privilege drop of the sftp jail child: setresuid and
# setresgid drop the saved set ids too, so the child cannot restore
# the root with seteuid(0) (the setuid alone leaves the saved id at
# zero).  The fallback without them verifies the drop instead.

check_c_source_compiles(
    "
    #include <sys/types.h>
    #include <unistd.h>
    int main(void) {
        uid_t uid = 0;
        gid_t gid = 0;
        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);
        return 0;
    }
    "
    S3_HAVE_SETRESUID)

unset(CMAKE_REQUIRED_DEFINITIONS)

# the system password verifier (the shadow step, PLAN.md 8.2): the
# crypt(3) hash check rides crypt_r of <crypt.h> (libcrypt), the
# shadow entry comes through getspnam(3) of <shadow.h>; both are
# unix-only - the win beachhead never compiles the auth module.  A
# build without crypt_r keeps the verifier fail-closed (every attempt
# declines), the file backend stays untouched
find_library(S3_CRYPT_LIBRARY NAMES crypt)
mark_as_advanced(S3_CRYPT_LIBRARY)

if(S3_CRYPT_LIBRARY)
    set(CMAKE_REQUIRED_LIBRARIES ${S3_CRYPT_LIBRARY})
endif()

check_c_source_compiles(
    "
    #include <crypt.h>
    int main(void) {
        struct crypt_data data;
        data.initialized = 0;
        return crypt_r (\"key\", \"aa\", &data) == 0;
    }
    "
    S3_HAVE_CRYPT_R)

unset(CMAKE_REQUIRED_LIBRARIES)

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
    src/ssh3/s3_ssh3_dos_guard.c
    src/ssh3/s3_ssh3_oidc.c
    src/ssh3/s3_ssh3_oidc_client.c
    src/ssh3/s3_ssh3_auth_jwt.c
    src/ssh3/s3_ssh3_session_cli.c
    src/ssh3/s3_ssh3_forward.c
    src/ssh3/s3_ssh3_forward_policy.c
    src/ssh3/s3_ssh3_reverse.c
    src/ssh3/s3_ssh3_agent.c
    src/ssh3/s3_ssh3_sftp_codec.c
    src/ssh3/s3_ssh3_sftp_srv.c
    src/ssh3/s3_ssh3_sftp_jail.c
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

# the crypt link of the system password verifier (the check above);
# a libcrypt-less host (crypt lives in libc there) still defines the
# switch when the compile check passed
if(S3_HAVE_CRYPT_R)

    if(S3_CRYPT_LIBRARY)
        target_link_libraries(s3core PUBLIC ${S3_CRYPT_LIBRARY})
    endif()

    target_compile_definitions(s3core PUBLIC S3_HAVE_CRYPT_R=1)

endif()

if(S3_HAVE_UDP_SEGMENT)
    target_compile_definitions(s3core PUBLIC S3_HAVE_UDP_SEGMENT=1)
endif()

if(S3_HAVE_SETRESUID)
    target_compile_definitions(s3core PUBLIC S3_HAVE_SETRESUID=1)
endif()

if(S3_HAVE_ADDRINFO_CMSG)
    target_compile_definitions(s3core PUBLIC S3_HAVE_ADDRINFO_CMSG=1)
endif()

# the quic branch of the udp event path (the win build defines it in
# the win branch above)
target_compile_definitions(s3core PUBLIC S3_HAVE_QUIC=1)

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

    # the product client (PLAN 8.1): the portable client logic of the
    # P9 beachhead over the unix legs (the termios tty helpers, the
    # SIGINT/SIGTERM stop flag and the SIGWINCH resize, the UDS agent
    # and control-master transports)
    add_executable(ssh3 app/ssh3_client.c)
    target_compile_options(ssh3 PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(ssh3 PRIVATE s3core Threads::Threads)
endif()

# the fuzz harnesses link the libFuzzer runtime through their own
# link options, the global linker flags stay fuzz-free so the CMake
# compiler checks keep linking their own main()

if(S3_BUILD_FUZZ)
    foreach(S3_FUZZ fuzz_sftp_frame fuzz_cm_frame fuzz_forward_target fuzz_wire fuzz_message
                    fuzz_quic_state fuzz_h3_parse)
        add_executable(${S3_FUZZ} tests/fuzz/${S3_FUZZ}.c)
        target_compile_options(${S3_FUZZ} PRIVATE -Wall -Wextra -Werror)
        target_link_options(${S3_FUZZ} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(${S3_FUZZ} PRIVATE s3core)
        set_target_properties(${S3_FUZZ} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests/fuzz)
    endforeach()

    # the stateful h3 target (P6.3): one session per exec, the qpack
    # table and the uni machines live across the input steps
    add_executable(fuzz_h3_state tests/fuzz/fuzz_h3_state.c)
    target_compile_options(fuzz_h3_state PRIVATE -Wall -Wextra -Werror)
    target_link_options(fuzz_h3_state PRIVATE -fsanitize=fuzzer)
    target_link_libraries(fuzz_h3_state PRIVATE s3core)
    set_target_properties(fuzz_h3_state PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests/fuzz)

    # the stateful ssh3 target (P6.4): one conversation per exec, the
    # channel registry, the accept queue and the datagram stores live
    # across the input steps
    add_executable(fuzz_ssh3_state tests/fuzz/fuzz_ssh3_state.c)
    target_compile_options(fuzz_ssh3_state PRIVATE -Wall -Wextra -Werror)
    target_link_options(fuzz_ssh3_state PRIVATE -fsanitize=fuzzer)
    target_link_libraries(fuzz_ssh3_state PRIVATE s3core)
    set_target_properties(fuzz_ssh3_state PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests/fuzz)

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
    test_cmsg
    test_quic_transport
    test_quic_frames
    test_quic_protection
    test_quic_tokens
    test_quic_ssl
    test_quic_core
    test_quic_output
    test_quic_ack
    test_quic_e2e
    test_quic_idle
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
    test_ssh3_dos_guard
    test_ssh3_oidc
    test_ssh3_auth_jwt
    test_ssh3_session_cli
    test_ssh3_forward
    test_ssh3_forward_policy
    test_ssh3_agent
    test_ssh3_reverse
    test_ssh3_sftp_codec
    test_ssh3_sftp_srv
    test_ssh3_sftp_jail
    test_ssh3_sftp_cli
    test_ssh3_cm
    test_auth_ct
)

enable_testing()

if(NOT S3_BUILD_FUZZ)
    foreach(S3_TEST ${S3_TESTS})
        add_executable(${S3_TEST} tests/${S3_TEST}.c)
        target_link_libraries(${S3_TEST} PRIVATE s3core)
        target_include_directories(${S3_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        target_compile_options(${S3_TEST} PRIVATE -Wall -Wextra -Werror)

        # the source path of the tree: the pins that read the sources
        # (the constant-time compares of the secrets) need it
        target_compile_definitions(${S3_TEST}
            PRIVATE S3_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

        add_test(NAME ${S3_TEST} COMMAND ${S3_TEST})
    endforeach()
endif()
