cmake_minimum_required(VERSION 3.20)

project(ssh3-c LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# XSI strerror_r (int return), posix_memalign, sysconf, STDERR_FILENO.
add_compile_definitions(_POSIX_C_SOURCE=200809L)

set(S3_CORE_SOURCES
    src/core/s3_string.c
    src/core/s3_palloc.c
    src/core/s3_buf.c
    src/core/s3_rbtree.c
    src/core/s3_log.c
    src/os/unix/s3_errno.c
    src/event/s3_event.c
    src/event/s3_event_posted.c
    src/event/s3_event_timer.c
    src/event/s3_connection.c
    src/event/s3_event_udp.c
    src/event/modules/s3_epoll_module.c
    src/os/unix/s3_udp_sendmsg_chain.c
    src/os/unix/s3_udp_recv.c
)

add_library(s3core STATIC ${S3_CORE_SOURCES})

target_include_directories(s3core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/event
        ${CMAKE_CURRENT_SOURCE_DIR}/src/os/unix
)

target_compile_options(s3core PRIVATE -Wall -Wextra -Werror)

find_package(Threads REQUIRED)

add_executable(s3gso_bench bench/gso_bench.c)
target_compile_options(s3gso_bench PRIVATE -Wall -Wextra -Werror)
target_link_libraries(s3gso_bench PRIVATE Threads::Threads)

set(S3_TESTS
    test_pool
    test_buf
    test_rbtree
    test_queue
    test_string
    test_log
    test_event
    test_udp
)

enable_testing()

foreach(S3_TEST ${S3_TESTS})
    add_executable(${S3_TEST} tests/${S3_TEST}.c)
    target_link_libraries(${S3_TEST} PRIVATE s3core)
    target_include_directories(${S3_TEST} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_compile_options(${S3_TEST} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${S3_TEST} COMMAND ${S3_TEST})
endforeach()
