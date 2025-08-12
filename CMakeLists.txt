cmake_minimum_required(VERSION 3.15)
project(betanet C)

set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/openssl")
find_package(OpenSSL REQUIRED)

set(CMAKE_C_STANDARD 11)

add_subdirectory(libbetanetc)
add_subdirectory(cli/bnetc-cli)

if(BETANET_ENABLE_QUIC)
    message(STATUS "QUIC transport enabled (picoquic/msquic must be available)")
endif()
enable_testing()
add_subdirectory(tests/unit)
add_subdirectory(tests/interop)