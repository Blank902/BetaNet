# Governance/compliance logic
set(GOV_SRC
    ../src/gov/gov.c
)
add_library(betanetc
    betanet.c
    ../include/betanet/betanet.h
    ../src/htx/htx.c
    ../src/htx/ticket.c
    ../src/noise/noise.c
    ../src/shape/shape.c
    ../src/path/path.c
    ../src/boot/boot.c
    ../src/util/util.c
    ../src/util/cert_utils.c
    ../src/pay/pay.c
)

target_include_directories(betanetc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    $<TARGET_PROPERTY:OpenSSL::SSL,INTERFACE_INCLUDE_DIRECTORIES>
)
target_link_libraries(betanetc PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(BETANET_ENABLE_QUIC)
    # Example: find_package(picoquic REQUIRED) or add_subdirectory(picoquic)
    # target_link_libraries(betanetc PUBLIC picoquic)
    target_compile_definitions(betanetc PUBLIC BETANET_ENABLE_QUIC=1)
endif()