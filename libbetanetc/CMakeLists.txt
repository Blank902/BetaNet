# Governance/compliance logic
set(GOV_SRC
    ../src/gov/gov.c
)
add_library(betanetc
    betanet.c
    ../include/betanet/betanet.h
    ../include/betanet/scion.h
    ../include/betanet/htx_frames.h
    ../include/betanet/htx_noise_integration.h
    ../include/betanet/htx_transport.h
    ../include/betanet/htx_calibration.h
    ../include/betanet/path_optimization.h
    ../include/betanet/http2_emulation.h
    ../include/betanet/pq_hybrid.h
    ../include/betanet/payment.h
    ../src/htx/htx.c
    ../src/htx/ticket.c
    ../src/htx/htx_tickets.c
    ../src/htx/htx_frames.c
    ../src/htx/htx_noise_integration.c
    ../src/htx/htx_transport.c
    ../src/htx/http2_emulation.c
    ../src/htx/origin_calibration.c
    ../src/noise/noise.c
    ../src/shape/shape.c
    ../src/path/path.c
    ../src/path/path_optimization.c
    ../src/path/scion.c
    ../src/boot/boot.c
    ../src/util/util.c
    ../src/util/cert_utils.c
    ../src/util/performance.c
    ../src/util/scion.c
    ../src/util/secure_utils.c
    ../src/util/secure_log.c
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