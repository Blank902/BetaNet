add_library(htx htx.c ticket.c htx_tickets.c http2_emulation.c)
target_include_directories(htx PUBLIC ../../include)
target_link_libraries(htx PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# QUIC integration logic
if(BETANET_ENABLE_QUIC)
    target_compile_definitions(htx PUBLIC BETANET_ENABLE_QUIC=1)
    # Link selected QUIC library to htx
    if(BETANET_QUIC_LIBRARY STREQUAL "PICOQUIC")
        # TODO: Ensure picoquic is available and linked
        target_link_libraries(htx PUBLIC picoquic)
        target_compile_definitions(htx PUBLIC BETANET_QUIC_LIB_PICOQUIC=1)
    elseif(BETANET_QUIC_LIBRARY STREQUAL "MSQUIC")
        # TODO: Ensure msquic is available and linked
        target_link_libraries(htx PUBLIC msquic)
        target_compile_definitions(htx PUBLIC BETANET_QUIC_LIB_MSQUIC=1)
    elseif(BETANET_QUIC_LIBRARY STREQUAL "QUICHE")
        # TODO: Ensure quiche is available and linked
        target_link_libraries(htx PUBLIC quiche)
        target_compile_definitions(htx PUBLIC BETANET_QUIC_LIB_QUICHE=1)
    else()
        message(FATAL_ERROR "BETANET_ENABLE_QUIC is ON, but BETANET_QUIC_LIBRARY is not set to a supported value.")
    endif()
endif()