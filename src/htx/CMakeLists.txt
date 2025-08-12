add_library(htx htx.c ticket.c)
target_include_directories(htx PUBLIC ../../include)

if(BETANET_ENABLE_QUIC)
    # Example: find_package(picoquic REQUIRED) or add_subdirectory(picoquic)
    # target_link_libraries(htx PUBLIC picoquic)
    target_compile_definitions(htx PUBLIC BETANET_ENABLE_QUIC=1)
endif()