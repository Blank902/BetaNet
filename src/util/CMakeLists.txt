# BetaNet Utilities Module
# Secure utilities, logging, and platform abstractions

add_library(betanet_util STATIC
    util.c
    secure_utils.c
    secure_log.c
    performance.c
    cert_utils.c
    scion.c
    platform.h  # Header-only platform abstractions
)

target_include_directories(betanet_util
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(betanet_util
        PRIVATE
            ws2_32      # Winsock
            bcrypt      # Windows cryptography
            crypt32     # Certificate management
    )
else()
    target_link_libraries(betanet_util
        PRIVATE
            pthread     # POSIX threads
            m           # Math library
    )
endif()

# Compiler-specific security flags
if(MSVC)
    target_compile_options(betanet_util
        PRIVATE
            /GS         # Buffer security check
            /guard:cf   # Control Flow Guard
            /analyze    # Code analysis
    )
else()
    target_compile_options(betanet_util
        PRIVATE
            -fstack-protector-strong    # Stack protection
            -D_FORTIFY_SOURCE=2         # Runtime buffer overflow detection
            -Wformat-security           # Format string security
    )
endif()

# Export target for other modules
set_target_properties(betanet_util PROPERTIES
    EXPORT_NAME util
    OUTPUT_NAME betanet_util
)