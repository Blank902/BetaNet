cmake_minimum_required(VERSION 3.15)
project(betanet C)

# Option to enable QUIC transport and select QUIC library
option(BETANET_ENABLE_QUIC "Enable QUIC transport support" OFF)
set(BETANET_QUIC_LIBRARY "" CACHE STRING "QUIC library to use (PICOQUIC, MSQUIC, QUICHE)")

set_property(CACHE BETANET_QUIC_LIBRARY PROPERTY STRINGS PICOQUIC MSQUIC QUICHE "")

if(BETANET_ENABLE_QUIC)
    if(NOT BETANET_QUIC_LIBRARY)
        message(FATAL_ERROR "BETANET_ENABLE_QUIC is ON, but BETANET_QUIC_LIBRARY is not set. Please set to one of: PICOQUIC, MSQUIC, QUICHE.")
    endif()

    if(BETANET_QUIC_LIBRARY STREQUAL "PICOQUIC")
        # TODO: find_package(picoquic REQUIRED) or add_subdirectory(picoquic)
        set(QUIC_LIB_TARGET picoquic)
        add_definitions(-DBETANET_QUIC_LIB_PICOQUIC)
        message(STATUS "QUIC transport enabled with picoquic")
    elseif(BETANET_QUIC_LIBRARY STREQUAL "MSQUIC")
        # TODO: find_package(msquic REQUIRED) or add_subdirectory(msquic)
        set(QUIC_LIB_TARGET msquic)
        add_definitions(-DBETANET_QUIC_LIB_MSQUIC)
        message(STATUS "QUIC transport enabled with msquic")
    elseif(BETANET_QUIC_LIBRARY STREQUAL "QUICHE")
        # TODO: find_package(quiche REQUIRED) or add_subdirectory(quiche)
        set(QUIC_LIB_TARGET quiche)
        add_definitions(-DBETANET_QUIC_LIB_QUICHE)
        message(STATUS "QUIC transport enabled with quiche")
    else()
        message(FATAL_ERROR "Unknown QUIC library: ${BETANET_QUIC_LIBRARY}")
    endif()
endif()

# Option to enable PQ hybrid handshake (Kyber768)
option(NOISE_PQ_HYBRID_ENABLED "Enable PQ hybrid handshake with Kyber768" OFF)
if(NOISE_PQ_HYBRID_ENABLED)
    add_definitions(-DNOISE_PQ_HYBRID_ENABLED)
    # TODO: Link Kyber768 implementation here (e.g., PQClean or liboqs)
    # Example for PQClean (assumes kyber768_clean sources in external/kyber768):
    # add_subdirectory(external/kyber768)
    # set(KYBER768_LIB kyber768_clean)
    # target_link_libraries(betanetc PRIVATE ${KYBER768_LIB})
    message(STATUS "PQ hybrid handshake enabled (Kyber768 will be linked)")
endif()

# Try to find OpenSSL in standard locations first
find_package(OpenSSL QUIET)

if(NOT OpenSSL_FOUND)
    # Try vcpkg or other package managers
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(OPENSSL QUIET openssl)
    endif()
    
    if(NOT OPENSSL_FOUND)
        # For development, we can use a minimal crypto implementation
        message(STATUS "OpenSSL not found, using minimal crypto stubs for development")
        add_definitions(-DBETANET_USE_MINIMAL_CRYPTO)
        set(OPENSSL_LIBRARIES "")
        set(OPENSSL_INCLUDE_DIRS "")
    endif()
else()
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
endif()

set(CMAKE_C_STANDARD 11)

add_subdirectory(libbetanetc)
add_subdirectory(cli/bnetc-cli)

if(BETANET_ENABLE_QUIC)
    message(STATUS "QUIC transport enabled (picoquic/msquic must be available)")
endif()
enable_testing()
add_subdirectory(tests/unit)
add_subdirectory(tests/interop)
add_subdirectory(tests/integration)
add_subdirectory(tests/performance)

# --- SLSA Provenance Metadata Generation ---
# Function to generate provenance metadata for a build artifact.
function(generate_provenance ARTIFACT_PATH)
    # Get current timestamp
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E date
        OUTPUT_VARIABLE BUILD_TIMESTAMP
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    # Compute SHA256 hash of the artifact
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E sha256sum ${ARTIFACT_PATH}
        OUTPUT_VARIABLE ARTIFACT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    # Write minimal provenance JSON (SLSA-style)
    file(WRITE "${ARTIFACT_PATH}.provenance.json"
        "{\n"
        "  \"_type\": \"https://in-toto.io/Statement/v0.1\",\n"
        "  \"subject\": [{\"name\": \"${ARTIFACT_PATH}\", \"digest\": {\"sha256\": \"${ARTIFACT_HASH}\"}}],\n"
        "  \"builder\": {\"id\": \"manual-cmake\"},\n"
        "  \"buildType\": \"cmake-build\",\n"
        "  \"invocation\": {\"command\": \"${CMAKE_COMMAND} --build .\"},\n"
        "  \"metadata\": {\"timestamp\": \"${BUILD_TIMESTAMP}\"}\n"
        "}\n"
    )
    # --- Cryptographically sign provenance metadata using OpenSSL ---
    # Generate detached signature for provenance file
    execute_process(
        COMMAND ${OPENSSL_EXECUTABLE} dgst -sha256 -sign "${CMAKE_SOURCE_DIR}/provenance-private.pem"
                -out "${ARTIFACT_PATH}.provenance.json.sig"
                "${ARTIFACT_PATH}.provenance.json"
        RESULT_VARIABLE SIGN_RESULT
        OUTPUT_VARIABLE SIGN_OUTPUT
        ERROR_VARIABLE SIGN_ERROR
    )
    if(NOT SIGN_RESULT EQUAL 0)
        message(WARNING "Provenance signing failed: ${SIGN_ERROR}")
    endif()
    # Store signed provenance (.provenance.json and .provenance.json.sig) alongside artifact

    # TODO: Add verification tooling for provenance consumers (e.g., OpenSSL verify)
    # TODO: Integrate signing and verification into CI/CD pipeline
    # TODO: Consider using DSSE/Sigstore for advanced provenance signing
endfunction()
# Usage: Call generate_provenance(<artifact-path>) after each build target if desired.