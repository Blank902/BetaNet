# Noise module build script

if(NOISE_PQ_HYBRID_ENABLED)
    # TODO: Add Kyber768 sources/headers here (e.g., PQClean or liboqs)
    # Example for PQClean:
    # target_include_directories(noise PRIVATE ${CMAKE_SOURCE_DIR}/external/kyber768)
    # target_link_libraries(noise PRIVATE kyber768_clean)
endif()

# --- SLSA Provenance Metadata Generation Example ---
# After building the noise library, generate provenance metadata.
# Replace <noise_lib_path> with the actual built artifact path if known.
# Example usage (uncomment and set correct path):
# generate_provenance(${CMAKE_CURRENT_BINARY_DIR}/libnoise.a)

# TODO: Integrate generate_provenance call after actual build step.