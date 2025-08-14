# Integration tests CMake file

add_executable(noise_handshake_test noise_handshake_test.c)
target_link_libraries(noise_handshake_test betanetc)
target_include_directories(noise_handshake_test PRIVATE ${CMAKE_SOURCE_DIR})

# Add to CTest
add_test(NAME noise_handshake_integration COMMAND noise_handshake_test)
