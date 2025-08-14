# Integration tests CMake file

add_executable(noise_handshake_test noise_handshake_test.c)
target_link_libraries(noise_handshake_test betanetc)
target_include_directories(noise_handshake_test PRIVATE ${CMAKE_SOURCE_DIR})

add_executable(tls_server_demo tls_server_demo.c)
target_link_libraries(tls_server_demo betanetc)
target_include_directories(tls_server_demo PRIVATE ${CMAKE_SOURCE_DIR})

add_executable(end_to_end_test end_to_end_test.c)
target_link_libraries(end_to_end_test betanetc)
target_include_directories(end_to_end_test PRIVATE ${CMAKE_SOURCE_DIR})

add_executable(performance_test performance_test.c)
target_link_libraries(performance_test betanetc)
target_include_directories(performance_test PRIVATE ${CMAKE_SOURCE_DIR})

# Add to CTest
add_test(NAME noise_handshake_integration COMMAND noise_handshake_test)
add_test(NAME tls_server_demo COMMAND tls_server_demo)
add_test(NAME end_to_end_test COMMAND end_to_end_test)
add_test(NAME performance_test COMMAND performance_test)
