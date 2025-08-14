# Unit tests CMake file

add_executable(fingerprint_regression_test fingerprint_regression_test.c)
target_link_libraries(fingerprint_regression_test betanetc)
target_include_directories(fingerprint_regression_test PRIVATE ${CMAKE_SOURCE_DIR})

add_executable(protocol_regression_test protocol_regression_test.c)
target_link_libraries(protocol_regression_test betanetc)
target_include_directories(protocol_regression_test PRIVATE ${CMAKE_SOURCE_DIR})

# SCION basic functionality test - BetaNet 1.1 compliance
add_executable(test_scion_basic test_scion_basic.c)
target_link_libraries(test_scion_basic betanetc)
target_include_directories(test_scion_basic PRIVATE ${CMAKE_SOURCE_DIR})

# Fuzzing harness (libFuzzer)
add_executable(ticket_parser_fuzz ticket_parser_fuzz.c)
target_link_libraries(ticket_parser_fuzz betanetc)
target_include_directories(ticket_parser_fuzz PRIVATE ${CMAKE_SOURCE_DIR})
# To build with libFuzzer: add -fsanitize=fuzzer,address,undefined to CMAKE_C_FLAGS