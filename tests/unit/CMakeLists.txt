# Unit tests CMake file

add_executable(fingerprint_regression_test fingerprint_regression_test.c)
target_link_libraries(fingerprint_regression_test betanetc)

add_executable(protocol_regression_test protocol_regression_test.c)
target_link_libraries(protocol_regression_test betanetc)

# Fuzzing harness (libFuzzer)
add_executable(ticket_parser_fuzz ticket_parser_fuzz.c)
target_link_libraries(ticket_parser_fuzz betanetc)
# To build with libFuzzer: add -fsanitize=fuzzer,address,undefined to CMAKE_C_FLAGS