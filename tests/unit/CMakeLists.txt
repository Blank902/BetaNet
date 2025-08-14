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

# HTX Transport Protocol test - BetaNet 1.1 compliance
add_executable(test_htx_transport test_htx_transport.c)
target_link_libraries(test_htx_transport betanetc)
target_include_directories(test_htx_transport PRIVATE ${CMAKE_SOURCE_DIR})

# HTX Origin Calibration test - BetaNet 1.1 §5.1 compliance
add_executable(test_htx_calibration test_htx_calibration.c)
target_link_libraries(test_htx_calibration betanetc)
target_include_directories(test_htx_calibration PRIVATE ${CMAKE_SOURCE_DIR})

# Fuzzing harness (libFuzzer)
add_executable(ticket_parser_fuzz ticket_parser_fuzz.c)
target_link_libraries(ticket_parser_fuzz betanetc)
target_include_directories(ticket_parser_fuzz PRIVATE ${CMAKE_SOURCE_DIR})
# To build with libFuzzer: add -fsanitize=fuzzer,address,undefined to CMAKE_C_FLAGS
add_executable(test_gov_protocol test_gov_protocol.c)
target_link_libraries(test_gov_protocol betanetc gov_protocol)
target_include_directories(test_gov_protocol PRIVATE ${CMAKE_SOURCE_DIR})

# Simple HTX calibration test for debugging
add_executable(test_htx_calibration_simple test_htx_calibration_simple.c)
target_link_libraries(test_htx_calibration_simple betanetc)
target_include_directories(test_htx_calibration_simple PRIVATE ${CMAKE_SOURCE_DIR})

# Minimal test for debugging
add_executable(test_minimal test_minimal.c)
target_include_directories(test_minimal PRIVATE ${CMAKE_SOURCE_DIR})

# Mock HTX calibration test (no OpenSSL)
add_executable(test_htx_calibration_mock test_htx_calibration_mock.c)
target_include_directories(test_htx_calibration_mock PRIVATE ${CMAKE_SOURCE_DIR})

# Path optimization test - BetaNet §4.3 compliance
add_executable(test_path_optimization test_path_optimization.c)
target_link_libraries(test_path_optimization betanetc)

# HTTP/2 emulation test - BetaNet §5.5 compliance
add_executable(http2_emulation_test http2_emulation_test.c)
target_link_libraries(http2_emulation_test betanetc)
target_include_directories(http2_emulation_test PRIVATE ${CMAKE_SOURCE_DIR})
target_include_directories(test_path_optimization PRIVATE ${CMAKE_SOURCE_DIR})