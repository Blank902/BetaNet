# HTTP/2 Emulation Tests CMakeLists.txt

# Unit test for HTTP/2 emulation
add_executable(http2_emulation_test http2_emulation_test.c)
target_include_directories(http2_emulation_test PRIVATE ../include)
target_link_libraries(http2_emulation_test htx)

# Integration test for HTX HTTP/2 emulation
add_executable(htx_http2_integration_test integration/htx_http2_integration_test.c)
target_include_directories(htx_http2_integration_test PRIVATE ../include)
target_link_libraries(htx_http2_integration_test htx)

# Add tests to CTest
add_test(NAME HTTP2EmulationUnitTest COMMAND http2_emulation_test)
add_test(NAME HTXHttp2IntegrationTest COMMAND htx_http2_integration_test)

# Set test properties
set_tests_properties(HTTP2EmulationUnitTest PROPERTIES
    TIMEOUT 30
    LABELS "unit;http2;emulation"
)

set_tests_properties(HTXHttp2IntegrationTest PROPERTIES
    TIMEOUT 60
    LABELS "integration;http2;htx"
)
