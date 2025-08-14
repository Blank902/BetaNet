# Performance tests CMake file

add_executable(htx_noise_performance_test htx_noise_performance_test.c)
target_link_libraries(htx_noise_performance_test betanetc)
target_include_directories(htx_noise_performance_test PRIVATE ${CMAKE_SOURCE_DIR})

# Add to CTest (optional for performance tests)
add_test(NAME htx_noise_performance COMMAND htx_noise_performance_test)
