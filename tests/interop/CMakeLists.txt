# Interop tests CMake file

add_executable(interop_protocol_test interop_protocol_test.c)
target_link_libraries(interop_protocol_test betanetc)
target_include_directories(interop_protocol_test PRIVATE ${CMAKE_SOURCE_DIR})