# CMakeLists.txt for BetaNet Government Layer
add_library(gov_protocol STATIC gov_protocol.c)
target_include_directories(gov_protocol PUBLIC ${CMAKE_SOURCE_DIR}/include)
