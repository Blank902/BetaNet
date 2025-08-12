add_library(pay STATIC pay.c)
target_include_directories(pay PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ../../include)