# CMake generated Testfile for 
# Source directory: C:/Users/xxlmn/Documents/BetaNet/tests/integration
# Build directory: C:/Users/xxlmn/Documents/BetaNet/build/tests/integration
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(noise_handshake_integration "C:/Users/xxlmn/Documents/BetaNet/build/tests/integration/Debug/noise_handshake_test.exe")
  set_tests_properties(noise_handshake_integration PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;8;add_test;C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(noise_handshake_integration "C:/Users/xxlmn/Documents/BetaNet/build/tests/integration/Release/noise_handshake_test.exe")
  set_tests_properties(noise_handshake_integration PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;8;add_test;C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(noise_handshake_integration "C:/Users/xxlmn/Documents/BetaNet/build/tests/integration/MinSizeRel/noise_handshake_test.exe")
  set_tests_properties(noise_handshake_integration PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;8;add_test;C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(noise_handshake_integration "C:/Users/xxlmn/Documents/BetaNet/build/tests/integration/RelWithDebInfo/noise_handshake_test.exe")
  set_tests_properties(noise_handshake_integration PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;8;add_test;C:/Users/xxlmn/Documents/BetaNet/tests/integration/CMakeLists.txt;0;")
else()
  add_test(noise_handshake_integration NOT_AVAILABLE)
endif()
