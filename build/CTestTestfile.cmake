# CMake generated Testfile for 
# Source directory: C:/Users/007/drvscan
# Build directory: C:/Users/007/drvscan/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test([=[drvscan_tests]=] "C:/Users/007/drvscan/build/Debug/drvscan_tests.exe")
  set_tests_properties([=[drvscan_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/007/drvscan/CMakeLists.txt;87;add_test;C:/Users/007/drvscan/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test([=[drvscan_tests]=] "C:/Users/007/drvscan/build/Release/drvscan_tests.exe")
  set_tests_properties([=[drvscan_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/007/drvscan/CMakeLists.txt;87;add_test;C:/Users/007/drvscan/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test([=[drvscan_tests]=] "C:/Users/007/drvscan/build/MinSizeRel/drvscan_tests.exe")
  set_tests_properties([=[drvscan_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/007/drvscan/CMakeLists.txt;87;add_test;C:/Users/007/drvscan/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test([=[drvscan_tests]=] "C:/Users/007/drvscan/build/RelWithDebInfo/drvscan_tests.exe")
  set_tests_properties([=[drvscan_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/007/drvscan/CMakeLists.txt;87;add_test;C:/Users/007/drvscan/CMakeLists.txt;0;")
else()
  add_test([=[drvscan_tests]=] NOT_AVAILABLE)
endif()
