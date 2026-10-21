cmake_minimum_required(VERSION 3.20)
project(drvscan VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# DRVSCAN_VERSION for code (also from project VERSION)
add_compile_definitions(DRVSCAN_VERSION="0.2.0" DRVSCAN_BLOCKLIST_SCHEMA="0.2.0")

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
  # Warnings as errors in Release (step 19 — enable after correctness fixes)
  add_compile_options($<$<CONFIG:Release>:/WX>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:/WX>)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  add_compile_options($<$<CONFIG:Release>:-Werror>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Werror>)
endif()

include_directories(${CMAKE_SOURCE_DIR}/vendor)

set(DRVSCAN_SOURCES
  src/main.cpp
)
add_executable(drvscan ${DRVSCAN_SOURCES})
target_include_directories(drvscan PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/vendor)
target_link_libraries(drvscan PRIVATE drvscan_lib)

# Copy bundled blocklist next to binary for out-of-tree builds
add_custom_command(TARGET drvscan POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:drvscan>/data"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/data/blocklist.json" "$<TARGET_FILE_DIR:drvscan>/data/blocklist.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/data/microsoft_roots.json" "$<TARGET_FILE_DIR:drvscan>/data/microsoft_roots.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/data/device_map.json" "$<TARGET_FILE_DIR:drvscan>/data/device_map.json"
)

# Install (20)
install(TARGETS drvscan RUNTIME DESTINATION .)
install(FILES data/blocklist.json data/microsoft_roots.json data/device_map.json DESTINATION data)
install(FILES data/blocklist.sha256 DESTINATION data OPTIONAL)

# Tests
enable_testing()
set(TEST_SOURCES
  tests/test_hash.cpp
  tests/test_pe.cpp
  tests/test_pe_structure.cpp
  tests/test_path.cpp
  tests/test_json.cpp
  tests/test_blocklist.cpp
  tests/test_risk.cpp
  tests/test_verify.cpp
  tests/test_handles.cpp
  tests/test_devmap.cpp
  tests/test_integration.cpp
)
add_library(drvscan_lib STATIC
  src/hash.cpp
  src/blocklist.cpp
  src/pathcheck.cpp
  src/pe.cpp
  src/risk.cpp
  src/output.cpp
  src/verify.cpp
  src/enum.cpp
  src/update.cpp
  src/handles.cpp
  src/devmap.cpp
  src/objscan.cpp
  src/sigcontext.cpp
)
target_include_directories(drvscan_lib PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/vendor)
target_link_libraries(drvscan_lib PUBLIC psapi bcrypt wintrust crypt32 shlwapi winhttp version)

# Single TU that provides doctest main
add_library(doctest_main STATIC tests/doctest_main.cpp)
target_include_directories(doctest_main PUBLIC ${CMAKE_SOURCE_DIR}/vendor)
target_compile_options(doctest_main PRIVATE /Wv:18)

add_executable(drvscan_tests ${TEST_SOURCES})
target_include_directories(drvscan_tests PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/vendor)
target_link_libraries(drvscan_tests PRIVATE drvscan_lib doctest_main)
target_compile_options(drvscan_tests PRIVATE /Wv:18)
add_test(NAME drvscan_tests COMMAND drvscan_tests)

install(TARGETS drvscan_tests RUNTIME DESTINATION . OPTIONAL)
