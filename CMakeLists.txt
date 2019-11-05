cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(libedgeless C CXX)
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/edgeless)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

#
# Targets
#
add_library(edgeless STATIC
    ${SRC}/crypto.cc)

target_compile_options(edgeless
    PUBLIC "-mrdrnd")

# link OpenSSL's crypto lib
# TODO: check for presence
target_link_libraries(edgeless
    PUBLIC crypto)

#
# Install
#
install(
  TARGETS edgeless
  EXPORT edgeless
  DESTINATION edgeless
)

install(
  EXPORT edgeless
  DESTINATION edgeless
  NAMESPACE edgeless::
)

#
# Tests
#
option(WITH_TESTS "Build tests" OFF)
if (WITH_TESTS)
    enable_testing()
    set(BUILD_GMOCK OFF CACHE BOOL "no gmock")
    set(INSTALL_GTEST OFF CACHE BOOL "no googletest install")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/googletest ./googletest)
    include(GoogleTest)

    # ecrypto
    add_executable(test_crypto
        tests/test_crypto.cc)

    target_link_libraries(test_crypto 
        gtest
        gtest_main
        edgeless)

    gtest_discover_tests(test_crypto)
endif()
