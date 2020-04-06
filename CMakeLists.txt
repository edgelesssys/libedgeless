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
set(sources ${SRC}/crypto.cc)
set(compileoptions "-mrdrnd")
set(libs crypto)
add_library(edgeless STATIC
    ${sources})

# Object library to be incorporated into other libraries
add_library(edgeless_o OBJECT
    ${sources})

target_compile_options(edgeless
    PUBLIC ${compileoptions})

target_compile_options(edgeless_o
    PUBLIC ${compileoptions})

# link OpenSSL's crypto lib
# TODO: check for presence
target_link_libraries(edgeless
    PUBLIC ${libs})

target_link_libraries(edgeless_o
    PUBLIC ${libs})

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
option(BUILD_TESTS "Build tests" OFF)
if (BUILD_TESTS)
    enable_testing()
    set(BUILD_GMOCK OFF CACHE BOOL "no gmock")
    set(INSTALL_GTEST OFF CACHE BOOL "no googletest install")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/googletest ./googletest)
    include(GoogleTest)

    # ecrypto
    add_executable(crypto_test
        tests/crypto_test.cc)

    target_link_libraries(crypto_test 
        gtest
        gtest_main
        edgeless)

    gtest_discover_tests(crypto_test)
endif()
