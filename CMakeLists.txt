cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(libedgeless C CXX)
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

#
# LIBS
#
add_library(ecrypto STATIC
    ${SRC}/ecrypto.cpp)

target_compile_options(ecrypto
    PUBLIC "-mrdrnd")

# link OpenSSL's crypto lib
# TODO: check for presence
target_link_libraries(ecrypto
    PUBLIC crypto)

#
# TESTS
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/googletest ./googletest)
include(GoogleTest)

# ecrypto
add_executable(test_ecrypto
    tests/test_crypto.cpp)

target_link_libraries(test_ecrypto 
    gtest
    ecrypto)

gtest_discover_tests(test_ecrypto)
