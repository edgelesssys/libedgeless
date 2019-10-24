cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(libedgeless C CXX)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/googletest ./googletest)

add_library(ecrypto STATIC
    crypto.cpp)

target_compile_options(ecrypto
    PUBLIC "-mrdrnd")

target_link_libraries(ecrypto
    PUBLIC crypto)

#
# TESTS
#
add_executable(test_ecrypto
    tests/test_crypto.cpp)

target_link_libraries(test_ecrypto
    PUBLIC ecrypto)   

#gtest_add_tests(TARGET test_ecrypto)
