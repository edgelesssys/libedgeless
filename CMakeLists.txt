cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(libedgeless C CXX)

add_library(ecrypto STATIC
    crypto.cpp)

target_link_libraries(ecrypto
    PUBLIC crypto)
