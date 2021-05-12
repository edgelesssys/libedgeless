cmake_minimum_required(VERSION 3.10)
project(libedgeless)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic -Werror)

if(NOT LIBEDG_NOTEST)
  execute_process(
    COMMAND git submodule update --init 3rdparty/googletest
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  set(GOOGLETEST_VERSION 1.10.0)
  add_subdirectory(3rdparty/googletest/googletest)
endif()

#
# lib
#

add_library(edgeless_o OBJECT
  src/crypto.cc)

target_include_directories(edgeless_o
  PUBLIC include
  PRIVATE include/edgeless)

target_link_libraries(edgeless_o crypto)

add_library(edgeless)
target_link_libraries(edgeless edgeless_o)

#
# test
#

if(NOT LIBEDG_NOTEST)
  add_executable(edgeless_test
    src/crypto_test.cc)

  target_link_libraries(edgeless_test edgeless gtest_main)

  include(GoogleTest)
  enable_testing()
  gtest_discover_tests(edgeless_test)
endif()
