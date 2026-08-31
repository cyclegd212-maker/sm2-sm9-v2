cmake_minimum_required(VERSION 3.16)
project(sm2_sm9_v2_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

enable_testing()

set(GMSSL_ROOT "" CACHE PATH "Path to an installed GmSSL prefix")
if(NOT GMSSL_ROOT)
    message(FATAL_ERROR "GMSSL_ROOT must point to the pinned GmSSL installation prefix")
endif()

find_path(GMSSL_INCLUDE_DIR
    NAMES gmssl/sm2.h
    PATHS "${GMSSL_ROOT}/include"
    NO_DEFAULT_PATH)

find_library(GMSSL_LIBRARY
    NAMES gmssl
    PATHS "${GMSSL_ROOT}/lib"
    NO_DEFAULT_PATH)

if(NOT GMSSL_INCLUDE_DIR OR NOT GMSSL_LIBRARY)
    message(FATAL_ERROR "Unable to locate GmSSL headers/library below GMSSL_ROOT=${GMSSL_ROOT}")
endif()

add_executable(test_compile tests/test_compile.c)
target_include_directories(test_compile PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${GMSSL_INCLUDE_DIR}")
target_link_libraries(test_compile PRIVATE "${GMSSL_LIBRARY}")

add_test(NAME native_compile COMMAND test_compile)
