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

function(v2_test_target name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${GMSSL_INCLUDE_DIR}")
    target_link_libraries(${name} PRIVATE "${GMSSL_LIBRARY}")
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

v2_test_target(test_compile tests/test_compile.c)
v2_test_target(test_v2 tests/test_v2.c)
