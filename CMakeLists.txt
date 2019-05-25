project(phc-winner-argon2)
cmake_minimum_required(VERSION 3.5)

set(ARGON2_VERSION 20171227)

###############
# Conan support
###############
find_file(CONANBUILDINFO "conanbuildinfo.cmake" PATHS ${CMAKE_BINARY_DIR})
if (CONANBUILDINFO)
    message(STATUS "CONANBUILDINFO: ${CONANBUILDINFO}")
    include(${CONANBUILDINFO})
    message(STATUS "conan_basic_setup()")
    conan_basic_setup()
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
    #set(CMAKE_BUILD_TYPE Debug)
endif()

message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")

option(MULTITHREADS "Enable multithreading" ON)
option(TESTS        "Enable unit tests"     ON)
option(BENCHMARKS   "Enable benchmark"      ON)
option(COVERAGE     "Enable coverage"       OFF)
option(SPECS        "Build documentation"   OFF)
option(ARCH         "Targeted architecture" "native")

set(ABI_VERSION 1)

#include(CheckCCompilerFlag)

if ((CMAKE_CXX_COMPILER_ID MATCHES "Clang")
 OR (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"))
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wno-type-limits")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")

    set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -g")
    set(CMAKE_C_FLAGS_RELEASE "-O3")

    if (COVERAGE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    endif()
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
if (MINGW)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
else()
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
set (CMAKE_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
set (CMAKE_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/lib")
set (CMAKE_INSTALL_BINDIR "${CMAKE_INSTALL_PREFIX}/bin")
message(STATUS "CMAKE_INSTALL_INCLUDEDIR: ${CMAKE_INSTALL_INCLUDEDIR}")
message(STATUS "CMAKE_INSTALL_LIBDIR: ${CMAKE_INSTALL_LIBDIR}")
message(STATUS "CMAKE_INSTALL_BINDIR: ${CMAKE_INSTALL_BINDIR}")

add_subdirectory(src)
add_subdirectory(tool)

if (UNIX)
    add_subdirectory(man)
endif()

if (NOT SPECS)
    message(STATUS "Skipping latex documentation")
else()
    add_subdirectory(latex)
endif()

if (NOT TESTS)
    message(STATUS "Skipping tests")
else()
    enable_testing()
    add_subdirectory(tests)
endif()
