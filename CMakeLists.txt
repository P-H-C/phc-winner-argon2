# CMake version 3.26 is outdated but is still used by some software.
# You should always use the latest available version of the CMake tool.
cmake_minimum_required(VERSION 3.26)

set(LIBRARY_VERSION_MAJOR 0)
set(LIBRARY_VERSION_MINOR 1)
set(LIBRARY_VERSION_PATCH 0)
set(LIBRARY_VERSION_TWEAK 0)
set(LIBRARY_VERSION_FULL ${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}.${LIBRARY_VERSION_TWEAK})

project(Argon2
        VERSION ${LIBRARY_VERSION_FULL}
        DESCRIPTION "Argon2"
        LANGUAGES C
)

set_target_properties(PROPERTIES VERSION ${PROJECT_VERSION})
set(CMAKE_C_STANDARD 23)

set (COMMON_VERSION ${LIBRARY_VERSION_MAJOR},${LIBRARY_VERSION_MINOR},${LIBRARY_VERSION_PATCH},${LIBRARY_VERSION_TWEAK})
set(PRODUCT_VERSION ${COMMON_VERSION})
set(PRODUCT_VERSION_STR ${PROJECT_VERSION})
set(FILE_VERSION ${COMMON_VERSION})
set(FILE_VERSION_STR ${PROJECT_VERSION})

set(PRODUCT_NAME "Argon2 library")
set(LIB_NAME "argon2")
set(VERSION_RC_FILE "version.rc")

include(GNUInstallDirs)

# List of source C files.
# To update the list of files, use following commands:
#   ls -1 src/*.c
#   ls -1 src/blake2/*.c
set(SOURCE_FILES_LIST
        src/argon2.c
        src/bench.c
        src/core.c
        src/encoding.c
        #src/genkat.c # ???
        #src/opt.c # 'fill_segment' function for AVX CPU.
        #src/ref.c # 'fill_segment' function for non-AVX CPU.
        #src/run.c # ???
        #src/test.c # ???
        src/thread.c
        src/blake2/blake2b.c
)

# List of public headers for the compiled library.
# To update the list of files, use following commands:
#   ls -1 include/*.h
set(PUBLIC_HEADER_FILES_LIST
        include/argon2.h
)

# CFG_USE_AVX is a custom configuration for AVX support.
# Default value: False.
set(CFG_USE_AVX "no" CACHE STRING "Is AVX support needed ?")
if (CFG_USE_AVX)
    list(APPEND SOURCE_FILES_LIST src/opt.c)
else ()
    list(APPEND SOURCE_FILES_LIST src/ref.c)
endif ()

# CFG_USE_VERSION_RC is a custom configuration for the 'version.rc' support.
# Default value: False.
set(CFG_USE_VERSION_RC "no" CACHE STRING "Include product information into DLL file ?")
if (CFG_USE_VERSION_RC)
    list(APPEND SOURCE_FILES_LIST ${CMAKE_CURRENT_BINARY_DIR}/${VERSION_RC_FILE})
else ()
endif ()

# Mini report.
message("Product Name: ${PRODUCT_NAME}")
message("Project Version: ${PROJECT_VERSION}.")
message("Product Version: ${PRODUCT_VERSION}.")
message("File Version: ${FILE_VERSION}.")
message("Source Files: ${SOURCE_FILES_LIST}.")
message("Public Header Files: ${PUBLIC_HEADER_FILES_LIST}.")
message("AVX: ${CFG_USE_AVX}.")
message("Version.rc: ${CFG_USE_VERSION_RC}.")

add_library(${LIB_NAME} SHARED ${SOURCE_FILES_LIST})

set_target_properties(${LIB_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${LIB_NAME} PROPERTIES PUBLIC_HEADER ${PUBLIC_HEADER_FILES_LIST})

target_include_directories(${LIB_NAME} PRIVATE include)
target_include_directories(${LIB_NAME} PRIVATE src)

configure_file(${LIB_NAME}.pc.in ${LIB_NAME}.pc @ONLY)
if (CFG_USE_VERSION_RC)
    configure_file(${VERSION_RC_FILE}.in ${VERSION_RC_FILE} @ONLY)
else ()
endif ()

install(TARGETS ${LIB_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_BINARY_DIR}/${LIB_NAME}.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
