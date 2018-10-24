if (MULTITHREADS)
    find_package(Threads REQUIRED)
endif()

set (ARGON2_SRC
    "argon2.c"
    "core.c"
    "blake2/blake2b.c"
    "thread.c"
    "encoding.c"
    )

message(STATUS "Checking support for hardware optimization:")
try_compile(WITH_OPTIMIZATIONS
    ${CMAKE_CURRENT_BINARY_DIR}/optimization
    ${CMAKE_CURRENT_SOURCE_DIR}/optimization
    check_cpu_features
    OUTPUT_VARIABLE OUTPUT_TEST_SUPPORT_OPTIMIZATION)
message(STATUS "${OUTPUT_TEST_SUPPORT_OPTIMIZATION}")

message(STATUS "Build with hardware optimization? ${WITH_OPTIMIZATIONS}")
if (WITH_OPTIMIZATIONS)
    list(APPEND ARGON2_SRC "opt.c")
else()
    list(APPEND ARGON2_SRC "ref.c")
endif()

##########
# SHARED #
##########
add_library (argon2-shared SHARED ${ARGON2_SRC})

target_compile_definitions(argon2-shared
    PUBLIC "A2_VISCTL")

target_include_directories(argon2-shared
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)

if (MULTITHREADS)
    target_link_libraries(argon2-shared PUBLIC Threads::Threads)
else()
    target_compile_definitions(argon2-shared PRIVATE "ARGON2_NO_THREADS=1")
endif()

if (WIN32 OR MINGW)
    set_target_properties(argon2-shared PROPERTIES
        C_STANDARD 90
        OUTPUT_NAME "argon2"
        PDB_OUTPUT_NAME "argon2"
        SUFFIX ".dll")
else()
    set_target_properties(argon2-shared PROPERTIES
        C_STANDARD 90
        OUTPUT_NAME "argon2"
        PDB_OUTPUT_NAME "argon2"
        SUFFIX ".so.${ABI_VERSION}")
endif()

install(TARGETS argon2-shared
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

if (UNIX)
    macro(install_symlink filepath sympath)
        install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath} \
                                      WORKING_DIRECTORY ${CMAKE_INSTALL_LIBDIR})")
        install(CODE "message(\"-- Created symlink: ${sympath} -> ${filepath}\")")
    endmacro(install_symlink)

    install_symlink(${CMAKE_SHARED_LIBRARY_PREFIX}argon2${CMAKE_SHARED_LIBRARY_SUFFIX}.${ABI_VERSION}
                    ${CMAKE_SHARED_LIBRARY_PREFIX}argon2${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

##########
# STATIC #
##########
add_library (argon2-static STATIC ${ARGON2_SRC})

target_compile_definitions(argon2-static
    PUBLIC "A2_VISCTL")

if (MULTITHREADS)
    target_link_libraries(argon2-static PUBLIC Threads::Threads)
else()
    target_compile_definitions(argon2-static PRIVATE "ARGON2_NO_THREADS=1")
endif()

target_include_directories(argon2-static PUBLIC
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)

if (UNIX)
    set(ARGON2_STATIC_LIB_NAME "argon2")
else()
    set(ARGON2_STATIC_LIB_NAME "argon2-static")
endif()
set_target_properties(argon2-static PROPERTIES
    C_STANDARD 90
    OUTPUT_NAME ${ARGON2_STATIC_LIB_NAME}
    PDB_OUTPUT_NAME "argon2")

install(TARGETS argon2-static
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )


install(FILES "${CMAKE_SOURCE_DIR}/include/argon2.h"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (UNIX)
    set (CPACK_PACKAGE_NAME argon2)
    set (PKGCONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    if (MULTITHREADS)
        set(CPACK_PACKAGE_LINKFLAGS "-pthread")
    endif()

    configure_file ("${CMAKE_SOURCE_DIR}/cmake/argon2.pc.in" "${PROJECT_BINARY_DIR}/lib${CPACK_PACKAGE_NAME}.pc" @ONLY)
    install (FILES "${PROJECT_BINARY_DIR}/lib${CPACK_PACKAGE_NAME}.pc" DESTINATION "${PKGCONFIG_INSTALL_DIR}")
endif()

######################################################
# STATIC for genkat (provide sew points for logging) #
######################################################
add_library (argon2-static-genkat STATIC ${ARGON2_SRC})

if (MULTITHREADS)
    target_link_libraries(argon2-static-genkat PUBLIC Threads::Threads)
else()
    target_compile_definitions(argon2-static-genkat PRIVATE "ARGON2_NO_THREADS=1")
endif()

target_include_directories(argon2-static-genkat PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)

target_compile_definitions(argon2-static-genkat
    PUBLIC "A2_VISCTL" "GENKAT")

set_target_properties(argon2-static-genkat PROPERTIES
    C_STANDARD 90
    OUTPUT_NAME "argon2-genkat")

