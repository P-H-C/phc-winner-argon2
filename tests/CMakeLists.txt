#############
# UNITTESTS #
#############

add_executable(argon2-tests "test.c")
target_link_libraries(argon2-tests PRIVATE argon2-shared)
add_test(NAME argon2-tests
    COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/argon2-tests")

##########
# GENKAT #
##########

add_executable(genkat "genkat.c")
target_link_libraries(genkat PRIVATE argon2-static-genkat)

if (WIN32)
    add_test(NAME argon2-genkat
        COMMAND "powershell" "-Command"
        "${CMAKE_CURRENT_SOURCE_DIR}/kats/test.ps1"
        "--genkat" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>/genkat")
else()
    # Testing powershell on Linux
    #add_test(NAME argon2-genkat
    #    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/kats/test.ps1"
    #    "--genkat" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/genkat")

    add_test(NAME argon2-genkat
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/kats/test.sh"
        "--genkat=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/genkat")
endif()

#############
# BENCHMARK #
#############
if (NOT BENCHMARKS)
    message(STATUS "Skipping benchmarks")
else()
    add_executable(benchmark "bench.c")
    target_link_libraries(benchmark PRIVATE argon2-static ${THREADS_DEP})
    add_custom_target(argon2-benchmark
        COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/benchmark")
endif()
