project(check_cpu_features)
cmake_minimum_required(VERSION 3.5)

set(optimized_src
    "${CMAKE_CURRENT_SOURCE_DIR}/../opt.c"
    )

add_library(test_cpu_features STATIC ${optimized_src})
target_include_directories(test_cpu_features PRIVATE
    "${CMAKE_SOURCE_DIR}/../../include")
