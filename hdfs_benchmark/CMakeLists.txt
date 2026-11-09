cmake_minimum_required(VERSION 3.10)

set(SOURCE_FILES main.cpp)
add_executable(hdfs_benchmark ${SOURCE_FILES})
add_dependencies(hdfs_benchmark libhdfs3-shared)

target_link_libraries(hdfs_benchmark pthread libhdfs3-shared)
