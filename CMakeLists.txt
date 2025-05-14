cmake_minimum_required(VERSION 3.31)
project(C_C__)

set(CMAKE_CXX_STANDARD 20)

# 添加 lib 目录到头文件搜索路径
include_directories("${PROJECT_SOURCE_DIR}/lib")

# 让编译器能找到相关的文件
add_executable(C_C__
        main.cpp
        ip2region_util.cpp
        lib/ip2region/xdb_bench.cc
        lib/ip2region/xdb_search.cc
        ip2region_util.h
)

# 把IP数据库文件复制到编译输出目录
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ip2region/ip2region.xdb
        ${CMAKE_CURRENT_BINARY_DIR}/ip2region/ip2region.xdb
        COPYONLY
)
