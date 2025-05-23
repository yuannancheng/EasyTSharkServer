cmake_minimum_required(VERSION 3.31)
project(C_C__)

set(CMAKE_CXX_STANDARD 20)

# 添加 lib 目录到头文件搜索路径
include_directories("${PROJECT_SOURCE_DIR}/lib")

# 让编译器能找到相关的文件
add_executable(C_C__
        main.cpp
        ip2region_util.cpp
        ip2region_util.h
        tshark_manager.cpp
        tshark_manager.h
        tshark_datatype.h
        lib/ip2region/xdb_bench.cc
        lib/ip2region/xdb_search.cc
        lib/loguru/loguru.cpp
        lib/loguru/loguru.hpp
)

# 把IP数据库文件复制到编译输出目录
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ip2region/ip2region.xdb
        ${CMAKE_CURRENT_BINARY_DIR}/ip2region/ip2region.xdb
        COPYONLY
)

# 检查内存问题
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
#set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
