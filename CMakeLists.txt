cmake_minimum_required(VERSION 3.31)
project(C_C__)

set(CMAKE_CXX_STANDARD 20)

# 添加 lib 目录到头文件搜索路径
include_directories("${PROJECT_SOURCE_DIR}/lib")

add_executable(C_C__ main.cpp)
