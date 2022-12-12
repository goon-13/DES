# 内部工程依赖方式导入第三方库

# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.22)

# 项目信息
project(wingetopt)

add_library(${PROJECT_NAME} getopt.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)