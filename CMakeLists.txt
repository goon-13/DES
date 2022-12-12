# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.22)

# 项目信息
project(DES)

include_directories(${PROJECT_SOURCE_DIR}/include/)

file(GLOB_RECURSE ALL_SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)
file(GLOB_RECURSE ALL_INCLUDES ${PROJECT_SOURCE_DIR}/include/*.h)
set(ALL_SRCS ${ALL_SOURCES} ${ALL_INCLUDES})

# 添加子工程
add_subdirectory(./external/wingetopt)

add_executable(${CMAKE_PROJECT_NAME} ${ALL_SRCS}) 

# 链接子工程
target_link_libraries(${PROJECT_NAME} wingetopt)