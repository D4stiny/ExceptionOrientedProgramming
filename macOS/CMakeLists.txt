cmake_minimum_required(VERSION 3.19)
project(ExceptionOrientedProgramming)

set(CMAKE_CXX_STANDARD 14)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories("./deps/zydis/include")

add_executable(ExceptionOrientedProgramming main.cpp)

target_link_libraries(ExceptionOrientedProgramming PRIVATE Zydis)