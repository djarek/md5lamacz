cmake_minimum_required(VERSION 2.6)
project(md5lamacz)
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")
add_executable(md5lamacz main.cpp hash.cpp hash.h thread_manager.cpp thread_manager.h)
target_link_libraries(md5lamacz crypto pthread)

install(TARGETS md5lamacz RUNTIME DESTINATION bin)
