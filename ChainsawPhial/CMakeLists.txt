cmake_minimum_required(VERSION 3.15)
project(ChainsawPhial)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 包含 .def 文件
add_library(ChainsawPhial SHARED dllmain.cpp ChainsawPhial.def)

if(MSVC)
    # 关掉 SDL 检查，加入多线程静态库，最大化兼容性
    target_compile_options(ChainsawPhial PRIVATE /MT /O2 /DNDEBUG /sdl-)
    set_target_properties(ChainsawPhial PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS")
endif()
