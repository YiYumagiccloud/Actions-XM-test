cmake_minimum_required(VERSION 3.15)
project(ChainsawPhial)

# 设置为 C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 生成 DLL
add_library(ChainsawPhial SHARED dllmain.cpp)

# 针对 MSVC 的优化（减小体积，去除无用的库链接）
if(MSVC)
    target_compile_options(ChainsawPhial PRIVATE /MT /O2 /DNDEBUG)
    set_target_properties(ChainsawPhial PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS")
endif()
