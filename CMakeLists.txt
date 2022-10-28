cmake_minimum_required(VERSION 3.17)
project(go_probe_ebpf)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/ebpf/libbpf/include/uapi)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

include(FetchContent)

FetchContent_Declare(
        go-symbol
        GIT_REPOSITORY https://github.com/Hackerl/go-symbol
        GIT_TAG b910d1de9ae0bc2555db2475cb0cf960ac31e054
)

FetchContent_MakeAvailable(go-symbol)

find_package(PkgConfig)

pkg_check_modules(zlib REQUIRED IMPORTED_TARGET zlib)
pkg_check_modules(libelf REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(libbpf REQUIRED IMPORTED_TARGET libbpf)

add_executable(go_probe_ebpf main.cpp)

target_link_libraries(
        go_probe_ebpf
        go_symbol
        PkgConfig::libbpf
        PkgConfig::zlib
        PkgConfig::libelf
        $<$<BOOL:${STATIC_BUILD}>:-static-pie>
)