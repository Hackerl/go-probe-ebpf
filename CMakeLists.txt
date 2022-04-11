cmake_minimum_required(VERSION 3.17)
project(go_probe_ebpf)

set(CMAKE_CXX_STANDARD 14)

include_directories(
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/ebpf/libbpf/include/uapi
)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

include(FetchContent)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG master
)

FetchContent_MakeAvailable(zero)

FetchContent_Declare(
        ELFIO
        GIT_REPOSITORY https://github.com/serge1/ELFIO
        GIT_TAG Release_3.9
)

FetchContent_MakeAvailable(ELFIO)

find_package(PkgConfig)

pkg_check_modules(zlib REQUIRED IMPORTED_TARGET zlib)
pkg_check_modules(libelf REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(libbpf REQUIRED IMPORTED_TARGET libbpf)

add_executable(
        go_probe_ebpf
        main.cpp
        go/symbol/line_table.cpp
        go/symbol/func.cpp
        go/symbol/build_info.cpp
)

target_link_libraries(go_probe_ebpf zero elfio PkgConfig::libbpf PkgConfig::zlib PkgConfig::libelf $<$<BOOL:${STATIC_BUILD}>:-static-pie>)
