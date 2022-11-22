cmake_minimum_required(VERSION 3.17)
project(go_probe_ebpf)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR}/ebpf/libbpf/include/uapi)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "disable shared library")
set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable event openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

set(JSON_BuildTests OFF CACHE BOOL "disable json library tests")

include(FetchContent)

FetchContent_Declare(
        go-symbol
        GIT_REPOSITORY https://github.com/Hackerl/go-symbol
        GIT_TAG b349b2314ec3626cb2c42085a692a739787ede42
)

FetchContent_MakeAvailable(go-symbol)

FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json
        GIT_TAG v3.11.2
)

FetchContent_MakeAvailable(json)

FetchContent_Declare(
        libevent
        GIT_REPOSITORY https://github.com/libevent/libevent
        GIT_TAG release-2.1.12-stable
)

FetchContent_MakeAvailable(libevent)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY https://github.com/zyantific/zydis
        GIT_TAG v4.0.0
)

FetchContent_MakeAvailable(zydis)

find_package(PkgConfig)

pkg_check_modules(zlib REQUIRED IMPORTED_TARGET zlib)
pkg_check_modules(libelf REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(libbpf REQUIRED IMPORTED_TARGET libbpf)

add_executable(go_probe_ebpf main.cpp)

target_link_libraries(
        go_probe_ebpf
        go_symbol
        Zydis
        nlohmann_json
        event_core_static
        event_pthreads_static
        PkgConfig::libbpf
        PkgConfig::zlib
        PkgConfig::libelf
        $<$<BOOL:${STATIC_BUILD}>:-static-pie>
)