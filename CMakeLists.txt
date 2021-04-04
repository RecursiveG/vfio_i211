cmake_minimum_required(VERSION 3.17)
project(vfio_i211)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-packed-bitfield-compat")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -ggdb -O0")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic")

include(FetchContent)

FetchContent_Declare(result
    GIT_REPOSITORY https://github.com/RecursiveG/result.git
    GIT_TAG        084c3106db35ac25ce0849d974bde42cacb89c09
)
FetchContent_Declare(abseil-cpp
    GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
    GIT_TAG 20200923.2
)
FetchContent_Declare(
        magic_enum
        GIT_REPOSITORY https://github.com/Neargye/magic_enum.git
        GIT_TAG        v0.7.0
)
FetchContent_Declare(backward-cpp
    GIT_REPOSITORY https://github.com/bombela/backward-cpp.git
    GIT_TAG        v1.5
)

FetchContent_MakeAvailable(result)
FetchContent_MakeAvailable(abseil-cpp)
FetchContent_MakeAvailable(backward-cpp)
FetchContent_MakeAvailable(magic_enum)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libpcap REQUIRED IMPORTED_TARGET libpcap)

add_library(i211 i211.cpp vfio.cpp)
target_link_libraries(i211 PUBLIC 
    absl::flags absl::flags_parse magic_enum result)
add_library(pcap_dumper pcap_dumper.cpp)
target_link_libraries(pcap_dumper PUBLIC PkgConfig::libpcap)

add_executable(send_udp send_udp.cpp ${BACKWARD_ENABLE})
target_link_libraries(send_udp PRIVATE i211 pcap_dumper -lbfd -ldl -ldw -ldwarf)
