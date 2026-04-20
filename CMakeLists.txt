cmake_minimum_required(VERSION 3.16)
project(AegisDPI VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -flto -Wall -Wextra")
elseif(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2 /GL /W4")
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/types.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/dpi_engine.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executable
add_executable(aegis_dpi ${SOURCES})

# Thread support
find_package(Threads REQUIRED)
target_link_libraries(aegis_dpi PRIVATE Threads::Threads)
