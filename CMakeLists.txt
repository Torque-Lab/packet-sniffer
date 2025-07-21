cmake_minimum_required(VERSION 3.10)
project(packet_sniffer VERSION 1.0 LANGUAGES CXX)

# Set C++ standard and properties
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Set include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

# Source files
set(SOURCES
    src/main.cpp
    src/packet/Packet.cpp
    src/packet/layers/EthernetLayer.cpp
    src/packet/layers/IPLayer.cpp
    src/packet/layers/TCPLayer.cpp
    src/packet/layers/UDPLayer.cpp
    src/packet/layers/ICMPLayer.cpp
    src/sniffer/PacketSniffer.cpp
    src/utils/HexDump.cpp
)

# Add executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Linux-specific settings
target_compile_definitions(${PROJECT_NAME} PRIVATE
    _GNU_SOURCE
    _DEFAULT_SOURCE
    _FORTIFY_SOURCE=2
)

# Compiler warnings and optimizations
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -fstack-protector-strong
    -fPIC
)

# Enable debug symbols in release mode
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -g")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,now -Wl,-z,relro")

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    ${PCAP_LIBRARIES}
    pcap
    pthread
)

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Install headers
install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Build documentation with Doxygen if available
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs)
    set(DOXYGEN_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set(DOXYGEN_RECURSIVE YES)
    set(DOXYGEN_GENERATE_HTML YES)
    
    doxygen_add_docs(docs
        ${DOXYGEN_INPUT}
        COMMENT "Generating API documentation with Doxygen"
    )
endif()
