cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # Needed by clang-tidy

# ============================================================
# Optional: Enable clang-tidy static analysis
# Usage: cmake -DENABLE_CLANG_TIDY=ON ..
# ============================================================
option(ENABLE_CLANG_TIDY "Run clang-tidy during build" OFF)
if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
    if(CLANG_TIDY_EXE)
        message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
        set(CMAKE_CXX_CLANG_TIDY
            "${CLANG_TIDY_EXE};-checks=modernize-*,readability-*,bugprone-*,performance-*;-warnings-as-errors=*")
    else()
        message(WARNING "clang-tidy NOT found — skipping static analysis")
    endif()
endif()

# ============================================================
# Shared source files (used by both executables and tests)
# ============================================================
set(SHARED_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================
# Target 1: dpi_simple  (single-threaded version)
# ============================================================
add_executable(dpi_simple
    src/main_working.cpp
    ${SHARED_SOURCES}
)
target_include_directories(dpi_simple PRIVATE ${CMAKE_SOURCE_DIR}/include)
# No -pthread needed for single-threaded version

# ============================================================
# Target 2: dpi_engine  (multi-threaded version)  ★ MAIN ★
# ============================================================
add_executable(dpi_engine
    src/dpi_mt.cpp
    ${SHARED_SOURCES}
)
target_include_directories(dpi_engine PRIVATE ${CMAKE_SOURCE_DIR}/include)
# Link pthreads on Linux/macOS
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# ============================================================
# Compiler optimisation flags
# ============================================================
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(dpi_simple  PRIVATE -O2)
    target_compile_options(dpi_engine  PRIVATE -O2)
endif()

# ============================================================
# CTest Unit Tests
# ============================================================
enable_testing()
include(CTest)

# Test 1: SNI + HTTP Host extraction
add_executable(test_sni
    tests/test_sni.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
target_include_directories(test_sni PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME SNIExtractorTest COMMAND test_sni)

# Test 2: sniToAppType + FiveTuple
add_executable(test_types
    tests/test_types.cpp
    src/types.cpp
)
target_include_directories(test_types PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME TypesTest COMMAND test_types)

# ============================================================
# Platform-specific settings
# ============================================================
if(APPLE)
    target_link_libraries(dpi_engine PRIVATE "-framework CoreFoundation")
endif()
