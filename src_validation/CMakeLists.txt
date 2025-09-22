# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

cmake_minimum_required(VERSION 3.21)

project(uni_ccsds_validation LANGUAGES CXX)

# Enable reusable modules that will live under src_validation/cmake
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(USLP_VALIDATION_WITH_NASA "Enable the NASA USLP reference bridge" ON)
option(USLP_VALIDATION_WITH_PYTHON "Enable the spacepackets Python bridge" OFF)
option(USLP_VALIDATION_EMBED_PYTHON "Embed the Python interpreter instead of using subprocess RPC" OFF)
option(USLP_VALIDATION_ENABLE_TESTS "Enable validation-specific unit tests" ${BUILD_TESTING})

set(USLP_VALIDATION_RESOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/resources"
    CACHE PATH "Path to default validation resources (scenario packs, report templates)"
)

# Adopt modern C++ across the validation harness
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CTest)

add_subdirectory(harness)

# Only add NASA bridge if the directory exists (allows incremental scaffolding)
if(USLP_VALIDATION_WITH_NASA AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bridges/nasa/CMakeLists.txt")
    add_subdirectory(bridges/nasa)
endif()

# Only add Python bridge if the directory exists (allows incremental scaffolding)
if(USLP_VALIDATION_WITH_PYTHON AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bridges/python/CMakeLists.txt")
    add_subdirectory(bridges/python)
endif()

# Only add CLI if the directory exists (allows incremental scaffolding)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cli/CMakeLists.txt")
    add_subdirectory(cli)
endif()

# Only add tests if the directory exists (allows incremental scaffolding)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()