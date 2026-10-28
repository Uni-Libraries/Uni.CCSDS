# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

#
# CMake
#

cmake_minimum_required(VERSION 3.10)
project(uni_ccsds VERSION 2.0.0 LANGUAGES C CXX)

#
# Options
#

# Tooling toggles
option(UNI_CCSDS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(UNI_CCSDS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(UNI_CCSDS_ENABLE_COVERAGE "Enable coverage flags" OFF)

# Instrument everything configured after this point (library, uni.crypto, tests, tools).
if(UNI_CCSDS_ENABLE_ASAN OR UNI_CCSDS_ENABLE_UBSAN OR UNI_CCSDS_ENABLE_COVERAGE)
    if(MSVC)
        message(FATAL_ERROR "UNI_CCSDS_ENABLE_ASAN/UBSAN/COVERAGE are supported with GCC and Clang only")
    endif()
    add_compile_options(-fno-omit-frame-pointer)
endif()
if(UNI_CCSDS_ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()
if(UNI_CCSDS_ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=undefined)
endif()
if(UNI_CCSDS_ENABLE_COVERAGE)
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()



#
# Dependencies
#

if(PROJECT_IS_TOP_LEVEL)
    include(cmake/cpm.cmake)
    include(cmake/cpm-catch.cmake)
    include(cmake/cpm-uni.crypto.cmake)
endif()

#
# Library
#

add_library(uni_ccsds)

include(GenerateExportHeader)
generate_export_header(uni_ccsds)
target_include_directories(uni_ccsds PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

target_sources(uni_ccsds PRIVATE
    src/uni_ccsds_lfsr_oid.c
    src/uni_ccsds_uslp_primary_header.c
    src/uni_ccsds_uslp_sdls.c
    src/uni_ccsds_uslp_status.c
    src/uni_ccsds_uslp_tfdf_header.c
    src/uni_cssds_uslp.c
)

target_include_directories(uni_ccsds PUBLIC include)

set_target_properties(uni_ccsds PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)

if(MSVC)
    target_compile_options(uni_ccsds PRIVATE /W4 /WX)
else()
    target_compile_options(uni_ccsds PRIVATE
        -Wall -Wextra -Werror
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wold-style-definition
        -pedantic
    )
endif()

if(PROJECT_IS_TOP_LEVEL)
    target_link_libraries(uni_ccsds PUBLIC uni_crypto)
endif()




#
# Tools
#

if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(src_tools)
endif()



#
# Installation
#

if(PROJECT_IS_TOP_LEVEL)
    install(
        TARGETS uni_ccsds
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
    )
endif()



#
# Tests
#

if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(src_validation)
    enable_testing()
    add_subdirectory(src_tests)
endif()



#
# Documentation
#

# `cmake --build <dir> --target uni_ccsds_docs` writes HTML to <source>/build/docs/html (path set in Doxyfile, so a
# plain `doxygen Doxyfile` from the source root gives the same result).
if(PROJECT_IS_TOP_LEVEL)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        add_custom_target(uni_ccsds_docs
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/build/docs"
            COMMAND Doxygen::doxygen "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            COMMENT "Generating Uni.CCSDS API documentation"
            VERBATIM)
    endif()
endif()
