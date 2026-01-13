# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

#
# CMake
#

cmake_minimum_required(VERSION 3.10)
project(uni_ccsds)

#
# Options
#

# Tooling toggles
option(UNI_CCSDS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(UNI_CCSDS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(UNI_CCSDS_ENABLE_COVERAGE "Enable coverage flags" OFF)



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
