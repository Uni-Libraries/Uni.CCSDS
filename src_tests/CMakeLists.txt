# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

include(../cmake/cpm.cmake)
include(../cmake/cpm-catch.cmake)

# catch
# Catch.cmake lives in extras/ of a CPM-fetched Catch2 and next to the package config of an installed one
# (CPM_USE_LOCAL_PACKAGES=ON or an offline build).
if(Catch2_SOURCE_DIR)
    list(APPEND CMAKE_MODULE_PATH "${Catch2_SOURCE_DIR}/extras")
else()
    list(APPEND CMAKE_MODULE_PATH "${Catch2_DIR}")
endif()
include(Catch)

# test
add_executable(uni_ccsds_test)
target_sources(uni_ccsds_test PRIVATE
    uni_ccsds_tests.cpp
    test_crc16_lfsr.cpp
    test_tm_coding.cpp
    test_primary_header.cpp
    test_tfdf_header.cpp
    test_frame_build_parse.cpp
    test_truncated_frames.cpp
    test_ocf_insert.cpp
    test_oid_frame.cpp
    test_fuzz_parser.cpp
    test_vcf_counters.cpp
    test_vcf_exp_counters.cpp
    test_octet_stream.cpp
    test_octet_stream_notify.cpp
    test_sdls_hmac.cpp
    test_sdls_aead.cpp
    test_sdls_security.cpp
    test_mapa_loss_flag.cpp
    test_mapa_notify.cpp
    test_packet_service.cpp
    test_vcp_service.cpp
    test_vca_service.cpp
    test_insert_service.cpp
    test_multiplexing.cpp
    test_master_channel_generation.cpp
)
target_link_libraries(uni_ccsds_test PRIVATE uni_ccsds)
target_link_libraries(uni_ccsds_test PRIVATE Catch2::Catch2WithMain)
# Tests are written in C++23 (AGENTS.md); without this the compiler default (C++17 on Clang) applies.
target_compile_features(uni_ccsds_test PRIVATE cxx_std_23)
catch_discover_tests(uni_ccsds_test)

# Additional tests for VCF/MCF/Insert/OCF loss flag, request/COPs management, and VC managed parameters
target_sources(uni_ccsds_test PRIVATE
    test_vcf_service.cpp
    test_mcf_service.cpp
    test_insert_loss_flag.cpp
    test_vcf_mcf_request.cpp
    test_directive_management.cpp
    test_vc_managed_params.cpp
    test_ocf_policy.cpp
    test_ocf_loss_flag.cpp
    test_vca_verification.cpp
)

# Documentation example (docs/uslp_sdls.md): compiled and run so it cannot drift from the API.
add_executable(uni_ccsds_example_sdls_quickstart ../examples/sdls_quickstart.c)
target_link_libraries(uni_ccsds_example_sdls_quickstart PRIVATE uni_ccsds)
set_target_properties(uni_ccsds_example_sdls_quickstart PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED ON)
add_test(NAME uni_ccsds_example_sdls_quickstart COMMAND uni_ccsds_example_sdls_quickstart)
