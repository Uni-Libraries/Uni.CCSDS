// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors
/**
 * @file test_master_channel_generation.cpp
 * @brief Tests for Master Channel Generation (CCSDS 732.1-B-3 §4.2.9) — USLP-100
 *
 * Verifies that build_next_frame composes frames along the chain MC→VC→MAP and
 * sets Primary Header fields consistently with the context SCID and selected VC/MAP.
 *
 * Covered items:
 *  - USLP-100 Master Channel Generation (§4.2.9): SINGLE MC, SCID assignment in PH,
 *    generation realized by uni_ccsds_uslp_build_next_frame() using MC→VC→MAP selection.
 *
 * Cross-refs:
 *  - USLP-101 Master Channel Multiplexing (§4.2.10): SINGLE (degenerate, one SCID)
 *  - USLP-99  VC Multiplexing (§4.2.8): selection of VC with pending SDUs
 *  - USLP-96  MAP Multiplexing (§4.2.5): selection of MAP within VC
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

static void parse_ph(const std::vector<uint8_t>& frame,
                     uni_uslp_primary_header_t& ph,
                     size_t& ph_len)
{
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &read) == UNI_USLP_SUCCESS);
    ph_len = read;
}

static void configure_common_varlen(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;      // variable-length
    p.fecf_capability = false;   // simplify: no CRC in this test
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    // No VCF in this minimal test
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;

    // MC/VC mux schemes (SINGLE for MC as per IUT; VC SINGLE for determinism here)
    p.mc_mux_scheme = UNI_USLP_MC_MUX_SINGLE;
    p.vc_mux_scheme = UNI_USLP_VC_MUX_SINGLE;
}

} // namespace

TEST_CASE("Master Channel Generation: build_next_frame composes MC→VC→MAP and sets SCID (USLP-100)", "[uslp][mc][gen][USLP-100]")
{
    uni_uslp_managed_params_t params{};
    configure_common_varlen(params);

    // Initialize context with a specific SCID to check PH assignment
    const uint16_t SCID = 0x7E01;
    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &params) == UNI_USLP_SUCCESS);

    // Configure one VC and one MAP (MAPA service)
    const uint8_t VC = 5;
    const uint8_t MAP = 1;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &params) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_MAPA, &params) == UNI_USLP_SUCCESS);

    // Queue a MAPA SDU
    const std::vector<uint8_t> sdu{0xDE, 0xAD, 0xBE};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    // Build next frame via MC→VC→MAP chain
    std::vector<uint8_t> frame(512, 0x00);
    size_t flen = frame.size();
    uint8_t out_vcid = 0xFF, out_map = 0xFF;
    REQUIRE(uni_ccsds_uslp_build_next_frame(&ctx, frame.data(), &flen, &out_vcid, &out_map) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Verify selection outputs
    CHECK(out_vcid == VC);
    CHECK(out_map  == MAP);

    // Verify Primary Header fields: TFVN, SCID, VCID, MAP ID, length consistency
    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    parse_ph(frame, ph, ph_len);

    CHECK(ph.tfvn == UNI_USLP_TFVN);     // §4.1.2.2.2.2 '1100'
    CHECK(ph.scid == SCID);              // §4.1.2.2.3 SCID from context (Master Channel generation)
    CHECK(ph.vcid == VC);                // §4.1.2.4.1
    CHECK(ph.map_id == MAP);             // §4.1.2.5.1

    // Check total length matches PH.C + 1 (§4.1.2.7.2)
    // Note: when FECF TX mode is OFFLOAD_APPEND, the CPU buffer may omit the final 2 bytes.
    const size_t expected_on_wire = (size_t)ph.frame_length + 1u;
    const bool fecf_present = params.fecf_capability;
    const bool fecf_offload_append = (params.fecf_tx_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND);
    if (fecf_present && fecf_offload_append) {
        CHECK(expected_on_wire == frame.size() + (size_t)UNI_USLP_FECF_LENGTH);
    } else {
        CHECK(expected_on_wire == frame.size());
    }

    // Accept path should succeed (completes the round-trip)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
}
