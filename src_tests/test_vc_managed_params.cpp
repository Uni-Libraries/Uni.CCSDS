/**
 * @file test_vc_managed_params.cpp
 * @brief Tests for VC managed parameters Table 5-3 (USLP-132..USLP-144)
 *
 * Scope:
 *  - USLP-132 COP in Effect: recorded and retrievable
 *  - USLP-133 CLCW Version: recorded and retrievable
 *  - USLP-134 CLCW Reporting Rate: recorded and retrievable
 *  - USLP-136 MAP Multiplexing Scheme: recorded field only (Support=N per PICS)
 *  - USLP-141/142 Repetitions: recorded and retrievable via dedicated getter
 *  - USLP-143 Max TFDF completion delay: recorded
 *  - USLP-144 Max delay between frames: recorded
 *
 * References: CCSDS 732.1-B-3 §5 (Table 5-3), §4.1.5 (OCF)
 */

#include <catch2/catch_test_macros.hpp>
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

TEST_CASE("VC managed params: COP/CLCW/MAP mux/Repetitions/Delays (USLP-132..USLP-144)", "[uslp][vc][managed]")
{
    // Base managed parameters to enable minimal context
    uni_uslp_managed_params_t base{};
    base.max_frame_length = 2048;
    base.min_frame_length = 0;  // variable-length
    base.fecf_capability = false;
    base.ocf_capability = true; // allow OCF (policy is tested elsewhere)
    base.insert_zone_capability = false;
    base.truncated_frame_capable = false;
    base.max_sdu_length = 1024;

    // VC-level specific fields under test
    base.cop_in_effect = UNI_USLP_COP_1; // USLP-132
    base.clcw_version = 1;               // USLP-133 (Type-1 CLCW version value range per mission)
    base.clcw_reporting_rate = 10;       // USLP-134 (units mission-defined)
    base.map_mux_scheme = UNI_USLP_MAP_MUX_PRIORITY; // USLP-136 (Support=N; record only)
    base.ocf_allowed_variable = true;    // USLP-139 (gating at build path)
    base.ocf_required_fixed = false;     // USLP-140 (irrelevant for varlen here)
    base.repetitions_seq = 3;            // USLP-141 (record only)
    base.repetitions_cop_ctrl = 2;       // USLP-142 (record only)
    base.max_tfdf_completion_delay = 250; // USLP-143 (record only)
    base.max_inter_frame_delay = 500;     // USLP-144 (record only)

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4242, &base) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 7;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &base) == UNI_USLP_SUCCESS);

    // Readback full params
    uni_uslp_managed_params_t out{};
    REQUIRE(uni_ccsds_uslp_get_vc_params(&ctx, VCID, &out) == UNI_USLP_SUCCESS);

    // Validate recorded fields
    REQUIRE(out.cop_in_effect == UNI_USLP_COP_1);              // USLP-132
    REQUIRE(out.clcw_version == 1);                            // USLP-133
    REQUIRE(out.clcw_reporting_rate == 10);                    // USLP-134
    REQUIRE(out.map_mux_scheme == UNI_USLP_MAP_MUX_PRIORITY);  // USLP-136 (record only)
    REQUIRE(out.ocf_allowed_variable == true);                 // USLP-139
    REQUIRE(out.ocf_required_fixed == false);                  // USLP-140
    REQUIRE(out.max_tfdf_completion_delay == 250);             // USLP-143
    REQUIRE(out.max_inter_frame_delay == 500);                 // USLP-144

    // Dedicated repetitions getter
    uint8_t rep_seq = 0, rep_cop = 0;
    REQUIRE(uni_ccsds_uslp_get_repetition_counts(&ctx, VCID, &rep_seq, &rep_cop) == UNI_USLP_SUCCESS);
    REQUIRE(rep_seq == 3);       // USLP-141
    REQUIRE(rep_cop == 2);       // USLP-142
}