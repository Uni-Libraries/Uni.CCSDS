/**
 * @file test_truncated_frames.cpp
 * @brief Tests for Truncated Transfer Frames (CCSDS 732.1-B-3 Annex D)
 *
 * Covers:
 * - Building truncated frames with minimum (6) and maximum (32) lengths
 * - Exact SDU length fit into TFDZ (one complete MAPA_SDU)
 * - Accept path detection and delivery
 * - Negative cases: SDU length mismatch, invalid TFDF rule, capability disabled
 *
 * References:
 * - CCSDS 732.1-B-3 Annex D (Truncated Transfer Frames)
 * - §4.1.2 Primary Header (bit layout reused in truncated PH)
 * - §4.1.4.2 TFDF header first octet (rule + UPID)
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstring>

namespace {

struct Cap {
    bool called = false;
    uint8_t vcid = 0;
    uint8_t map_id = 0;
    uni_uslp_service_type_t service = UNI_USLP_SERVICE_MAPA;
    std::vector<uint8_t> sdu;
    bool gap = false;
};

void sdu_cb(uni_uslp_context_t* ctx,
            uint8_t vcid,
            uint8_t map_id,
            uni_uslp_service_type_t service_type,
            const uint8_t* sdu_data,
            size_t sdu_length,
            uni_uslp_verification_status_t verification_status, bool gap_detected,
            void* user)
{
    (void)ctx;
    auto* c = static_cast<Cap*>(user);
    c->called = true;
    c->vcid = vcid;
    c->map_id = map_id;
    c->service = service_type;
    c->gap = gap_detected;
    c->sdu.assign(sdu_data, sdu_data + sdu_length);
}

uni_uslp_managed_params_t base_params_varlen()
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 4096;
    p.min_frame_length = 0;                // variable-length semantics in current code
    p.truncated_frame_capable = true;
    p.truncated_frame_length = 0;          // to be set per VC
    p.mcf_count_length = 0;
    p.vcf_count_length = 0;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.insert_zone_length = 0;
    p.fecf_capability = false;             // must be absent for truncated frames
    p.segmentation_permitted = false;
    p.blocking_permitted = false;
    p.max_sdu_length = 2048;
    return p;
}

} // namespace

TEST_CASE("Build+Accept truncated frame: minimum length (6 octets)", "[uslp][truncated][min]")
{
    constexpr uint16_t SCID = 0x1001;
    constexpr uint8_t VCID = 3;
    constexpr uint8_t MAP = 2;

    auto global = base_params_varlen();

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &global) == UNI_USLP_SUCCESS);

    auto vc_params = global;
    vc_params.truncated_frame_capable = true;
    vc_params.truncated_frame_length = UNI_USLP_TRUNCATED_MIN_LENGTH; // 6
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    Cap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // TFDZ length must be total - (truncated PH=4 + TFDF hdr=1) = 1
    std::vector<uint8_t> sdu{0xAB};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(UNI_USLP_TRUNCATED_MIN_LENGTH, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_truncated(&ctx, VCID, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    REQUIRE(out_len == UNI_USLP_TRUNCATED_MIN_LENGTH);

    // Accept and verify callback
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.vcid == VCID);
    REQUIRE(cap.map_id == MAP);
    REQUIRE(cap.service == UNI_USLP_SERVICE_MAPA);
    REQUIRE(cap.gap == false);
    REQUIRE(cap.sdu == sdu);
}

TEST_CASE("Build+Accept truncated frame: maximum length (32 octets)", "[uslp][truncated][max]")
{
    constexpr uint16_t SCID = 0x2002;
    constexpr uint8_t VCID = 5;
    constexpr uint8_t MAP = 1;

    auto global = base_params_varlen();

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &global) == UNI_USLP_SUCCESS);

    auto vc_params = global;
    vc_params.truncated_frame_capable = true;
    vc_params.truncated_frame_length = 32;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    Cap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    const size_t tfdz_len = 32 - (size_t)UNI_USLP_TRUNCATED_PH_LENGTH - 1u; // 27
    std::vector<uint8_t> sdu(tfdz_len);
    for (size_t i = 0; i < sdu.size(); ++i) sdu[i] = static_cast<uint8_t>(i & 0xFF);

    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(32, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_truncated(&ctx, VCID, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    REQUIRE(out_len == 32);

    // Accept and verify
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.sdu == sdu);
}

TEST_CASE("Build truncated: SDU size mismatch produces error", "[uslp][truncated][error]")
{
    constexpr uint16_t SCID = 0x3003;
    constexpr uint8_t VCID = 1;
    constexpr uint8_t MAP = 0;

    auto global = base_params_varlen();

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &global) == UNI_USLP_SUCCESS);

    auto vc_params = global;
    vc_params.truncated_frame_capable = true;
    vc_params.truncated_frame_length = UNI_USLP_TRUNCATED_MIN_LENGTH; // 6
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    // Expected TFDZ length = 1, but provide 2 bytes
    std::vector<uint8_t> sdu{0xAA, 0xBB};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(UNI_USLP_TRUNCATED_MIN_LENGTH, 0x00);
    size_t out_len = frame.size();
    auto st = uni_ccsds_uslp_build_truncated(&ctx, VCID, frame.data(), &out_len);
    REQUIRE(st == UNI_USLP_ERROR_INVALID_PARAM);
}

TEST_CASE("Accept truncated: invalid TFDF rule rejected", "[uslp][truncated][error]")
{
    constexpr uint16_t SCID = 0x4444;
    constexpr uint8_t VCID = 7;
    constexpr uint8_t MAP = 3;

    auto global = base_params_varlen();

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &global) == UNI_USLP_SUCCESS);

    auto vc_params = global;
    vc_params.truncated_frame_capable = true;
    vc_params.truncated_frame_length = 8;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    // Prepare SDU of length = 8 - (4 + 1) = 3
    std::vector<uint8_t> sdu{0x01, 0x02, 0x03};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(8, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_truncated(&ctx, VCID, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    REQUIRE(out_len == 8);

    // Corrupt TFDF header: set rule to 0 (should be 7)
    frame[UNI_USLP_TRUNCATED_PH_LENGTH] = (uint8_t)((0u << 5) | (frame[UNI_USLP_TRUNCATED_PH_LENGTH] & 0x1Fu));

    auto st = uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size());
    REQUIRE(st == UNI_USLP_ERROR_INVALID_FRAME);
}

TEST_CASE("Accept truncated: capability disabled causes reject", "[uslp][truncated][error]")
{
    constexpr uint16_t SCID = 0x5555;
    constexpr uint8_t VCID = 9;
    constexpr uint8_t MAP = 4;

    auto global = base_params_varlen();

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &global) == UNI_USLP_SUCCESS);

    // VC configured but truncated not enabled
    auto vc_params = global;
    vc_params.truncated_frame_capable = false;
    vc_params.truncated_frame_length = UNI_USLP_TRUNCATED_MIN_LENGTH;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    // Build a valid truncated frame by temporarily enabling capability on a scratch VC
    // Instead, construct using the public builder with a separate context to avoid internal access.
    uni_uslp_context_t ctx2{};
    REQUIRE(uni_ccsds_uslp_init(&ctx2, SCID, &global) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx2, VCID, &vc_params) == UNI_USLP_SUCCESS);
    // Enable capability for builder
    vc_params.truncated_frame_capable = true;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx2, VCID, &vc_params) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx2, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> sdu{0xEE};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx2, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(UNI_USLP_TRUNCATED_MIN_LENGTH, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_truncated(&ctx2, VCID, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    REQUIRE(out_len == UNI_USLP_TRUNCATED_MIN_LENGTH);

    // Now accept with capability disabled in ctx: should be rejected as non-truncated path cannot parse
    auto st = uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size());
    REQUIRE(st == UNI_USLP_ERROR_INVALID_FRAME);
}