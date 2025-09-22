/**
 * @file test_vca_verification.cpp
 * @brief VCA.indication delivers Verification Status Code (USLP-35, C2) when SDLS is enabled
 *
 * CCSDS 732.1-B-3:
 *  - §3.6.3.2 VCA_SDU (USLP-30)
 *  - §3.6.3.5 Service Type (USLP-33)
 *  - §3.6.3.7 Verification Status Code (USLP-35, C2): present on indication when SDLS option is enabled
 *  - §6 SDLS integration with USLP (ApplySecurity/ProcessSecurity on TFDF only)
 *
 * This test configures SDLS HMAC-SHA256 (auth-only) and verifies that the Verification Status Code
 * delivered to the generic SDU callback (for VCA service) is SUCCESS. Without SDLS, the code would be
 * NOT_APPLICABLE per C2 conditional note.
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>

#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct SduCap {
    bool called{false};
    uint8_t vcid{};
    uint8_t map{};
    uni_uslp_service_type_t service{};
    uni_uslp_verification_status_t ver{};
    std::vector<uint8_t> sdu;
};

static void sdu_cb(uni_uslp_context_t*,
                   uint8_t vcid,
                   uint8_t map_id,
                   uni_uslp_service_type_t service_type,
                   const uint8_t* sdu_data,
                   size_t sdu_length,
                   uni_uslp_verification_status_t verification_status,
                   bool /*gap_detected*/,
                   void* user)
{
    auto* cap = static_cast<SduCap*>(user);
    cap->called = true;
    cap->vcid = vcid;
    cap->map = map_id;
    cap->service = service_type;
    cap->ver = verification_status;
    cap->sdu.assign(sdu_data, sdu_data + sdu_length);
}

} // namespace

TEST_CASE("VCA + SDLS HMAC: Verification Status Code = SUCCESS (USLP-35, C2)", "[uslp][vca][sdls][verification]")
{
    // Variable-length, disable FECF to isolate SDLS behavior
    uni_uslp_managed_params_t p{};
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 2048;
    p.min_frame_length = 0;         // variable-length
    p.fecf_capability = false;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 1024;

    const uint8_t VCID = 7;
    const uint8_t MAP  = 2;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x6A6A, &p) == UNI_USLP_SUCCESS);

    // Register built-in SDLS engine and RX work buffer
    REQUIRE(uni_ccsds_uslp_register_builtin_sdls(&ctx) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> work(4096);
    REQUIRE(uni_ccsds_uslp_set_work_buffer(&ctx, work.data(), work.size()) == UNI_USLP_SUCCESS);

    // Configure VC and VCA MAP
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_VCA, &p) == UNI_USLP_SUCCESS);

    // SDLS HMAC configuration (Header=SPI(1)+SN(8)=9, Trailer=16)
    static const uint8_t key[] = {
        0x10,0x11,0x12,0x13,0x21,0x22,0x23,0x24,
        0x30,0x31,0x32,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
    };
    uni_uslp_sdls_config_t sdls{};
    sdls.enabled = true;
    sdls.spi = 0x42;
    sdls.iv_length = 0;
    sdls.mac_length = 16;
    sdls.authentication_only = true;
    sdls.encryption_enabled = false;
    sdls.suite = UNI_USLP_SDLS_SUITE_HMAC_SHA256;
    sdls.key = key;
    sdls.key_length = sizeof(key);
    sdls.anti_replay_enabled = true;
    sdls.anti_replay_window = 64;
    sdls.sec_header_present = true;
    sdls.sec_trailer_present = true;
    sdls.sec_header_length = 9;
    sdls.sec_trailer_length = 16;
    REQUIRE(uni_ccsds_uslp_configure_sdls(&ctx, VCID, &sdls) == UNI_USLP_SUCCESS);

    // Register generic SDU callback; VCA uses Rule '111' minimal path delivered via SDU callback
    SduCap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Send VCA SDU (Sequence-Controlled by default via wrapper -> Bypass=0)
    const uint8_t vca_sdu[] = { 0xF0, 0x0D, 0xBA, 0xBE, 0x12 };
    REQUIRE(uni_ccsds_uslp_send_vca_ex(&ctx, VCID, MAP, vca_sdu, sizeof(vca_sdu), false, 0u) == UNI_USLP_SUCCESS);

    // Build and accept
    std::vector<uint8_t> frame(512, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    frame.resize(out_len);

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

    // Validate that verification status is SUCCESS (C2) and service reported as VCA
    REQUIRE(cap.called == true);
    CHECK(cap.service == UNI_USLP_SERVICE_VCA);
    CHECK(cap.sdu == std::vector<uint8_t>(vca_sdu, vca_sdu + sizeof(vca_sdu)));
    CHECK(cap.ver == UNI_USLP_VERIF_SUCCESS);
}