// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

/*
 * SDLS HMAC-SHA256 (authentication-only) tests for USLP (CCSDS 732.1-B-3 §6 with CCSDS 355.0-B-2)
 *
 * Coverage mapping to PICS (Table A-7/A-8):
 * - USLP-151: SDLS Protocol (option) — exercised via built-in SDLS engine registration
 * - USLP-152: Security Header — header format SPI(1)+SN(8), length=9
 * - USLP-153: Security Trailer — ICV/tag length=16
 * - USLP-154: TFDF with SDLS — authentication over TFDF (header+TFDZ) only
 * - USLP-156: FECF with SDLS — FECF excluded from integrity scope; FECF disabled in these tests to focus SDLS
 * - USLP-157–165: Send with SDLS — ApplySecurity invoked in build path before OCF/FECF
 * - USLP-166–175: Receive with SDLS — ProcessSecurity invoked before TFDF unpack; anti-replay enforced
 * - USLP-176–179: Managed params — presence/length of SecHeader/SecTrailer used for sizing and validation
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds_uslp_internal.h"

// stdlib
#include <vector>
#include <cstring>
#include <cstdint>

struct CapVer {
    std::vector<uint8_t> data;
    uni_uslp_verification_status_t ver{};
};

static void sdu_capture_cb(uni_uslp_context_t*,
                           uint8_t vcid,
                           uint8_t map_id,
                           uni_uslp_service_type_t service_type,
                           const uint8_t* sdu_data,
                           size_t sdu_length,
                           uni_uslp_verification_status_t verification_status, bool gap_detected,
                           void* user)
{
    (void)vcid; (void)map_id; (void)service_type; (void)gap_detected;
    auto* out = static_cast<CapVer*>(user);
    out->data.assign(sdu_data, sdu_data + sdu_length);
    out->ver = verification_status;
}

static void configure_common_varlen_no_fecf(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;          // variable-length
    p.fecf_capability = false;       // disable FECF to allow SDLS tampering without CRC impact
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    // VCF absent in this test
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
}

TEST_CASE("SDLS HMAC: protect/unprotect MAPA round-trip; trailer tamper detected; duplicate rejected", "[sdls][hmac][auth-only]")
{
    // Global managed params
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5151, &p) == UNI_USLP_SUCCESS);

    // Register built-in SDLS callbacks
    REQUIRE(uni_ccsds_uslp_register_builtin_sdls(&ctx) == UNI_USLP_SUCCESS);

    // Work buffer for RX SDLS Process
    std::vector<uint8_t> work(4096);
    REQUIRE(uni_ccsds_uslp_set_work_buffer(&ctx, work.data(), work.size()) == UNI_USLP_SUCCESS);

    // Configure VC and MAPA
    const uint8_t VC = 2, MAP = 1;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    // SDLS config (HMAC-SHA256, ICV len 16, Header=SPI(1)+SN(8)=9, anti-replay window 64)
    static const uint8_t hmac_key[] = { 0x10,0x11,0x12,0x13,0x21,0x22,0x23,0x24,0x30,0x31,0x32,0x33,0x44,0x55,0x66,0x77,
                                        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };

    uni_uslp_sdls_config_t sdls{};
    sdls.enabled = true;
    sdls.spi = 1;
    sdls.iv_length = 0;          // not used in HMAC
    sdls.mac_length = 16;        // trailer tag length
    sdls.authentication_only = true;
    sdls.encryption_enabled = false;
    sdls.suite = UNI_USLP_SDLS_SUITE_HMAC_SHA256;
    sdls.key = hmac_key;
    sdls.key_length = sizeof(hmac_key);
    sdls.anti_replay_enabled = true;
    sdls.anti_replay_window = 64;
    sdls.sec_header_present = true;
    sdls.sec_trailer_present = true;
    sdls.sec_header_length = 9;  // SPI(1) + SN(8)
    sdls.sec_trailer_length = 16;

    REQUIRE(uni_ccsds_uslp_configure_sdls(&ctx, VC, &sdls) == UNI_USLP_SUCCESS);

    // SDU and SDU callback (capture verification status per §3.5.2.8 C2)
    CapVer cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC, MAP, sdu_capture_cb, &cap) == UNI_USLP_SUCCESS);

    // Send MAPA SDU and build frame
    const std::vector<uint8_t> sdu = { 0xDE,0xAD,0xBE,0xEF,0x01,0x23 };
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(512);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Accept: should authenticate and deliver SDU with Verification Status Code = SUCCESS (C2)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.data == sdu);
    REQUIRE(cap.ver == UNI_USLP_VERIF_SUCCESS);

    // Duplicate replay: re-accept same frame should be rejected by anti-replay
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_ERROR_SDLS_FAILURE);

    // Tamper trailer: flip one bit in last byte of frame; expect SDLS failure
    std::vector<uint8_t> bad = frame;
    REQUIRE(bad.size() > 0);
    bad[bad.size() - 1] ^= 0x01;
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, bad.data(), bad.size()) == UNI_USLP_ERROR_SDLS_FAILURE);
}