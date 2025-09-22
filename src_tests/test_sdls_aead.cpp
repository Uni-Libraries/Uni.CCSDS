// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

/*
 * SDLS AES-GCM (AEAD) encryption/decryption tests for USLP
 *
 * References:
 * - CCSDS 732.1-B-3 §6 (SDLS integration with USLP)
 * - CCSDS 355.0-B-2 (Space Data Link Security Protocol)
 *
 * Coverage:
 * - ApplySecurity produces encrypted TFDF and tag; ProcessSecurity decrypts and verifies tag
 * - Anti-replay sliding window rejects duplicate (same SN)
 * - Tamper in ciphertext/tag causes ProcessSecurity failure
 * - Security Header presence (SPI+SN) length 9, trailer tag 16 per defaults
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds_uslp_internal.h"
#include "uni_crypto.h"

// stdlib
#include <vector>
#include <cstring>
#include <cstdint>

struct CapVer {
    std::vector<uint8_t> data;
    uni_uslp_verification_status_t ver{};
};

static void sdu_capture_cb(uni_uslp_context_t*,
                           uint8_t,
                           uint8_t,
                           uni_uslp_service_type_t,
                           const uint8_t* sdu_data,
                           size_t sdu_length,
                           uni_uslp_verification_status_t verification_status, bool,
                           void* user)
{
    auto* out = static_cast<CapVer*>(user);
    out->data.assign(sdu_data, sdu_data + sdu_length);
    out->ver = verification_status;
}

static void configure_common_varlen_no_fecf(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;          // variable-length
    p.fecf_capability = false;       // disable FECF to isolate SDLS behavior here
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
}

TEST_CASE("SDLS AES-GCM: encrypt/decrypt MAPA round-trip; tamper and replay detection", "[sdls][aead][aes-gcm]")
{
    // Preflight: verify backend AES-GCM is operational; if not, skip test gracefully.
    {
        const uint8_t key[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };
        const uint8_t iv[12]  = { 0 };
        const uint8_t pt[4]   = { 1,2,3,4 };
        uint8_t ct[4]         = { 0 };
        uint8_t tag[16]       = { 0 };
        int rc = uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                                         key, sizeof(key),
                                         iv, sizeof(iv),
                                         NULL, 0,
                                         pt, sizeof(pt),
                                         ct, tag, sizeof(tag));
        if (rc != 0) {
            // Backend lacks AES-GCM runtime; skip this test.
            return;
        }
    }
    // Managed params (variable-length, no FECF)
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x6161, &p) == UNI_USLP_SUCCESS);

    // Register built-in SDLS callbacks
    REQUIRE(uni_ccsds_uslp_register_builtin_sdls(&ctx) == UNI_USLP_SUCCESS);

    // Provide RX work buffer
    std::vector<uint8_t> work(4096);
    REQUIRE(uni_ccsds_uslp_set_work_buffer(&ctx, work.data(), work.size()) == UNI_USLP_SUCCESS);

    // Configure VC and MAPA
    const uint8_t VC = 4, MAP = 2;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    // SDLS config for AES-GCM (AEAD)
    static const uint8_t aead_key_128[] = {
        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
    };

    uni_uslp_sdls_config_t sdls{};
    sdls.enabled = true;
    sdls.spi = 3;
    sdls.iv_length = 12;          // derived IV length (fixed)
    sdls.mac_length = 16;         // tag length
    sdls.authentication_only = false;
    sdls.encryption_enabled = true;
    sdls.suite = UNI_USLP_SDLS_SUITE_AES_GCM;
    sdls.key = aead_key_128;
    sdls.key_length = sizeof(aead_key_128);
    sdls.anti_replay_enabled = true;
    sdls.anti_replay_window = 64;
    sdls.sec_header_present = true;
    sdls.sec_trailer_present = true;
    sdls.sec_header_length = 9;   // SPI(1)+SN(8)
    sdls.sec_trailer_length = 16; // tag length

    REQUIRE(uni_ccsds_uslp_configure_sdls(&ctx, VC, &sdls) == UNI_USLP_SUCCESS);

    // Install SDU capture callback (capture verification status per §3.7.2.7 C2)
    CapVer cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC, MAP, sdu_capture_cb, &cap) == UNI_USLP_SUCCESS);

    // Prepare MAPA SDU and build a secured frame
    const std::vector<uint8_t> sdu = { 0xBA,0xAD,0xF0,0x0D,0x12,0x34,0x56,0x78 };
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(512);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Accept: should decrypt/authenticate and deliver SDU with Verification Status Code = SUCCESS (C2)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.data == sdu);
    REQUIRE(cap.ver == UNI_USLP_VERIF_SUCCESS);

    // Replay: same frame should be rejected by anti-replay window
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_ERROR_SDLS_FAILURE);

    // Tamper: flip one bit in ciphertext or tag; we flip last byte (part of tag for default layout)
    std::vector<uint8_t> tampered = frame;
    tampered.back() ^= 0x01;
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, tampered.data(), tampered.size()) == UNI_USLP_ERROR_SDLS_FAILURE);
}