/**
 * @file test_frame_build_parse.cpp
 * @brief Integration tests for frame build/accept minimal MAPA path
 *
 * Covers:
 * - Context init and configuration
 * - Enqueue MAPA SDU (zero-copy), build frame (variable-length, Rule '111')
 * - CRC-16 FECF append/verify
 * - Accept frame, parse headers, deliver SDU via callback
 *
 * References:
 * - CCSDS 732.1-B-3 §4.1 Transfer Frame
 * - §4.1.2 Primary Header
 * - §4.1.4 TFDF and TFDF Header ('111' No Segmentation)
 * - Annex B CRC-16
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include "uni_crypto.h"
#include <vector>
#include <cstring>

namespace {

struct CallbackCapture {
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
    auto* cap = static_cast<CallbackCapture*>(user);
    cap->called = true;
    cap->vcid = vcid;
    cap->map_id = map_id;
    cap->service = service_type;
    cap->gap = gap_detected;
    cap->sdu.assign(sdu_data, sdu_data + sdu_length);
}

} // namespace

TEST_CASE("Build and accept MAPA frame (variable-length, Rule '111', with FECF)", "[frame][mapa]")
{
    // Managed parameters set to enable variable-length frames and FECF
    uni_uslp_managed_params_t global{};
    global.max_frame_length = 4096;
    global.min_frame_length = 0;        // != max -> treated as variable in current minimal path
    global.truncated_frame_capable = false;
    global.truncated_frame_length = 0;
    global.mcf_count_length = 0;
    global.vcf_count_length = 0;
    global.ocf_capability = false;
    global.insert_zone_capability = false;
    global.insert_zone_length = 0;
    global.fecf_capability = true;      // enable FECF
    global.segmentation_permitted = false;
    global.blocking_permitted = false;
    global.max_sdu_length = 2048;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4242, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 2;
    uni_uslp_managed_params_t vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    const uint8_t MAP_ID = 5;
    uni_uslp_managed_params_t map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP_ID, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    CallbackCapture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP_ID, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Prepare a MAPA SDU
    std::vector<uint8_t> sdu{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP_ID, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    // Build frame
    std::vector<uint8_t> frame(256, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP_ID, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    REQUIRE(out_len > 0);
    frame.resize(out_len);

    // Verify CRC if FECF present (Annex B)
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == true);

    // Feed back to accept() and expect callback
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.vcid == VCID);
    REQUIRE(cap.map_id == MAP_ID);
    REQUIRE(cap.service == UNI_USLP_SERVICE_MAPA);
    REQUIRE(cap.gap == false);
    REQUIRE(cap.sdu == sdu);
}

TEST_CASE("Build MAPA frame with FECF TX offload append (PH counts FECF, buffer omits it)", "[frame][mapa][fecf][offload]")
{
    // Variable-length, FECF present on the wire but appended by hardware after the CPU buffer.
    uni_uslp_managed_params_t global{};
    global.max_frame_length = 4096;
    global.min_frame_length = 0;
    global.truncated_frame_capable = false;
    global.ocf_capability = false;
    global.insert_zone_capability = false;
    global.fecf_capability = true;
    global.fecf_tx_mode = UNI_USLP_FECF_TX_OFFLOAD_APPEND;
    global.max_sdu_length = 2048;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5555, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 1;
    const uint8_t MAP_ID = 2;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &global) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP_ID, UNI_USLP_SERVICE_MAPA, &global) == UNI_USLP_SUCCESS);

    // SDU
    std::vector<uint8_t> sdu{0x01, 0x02, 0x03, 0x04};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP_ID, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    // Build into a buffer that intentionally does NOT include the final 2 FECF bytes.
    std::vector<uint8_t> frame(256, 0xEE);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP_ID, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    frame.resize(out_len);

    // The returned buffer omits FECF bytes, so CRC verify must fail.
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == false);

    // Primary Header must still count the on-wire FECF bytes.
    uni_uslp_primary_header_t ph{};
    size_t ph_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
    REQUIRE((size_t)ph.frame_length + 1u == frame.size() + (size_t)UNI_USLP_FECF_LENGTH);
}

TEST_CASE("Fixed-length frame with Insert Zone and exact SDU fit", "[frame][fixed][iz]")
{
    // A fixed-length frame must be padded to its exact size.
    // This scenario tests a case where the SDU, headers, IZ, and FECF
    // perfectly fill the frame without needing extra idle padding.
    const uint16_t FIXED_LEN = 128;

    uni_uslp_managed_params_t p{};
    p.min_frame_length = FIXED_LEN;
    p.max_frame_length = FIXED_LEN;
    p.insert_zone_capability = true;
    p.insert_zone_length = 16;
    p.fecf_capability = true;
    p.segmentation_permitted = false;
    p.blocking_permitted = false;
    p.max_sdu_length = 256;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x123, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, 0, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, 0, 0, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    CallbackCapture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, 0, 0, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Prepare Insert Zone data (16 bytes)
    std::vector<uint8_t> iz_data(16);
    for (int i = 0; i < 16; ++i) iz_data[i] = static_cast<uint8_t>(0xA0 + i);
    REQUIRE(uni_ccsds_uslp_send_insert(&ctx, 0, iz_data.data(), iz_data.size()) == UNI_USLP_SUCCESS);

    // SDU size calculated to perfectly fit:
    // total = FIXED_LEN - PH - IZ - TFDF.hdr (Rule '111' = 1) - FECF(2)
    const size_t tfdf_hdr_len = 1u; // Rule '111' (no pointer)
    const size_t required_sdu_len = (size_t)FIXED_LEN
        - (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH
        - (size_t)iz_data.size()
        - tfdf_hdr_len
        - (size_t)UNI_USLP_FECF_LENGTH;
    std::vector<uint8_t> sdu(required_sdu_len, 0x5A);
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, 0, 0, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    // Build frame
    std::vector<uint8_t> frame(FIXED_LEN, 0xFF);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, 0, 0, frame.data(), &out_len) == UNI_USLP_SUCCESS);

    // Verify expectations
    REQUIRE(out_len == FIXED_LEN);
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == true);
    // IZ should be placed right after the 7-byte primary header
    REQUIRE(std::memcmp(frame.data() + 7, iz_data.data(), iz_data.size()) == 0);

    // Feed back to receiver
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.vcid == 0);
    REQUIRE(cap.map_id == 0);
    REQUIRE(cap.sdu == sdu);
}

TEST_CASE("Fixed-length frame with idle padding", "[frame][fixed][padding]")
{
    const uint16_t FIXED_LEN = 256;
    uni_uslp_managed_params_t p{};
    p.min_frame_length = FIXED_LEN;
    p.max_frame_length = FIXED_LEN;
    p.insert_zone_capability = false;
    p.fecf_capability = true;
    p.segmentation_permitted = false;
    p.blocking_permitted = false;
    p.max_sdu_length = 512;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x123, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, 0, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, 0, 0, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    CallbackCapture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, 0, 0, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // SDU is smaller than available TFDZ, requiring idle padding
    std::vector<uint8_t> sdu(100, 0xBB);
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, 0, 0, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(FIXED_LEN);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, 0, 0, frame.data(), &out_len) == UNI_USLP_SUCCESS);

    REQUIRE(out_len == FIXED_LEN);
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == true);

    // TFDZ starts after PH (7) and TFDF Header (1) for Rule '111' (no pointer per §4.1.4.2.4.1)
    const size_t tfdz_start = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + 1u;
    // SDU should be at the start
    REQUIRE(std::memcmp(frame.data() + tfdz_start, sdu.data(), sdu.size()) == 0);
    // Idle padding should follow the SDU until the FECF
    const size_t idle_start = tfdz_start + sdu.size();
    const size_t idle_end = FIXED_LEN - UNI_USLP_FECF_LENGTH;
    for (size_t i = idle_start; i < idle_end; ++i) {
        REQUIRE(frame[i] == UNI_USLP_DEFAULT_IDLE_FILLER);
    }
}

TEST_CASE("Truncated frame build and accept", "[frame][truncated]")
{
    uni_uslp_managed_params_t p{};
    p.truncated_frame_capable = true;
    p.truncated_frame_length = 20; // 4 PH + 1 TFDF.hdr + 15 TFDZ
    p.max_sdu_length = 32;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x123, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, 0, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, 0, 0, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    CallbackCapture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, 0, 0, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // SDU is smaller than the TFDZ, which is valid for truncated frames
    std::vector<uint8_t> sdu(15, 0xCC);
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, 0, 0, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(p.truncated_frame_length);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_truncated(&ctx, 0, frame.data(), &out_len) == UNI_USLP_SUCCESS);

    REQUIRE(out_len == p.truncated_frame_length);
    
    // No FECF on truncated frames
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == false);

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.vcid == 0);
    REQUIRE(cap.map_id == 0);
    REQUIRE(cap.sdu == sdu);
}
