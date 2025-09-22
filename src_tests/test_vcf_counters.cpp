/**
 * @file test_vcf_counters.cpp
 * @brief Tests for USLP VCF counters (Sequence-controlled) TX/RX behavior per CCSDS 732.1-B-3
 *
 * Covers:
 * - Per-VC VCF-SEQ length configuration (USLP-130) with 1-octet counter on-wire
 * - Primary Header contains VCF Count field with correct length and value
 * - RX initial synchronization (first frame with VCF Count)
 * - In-order delivery: no gap_detected
 * - Gap detection when a frame with skipped counter is received
 * - Duplicate detection (previous value): no gap_detected
 *
 * References:
 * - §4.1.2 Primary Header (VCF Count Length/Count)
 * - §2.1.2.3 VCF procedures (Sequence-Controlled vs Expedited)
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

struct CaptureSeq {
    std::vector<bool> gaps;
    std::vector<std::vector<uint8_t>> sdu_list;
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
    (void)ctx; (void)vcid; (void)map_id; (void)service_type;
    auto* cap = static_cast<CaptureSeq*>(user);
    cap->gaps.push_back(gap_detected);
    cap->sdu_list.emplace_back(sdu_data, sdu_data + sdu_length);
}

static void unpack_ph(const std::vector<uint8_t>& frame,
                      uni_uslp_primary_header_t& ph,
                      size_t& ph_len)
{
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &read) == UNI_USLP_SUCCESS);
    ph_len = read;
}

} // namespace

TEST_CASE("VCF-SEQ: TX emits 1-octet counter, RX sync and in-order without gaps", "[uslp][vcf][seq][no-gap]")
{
    // Global managed params: variable-length, no FECF to simplify tampering later
    uni_uslp_managed_params_t global{};
    global.max_frame_length = 4096;
    global.min_frame_length = 0;
    global.truncated_frame_capable = false;
    global.truncated_frame_length = 0;
    global.mcf_count_length = 0;
    global.vcf_count_length = 0;            // legacy; keep zero
    global.vcf_seq_count_len_octets = 1;    // USLP-130: enable 1-octet VCF-SEQ
    global.vcf_exp_count_len_octets = 0;
    global.vcf_persist = false;
    global.vcf_duplicate_window = 1;
    global.ocf_capability = false;
    global.insert_zone_capability = false;
    global.insert_zone_length = 0;
    global.fecf_capability = false;         // keep CRC out for simplicity in tamper tests
    global.segmentation_permitted = false;
    global.blocking_permitted = false;
    global.max_sdu_length = 1024;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4242, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 2;
    const uint8_t MAP  = 5;

    auto vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);
    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    CaptureSeq cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // First SDU/frame (counter expected 0x00)
    std::vector<uint8_t> sdu1{0xAA, 0xBB, 0xCC};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu1.data(), sdu1.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> f1(256, 0x00);
    size_t len1 = f1.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f1.data(), &len1) == UNI_USLP_SUCCESS);
    f1.resize(len1);

    // Verify PH has VCF length=1 and value=0 for first frame
    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    unpack_ph(f1, ph, ph_len);
    REQUIRE(ph.vcf_count_len == 1);
    REQUIRE(ph.vcf_count == 0x00);

    // Accept -> initial sync, no gap, SDU delivered
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f1.data(), f1.size()) == UNI_USLP_SUCCESS);

    // Second SDU/frame (counter expected 0x01)
    std::vector<uint8_t> sdu2{0x11, 0x22};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu2.data(), sdu2.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> f2(256, 0x00);
    size_t len2 = f2.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f2.data(), &len2) == UNI_USLP_SUCCESS);
    f2.resize(len2);

    unpack_ph(f2, ph, ph_len);
    REQUIRE(ph.vcf_count_len == 1);
    REQUIRE(ph.vcf_count == 0x01);

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f2.data(), f2.size()) == UNI_USLP_SUCCESS);

    // Check callback results for two frames: no gaps and SDUs match
    REQUIRE(cap.gaps.size() == 2);
    REQUIRE(cap.sdu_list.size() == 2);
    REQUIRE(cap.gaps[0] == false);
    REQUIRE(cap.gaps[1] == false);
    REQUIRE(cap.sdu_list[0] == sdu1);
    REQUIRE(cap.sdu_list[1] == sdu2);
}

TEST_CASE("VCF-SEQ: gap detection when counter skips ahead; duplicate does not assert gap", "[uslp][vcf][seq][gap-dup]")
{
    uni_uslp_managed_params_t global{};
    global.max_frame_length = 4096;
    global.min_frame_length = 0;
    global.truncated_frame_capable = false;
    global.mcf_count_length = 0;
    global.vcf_seq_count_len_octets = 1;
    global.vcf_exp_count_len_octets = 0;
    global.fecf_capability = false; // so we can tamper PH without recalculating CRC
    global.max_sdu_length = 1024;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x5151, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 4;
    const uint8_t MAP  = 7;
    auto vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);
    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    CaptureSeq cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Build and accept first frame (VCF=0)
    std::vector<uint8_t> sdu0{0x01};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu0.data(), sdu0.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> f0(128, 0x00);
    size_t l0 = f0.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f0.data(), &l0) == UNI_USLP_SUCCESS);
    f0.resize(l0);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f0.data(), f0.size()) == UNI_USLP_SUCCESS);

    // Build second frame normally (VCF=1), then tamper VCF Count to 3 (skip one => gap)
    std::vector<uint8_t> sdu_gap{0x02, 0x03};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu_gap.data(), sdu_gap.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fg(128, 0x00);
    size_t lg = fg.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, fg.data(), &lg) == UNI_USLP_SUCCESS);
    fg.resize(lg);

    // Tamper PH VCF octet: set to 3
    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    unpack_ph(fg, ph, ph_len);
    REQUIRE(ph.vcf_count_len == 1);
    fg[UNI_USLP_PRIMARY_HEADER_LENGTH + 0] = 0x03; // overwrite VCF Count to 3

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fg.data(), fg.size()) == UNI_USLP_SUCCESS);

    // Build third frame normally (builder counter advanced internally), then tamper as duplicate of previous expected-1
    std::vector<uint8_t> sdu_dup{0x99};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu_dup.data(), sdu_dup.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fd(128, 0x00);
    size_t ld = fd.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, fd.data(), &ld) == UNI_USLP_SUCCESS);
    fd.resize(ld);

    // Make it a duplicate of just-received value 3 -> duplicate should not assert gap (policy gap=false)
    fd[UNI_USLP_PRIMARY_HEADER_LENGTH + 0] = 0x03;

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fd.data(), fd.size()) == UNI_USLP_SUCCESS);

    // Expect: three deliveries; gaps: [false (initial sync), true (skip), false (duplicate)]
    REQUIRE(cap.gaps.size() == 3);
    REQUIRE(cap.gaps[0] == false);
    REQUIRE(cap.gaps[1] == true);
    REQUIRE(cap.gaps[2] == false);
    REQUIRE(cap.sdu_list.size() == 3);
    REQUIRE(cap.sdu_list[0] == sdu0);
    REQUIRE(cap.sdu_list[1] == sdu_gap);
    REQUIRE(cap.sdu_list[2] == sdu_dup);
}