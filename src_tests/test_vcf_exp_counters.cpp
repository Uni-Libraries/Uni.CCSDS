/**
 * @file test_vcf_exp_counters.cpp
 * @brief Tests for USLP VCF counters (Expedited QoS) and MAPA QoS behavior
 *
 * Coverage:
 * - USLP-131 (VCF Count Length — Expedited): Partial
 *   - TX shall NOT emit an Expedited VCF Count (set vcf_count_len=0 when PH.Bypass=1)
 *   - RX continuity is supported when the field is present (accept path honors Bypass=1)
 *   - §4.1.2.11; §2.1.2.3
 * - USLP-27 (MAPA QoS): M, Support=N — No COP/QoS for MAPA (§3.5.2.5)
 *   - Builder always sets PH.Bypass=0 for MAPA (no QoS parameter on MAPA.request)
 *
 * References:
 * - CCSDS 732.1-B-3 §4.1.2 Primary Header (Bypass flag, VCF Count Length/Count)
 * - CCSDS 732.1-B-3 §4.1.4 TFDF header (Rule selection)
 * - CCSDS 732.1-B-3 §3.5.2.5 (MAPA QoS)
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

// Capture gap flags from SDU callback (used for RX continuity checks)
struct GapCapture {
    std::vector<bool> gaps;
    std::vector<std::vector<uint8_t>> sdu_list;
};

void sdu_gap_cb(uni_uslp_context_t*,
                uint8_t,
                uint8_t,
                uni_uslp_service_type_t,
                const uint8_t* sdu_data,
                size_t sdu_length,
                uni_uslp_verification_status_t,
                bool gap_detected,
                void* user)
{
    auto* cap = static_cast<GapCapture*>(user);
    cap->gaps.push_back(gap_detected);
    cap->sdu_list.emplace_back(sdu_data, sdu_data + sdu_length);
}

// Minimal, variable-length, no FECF/Insert/OCF global params
static void configure_common_varlen_no_fecf(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;        // variable-length
    p.fecf_capability = false;     // disable FECF to simplify manual tamper/build
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;

    // VCF defaults; tests will set Exp/Seq lengths explicitly
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
}

// Helper to build an expedited (Bypass=1) variable-length frame with a given VCF Count octet (len=1)
// PH: vcf_count_len=1, vcf_count = value
// TFDF: Rule '011' (Octet Stream), UPID=2, 1-byte payload
static void build_expedited_with_vcf1(uint16_t scid,
                                      uint8_t vcid,
                                      uint8_t map_id,
                                      uint8_t vcf_val,
                                      const std::vector<uint8_t>& tfdz_payload,
                                      std::vector<uint8_t>& out_frame)
{
    REQUIRE(tfdz_payload.size() > 0);

    // PH fields
    uni_uslp_primary_header_t ph{};
    ph.tfvn = UNI_USLP_TFVN;
    ph.scid = scid;
    ph.source_dest = false;  // SCID refers to source
    ph.vcid = vcid;
    ph.map_id = map_id;
    ph.eof_ph_flag = false;
    ph.bypass_flag = true;   // Expedited path (Bypass=1)
    ph.cc_flag = false;
    ph.ocf_flag = false;
    ph.vcf_count_len = 1;    // FORCE presence of Expedited VCF Count (RX continuity test)
    ph.vcf_count = vcf_val;

    // TFDF header: Rule '011' (variable, Octet Stream), no pointer
    uni_uslp_tfdf_header_t th{};
    th.construction_rule = UNI_USLP_TFDZ_RULE_3;
    th.upid = 2; // example UPID for Octet Stream
    th.first_header_ptr = 0;
    th.last_valid_ptr = 0;

    // Total length (no Insert/OCF/FECF):
    //  PH(7) + VCF(1) + TH(1) + TFDZ(N)
    const size_t total = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + 1u + 1u + tfdz_payload.size();
    ph.frame_length = (uint16_t)(total - 1u);

    out_frame.assign(total, 0x00);
    size_t off = 0;

    // Pack PH
    size_t ph_written = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_pack(&ph, out_frame.data(), out_frame.size(), &ph_written) == UNI_USLP_SUCCESS);
    off += ph_written;
    REQUIRE(ph_written == (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + 1u);

    // Pack TFDF header
    size_t th_written = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&th, &out_frame[off], out_frame.size() - off, &th_written) == UNI_USLP_SUCCESS);
    off += th_written;
    REQUIRE(th_written == 1u);

    // Copy TFDZ
    REQUIRE(off + tfdz_payload.size() == out_frame.size());
    std::memcpy(&out_frame[off], tfdz_payload.data(), tfdz_payload.size());
}

} // namespace


TEST_CASE("VCF-EXP: TX omits Expedited VCF Count (vcf_count_len=0) while Bypass=1", "[uslp][vcf][exp][tx]")
{
    // Global managed params
    uni_uslp_managed_params_t global{};
    configure_common_varlen_no_fecf(global);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5252, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 6;
    const uint8_t MAP  = 1;

    // VC params: set Expedited VCF length to 1 octet (managed param), but builder must not emit it
    auto vc_params = global;
    vc_params.vcf_seq_count_len_octets = 0;
    vc_params.vcf_exp_count_len_octets = 1; // configured, but TX shall still set PH.vcf_count_len=0 for Bypass=1
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    // MAP configured for Octet Stream Service (expedited default true)
    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &map_params) == UNI_USLP_SUCCESS);

    // Queue two Octet Stream portions (wrapper defaults to expedited=true)
    const std::vector<uint8_t> os1 = { 0xAA, 0xBB, 0xCC };
    REQUIRE(uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, os1.data(), os1.size(), true, 0u) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> f1(256, 0x00);
    size_t l1 = f1.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f1.data(), &l1) == UNI_USLP_SUCCESS);
    f1.resize(l1);

    // PH shall have Bypass=1, but vcf_count_len==0 (no Expedited VCF transmitted) — USLP-131 Partial (TX omission)
    uni_uslp_primary_header_t ph{};
    size_t ph_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(f1.data(), f1.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
    REQUIRE(ph.bypass_flag == true);
    REQUIRE(ph.vcf_count_len == 0);

    // Second
    const std::vector<uint8_t> os2 = { 0x01, 0x02 };
    REQUIRE(uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, os2.data(), os2.size(), true, 0u) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> f2(256, 0x00);
    size_t l2 = f2.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f2.data(), &l2) == UNI_USLP_SUCCESS);
    f2.resize(l2);

    uni_uslp_primary_header_t ph2{};
    size_t ph2_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(f2.data(), f2.size(), &ph2, &ph2_read) == UNI_USLP_SUCCESS);
    REQUIRE(ph2.bypass_flag == true);
    REQUIRE(ph2.vcf_count_len == 0);
}

TEST_CASE("VCF-EXP: RX continuity when Expedited VCF Count is present", "[uslp][vcf][exp][rx]")
{
    uni_uslp_managed_params_t global{};
    configure_common_varlen_no_fecf(global);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5353, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 3;
    const uint8_t MAP  = 2;

    // Configure VC/MAP for Octet Stream; no need to enable any VCF lengths for accept path
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &global) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &global) == UNI_USLP_SUCCESS);

    // Register SDU callback to capture gap flags (derived from VCF Count continuity per §4.3.7.4)
    GapCapture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_gap_cb, &cap) == UNI_USLP_SUCCESS);

    // Build three expedited frames manually with vcf_count_len=1 and counts: 0 (sync), 1 (in-order), 3 (gap)
    std::vector<uint8_t> f0, f1, fdup;
    build_expedited_with_vcf1(/*SCID*/ 0x5353, VCID, MAP, /*R=*/0x00, std::vector<uint8_t>{0x10}, f0);
    build_expedited_with_vcf1(/*SCID*/ 0x5353, VCID, MAP, /*R=*/0x01, std::vector<uint8_t>{0x11,0x22}, f1);
    build_expedited_with_vcf1(/*SCID*/ 0x5353, VCID, MAP, /*R=*/0x03, std::vector<uint8_t>{0x33}, fdup);

    // Accept in sequence: expect gaps = [false (initial sync), false (in-order), true (skip from expected=2 to 3)]
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f0.data(), f0.size()) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f1.data(), f1.size()) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fdup.data(), fdup.size()) == UNI_USLP_SUCCESS);

    REQUIRE(cap.gaps.size() == 3);
    REQUIRE(cap.gaps[0] == false);
    REQUIRE(cap.gaps[1] == false);
    REQUIRE(cap.gaps[2] == true);

    // Accept a duplicate of last value (R=3 again) — should not assert gap (duplicate policy)
    std::vector<uint8_t> fdup2;
    build_expedited_with_vcf1(/*SCID*/ 0x5353, VCID, MAP, /*R=*/0x03, std::vector<uint8_t>{0x34}, fdup2);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fdup2.data(), fdup2.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.gaps.size() == 4);
    REQUIRE(cap.gaps[3] == false);
}

TEST_CASE("MAPA QoS: PH.Bypass=0 (No QoS on MAPA.request per §3.5.2.5; USLP-27 Support=N)", "[uslp][mapa][qos]")
{
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5454, &p) == UNI_USLP_SUCCESS);

    const uint8_t VC = 1, MAP = 5;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    const std::vector<uint8_t> sdu = { 0xDE, 0xAD, 0xBE, 0xEF };
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(256, 0x00);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Verify PH.Bypass == 0 for MAPA (no QoS on MAPA_SDU)
    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_len) == UNI_USLP_SUCCESS);
    REQUIRE(ph.bypass_flag == false);
}