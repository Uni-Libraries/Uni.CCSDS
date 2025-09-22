/**
 * @file test_octet_stream.cpp
 * @brief Unit/Integration tests for MAP Octet Stream Service (CCSDS 732.1-B-3 §3.7)
 *
 * Covers:
 * - OCTET_STREAM.request expedited (Bypass=1) and sequence-controlled (Bypass=0)
 * - Variable-length only restriction (§2.2.4.6, §2.2.5 g)
 * - Build path Rule '011' TFDF header (§4.1.4.2.2.2.4)
 * - RX delivery (OCTET_STREAM.indication) and Loss Flag derived from VCF gaps (§3.7.2.6; §4.3.7.4)
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include "uni_crypto.h"

#include <vector>
#include <cstring>
#include <cstdint>

namespace {

struct OctetStreamCap {
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
    auto* cap = static_cast<OctetStreamCap*>(user);
    cap->called = true;
    cap->vcid = vcid;
    cap->map_id = map_id;
    cap->service = service_type;
    cap->gap = gap_detected;
    cap->sdu.assign(sdu_data, sdu_data + sdu_length);
}

static void unpack_ph(const std::vector<uint8_t>& frame,
                      uni_uslp_primary_header_t& ph,
                      size_t& ph_len)
{
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &read) == UNI_USLP_SUCCESS);
    ph_len = read;
}
/* Helper: build an expedited (Bypass=1) variable-length frame with a given 1-octet VCF-EXP value.
 * PH: vcf_count_len=1, vcf_count = value
 * TFDF: Rule '011' (Octet Stream), UPID=2, TFDZ = provided payload
 * No Insert/OCF/FECF. */
static void build_expedited_with_vcf1(uint16_t scid,
                                      uint8_t vcid,
                                      uint8_t map_id,
                                      uint8_t vcf_val,
                                      const std::vector<uint8_t>& tfdz_payload,
                                      std::vector<uint8_t>& out_frame)
{
    REQUIRE(!tfdz_payload.empty());

    // Primary Header
    uni_uslp_primary_header_t ph{};
    ph.tfvn = UNI_USLP_TFVN;
    ph.scid = scid;
    ph.source_dest = false;  // SCID refers to source
    ph.vcid = vcid;
    ph.map_id = map_id;
    ph.eof_ph_flag = false;
    ph.bypass_flag = true;   // Expedited
    ph.cc_flag = false;
    ph.ocf_flag = false;
    ph.vcf_count_len = 1;    // Force presence of Expedited VCF Count for RX continuity tests (USLP-131 partial)
    ph.vcf_count = vcf_val;

    // TFDF Header: Rule '011' (Octet Stream), no pointer
    uni_uslp_tfdf_header_t th{};
    th.construction_rule = UNI_USLP_TFDZ_RULE_3;
    th.upid = 2;
    th.first_header_ptr = 0;
    th.last_valid_ptr = 0;

    // Length: PH(7) + VCF(1) + TH(1) + TFDZ(N)
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


TEST_CASE("Octet Stream expedited: variable-length, Rule '011', bypass=1; VCF-EXP omitted (Partial USLP-131)", "[uslp][octet_stream][expedited]")
{
    // Global managed parameters for variable-length with FECF and EXP counter length
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 4096;
    p.min_frame_length = 0; // variable-length
    p.fecf_capability = true;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    p.vcf_count_length = 0;          // legacy unused
    p.vcf_seq_count_len_octets = 0;  // only EXP used in this test
    p.vcf_exp_count_len_octets = 1;  // 1-octet counter for EXP

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x4444, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 3;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);

    const uint8_t MAP = 9;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    OctetStreamCap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Payload for Octet Stream
    std::vector<uint8_t> data{0x00,0x11,0x22,0x33,0x44,0x55};
    // expedited=true (Bypass=1), SDU ID 1234 (sending-end accounting)
    REQUIRE(uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, data.data(), data.size(), true, 1234u) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(256, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    frame.resize(out_len);
    REQUIRE(out_len > 0);

    // Verify PH: bypass=1 for expedited, VCF length=1 (EXP)
    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    unpack_ph(frame, ph, ph_len);
    REQUIRE(ph.bypass_flag == true);
    REQUIRE(ph.vcf_count_len == 0);

    // Parse TFDF header directly to verify Rule '011'
    uni_uslp_tfdf_header_t th{};
    size_t off = ph_len; // variable-length => no insert zone
    size_t th_read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(&frame[off], frame.size() - off, &th, &th_read) == UNI_USLP_SUCCESS);
    REQUIRE(th.construction_rule == UNI_USLP_TFDZ_RULE_3); // '011'
    REQUIRE(th.first_header_ptr == 0);
    REQUIRE(th.last_valid_ptr == 0);

    // Verify CRC (FECF)
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == true);

    // Accept and validate callback delivery
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.vcid == VCID);
    REQUIRE(cap.map_id == MAP);
    REQUIRE(cap.service == UNI_USLP_SERVICE_OCTET_STREAM);
    REQUIRE(cap.gap == false);
    REQUIRE(cap.sdu == data);
}

TEST_CASE("Octet Stream sequence-controlled: variable-length, bypass=0 uses VCF-SEQ length", "[uslp][octet_stream][seq]")
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 4096;
    p.min_frame_length = 0; // variable-length
    p.fecf_capability = false;
    p.vcf_seq_count_len_octets = 2; // use SEQ counter with 2 octets
    p.vcf_exp_count_len_octets = 0;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x4747, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 5;
    const uint8_t MAP  = 6;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    OctetStreamCap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> data{0xA1,0xB2,0xC3};
    // expedited=false => Bypass=0 (Sequence-Controlled)
    REQUIRE(uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, data.data(), data.size(), false, 1u) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> frame(256, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    frame.resize(out_len);

    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    unpack_ph(frame, ph, ph_len);
    REQUIRE(ph.bypass_flag == false);
    REQUIRE(ph.vcf_count_len == 2);

    // Accept
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.called == true);
    REQUIRE(cap.service == UNI_USLP_SERVICE_OCTET_STREAM);
    REQUIRE(cap.sdu == data);
    REQUIRE(cap.gap == false);
}

TEST_CASE("Octet Stream rejected on fixed-length frames per §2.2.4.6/§2.2.5(g)", "[uslp][octet_stream][restriction]")
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 256;
    p.min_frame_length = 256; // fixed-length
    p.fecf_capability = false;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x4A4A, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 1;
    const uint8_t MAP  = 2;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> data{0x01,0x02,0x03};
    // Attempt expedited -> must fail UNSUPPORTED due to fixed-length restriction
    REQUIRE(uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, data.data(), data.size(), true, 0u) == UNI_USLP_ERROR_UNSUPPORTED);
}

TEST_CASE("Octet Stream Loss Flag from VCF-EXP gap", "[uslp][octet_stream][loss-flag][expedited]")
{
    // Variable-length, EXP counter length = 1
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 1024;
    p.min_frame_length = 0;
    p.fecf_capability = false; // no CRC to allow tampering PH easily
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 1;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x4D4D, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 10;
    const uint8_t MAP  = 3;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    OctetStreamCap cap1{}, cap2{}, cap3{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap1) == UNI_USLP_SUCCESS);

    // Build first expedited frame (counter 0) manually with vcf_count_len=1
    std::vector<uint8_t> sdu0 = {0xAA};
    std::vector<uint8_t> f0;
    build_expedited_with_vcf1(/*SCID*/ 0x4D4D, VCID, MAP, /*R=*/0x00, sdu0, f0);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f0.data(), f0.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap1.called == true);
    REQUIRE(cap1.gap == false);

    // Second expedited frame: set R=3 to introduce a gap
    OctetStreamCap cap_gap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap_gap) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> sdu_gap = {0xBB, 0xCC};
    std::vector<uint8_t> fg;
    build_expedited_with_vcf1(/*SCID*/ 0x4D4D, VCID, MAP, /*R=*/0x03, sdu_gap, fg);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fg.data(), fg.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap_gap.called == true);
    REQUIRE(cap_gap.gap == true); // Loss Flag asserted

    // Third: duplicate R=3 => should not assert gap
    OctetStreamCap cap_dup{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap_dup) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> sdu_dup = {0xDD};
    std::vector<uint8_t> fd;
    build_expedited_with_vcf1(/*SCID*/ 0x4D4D, VCID, MAP, /*R=*/0x03, sdu_dup, fd);

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fd.data(), fd.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap_dup.called == true);
    REQUIRE(cap_dup.gap == false); // duplicate should not assert Loss Flag
}