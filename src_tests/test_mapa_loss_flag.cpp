/**
 * @file test_mapa_loss_flag.cpp
 * @brief MAPA_SDU Loss Flag (USLP-28) derived from VCF-SEQ continuity (§3.5.2.7; §4.1.2.11)
 *
 * Verifies that for MAPA Rule '111' variable-length frames built with Bypass=0 (Sequence-Controlled),
 * the Loss Flag delivered on MAPA.indication is asserted when a VCF-SEQ gap is observed and
 * not asserted for in-order frames nor duplicates.
 *
 * References:
 * - CCSDS 732.1-B-3 §3.5.2.7 MAPA_SDU Loss Flag (parameter)
 * - CCSDS 732.1-B-3 §4.1.2.11 VCF Count Length and VCF Count (continuity)
 * - CCSDS 732.1-B-3 §4.3.7.4 Receiving VC Procedures (continuity handling)
 */

#include <catch2/catch_test_macros.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {
struct Cap {
    std::vector<bool> gaps;
    std::vector<uni_uslp_service_type_t> services;
    std::vector<std::vector<uint8_t>> sdus;
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
    (void)ctx; (void)vcid; (void)map_id; (void)verification_status;
    auto* cap = static_cast<Cap*>(user);
    cap->services.push_back(service_type);
    cap->gaps.push_back(gap_detected);
    cap->sdus.emplace_back(sdu_data, sdu_data + sdu_length);
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

TEST_CASE("MAPA Loss Flag from VCF-SEQ gap", "[uslp][mapa][loss-flag][seq]")
{
    // Global managed params: variable-length, no FECF to simplify tampering
    uni_uslp_managed_params_t global{};
    global.max_frame_length = 2048;
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
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x2A2A, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 1;
    const uint8_t MAP  = 3;

    auto vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);
    auto map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    Cap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // First frame (VCF=0)
    std::vector<uint8_t> sdu0{0x01};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu0.data(), sdu0.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> f0(128, 0x00);
    size_t l0 = f0.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f0.data(), &l0) == UNI_USLP_SUCCESS);
    f0.resize(l0);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f0.data(), f0.size()) == UNI_USLP_SUCCESS);

    // Second frame (builder would set VCF=1). Tamper to 3 => gap
    std::vector<uint8_t> sdu_gap{0x02, 0x03};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu_gap.data(), sdu_gap.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fg(128, 0x00);
    size_t lg = fg.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, fg.data(), &lg) == UNI_USLP_SUCCESS);
    fg.resize(lg);

    // Verify we have 1-octet VCF and then tamper its value to 3
    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    unpack_ph(fg, ph, ph_len);
    REQUIRE(ph.vcf_count_len == 1);
    fg[UNI_USLP_PRIMARY_HEADER_LENGTH + 0] = 0x03;

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fg.data(), fg.size()) == UNI_USLP_SUCCESS);

    // Third frame: build and make it a duplicate (3) => no new gap
    std::vector<uint8_t> sdu_dup{0xAA};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu_dup.data(), sdu_dup.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fd(128, 0x00);
    size_t ld = fd.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, fd.data(), &ld) == UNI_USLP_SUCCESS);
    fd.resize(ld);
    fd[UNI_USLP_PRIMARY_HEADER_LENGTH + 0] = 0x03; // duplicate of last received
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fd.data(), fd.size()) == UNI_USLP_SUCCESS);

    // Expectations
    REQUIRE(cap.services.size() == 3);
    REQUIRE(cap.gaps.size() == 3);
    REQUIRE(cap.services[0] == UNI_USLP_SERVICE_MAPA);
    REQUIRE(cap.services[1] == UNI_USLP_SERVICE_MAPA);
    REQUIRE(cap.services[2] == UNI_USLP_SERVICE_MAPA);
    REQUIRE(cap.gaps[0] == false);
    REQUIRE(cap.gaps[1] == true);  // Loss Flag asserted on gap
    REQUIRE(cap.gaps[2] == false); // Duplicate should not assert Loss Flag
}