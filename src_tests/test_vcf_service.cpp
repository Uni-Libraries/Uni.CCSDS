/**
 * @file test_vcf_service.cpp
 * @brief Tests for VCF Service parameters (USLP-45..USLP-47) — CCSDS 732.1-B-3 §3.9
 *
 * Scope:
 *  - USLP-45: USLP Frame (delivered via VCF.indication) (§3.9.2.2)
 *  - USLP-46: GVCID (SCID + VCID conveyed by Primary Header) (§3.9.2.3; §4.1.2.2.3, §4.1.2.4.1)
 *  - USLP-47: Frame Loss Flag (Optional), derived by examining VCF Count continuity (§3.9.2.4.2; §4.3.7.4)
 *
 * Strategy:
 *  - Enable VCF-SEQ (1 octet) on the VC.
 *  - Build three MAPA frames (Rule '111') and accept them:
 *     1) First frame: initial sync => no loss.
 *     2) Second frame: tamper the VCF byte to '3' to simulate a gap => loss flag true.
 *     3) Third frame: duplicate of '3' => not a gap (duplicate) => loss flag false.
 *  - Register VCF.indication and verify SCID/VCID and the Frame Loss Flag sequence [false, true, false].
 *
 * Notes:
 *  - FECF disabled to allow tampering of the Primary Header without CRC mismatch.
 *  - The entire frame (PH..FECF if present) is delivered to the VCF.indication per §3.9.2.2.
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct VcfCap {
    std::vector<bool> loss_flags;
    std::vector<uint16_t> scids;
    std::vector<uint8_t> vcids;
    size_t calls = 0;
};

static void vcf_cb(uni_uslp_context_t* ctx,
                   uint16_t scid,
                   uint8_t vcid,
                   const uint8_t* frame,
                   size_t frame_length,
                   bool frame_loss_flag,
                   void* user)
{
    (void)ctx;
    (void)frame;
    (void)frame_length;
    auto* cap = static_cast<VcfCap*>(user);
    cap->calls++;
    cap->scids.push_back(scid);
    cap->vcids.push_back(vcid);
    cap->loss_flags.push_back(frame_loss_flag);
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

TEST_CASE("VCF.indication delivers frame, GVCID, and Frame Loss Flag derived from VCF continuity", "[uslp][vcf][loss-flag]")
{
    // Managed parameters: variable-length, VCF-SEQ=1 octet; FECF disabled to allow tamper
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 2048;
    p.min_frame_length = 0;      // variable-length
    p.fecf_capability = false;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.vcf_count_length = 0;      // legacy unused
    p.vcf_seq_count_len_octets = 1; // enable SEQ counter
    p.vcf_exp_count_len_octets = 0;
    p.max_sdu_length = 1024;

    const uint16_t SCID = 0x1234;
    const uint8_t VCID = 7;
    const uint8_t MAP  = 3;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    VcfCap cap{};
    REQUIRE(uni_ccsds_uslp_register_vcf_indication_callback(&ctx, VCID, vcf_cb, &cap) == UNI_USLP_SUCCESS);

    // A minimal SDU to carry in each frame
    std::vector<uint8_t> sdu0{0x01};
    std::vector<uint8_t> sdu1{0x02};
    std::vector<uint8_t> sdu2{0x03};

    // Frame 0: initial sync -> no loss
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu0.data(), sdu0.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> f0(128, 0x00);
    size_t l0 = f0.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, f0.data(), &l0) == UNI_USLP_SUCCESS);
    f0.resize(l0);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, f0.data(), f0.size()) == UNI_USLP_SUCCESS);

    // Frame gap: build frame 1 normally, then tamper VCF-SEQ to 3 to create a gap (expected was 1)
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu1.data(), sdu1.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fg(128, 0x00);
    size_t lg = fg.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, fg.data(), &lg) == UNI_USLP_SUCCESS);
    fg.resize(lg);

    uni_uslp_primary_header_t ph{};
    size_t ph_len = 0;
    unpack_ph(fg, ph, ph_len);
    REQUIRE(ph.vcf_count_len == 1);
    // Tamper the first VCF count octet to 3 (gap relative to expected 1)
    fg[UNI_USLP_PRIMARY_HEADER_LENGTH + 0] = 0x03;

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fg.data(), fg.size()) == UNI_USLP_SUCCESS);

    // Frame duplicate: build frame 2 and tamper VCF-SEQ to 3 again (duplicate => no loss)
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu2.data(), sdu2.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fd(128, 0x00);
    size_t ld = fd.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, fd.data(), &ld) == UNI_USLP_SUCCESS);
    fd.resize(ld);
    fd[UNI_USLP_PRIMARY_HEADER_LENGTH + 0] = 0x03; // duplicate previous value

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fd.data(), fd.size()) == UNI_USLP_SUCCESS);

    // Expectations
    REQUIRE(cap.calls == 3);
    REQUIRE(cap.scids.size() == 3);
    REQUIRE(cap.vcids.size() == 3);
    REQUIRE(cap.loss_flags.size() == 3);

    for (auto s : cap.scids) REQUIRE(s == SCID);
    for (auto v : cap.vcids) REQUIRE(v == VCID);

    REQUIRE(cap.loss_flags[0] == false); // initial sync, no loss
    REQUIRE(cap.loss_flags[1] == true);  // gap detected
    REQUIRE(cap.loss_flags[2] == false); // duplicate, not a gap
}