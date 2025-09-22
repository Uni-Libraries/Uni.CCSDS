/**
 * @file test_vcf_mcf_request.cpp
 * @brief Tests for VCF.request (USLP-78, §3.9.3.2) and MCF.request (USLP-80, §3.10.3.2)
 *
 * Scope:
 *  - VCF.request provider bridging to underlying C&S via registered callback
 *  - MCF.request provider bridging to underlying C&S via registered callback
 *  - Minimal validation per implementation: TFVN/SCID/VCID (VCF) and MCID (MCF)
 *  - Negative cases: provider not registered => UNSUPPORTED, mismatched IDs => INVALID_PARAM
 *
 * Notes:
 *  - Externally supplied frames shall be partially formatted per §3.2.7.
 *    For test simplicity we generate a valid variable-length frame without FECF/OCF using build path,
 *    then submit it to VCF/MCF.request (no modification applied by provider).
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct VcfTxCap {
    size_t calls = 0;
    std::vector<uint8_t> last_frame;
    uint8_t last_vcid = 0xFF;
};

static void vcf_tx_cb(uni_uslp_context_t* ctx,
                      uint8_t vcid,
                      const uint8_t* frame,
                      size_t frame_length,
                      void* user)
{
    (void)ctx;
    auto* cap = static_cast<VcfTxCap*>(user);
    cap->calls++;
    cap->last_vcid = vcid;
    cap->last_frame.assign(frame, frame + frame_length);
}

struct McfTxCap {
    size_t calls = 0;
    std::vector<uint8_t> last_frame;
    uint32_t last_mcid = 0;
};

static void mcf_tx_cb(uni_uslp_context_t* ctx,
                      uint32_t mcid,
                      const uint8_t* frame,
                      size_t frame_length,
                      void* user)
{
    (void)ctx;
    auto* cap = static_cast<McfTxCap*>(user);
    cap->calls++;
    cap->last_mcid = mcid;
    cap->last_frame.assign(frame, frame + frame_length);
}

static std::vector<uint8_t> build_mapa_frame(uni_uslp_context_t& ctx,
                                             uint8_t vcid,
                                             uint8_t map,
                                             const std::vector<uint8_t>& sdu)
{
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, vcid, map, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> frame(256, 0x00);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, vcid, map, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);
    return frame;
}

} // namespace

TEST_CASE("VCF.request provider bridging forwards frame unchanged to underlying C&S", "[uslp][vcf][request]")
{
    // Managed parameters: variable-length; FECF/OCF/Insert disabled; no VCF Count for simplicity
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 2048;
    p.min_frame_length = 0;            // variable-length
    p.fecf_capability = false;         // ensure no FECF in built frame
    p.ocf_capability = false;          // no OCF
    p.insert_zone_capability = false;  // no Insert Zone
    p.truncated_frame_capable = false;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;

    const uint16_t SCID = 0x2345;
    const uint8_t VCID = 10;
    const uint8_t MAP  = 1;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    // Build a valid frame (variable-length, no FECF/OCF/Insert)
    std::vector<uint8_t> sdu{0xAA, 0xBB, 0xCC};
    auto frame = build_mapa_frame(ctx, VCID, MAP, sdu);

    // 1) Provider not registered => expect UNSUPPORTED
    REQUIRE(uni_ccsds_uslp_vcf_request(&ctx, VCID, frame.data(), frame.size()) == UNI_USLP_ERROR_UNSUPPORTED);

    // 2) Register provider; expect SUCCESS and forwarded frame
    VcfTxCap cap{};
    REQUIRE(uni_ccsds_uslp_register_vcf_tx_callback(&ctx, VCID, vcf_tx_cb, &cap) == UNI_USLP_SUCCESS);

    REQUIRE(uni_ccsds_uslp_vcf_request(&ctx, VCID, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.calls == 1);
    REQUIRE(cap.last_vcid == VCID);
    REQUIRE(cap.last_frame == frame);

    // 3) Mismatched SCID in Primary Header => INVALID_PARAM
    //    Unpack, modify SCID, repack into the same frame buffer.
    {
        uni_uslp_primary_header_t ph{};
        size_t ph_read = 0;
        REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
        ph.scid = (uint16_t)(SCID ^ 0x0001); // change SCID
        size_t ph_written = 0;
        REQUIRE(uni_ccsds_uslp_primary_header_pack(&ph, frame.data(), frame.size(), &ph_written) == UNI_USLP_SUCCESS);
        REQUIRE(ph_written == ph_read); // header size should remain the same (no VCF Count)
        REQUIRE(uni_ccsds_uslp_vcf_request(&ctx, VCID, frame.data(), frame.size()) == UNI_USLP_ERROR_INVALID_PARAM);
    }
}

TEST_CASE("MCF.request provider bridging forwards frame unchanged to underlying C&S", "[uslp][mcf][request]")
{
    // Managed parameters: variable-length; FECF disabled to avoid any mismatch
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 1024;
    p.min_frame_length = 0;            // variable-length
    p.fecf_capability = false;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;

    const uint16_t SCID = 0x0BEE;
    const uint8_t VCID = 3;
    const uint8_t MAP  = 2;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    // Build a valid frame (variable-length, no FECF/OCF/Insert)
    std::vector<uint8_t> sdu{0x10, 0x11};
    auto frame = build_mapa_frame(ctx, VCID, MAP, sdu);

    const uint32_t expected_mcid = ((uint32_t)UNI_USLP_TFVN << 16) | (uint32_t)SCID;

    // 1) Provider not registered => expect UNSUPPORTED
    REQUIRE(uni_ccsds_uslp_mcf_request(&ctx, expected_mcid, frame.data(), frame.size()) == UNI_USLP_ERROR_UNSUPPORTED);

    // 2) Register provider; expect SUCCESS and forwarded frame
    McfTxCap cap{};
    REQUIRE(uni_ccsds_uslp_register_mcf_tx_callback(&ctx, mcf_tx_cb, &cap) == UNI_USLP_SUCCESS);

    REQUIRE(uni_ccsds_uslp_mcf_request(&ctx, expected_mcid, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.calls == 1);
    REQUIRE(cap.last_mcid == expected_mcid);
    REQUIRE(cap.last_frame == frame);

    // 3) Wrong MCID => INVALID_PARAM
    const uint32_t wrong_mcid = expected_mcid ^ 0x00010000u;
    REQUIRE(uni_ccsds_uslp_mcf_request(&ctx, wrong_mcid, frame.data(), frame.size()) == UNI_USLP_ERROR_INVALID_PARAM);
}