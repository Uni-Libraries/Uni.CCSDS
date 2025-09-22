/**
 * @file test_mcf_service.cpp
 * @brief Tests for MCF Service parameters (USLP-48..USLP-50) — CCSDS 732.1-B-3 §3.10
 *
 * Scope:
 *  - USLP-48: USLP Frame (entire Transfer Frame) delivered via MCF.indication (§3.10.2.2; §3.10.3.3)
 *  - USLP-49: MCID = TFVN + SCID (MCID = (TFVN << 16) | SCID) (§2.1.3, §4.1.2.2)
 *  - USLP-50: Frame Loss Flag (Optional) derived from underlying C&S loss signal (§3.10.2.4.2; §4.3.10.3)
 *
 * Strategy:
 *  - Register MCF.indication and build MAPA frames (Rule '111') on a variable-length physical channel.
 *  - Accept frames under three conditions:
 *     1) No C&S loss signaled -> loss_flag=false
 *     2) C&S loss signaled before accept -> loss_flag=true
 *     3) Again no C&S loss signaled (verify latch is consumed) -> loss_flag=false
 *  - Verify MCID equals (UNI_USLP_TFVN<<16)|SCID in each callback.
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct McfCap {
    std::vector<uint32_t> mcids;
    std::vector<bool> loss_flags;
    std::vector<size_t> frame_lengths;
    size_t calls = 0;
};

static void mcf_cb(uni_uslp_context_t* ctx,
                   uint32_t mcid,
                   const uint8_t* frame,
                   size_t frame_length,
                   bool frame_loss_flag,
                   void* user)
{
    (void)ctx;
    auto* cap = static_cast<McfCap*>(user);
    cap->calls++;
    cap->mcids.push_back(mcid);
    cap->loss_flags.push_back(frame_loss_flag);
    cap->frame_lengths.push_back(frame_length);
}

} // namespace

TEST_CASE("MCF.indication delivers frame and MCID; Frame Loss Flag follows C&S signal", "[uslp][mcf][loss-flag]")
{
    // Managed parameters: variable-length, FECF enabled to exercise normal path
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 1024;
    p.min_frame_length = 0; // variable-length
    p.fecf_capability = true;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 256;

    const uint16_t SCID = 0x55AA;
    const uint8_t VCID = 4;
    const uint8_t MAP  = 2;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);

    // Configure VC + MAPA
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    McfCap cap{};
    REQUIRE(uni_ccsds_uslp_register_mcf_indication_callback(&ctx, mcf_cb, &cap) == UNI_USLP_SUCCESS);

    const uint32_t expected_mcid = ((uint32_t)UNI_USLP_TFVN << 16) | (uint32_t)SCID;

    // 1) No C&S loss signaled => expect loss=false
    {
        std::vector<uint8_t> sdu{0x10, 0x11, 0x12};
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

        std::vector<uint8_t> frame(256, 0x00);
        size_t len = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &len) == UNI_USLP_SUCCESS);
        frame.resize(len);

        // Do NOT set rx C&S loss flag
        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.calls >= 1);
        const size_t i = cap.calls - 1;
        REQUIRE(cap.mcids[i] == expected_mcid);
        REQUIRE(cap.loss_flags[i] == false);
        REQUIRE(cap.frame_lengths[i] == frame.size());
    }

    // 2) C&S loss signaled => expect loss=true
    {
        std::vector<uint8_t> sdu{0x20, 0x21};
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

        std::vector<uint8_t> frame(256, 0x00);
        size_t len = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &len) == UNI_USLP_SUCCESS);
        frame.resize(len);

        // Signal C&S loss for the next frame (§3.10.2.4.2)
        REQUIRE(uni_ccsds_uslp_set_rx_cs_loss_signaled(&ctx, true) == UNI_USLP_SUCCESS);

        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.calls >= 2);
        const size_t i = cap.calls - 1;
        REQUIRE(cap.mcids[i] == expected_mcid);
        REQUIRE(cap.loss_flags[i] == true);
        REQUIRE(cap.frame_lengths[i] == frame.size());
    }

    // 3) Latch consumed; next frame without signaling => expect loss=false
    {
        std::vector<uint8_t> sdu{0x30};
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

        std::vector<uint8_t> frame(256, 0x00);
        size_t len = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &len) == UNI_USLP_SUCCESS);
        frame.resize(len);

        // Do NOT set rx C&S loss flag this time (latch should be cleared)
        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.calls >= 3);
        const size_t i = cap.calls - 1;
        REQUIRE(cap.mcids[i] == expected_mcid);
        REQUIRE(cap.loss_flags[i] == false);
        REQUIRE(cap.frame_lengths[i] == frame.size());
    }
}