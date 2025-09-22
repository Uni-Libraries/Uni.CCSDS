/**
 * @file test_ocf_loss_flag.cpp
 * @brief Tests for USLP-44 OCF_SDU Loss Flag (§3.8.2.4) via OCF.indication v2
 *
 * Derivation per CCSDS 732.1-B-3 §3.8.2.4.2: Loss Flag derived from the underlying
 * Synchronization and Channel Coding sublayer signal. This test verifies that:
 *  - When no C&S loss is signaled prior to accept, ocf_sdu_loss_flag=false.
 *  - When C&S loss is signaled via uni_ccsds_uslp_set_rx_cs_loss_signaled() prior to accept,
 *    ocf_sdu_loss_flag=true on the next successful accept (latch consumed).
 *
 * The frame includes an OCF placed after TFDF and before FECF per §4.1.5 and §6.3.7.
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

struct Ocf2Cap {
    std::vector<bool> loss_flags;
    std::vector<uint32_t> ocf_values;
    std::vector<uint8_t> vcids;
    size_t calls{0};
};

static void ocf2_cb(uni_uslp_context_t* ctx,
                    uint8_t vcid,
                    const uni_uslp_ocf_t* ocf,
                    bool ocf_sdu_loss_flag,
                    void* user)
{
    (void)ctx;
    auto* cap = static_cast<Ocf2Cap*>(user);
    cap->calls++;
    cap->vcids.push_back(vcid);
    cap->ocf_values.push_back(ocf ? ocf->data : 0);
    cap->loss_flags.push_back(ocf_sdu_loss_flag);
}

} // namespace

TEST_CASE("OCF_SDU Loss Flag: false without C&S signal, true when signaled (USLP-44)", "[uslp][ocf][loss-flag]")
{
    // Variable-length, no FECF to keep test simple
    uni_uslp_managed_params_t p{};
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 1024;
    p.min_frame_length = 0;          // variable-length frames
    p.fecf_capability = false;       // no CRC in this test
    p.ocf_capability = true;         // OCF supported
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 256;

    // Allow OCF on variable-length frames (USLP-139 gate)
    const uint8_t VCID = 3;
    const uint8_t MAP  = 1;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4C4C, &p) == UNI_USLP_SUCCESS);

    auto vc_params = p;
    vc_params.ocf_allowed_variable = true;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    // Use MAPA minimal path to carry payload (Rule '111')
    auto map_params = p;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    // Register OCF v2 (with Loss Flag)
    Ocf2Cap cap{};
    REQUIRE(uni_ccsds_uslp_register_ocf2_callback(&ctx, VCID, ocf2_cb, &cap) == UNI_USLP_SUCCESS);

    // Helper to build a frame with OCF (ocf_pending=true)
    auto build_with_ocf = [&](uint32_t ocf_value, std::vector<uint8_t>& out_frame) {
        // Queue payload SDU so a frame can be built
        const std::vector<uint8_t> sdu{0xA0,0xB1,0xC2,0xD3};
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
        // Queue OCF
        uni_uslp_ocf_t ocf{};
        ocf.type = UNI_USLP_OCF_TYPE_1;
        ocf.data = ocf_value;
        REQUIRE(uni_ccsds_uslp_send_ocf(&ctx, VCID, &ocf) == UNI_USLP_SUCCESS);

        out_frame.assign(256, 0x00);
        size_t len = out_frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, out_frame.data(), &len) == UNI_USLP_SUCCESS);
        out_frame.resize(len);
    };

    // 1) No C&S loss signaled: expect ocf_sdu_loss_flag=false
    {
        std::vector<uint8_t> frame;
        build_with_ocf(0xCAFEBABEu, frame);

        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.calls >= 1);
        const size_t i = cap.calls - 1;
        CHECK(cap.vcids[i] == VCID);
        CHECK(cap.ocf_values[i] == 0xCAFEBABEu);
        CHECK(cap.loss_flags[i] == false);
    }

    // 2) Signal C&S loss prior to accept: expect ocf_sdu_loss_flag=true for next frame
    {
        std::vector<uint8_t> frame;
        build_with_ocf(0xDEADBEEFu, frame);

        REQUIRE(uni_ccsds_uslp_set_rx_cs_loss_signaled(&ctx, true) == UNI_USLP_SUCCESS);
        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.calls >= 2);
        const size_t i = cap.calls - 1;
        CHECK(cap.vcids[i] == VCID);
        CHECK(cap.ocf_values[i] == 0xDEADBEEFu);
        CHECK(cap.loss_flags[i] == true);
    }

    // 3) Latch consumed; next frame again without signaling => false
    {
        std::vector<uint8_t> frame;
        build_with_ocf(0x11223344u, frame);

        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.calls >= 3);
        const size_t i = cap.calls - 1;
        CHECK(cap.vcids[i] == VCID);
        CHECK(cap.ocf_values[i] == 0x11223344u);
        CHECK(cap.loss_flags[i] == false);
    }
}