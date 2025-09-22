/**
 * @file test_insert_loss_flag.cpp
 * @brief Tests for INSERT.indication v2 with IN_SDU Loss Flag (USLP-53) — CCSDS 732.1-B-3 §3.11
 *
 * Scope:
 *  - USLP-51: IN_SDU carried by Insert Zone only (§3.11.2.2)
 *  - USLP-52: Physical Channel Name (managed parameter) (§3.11.2.3)
 *  - USLP-53: IN_SDU Loss Flag (Optional) derived from underlying C&S loss signal (§3.11.2.4.2)
 *  - INSERT.indication primitive (§3.11.3.3)
 *
 * Strategy:
 *  - Configure fixed-length frames with Insert Zone present (§4.1.3).
 *  - Register INSERT.indication v2 callback (with Loss Flag).
 *  - Build a frame carrying IN_SDU in Insert Zone and a MAPA SDU in TFDZ to reach exact fixed length.
 *  - Accept frames under two conditions:
 *     1) No C&S loss signaled: expect in_sdu_loss_flag=false.
 *     2) C&S loss signaled before accept: expect in_sdu_loss_flag=true.
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct Insert2Cap {
    bool called = false;
    uint8_t vcid = 0;
    std::vector<uint8_t> data;
    bool loss = false;
};

static void insert2_cb(uni_uslp_context_t* ctx,
                       uint8_t vcid,
                       const uint8_t* insert_data,
                       size_t insert_length,
                       bool in_sdu_loss_flag,
                       void* user)
{
    (void)ctx;
    auto* cap = static_cast<Insert2Cap*>(user);
    cap->called = true;
    cap->vcid = vcid;
    cap->data.assign(insert_data, insert_data + insert_length);
    cap->loss = in_sdu_loss_flag;
}

} // namespace

TEST_CASE("INSERT.indication v2 delivers IN_SDU Loss Flag derived from C&S signal", "[uslp][insert][loss-flag]")
{
    // Fixed-length physical channel with Insert Zone present (§4.1.3)
    uni_uslp_managed_params_t global{};
    global.physical_channel_name = "PC-FIX";
    global.max_frame_length = 64;
    global.min_frame_length = 64;            // fixed-length
    global.insert_zone_capability = true;
    global.insert_zone_length = 8;           // Insert Zone size
    global.fecf_capability = true;           // FECF present (§4.1.6)
    global.ocf_capability = false;
    global.truncated_frame_capable = false;
    global.max_sdu_length = 512;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x5A5A, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 11;
    const uint8_t MAP  = 1;

    // Configure VC and MAPA (Rule '111' minimal path)
    uni_uslp_managed_params_t vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);
    uni_uslp_managed_params_t map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    // Register INSERT.indication v2
    Insert2Cap cap{};
    REQUIRE(uni_ccsds_uslp_register_insert2_callback(&ctx, VCID, insert2_cb, &cap) == UNI_USLP_SUCCESS);

    // Prepare IN_SDU exactly equal to Insert Zone Length (§4.1.3 exact fit)
    std::vector<uint8_t> in_sdu(global.insert_zone_length);
    for (size_t i = 0; i < in_sdu.size(); ++i) in_sdu[i] = static_cast<uint8_t>(0xC0u + i);

    // Compute payload size required to reach fixed total:
    // total(64) = PH(7) + VCF(0 default) + INSERT(8) + TFDF(1 for rule '111') + SDU + OCF(0) + FECF(2)
    const size_t required_sdu = 64u
        - static_cast<size_t>(UNI_USLP_PRIMARY_HEADER_LENGTH)
        - static_cast<size_t>(global.insert_zone_length)
        - 1u
        - static_cast<size_t>(UNI_USLP_FECF_LENGTH);
    REQUIRE(required_sdu > 0);

    // Prepare MAPA SDU
    std::vector<uint8_t> sdu(required_sdu, 0xEE);

    // 1) Accept without C&S loss signaled -> expect in_sdu_loss_flag=false
    {
        cap = Insert2Cap{};
        REQUIRE(uni_ccsds_uslp_send_insert(&ctx, VCID, in_sdu.data(), in_sdu.size()) == UNI_USLP_SUCCESS);
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

        std::vector<uint8_t> frame(64, 0x00);
        size_t out_len = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
        REQUIRE(out_len == 64);

        // Accept — no C&S loss signaled
        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.called == true);
        REQUIRE(cap.vcid == VCID);
        REQUIRE(cap.data == in_sdu);
        REQUIRE(cap.loss == false);
    }

    // 2) Accept with C&S loss signaled -> expect in_sdu_loss_flag=true
    {
        cap = Insert2Cap{};
        // Queue another insert and SDU for the next frame
        REQUIRE(uni_ccsds_uslp_send_insert(&ctx, VCID, in_sdu.data(), in_sdu.size()) == UNI_USLP_SUCCESS);
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

        std::vector<uint8_t> frame(64, 0x00);
        size_t out_len = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
        REQUIRE(out_len == 64);

        // Signal C&S loss prior to accept (§3.11.2.4.2)
        REQUIRE(uni_ccsds_uslp_set_rx_cs_loss_signaled(&ctx, true) == UNI_USLP_SUCCESS);

        REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

        REQUIRE(cap.called == true);
        REQUIRE(cap.vcid == VCID);
        REQUIRE(cap.data == in_sdu);
        REQUIRE(cap.loss == true);
    }
}