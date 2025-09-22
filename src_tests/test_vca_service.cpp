/**
 * @file test_vca_service.cpp
 * @brief Tests for VCA Service (CCSDS 732.1-B-3 §3.6) — VCA.request, VCA_Notify.indication, VCA.indication
 *
 * Covers:
 *  - VCA.request enqueue (QUEUED) and SENT notification (§3.6.4.2, §3.6.4.3)
 *  - Build frame for VCA_SDU using Rule '111' (variable-length, no segmentation) consistent with MAPA minimal path (§4.1.4.2.2; Table 4-3)
 *  - Accept frame and deliver VCA.indication via sdu_callback (§3.6.4.4)
 *
 * Notes:
 *  - Minimal sending path for VCA uses Rule '111' (variable-length) analogous to MAPA minimal path.
 *  - Service Type (USLP-33) is mapped to Primary Header Bypass flag (§4.1.2.8.1).
 *  - Verification Status Code (USLP-35) is N/A for VCA per PICS; sdu_callback includes a field for consistency across services.
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds_uslp.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct VcaNotifyEvent {
    uint8_t vcid{};
    uint8_t map_id{};
    uni_uslp_vca_notify_type_t type{};
};

struct VcaNotifyCap {
    std::vector<VcaNotifyEvent> events;
};

void vca_notify_cb(uni_uslp_context_t* ctx,
                   uint8_t vcid,
                   uint8_t map_id,
                   uni_uslp_vca_notify_type_t nt,
                   void* user)
{
    (void)ctx;
    auto* cap = static_cast<VcaNotifyCap*>(user);
    cap->events.push_back(VcaNotifyEvent{vcid, map_id, nt});
}

struct SduCap {
    bool called{false};
    uint8_t vcid{};
    uint8_t map_id{};
    uni_uslp_service_type_t service{};
    bool gap{};
    std::vector<uint8_t> sdu;
};

void sdu_cb(uni_uslp_context_t* ctx,
            uint8_t vcid,
            uint8_t map_id,
            uni_uslp_service_type_t service_type,
            const uint8_t* sdu_data,
            size_t sdu_length,
            uni_uslp_verification_status_t /*verification_status*/,
            bool gap_detected,
            void* user)
{
    (void)ctx;
    auto* cap = static_cast<SduCap*>(user);
    cap->called = true;
    cap->vcid = vcid;
    cap->map_id = map_id;
    cap->service = service_type;
    cap->gap = gap_detected;
    cap->sdu.assign(sdu_data, sdu_data + sdu_length);
}

} // namespace

TEST_CASE("VCA: QUEUED then SENT; VCA.indication delivery (Rule '111')", "[uslp][vca]")
{
    // Variable-length VC without FECF to simplify
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 4096;
    p.min_frame_length = 0; // variable-length
    p.fecf_capability = false;
    p.vcf_seq_count_len_octets = 1; // exercise VCF update on SEQ path

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x6161, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 6;
    const uint8_t MAP  = 3;

    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_VCA, &p) == UNI_USLP_SUCCESS);

    // Register notifications and SDU delivery
    VcaNotifyCap ncap{};
    REQUIRE(uni_ccsds_uslp_register_vca_notify_callback(&ctx, VCID, MAP, vca_notify_cb, &ncap) == UNI_USLP_SUCCESS);

    SduCap scap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &scap) == UNI_USLP_SUCCESS);

    // Send a VCA SDU (Sequence-Controlled by default; Bypass=0)
    const uint8_t vca_sdu[] = {0xA1, 0xB2, 0xC3, 0xD4};
    REQUIRE(uni_ccsds_uslp_send_vca_ex(&ctx, VCID, MAP, vca_sdu, sizeof(vca_sdu), false, 0u) == UNI_USLP_SUCCESS);

    // Expect immediate QUEUED
    REQUIRE(ncap.events.size() == 1);
    CHECK(ncap.events[0].vcid == VCID);
    CHECK(ncap.events[0].map_id == MAP);
    CHECK(ncap.events[0].type == UNI_USLP_VCA_NOTIFY_QUEUED);

    // Build frame
    std::vector<uint8_t> frame(256, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    frame.resize(out_len);

    // Expect SENT at sending end
    REQUIRE(ncap.events.size() == 2);
    CHECK(ncap.events[1].vcid == VCID);
    CHECK(ncap.events[1].map_id == MAP);
    CHECK(ncap.events[1].type == UNI_USLP_VCA_NOTIFY_SENT);

    // Feed back to accept() and expect one VCA SDU delivered
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(scap.called == true);
    CHECK(scap.vcid == VCID);
    CHECK(scap.map_id == MAP);
    CHECK(scap.service == UNI_USLP_SERVICE_VCA);
    CHECK(scap.gap == false);
    CHECK(scap.sdu == std::vector<uint8_t>(vca_sdu, vca_sdu + sizeof(vca_sdu)));
}

TEST_CASE("VCA_Notify: REJECTED_INVALID on zero-length", "[uslp][vca][invalid]")
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 1024;
    p.min_frame_length = 0;
    p.fecf_capability = false;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x6262, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 2;
    const uint8_t MAP  = 1;

    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_VCA, &p) == UNI_USLP_SUCCESS);

    VcaNotifyCap ncap{};
    REQUIRE(uni_ccsds_uslp_register_vca_notify_callback(&ctx, VCID, MAP, vca_notify_cb, &ncap) == UNI_USLP_SUCCESS);

    // Invalid: NULL data and zero length
    const uint8_t* data = nullptr;
    auto st = uni_ccsds_uslp_send_vca_ex(&ctx, VCID, MAP, data, 0, false, 0u);
    REQUIRE(st == UNI_USLP_ERROR_INVALID_PARAM);

    // Expect REJECTED_INVALID
    REQUIRE(ncap.events.size() == 1);
    CHECK(ncap.events[0].vcid == VCID);
    CHECK(ncap.events[0].map_id == MAP);
    CHECK(ncap.events[0].type == UNI_USLP_VCA_NOTIFY_REJECTED_INVALID);
}