/**
 * @file test_octet_stream_notify.cpp
 * @brief Tests for OCTET_STREAM_Notify.indication (CCSDS 732.1-B-3 §3.7.3.4)
 *
 * Validates:
 *  - QUEUED notification on successful OCTET_STREAM.request
 *  - SENT notification after successful frame build
 *  - REJECTED_UNSUPPORTED when VC is fixed-length (§2.2.4.6, §2.2.5 g)
 *  - REJECTED_INVALID on invalid parameters (e.g., zero-length)
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

struct NotifyEvent {
    uint8_t vcid{};
    uint8_t map_id{};
    uint32_t sdu_id{};
    bool expedited{};
    uni_uslp_octet_stream_notify_type_t type{};
};

struct NotifyCap {
    std::vector<NotifyEvent> events;
};

void notify_cb(uni_uslp_context_t* ctx,
               uint8_t vcid,
               uint8_t map_id,
               uint32_t sdu_id,
               bool expedited,
               uni_uslp_octet_stream_notify_type_t nt,
               void* user)
{
    (void)ctx;
    auto* cap = static_cast<NotifyCap*>(user);
    cap->events.push_back(NotifyEvent{vcid, map_id, sdu_id, expedited, nt});
}

} // namespace

TEST_CASE("OCTET_STREAM_Notify: QUEUED then SENT", "[uslp][octet_stream][notify]")
{
    // Variable-length VC with EXP VCF counter = 1 octet to exercise PH update
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 4096;
    p.min_frame_length = 0; // variable-length
    p.fecf_capability = false;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 1;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x5151, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 2;
    const uint8_t MAP  = 7;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    NotifyCap cap{};
    REQUIRE(uni_ccsds_uslp_register_octet_stream_notify_callback(&ctx, VCID, MAP, notify_cb, &cap) == UNI_USLP_SUCCESS);

    // Send expedited portion (expedited=true)
    const uint32_t SDU_ID = 42u;
    const uint8_t payload[] = {0x10,0x20,0x30};
    REQUIRE(uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, payload, sizeof(payload), true, SDU_ID) == UNI_USLP_SUCCESS);

    // Expect immediate QUEUED
    REQUIRE(cap.events.size() == 1);
    CHECK(cap.events[0].vcid == VCID);
    CHECK(cap.events[0].map_id == MAP);
    CHECK(cap.events[0].sdu_id == SDU_ID);
    CHECK(cap.events[0].expedited == true);
    CHECK(cap.events[0].type == UNI_USLP_OS_NOTIFY_QUEUED);

    // Build a frame => should emit SENT
    std::vector<uint8_t> frame(256, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    frame.resize(out_len);

    REQUIRE(cap.events.size() == 2);
    CHECK(cap.events[1].type == UNI_USLP_OS_NOTIFY_SENT);
    CHECK(cap.events[1].vcid == VCID);
    CHECK(cap.events[1].map_id == MAP);
    CHECK(cap.events[1].sdu_id == SDU_ID);
    CHECK(cap.events[1].expedited == true);
}

TEST_CASE("OCTET_STREAM_Notify: REJECTED_UNSUPPORTED for fixed-length VC", "[uslp][octet_stream][notify][restriction]")
{
    // Fixed-length VC => Octet Stream prohibited (§2.2.4.6/§2.2.5 g)
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 256;
    p.min_frame_length = 256; // fixed-length
    p.fecf_capability = false;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x5252, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 1;
    const uint8_t MAP  = 1;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    NotifyCap cap{};
    REQUIRE(uni_ccsds_uslp_register_octet_stream_notify_callback(&ctx, VCID, MAP, notify_cb, &cap) == UNI_USLP_SUCCESS);

    const uint8_t data[] = {0xAA};
    const uint32_t sdu_id = 7u;
    auto st = uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, data, sizeof(data), true, sdu_id);
    REQUIRE(st == UNI_USLP_ERROR_UNSUPPORTED);

    // Expect REJECTED_UNSUPPORTED
    REQUIRE(cap.events.size() == 1);
    CHECK(cap.events[0].type == UNI_USLP_OS_NOTIFY_REJECTED_UNSUPPORTED);
    CHECK(cap.events[0].vcid == VCID);
    CHECK(cap.events[0].map_id == MAP);
    CHECK(cap.events[0].sdu_id == sdu_id);
    CHECK(cap.events[0].expedited == true);
}

TEST_CASE("OCTET_STREAM_Notify: REJECTED_INVALID on zero-length", "[uslp][octet_stream][notify][invalid]")
{
    // Variable-length setup
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 1024;
    p.min_frame_length = 0;
    p.fecf_capability = false;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x5353, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 4;
    const uint8_t MAP  = 2;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_OCTET_STREAM, &p) == UNI_USLP_SUCCESS);

    NotifyCap cap{};
    REQUIRE(uni_ccsds_uslp_register_octet_stream_notify_callback(&ctx, VCID, MAP, notify_cb, &cap) == UNI_USLP_SUCCESS);

    // Zero-length invalid
    const uint8_t* data = nullptr;
    const uint32_t sdu_id = 9u;
    auto st = uni_ccsds_uslp_send_octet_stream_ex(&ctx, VCID, MAP, data, 0, false, sdu_id);
    REQUIRE(st == UNI_USLP_ERROR_INVALID_PARAM);

    // Expect REJECTED_INVALID
    REQUIRE(cap.events.size() == 1);
    CHECK(cap.events[0].type == UNI_USLP_OS_NOTIFY_REJECTED_INVALID);
    CHECK(cap.events[0].vcid == VCID);
    CHECK(cap.events[0].map_id == MAP);
    CHECK(cap.events[0].sdu_id == sdu_id);
    CHECK(cap.events[0].expedited == false);
}