// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors
/**
 * @file test_vcp_service.cpp
 * @brief Tests for VCP Service (CCSDS 732.1-B-3 §3.4) — VCP.request, VCP_Notify.indication, VCP.indication
 *
 * Coverage (Table A-2b / A-3):
 *  - USLP-16 Packet: one complete Space Packet per frame; TFDF Rule '000' with FHP (§3.4.2.2; §4.1.4.2.2.2.1)
 *  - USLP-17 GVCID: SCID/VCID in Primary Header (§3.4.2.3; §4.1.2)
 *  - USLP-18 PVN: API parameter (not transmitted by USLP) (§3.4.2.4)
 *  - USLP-19 SDU ID: API parameter for accounting only (§3.4.2.5; §2.2.2)
 *  - USLP-20 Service Type: expedited => Bypass=1; sequence => Bypass=0 (§3.4.2.6; §4.1.2.8.1)
 *  - USLP-21 Notification Type: VCP_Notify.indication at sending end (§3.4.2.7; §3.4.3.3)
 *  - USLP-22 Packet Quality Indicator: delivered as COMPLETE (no segmentation in minimal path) (§3.4.2.8)
 *  - USLP-23 Verification Status Code (C2): delivered on indication when SDLS option enabled (§3.4.2.9; §6)
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds_uslp_internal.h"

// std
#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct VcpNotifyEvent {
    uint8_t vcid{};
    uni_uslp_vcp_notify_type_t type{};
};

struct VcpNotifyCap {
    std::vector<VcpNotifyEvent> events;
};

void vcp_notify_cb(uni_uslp_context_t* ctx,
                   uint8_t vcid,
                   uni_uslp_vcp_notify_type_t nt,
                   void* user)
{
    (void)ctx;
    auto* cap = static_cast<VcpNotifyCap*>(user);
    cap->events.push_back(VcpNotifyEvent{vcid, nt});
}

struct VcpIndCap {
    bool called{false};
    uint8_t vcid{};
    std::vector<uint8_t> pkt;
    uni_uslp_packet_quality_t pqi{};
    uni_uslp_verification_status_t ver{};
};

void vcp_ind_cb(uni_uslp_context_t* ctx,
                uint8_t vcid,
                const uint8_t* packet,
                size_t packet_length,
                uni_uslp_packet_quality_t pqi,
                uni_uslp_verification_status_t ver,
                void* user)
{
    (void)ctx;
    auto* cap = static_cast<VcpIndCap*>(user);
    cap->called = true;
    cap->vcid = vcid;
    cap->pkt.assign(packet, packet + packet_length);
    cap->pqi = pqi;
    cap->ver = ver;
}

static void configure_common_varlen_no_fecf(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;        // variable-length
    p.fecf_capability = false;     // disable FECF for simplicity
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    // VCF present to exercise counter update (not strictly needed for this test)
    p.vcf_seq_count_len_octets = 1;
    p.vcf_exp_count_len_octets = 1;
}

} // namespace

TEST_CASE("VCP: QUEUED then SENT; VCP.indication delivery; Rule '000' and QoS mapping", "[uslp][vcp]")
{
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x7001, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 7;
    const uint8_t MAP0 = 0; // internal MAP used for VCP routing

    // Configure VC and set MAP 0 to VCP service (§3.4 is VC-level; internal MAP 0 used by implementation)
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP0, UNI_USLP_SERVICE_VCP, &p) == UNI_USLP_SUCCESS);

    // Register VCP notify and indication callbacks
    VcpNotifyCap ncap{};
    REQUIRE(uni_ccsds_uslp_register_vcp_notify_callback(&ctx, VCID, vcp_notify_cb, &ncap) == UNI_USLP_SUCCESS);

    VcpIndCap icap{};
    REQUIRE(uni_ccsds_uslp_register_vcp_indication_callback(&ctx, VCID, vcp_ind_cb, &icap) == UNI_USLP_SUCCESS);

    // Send a complete Space Packet using Sequence-Controlled Service (Bypass=0)
    const std::vector<uint8_t> packet = { 0x08, 0x00, 0x90, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };
    REQUIRE(uni_ccsds_uslp_send_vcp_ex(&ctx, VCID, packet.data(), packet.size(),
                                 /*PVN*/ 0u, /*expedited*/ false, /*SDU_ID*/ 0u) == UNI_USLP_SUCCESS);

    // Expect QUEUED
    REQUIRE(ncap.events.size() == 1);
    CHECK(ncap.events[0].vcid == VCID);
    CHECK(ncap.events[0].type == UNI_USLP_VCP_NOTIFY_QUEUED);

    // Build frame on (VC, MAP0)
    std::vector<uint8_t> frame(512, 0x00);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP0, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Expect SENT
    REQUIRE(ncap.events.size() == 2);
    CHECK(ncap.events[1].vcid == VCID);
    CHECK(ncap.events[1].type == UNI_USLP_VCP_NOTIFY_SENT);

    // Parse PH and TFDF: Rule 000, FHP present (3 octets), Bypass=0
    uni_uslp_primary_header_t ph{};
    size_t ph_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
    CHECK(ph.vcid == VCID);
    CHECK(ph.map_id == MAP0);
    CHECK(ph.bypass_flag == false);

    const size_t vcf_octets = (size_t)(ph.vcf_count_len & 0x7);
    const size_t off = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + vcf_octets;
    REQUIRE(off + 3 <= frame.size()); // 3 octets TFDF header for Rule 000

    uni_uslp_tfdf_header_t th{};
    size_t th_read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(&frame[off], frame.size() - off, &th, &th_read) == UNI_USLP_SUCCESS);
    CHECK(th.construction_rule == UNI_USLP_TFDZ_RULE_0);
    CHECK(th_read == 3);
    CHECK(th.first_header_ptr == 0); // packet starts at TFDZ[0]

    // Feed to RX: expect VCP.indication with PQI=COMPLETE and ver=NOT_APPLICABLE (no SDLS)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(icap.called == true);
    CHECK(icap.vcid == VCID);
    CHECK(icap.pqi == UNI_USLP_PQI_COMPLETE);
    CHECK(icap.ver == UNI_USLP_VERIF_NOT_APPLICABLE);
    CHECK(icap.pkt == packet);

    // Expedited path: expedited => Bypass=1
    icap = VcpIndCap{};
    ncap.events.clear();

    const std::vector<uint8_t> pkt2 = { 0x08, 0x00, 0x90, 0x02, 0xAA, 0xBB, 0xCC };
    REQUIRE(uni_ccsds_uslp_send_vcp_ex(&ctx, VCID, pkt2.data(), pkt2.size(),
                                 0u, /*expedited*/ true, 0u) == UNI_USLP_SUCCESS);
    REQUIRE(ncap.events.size() == 1);
    CHECK(ncap.events[0].type == UNI_USLP_VCP_NOTIFY_QUEUED);

    std::vector<uint8_t> frame2(256, 0x00);
    size_t flen2 = frame2.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP0, frame2.data(), &flen2) == UNI_USLP_SUCCESS);
    frame2.resize(flen2);

    REQUIRE(ncap.events.size() == 2);
    CHECK(ncap.events[1].type == UNI_USLP_VCP_NOTIFY_SENT);

    uni_uslp_primary_header_t ph2{};
    size_t ph2_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame2.data(), frame2.size(), &ph2, &ph2_read) == UNI_USLP_SUCCESS);
    CHECK(ph2.bypass_flag == true);

    // RX delivery again
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame2.data(), frame2.size()) == UNI_USLP_SUCCESS);
    REQUIRE(icap.called == true);
    CHECK(icap.vcid == VCID);
}

TEST_CASE("VCP + SDLS HMAC: deliver Verification Status Code (C2), replay reject, tamper fail", "[uslp][vcp][sdls]")
{
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p); // FECF disabled for tamper testing

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x7002, &p) == UNI_USLP_SUCCESS);

    // Register built-in SDLS engine
    REQUIRE(uni_ccsds_uslp_register_builtin_sdls(&ctx) == UNI_USLP_SUCCESS);

    // RX work buffer
    std::vector<uint8_t> work(4096, 0x00);
    REQUIRE(uni_ccsds_uslp_set_work_buffer(&ctx, work.data(), work.size()) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 3, MAP0 = 0;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP0, UNI_USLP_SERVICE_VCP, &p) == UNI_USLP_SUCCESS);

    // SDLS HMAC config (Header=SPI(1)+SN(8)=9, Trailer=16)
    static const uint8_t key[] = {
        0x10,0x11,0x12,0x13,0x21,0x22,0x23,0x24,0x30,0x31,0x32,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
    };
    uni_uslp_sdls_config_t sdls{};
    sdls.enabled = true;
    sdls.spi = 7;
    sdls.iv_length = 0;
    sdls.mac_length = 16;
    sdls.authentication_only = true;
    sdls.encryption_enabled = false;
    sdls.suite = UNI_USLP_SDLS_SUITE_HMAC_SHA256;
    sdls.key = key;
    sdls.key_length = sizeof(key);
    sdls.anti_replay_enabled = true;
    sdls.anti_replay_window = 64;
    sdls.sec_header_present = true;
    sdls.sec_trailer_present = true;
    sdls.sec_header_length = 9;
    sdls.sec_trailer_length = 16;
    REQUIRE(uni_ccsds_uslp_configure_sdls(&ctx, VCID, &sdls) == UNI_USLP_SUCCESS);

    // Register VCP.indication
    VcpIndCap icap{};
    REQUIRE(uni_ccsds_uslp_register_vcp_indication_callback(&ctx, VCID, vcp_ind_cb, &icap) == UNI_USLP_SUCCESS);

    // Send a Packet SDU (sequence-controlled)
    const std::vector<uint8_t> pkt = { 0x01,0x02,0x03,0x04,0x05 };
    REQUIRE(uni_ccsds_uslp_send_vcp_ex(&ctx, VCID, pkt.data(), pkt.size(), 0u, false, 0u) == UNI_USLP_SUCCESS);

    // Build a secured frame
    std::vector<uint8_t> frame(512, 0x00);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP0, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Accept: expect SUCCESS Verification Status (C2)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(icap.called == true);
    CHECK(icap.pkt == pkt);
    CHECK(icap.ver == UNI_USLP_VERIF_SUCCESS);

    // Replay rejected
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_ERROR_SDLS_FAILURE);

    // Tamper: flip last byte — should fail SDLS verification
    std::vector<uint8_t> tampered = frame;
    tampered.back() ^= 0x01;
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, tampered.data(), tampered.size()) == UNI_USLP_ERROR_SDLS_FAILURE);
}