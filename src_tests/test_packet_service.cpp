// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

/*
 * Packet SDU (MAPP) tests — CCSDS 732.1-B-3 §3.2.2, §3.3 (Table A-2a USLP-8..USLP-15)
 *
 * Coverage:
 * - USLP-1  Packet SDU: Send/Build/Accept one complete Space Packet per frame (no segmentation)
 * - USLP-8  Packet: API parameter packet_data/packet_length in MAPP.request wrapper
 * - USLP-9  GMAP ID: via (VCID, MAP ID) -> Primary Header MAP ID field
 * - USLP-10 PVN: parameter accepted by request API (not transmitted by USLP)
 * - USLP-11 SDU ID: parameter accepted (accounting only; not transmitted)
 * - USLP-12 QoS: expedited -> PH.Bypass=1; sequence -> PH.Bypass=0
 * - USLP-15 Verification Status Code (C2): delivered on indication when SDLS option enabled
 *
 * Notes:
 * - Minimal behavior per standard: one complete packet per frame; TFDF Rule '000' with FHP=0.
 * - Optional items USLP-13 (Notification Type) and USLP-14 (Packet Quality Indicator) are not implemented.
 */

#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds_uslp_internal.h"

// std
#include <vector>
#include <cstdint>
#include <cstring>

struct Capture {
    std::vector<uint8_t> data;
    uni_uslp_verification_status_t ver{};
};

static void sdu_capture_cb(uni_uslp_context_t*,
                           uint8_t,
                           uint8_t,
                           uni_uslp_service_type_t,
                           const uint8_t* sdu_data,
                           size_t sdu_length,
                           uni_uslp_verification_status_t verification_status,
                           bool,
                           void* user)
{
    auto* out = static_cast<Capture*>(user);
    out->data.assign(sdu_data, sdu_data + sdu_length);
    out->ver = verification_status;
}

struct NotifySeq {
    std::vector<int> seq;
};

static void mapp_notify_cb(uni_uslp_context_t*, uint8_t, uint8_t, uni_uslp_mapp_notify_type_t t, void* u)
{
    static_cast<NotifySeq*>(u)->seq.push_back((int)t);
}

static void configure_common_varlen_no_fecf(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;        // variable-length
    p.fecf_capability = false;     // disable FECF in these tests unless needed
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    // VCF absent in these tests
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
}

TEST_CASE("MAPP: build/accept round-trip; TFDF Rule 000 with FHP=0; QoS mapping", "[mapp][packet]")
{
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4242, &p) == UNI_USLP_SUCCESS);

    const uint8_t VC = 1, MAP = 2;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_PACKET, &p) == UNI_USLP_SUCCESS);

    // Register SDU and MAPP notify callbacks
    Capture cap{};
    NotifySeq note{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC, MAP, sdu_capture_cb, &cap) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_register_mapp_notify_callback(&ctx, VC, MAP, mapp_notify_cb, &note) == UNI_USLP_SUCCESS);

    // Prepare a dummy Space Packet payload (any octets; not parsed by USLP)
    const std::vector<uint8_t> packet = { 0x08, 0x00, 0x12, 0x34, 0xBE, 0xEF, 0xAA };

    // Send MAPP.request: PVN=0, QoS=Sequence (Bypass=0), SDU ID=0
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, packet.data(), packet.size(),
                                    /*PVN*/ 0u, /*expedited*/ false, /*sdu_id*/ 0u) == UNI_USLP_SUCCESS);

    // Expect QUEUED notify
    REQUIRE(note.seq.size() == 1);
    REQUIRE(note.seq[0] == (int)UNI_USLP_MAPP_NOTIFY_QUEUED);

    // Build
    std::vector<uint8_t> frame(512);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Expect SENT notify
    REQUIRE(note.seq.size() == 2);
    REQUIRE(note.seq[1] == (int)UNI_USLP_MAPP_NOTIFY_SENT);

    // Parse PH to check Bypass=0
    uni_uslp_primary_header_t ph{};
    size_t ph_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
    REQUIRE(ph.bypass_flag == false);

    // Compute TFDF offset and parse TFDF header
    const size_t vcf_octets = (size_t)(ph.vcf_count_len & 0x7);
    const size_t off = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + vcf_octets;
    REQUIRE(off < frame.size());
    uni_uslp_tfdf_header_t th{};
    size_t th_read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(&frame[off], frame.size() - off, &th, &th_read) == UNI_USLP_SUCCESS);
    REQUIRE(th.construction_rule == UNI_USLP_TFDZ_RULE_0); // Rule 000
    REQUIRE(th_read == 3);                                 // pointer present
    REQUIRE(th.first_header_ptr == 0);                     // FHP=0 for "packet starts at TFDZ[0]"

    // Accept: should deliver Packet SDU with NOT_APPLICABLE (no SDLS)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.data == packet);
    REQUIRE(cap.ver == UNI_USLP_VERIF_NOT_APPLICABLE);

    // Expedited QoS path (Bypass=1)
    note.seq.clear();
    const std::vector<uint8_t> pkt2 = { 0xDE, 0xAD, 0xBE, 0xEF };
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, pkt2.data(), pkt2.size(),
                                    0u, /*expedited*/ true, 0u) == UNI_USLP_SUCCESS);
    REQUIRE(note.seq.size() == 1);
    REQUIRE(note.seq[0] == (int)UNI_USLP_MAPP_NOTIFY_QUEUED);

    std::vector<uint8_t> frame2(256);
    size_t flen2 = frame2.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame2.data(), &flen2) == UNI_USLP_SUCCESS);
    frame2.resize(flen2);
    REQUIRE(note.seq.size() == 2);
    REQUIRE(note.seq[1] == (int)UNI_USLP_MAPP_NOTIFY_SENT);

    uni_uslp_primary_header_t ph2{};
    size_t ph2_read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame2.data(), frame2.size(), &ph2, &ph2_read) == UNI_USLP_SUCCESS);
    REQUIRE(ph2.bypass_flag == true);
}

TEST_CASE("MAPP + SDLS HMAC: verify tag, replay reject, tamper fail", "[mapp][sdls][hmac]")
{
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p); // disable FECF to allow tamper testing

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5151, &p) == UNI_USLP_SUCCESS);

    // Register built-in SDLS engine
    REQUIRE(uni_ccsds_uslp_register_builtin_sdls(&ctx) == UNI_USLP_SUCCESS);

    // RX work buffer
    std::vector<uint8_t> work(4096);
    REQUIRE(uni_ccsds_uslp_set_work_buffer(&ctx, work.data(), work.size()) == UNI_USLP_SUCCESS);

    const uint8_t VC = 3, MAP = 1;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_PACKET, &p) == UNI_USLP_SUCCESS);

    // SDLS HMAC config (Header=SPI(1)+SN(8)=9, Trailer=16)
    static const uint8_t key[] = {
        0x10,0x11,0x12,0x13,0x21,0x22,0x23,0x24,0x30,0x31,0x32,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
    };
    uni_uslp_sdls_config_t sdls{};
    sdls.enabled = true;
    sdls.spi = 5;
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
    REQUIRE(uni_ccsds_uslp_configure_sdls(&ctx, VC, &sdls) == UNI_USLP_SUCCESS);

    // SDU capture
    Capture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC, MAP, sdu_capture_cb, &cap) == UNI_USLP_SUCCESS);

    // Send a Packet SDU
    const std::vector<uint8_t> pkt = { 0x01,0x02,0x03,0x04,0x05 };
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, pkt.data(), pkt.size(), 0u, false, 0u) == UNI_USLP_SUCCESS);

    // Build a secured frame
    std::vector<uint8_t> frame(512);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    // Accept: expect SUCCESS verification status (C2)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
    REQUIRE(cap.data == pkt);
    REQUIRE(cap.ver == UNI_USLP_VERIF_SUCCESS);

    // Replay rejected
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_ERROR_SDLS_FAILURE);

    // Tamper: flip last byte — should fail SDLS verification
    std::vector<uint8_t> tampered = frame;
    tampered.back() ^= 0x01;
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, tampered.data(), tampered.size()) == UNI_USLP_ERROR_SDLS_FAILURE);
}

// Additional tests for MAPP PQI (USLP-14) — appended by Roo

struct MappPqiCapture {
    std::vector<uint8_t> packet;
    uni_uslp_packet_quality_t pqi{};
    uni_uslp_verification_status_t ver{};
    bool called{false};
};

static void mapp_indication_cb(uni_uslp_context_t*,
                               uint8_t,
                               uint8_t,
                               const uint8_t* packet,
                               size_t packet_length,
                               uni_uslp_packet_quality_t pqi,
                               uni_uslp_verification_status_t ver,
                               void* user)
{
    auto* cap = static_cast<MappPqiCapture*>(user);
    cap->packet.assign(packet, packet + packet_length);
    cap->pqi = pqi;
    cap->ver = ver;
    cap->called = true;
}

/* USLP-14 Packet Quality Indicator (optional) — this implementation delivers complete packets (no segmentation),
 * therefore PQI=COMPLETE. Verification Status Code is NOT_APPLICABLE without SDLS. (§3.3.2.8..§3.3.2.9) */
TEST_CASE("MAPP: MAPP.indication delivers PQI=COMPLETE, ver=NOT_APPLICABLE", "[mapp][pqi]")
{
    uni_uslp_managed_params_t p{};
    configure_common_varlen_no_fecf(p);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4243, &p) == UNI_USLP_SUCCESS);

    const uint8_t VC = 2, MAP = 3;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_PACKET, &p) == UNI_USLP_SUCCESS);

    // Register MAPP.indication (with PQI)
    MappPqiCapture cap{};
    REQUIRE(uni_ccsds_uslp_register_mapp_indication_callback(&ctx, VC, MAP, mapp_indication_cb, &cap) == UNI_USLP_SUCCESS);

    // Send a single complete Space Packet; no segmentation in this minimal path
    const std::vector<uint8_t> packet = { 0x20, 0x00, 0xAB, 0xCD, 0x12, 0x34 };
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, packet.data(), packet.size(),
                                    /*PVN*/ 0u, /*expedited*/ false, /*sdu_id*/ 0u) == UNI_USLP_SUCCESS);

    // Build and accept
    std::vector<uint8_t> frame(512);
    size_t flen = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    frame.resize(flen);

    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

    // Validate PQI and Verification Status Code (C2)
    REQUIRE(cap.called == true);
    REQUIRE(cap.packet == packet);
    REQUIRE(cap.pqi == UNI_USLP_PQI_COMPLETE);
    REQUIRE(cap.ver == UNI_USLP_VERIF_NOT_APPLICABLE);
}

// === Added tests for Table 5-5: USLP-148..USLP-150 (Packet Transfer Parameters) ===

struct MappMultiSeg {
    std::vector<uint8_t> data;
    uni_uslp_packet_quality_t pqi{};
    uni_uslp_verification_status_t ver{};
};

struct MappMultiCap {
    std::vector<MappMultiSeg> segs;
};

static void mapp_ind_multi_cb(uni_uslp_context_t*,
                              uint8_t,
                              uint8_t,
                              const uint8_t* packet,
                              size_t packet_length,
                              uni_uslp_packet_quality_t pqi,
                              uni_uslp_verification_status_t ver,
                              void* user)
{
    auto* cap = static_cast<MappMultiCap*>(user);
    cap->segs.push_back(MappMultiSeg{std::vector<uint8_t>(packet, packet + packet_length), pqi, ver});
}

/* Helper: common variable-length, no FECF, no Insert/OCF, no VCF */
static void configure_common_varlen_no_fecf_base(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;        // variable-length
    p.fecf_capability = false;     // disable FECF for these tests unless needed
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    // VCF absent in these tests
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
}

/* USLP-148 (Valid PVNs) + USLP-149 (Maximum Packet Length) for MAPP */
TEST_CASE("MAPP: Packet Transfer parameters — Valid PVNs mask and Maximum Packet Length", "[mapp][packet][table5-5][USLP-148][USLP-149]")
{
    uni_uslp_managed_params_t p_vc{};
    configure_common_varlen_no_fecf_base(p_vc);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4244, &p_vc) == UNI_USLP_SUCCESS);

    const uint8_t VC = 4, MAP = 1;

    // VC configure with base params
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p_vc) == UNI_USLP_SUCCESS);

    // MAP-specific: allow only PVN=1; limit max packet length to 4 bytes
    uni_uslp_managed_params_t p_map = p_vc;
    p_map.valid_pvns_mask = (uint8_t)(1u << 1); // PVN=1 only
    p_map.max_packet_length = 4;                // bytes
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_PACKET, &p_map) == UNI_USLP_SUCCESS);

    // Try PVN not allowed -> reject
    const std::vector<uint8_t> pkt3 = { 0xDE, 0xAD, 0xBE };
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, pkt3.data(), pkt3.size(),
                                    /*PVN*/ 0u, /*expedited*/ false, /*sdu_id*/ 0u) == UNI_USLP_ERROR_INVALID_PARAM);

    // Allowed PVN=1 -> accept
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, pkt3.data(), pkt3.size(),
                                    /*PVN*/ 1u, /*expedited*/ false, /*sdu_id*/ 0u) == UNI_USLP_SUCCESS);
    // Build to flush queue
    {
        std::vector<uint8_t> frame(256);
        size_t flen = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    }

    // Max Packet Length: 5 bytes should be rejected; 4 bytes should pass
    const std::vector<uint8_t> pkt5 = { 0,1,2,3,4 };
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, pkt5.data(), pkt5.size(),
                                    /*PVN*/ 1u, /*expedited*/ false, /*sdu_id*/ 0u) == UNI_USLP_ERROR_INVALID_PARAM);

    const std::vector<uint8_t> pkt4 = { 9,8,7,6 };
    REQUIRE(uni_ccsds_uslp_send_packet_ex(&ctx, VC, MAP, pkt4.data(), pkt4.size(),
                                    /*PVN*/ 1u, /*expedited*/ false, /*sdu_id*/ 0u) == UNI_USLP_SUCCESS);
    {
        std::vector<uint8_t> frame(256);
        size_t flen = frame.size();
        REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &flen) == UNI_USLP_SUCCESS);
    }
}

/* USLP-150: Deliver incomplete packets (Table 5-5) — MAPP, RX path using FHP (Rule '000') */
TEST_CASE("MAPP: Deliver incomplete packets using FHP (USLP-150)", "[mapp][incomplete][USLP-150]")
{
    uni_uslp_managed_params_t p_vc{};
    configure_common_varlen_no_fecf_base(p_vc);

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4245, &p_vc) == UNI_USLP_SUCCESS);

    const uint8_t VC = 5, MAP = 2;

    // MAP configured for Packet service; enable deliver_incomplete_packets
    uni_uslp_managed_params_t p_map = p_vc;
    p_map.deliver_incomplete_packets = true;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &p_vc) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_PACKET, &p_map) == UNI_USLP_SUCCESS);

    // Register MAPP.indication callback (with PQI)
    MappMultiCap cap{};
    REQUIRE(uni_ccsds_uslp_register_mapp_indication_callback(&ctx, VC, MAP, mapp_ind_multi_cb, &cap) == UNI_USLP_SUCCESS);

    // Build a manual frame: Rule '000' with FHP = pre_len
    const std::vector<uint8_t> pre  = { 0xAA, 0xBB };
    const std::vector<uint8_t> post = { 0x10, 0x20, 0x30, 0x40 }; // treated as one "complete" packet region in minimal path

    // Primary Header
    uni_uslp_primary_header_t ph{};
    ph.tfvn = UNI_USLP_TFVN;
    ph.scid = 0x4245;
    ph.source_dest = false;
    ph.vcid = VC;
    ph.map_id = MAP;
    ph.eof_ph_flag = false;
    ph.bypass_flag = false;
    ph.cc_flag = false;
    ph.ocf_flag = false;
    ph.vcf_count_len = 0;
    ph.vcf_count = 0;

    // TFDF header: Rule 000 with FHP
    uni_uslp_tfdf_header_t th{};
    th.construction_rule = UNI_USLP_TFDZ_RULE_0;
    th.upid = 1;
    th.first_header_ptr = (uint16_t)pre.size();
    th.last_valid_ptr = 0;

    // Compute lengths and allocate buffer
    const size_t total = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + 3 /*TFDF hdr*/ + pre.size() + post.size();
    ph.frame_length = (uint16_t)(total - 1u);

    std::vector<uint8_t> frame(total, 0x00);
    size_t off = 0;

    // Pack PH
    size_t ph_written = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_pack(&ph, frame.data(), frame.size(), &ph_written) == UNI_USLP_SUCCESS);
    off += ph_written;

    // Pack TFDF header
    size_t th_written = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&th, &frame[off], frame.size() - off, &th_written) == UNI_USLP_SUCCESS);
    off += th_written;

    // TFDZ: pre (tail) + post (complete)
    REQUIRE(off + pre.size() + post.size() == frame.size());
    std::memcpy(&frame[off], pre.data(), pre.size());
    off += pre.size();
    std::memcpy(&frame[off], post.data(), post.size());
    off += post.size();

    // Accept: expect two deliveries — PARTIAL (pre), COMPLETE (post)
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

    REQUIRE(cap.segs.size() == 2);
    REQUIRE(cap.segs[0].pqi == UNI_USLP_PQI_PARTIAL);
    REQUIRE(cap.segs[0].data == pre);
    REQUIRE(cap.segs[1].pqi == UNI_USLP_PQI_COMPLETE);
    REQUIRE(cap.segs[1].data == post);
}
