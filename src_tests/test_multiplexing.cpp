/**
 * @file test_multiplexing.cpp
 * @brief Tests for USLP multiplexing and demultiplexing:
 * 
 * Implements and verifies:
 *  - USLP-96  MAP Multiplexing Function (§4.2.5): SINGLE and RR
 *  - USLP-99  Virtual Channel Multiplexing (§4.2.8): SINGLE and RR
 *  - USLP-101 Master Channel Multiplexing (§4.2.10): SINGLE (degenerate, single MC)
 *  - USLP-106 MAP Demultiplexing (§4.3.5): by PH.MAP ID and TFDF rule in accept path
 *  - USLP-109 VC Demultiplexing (§4.3.8): by PH.VCID in accept path
 *  - USLP-111 Master Channel Demultiplexing (§4.3.10): by TFVN/SCID in accept path
 *
 * Notes:
 *  - Scheduling options PRIORITY/DRR are recognized; this minimal IUT uses RR and SINGLE.
 *  - MC mux degenerates to SINGLE because the IUT uses one MC (one SCID).
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

static void parse_ph(const std::vector<uint8_t>& frame,
                     uni_uslp_primary_header_t& ph,
                     size_t& ph_len)
{
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &read) == UNI_USLP_SUCCESS);
    ph_len = read;
}

struct RxCap {
    struct Rec {
        uint8_t vcid{};
        uint8_t map{};
        std::vector<uint8_t> sdu;
    };
    std::vector<Rec> recs;
};

static void sdu_cb(uni_uslp_context_t*,
                   uint8_t vcid,
                   uint8_t map_id,
                   uni_uslp_service_type_t,
                   const uint8_t* sdu_data,
                   size_t sdu_length,
                   uni_uslp_verification_status_t,
                   bool,
                   void* user)
{
    auto* cap = static_cast<RxCap*>(user);
    RxCap::Rec r{};
    r.vcid = vcid;
    r.map = map_id;
    r.sdu.assign(sdu_data, sdu_data + sdu_length);
    cap->recs.push_back(std::move(r));
}

static void set_common_varlen(uni_uslp_managed_params_t& p)
{
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;    // variable-length
    p.fecf_capability = false; // simplify tests (no CRC required)
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 2048;
    // No VCF for these tests
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
    // Mux schemes default to UNSPECIFIED -> treated as SINGLE
    p.mc_mux_scheme = UNI_USLP_MC_MUX_SINGLE;
    p.vc_mux_scheme = UNI_USLP_VC_MUX_SINGLE;
}

} // namespace

TEST_CASE("MAP mux: RR alternates MAP selection in a VC (USLP-96)", "[uslp][mux][map][rr]")
{
    uni_uslp_managed_params_t global{};
    set_common_varlen(global);
    global.vc_mux_scheme = UNI_USLP_VC_MUX_SINGLE; // single VC focus

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x4242, &global) == UNI_USLP_SUCCESS);

    const uint8_t VC = 1;
    uni_uslp_managed_params_t vc_params = global;
    vc_params.map_mux_scheme = UNI_USLP_MAP_MUX_RR; // MAP RR in VC
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &vc_params) == UNI_USLP_SUCCESS);

    const uint8_t MAP_A = 2, MAP_B = 3;
    uni_uslp_managed_params_t map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP_A, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP_B, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    const std::vector<uint8_t> sduA{0xAA,0xAA};
    const std::vector<uint8_t> sduB{0xBB,0xBB};

    // Queue both
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP_A, sduA.data(), sduA.size()) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP_B, sduB.data(), sduB.size()) == UNI_USLP_SUCCESS);

    // Build next frame 1: should pick MAP_A first (RR start)
    {
        std::vector<uint8_t> frame(256, 0);
        size_t len = frame.size();
        uint8_t out_vc = 0xFF, out_map = 0xFF;
        REQUIRE(uni_ccsds_uslp_build_next_frame(&ctx, frame.data(), &len, &out_vc, &out_map) == UNI_USLP_SUCCESS);
        frame.resize(len);

        uni_uslp_primary_header_t ph{};
        size_t ph_len = 0;
        parse_ph(frame, ph, ph_len);
        CHECK(ph.vcid == VC);
        CHECK(ph.map_id == MAP_A);
        CHECK(out_vc == VC);
        CHECK(out_map == MAP_A);
    }

    // Build next frame 2: RR alternates to MAP_B
    {
        std::vector<uint8_t> frame(256, 0);
        size_t len = frame.size();
        uint8_t out_vc = 0xFF, out_map = 0xFF;
        REQUIRE(uni_ccsds_uslp_build_next_frame(&ctx, frame.data(), &len, &out_vc, &out_map) == UNI_USLP_SUCCESS);
        frame.resize(len);

        uni_uslp_primary_header_t ph{};
        size_t ph_len = 0;
        parse_ph(frame, ph, ph_len);
        CHECK(ph.vcid == VC);
        CHECK(ph.map_id == MAP_B);
        CHECK(out_vc == VC);
        CHECK(out_map == MAP_B);
    }
}

TEST_CASE("VC mux: RR alternates VC selection when multiple VCs have pending SDUs (USLP-99/USLP-101)", "[uslp][mux][vc][rr]")
{
    uni_uslp_managed_params_t global{};
    set_common_varlen(global);
    global.vc_mux_scheme = UNI_USLP_VC_MUX_RR; // VC RR across channel

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x5151, &global) == UNI_USLP_SUCCESS);

    // VC1
    const uint8_t VC1 = 1, MAP10 = 0;
    uni_uslp_managed_params_t vc1 = global;
    vc1.map_mux_scheme = UNI_USLP_MAP_MUX_SINGLE;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC1, &vc1) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC1, MAP10, UNI_USLP_SERVICE_MAPA, &vc1) == UNI_USLP_SUCCESS);

    // VC2
    const uint8_t VC2 = 2, MAP20 = 0;
    uni_uslp_managed_params_t vc2 = global;
    vc2.map_mux_scheme = UNI_USLP_MAP_MUX_SINGLE;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC2, &vc2) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC2, MAP20, UNI_USLP_SERVICE_MAPA, &vc2) == UNI_USLP_SUCCESS);

    const std::vector<uint8_t> sdu1{0x11}, sdu2{0x22};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC1, MAP10, sdu1.data(), sdu1.size()) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC2, MAP20, sdu2.data(), sdu2.size()) == UNI_USLP_SUCCESS);

    // First build: expect VC1 selected
    {
        std::vector<uint8_t> frame(256, 0);
        size_t len = frame.size();
        uint8_t out_vc = 0xFF, out_map = 0xFF;
        REQUIRE(uni_ccsds_uslp_build_next_frame(&ctx, frame.data(), &len, &out_vc, &out_map) == UNI_USLP_SUCCESS);
        frame.resize(len);

        uni_uslp_primary_header_t ph{};
        size_t ph_len = 0;
        parse_ph(frame, ph, ph_len);
        CHECK(ph.vcid == VC1);
        CHECK(out_vc == VC1);
        CHECK(out_map == MAP10);
    }

    // Second build: RR alternates to VC2
    {
        std::vector<uint8_t> frame(256, 0);
        size_t len = frame.size();
        uint8_t out_vc = 0xFF, out_map = 0xFF;
        REQUIRE(uni_ccsds_uslp_build_next_frame(&ctx, frame.data(), &len, &out_vc, &out_map) == UNI_USLP_SUCCESS);
        frame.resize(len);

        uni_uslp_primary_header_t ph{};
        size_t ph_len = 0;
        parse_ph(frame, ph, ph_len);
        CHECK(ph.vcid == VC2);
        CHECK(out_vc == VC2);
        CHECK(out_map == MAP20);
    }
}

TEST_CASE("Demultiplexing on RX: frames routed by MC/VC/MAP to correct SAPs (USLP-111/109/106)", "[uslp][demux][rx]")
{
    uni_uslp_managed_params_t global{};
    set_common_varlen(global);
    global.vc_mux_scheme = UNI_USLP_VC_MUX_SINGLE;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, /*SCID*/ 0x6161, &global) == UNI_USLP_SUCCESS);

    // VC=3 MAP=2 and VC=4 MAP=1, both MAPA services
    const uint8_t VC3 = 3, MAP32 = 2;
    const uint8_t VC4 = 4, MAP41 = 1;

    uni_uslp_managed_params_t vcp = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC3, &vcp) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC4, &vcp) == UNI_USLP_SUCCESS);

    uni_uslp_managed_params_t mp = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC3, MAP32, UNI_USLP_SERVICE_MAPA, &mp) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC4, MAP41, UNI_USLP_SERVICE_MAPA, &mp) == UNI_USLP_SUCCESS);

    RxCap cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC3, MAP32, sdu_cb, &cap) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC4, MAP41, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Build a frame for VC3/MAP32
    const std::vector<uint8_t> sduA{0xA1,0xA2};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC3, MAP32, sduA.data(), sduA.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fA(256, 0);
    size_t lA = fA.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC3, MAP32, fA.data(), &lA) == UNI_USLP_SUCCESS);
    fA.resize(lA);

    // Build a frame for VC4/MAP41
    const std::vector<uint8_t> sduB{0xB1,0xB2,0xB3};
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC4, MAP41, sduB.data(), sduB.size()) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> fB(256, 0);
    size_t lB = fB.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC4, MAP41, fB.data(), &lB) == UNI_USLP_SUCCESS);
    fB.resize(lB);

    // Accept both and verify routing
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fA.data(), fA.size()) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, fB.data(), fB.size()) == UNI_USLP_SUCCESS);

    REQUIRE(cap.recs.size() == 2);
    CHECK(cap.recs[0].vcid == VC3);
    CHECK(cap.recs[0].map == MAP32);
    CHECK(cap.recs[0].sdu == sduA);

    CHECK(cap.recs[1].vcid == VC4);
    CHECK(cap.recs[1].map == MAP41);
    CHECK(cap.recs[1].sdu == sduB);
}