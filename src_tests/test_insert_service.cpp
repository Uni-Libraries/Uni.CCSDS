/**
 * @file test_insert_service.cpp
 * @brief Tests for USLP Insert Data SDU service (INSERT.request/INSERT.indication) and Insert Zone handling
 *
 * Coverage (CCSDS 732.1-B-3):
 *  - USLP-7  Insert Data SDU (§3.2.8): Insert Zone only
 *  - USLP-51 IN_SDU (§3.11.2.2): Insert Zone only
 *  - USLP-52 Physical Channel Name (§3.11.2.3): managed parameter (not on-wire)
 *  - USLP-82 INSERT.request (§3.11.3.2): request to place IN_SDU into next frame's Insert Zone
 *  - USLP-83 INSERT.indication (§3.11.3.3): delivered from Insert Zone on reception
 *
 * Insert Zone format (§4.1.3): present only for fixed-length Transfer Frames and of configured length.
 * We enforce that the IN_SDU provided equals the configured Insert Zone length (no padding invented).
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstring>

namespace {

struct SduCap {
    bool called = false;
    uint8_t vcid = 0;
    uint8_t map = 0;
    std::vector<uint8_t> sdu;
};

struct InsertCap {
    bool called = false;
    uint8_t vcid = 0;
    std::vector<uint8_t> data;
};

void sdu_cb(uni_uslp_context_t* ctx,
            uint8_t vcid,
            uint8_t map_id,
            uni_uslp_service_type_t service_type,
            const uint8_t* sdu_data,
            size_t sdu_length,
            uni_uslp_verification_status_t verification_status,
            bool gap_detected,
            void* user)
{
    (void)ctx; (void)service_type; (void)verification_status; (void)gap_detected;
    auto* c = static_cast<SduCap*>(user);
    c->called = true;
    c->vcid = vcid;
    c->map = map_id;
    c->sdu.assign(sdu_data, sdu_data + sdu_length);
}

void insert_cb(uni_uslp_context_t* ctx,
               uint8_t vcid,
               const uint8_t* insert_data,
               size_t insert_length,
               void* user)
{
    (void)ctx;
    auto* c = static_cast<InsertCap*>(user);
    c->called = true;
    c->vcid = vcid;
    c->data.assign(insert_data, insert_data + insert_length);
}

} // namespace

TEST_CASE("INSERT.request populates fixed-length Insert Zone and triggers INSERT.indication", "[uslp][insert][fixed]")
{
    // Physical channel with fixed-length frames and Insert Zone present (§4.1.3)
    uni_uslp_managed_params_t global{};
    global.physical_channel_name = "PC-FIXED";
    global.max_frame_length = 64;
    global.min_frame_length = 64;            // fixed-length
    global.insert_zone_capability = true;
    global.insert_zone_length = 8;           // Insert Zone size
    global.fecf_capability = true;           // include FECF (§4.1.6)
    global.ocf_capability = false;
    global.truncated_frame_capable = false;
    global.max_sdu_length = 1024;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x2222, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 5;
    const uint8_t MAP  = 3;

    // VC params inherit global (Insert Zone presence/length)
    uni_uslp_managed_params_t vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    // MAP configured for MAPA (Rule '111' minimal path)
    uni_uslp_managed_params_t map_params = global;
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);

    // Register SDU and INSERT.indication callbacks
    SduCap scap{};
    InsertCap icap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &scap) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_register_insert_callback(&ctx, VCID, insert_cb, &icap) == UNI_USLP_SUCCESS);

    // Prepare IN_SDU == Insert Zone length (enforce exact fit per §4.1.3)
    std::vector<uint8_t> in_sdu(global.insert_zone_length);
    for (size_t i = 0; i < in_sdu.size(); ++i) in_sdu[i] = static_cast<uint8_t>(0xA0u + i);

    // Queue IN_SDU for next frame (INSERT.request, §3.11.3.2)
    REQUIRE(uni_ccsds_uslp_send_insert(&ctx, VCID, in_sdu.data(), in_sdu.size()) == UNI_USLP_SUCCESS);

    // Compute SDU length to exactly fill fixed-length frame:
    // total(64) = PH(7) + VCF(0) + INSERT(8) + TFDF(1 for rule '111') + SDU + OCF(0) + FECF(2)
    const size_t required_sdu = 64u
        - static_cast<size_t>(UNI_USLP_PRIMARY_HEADER_LENGTH)
        - static_cast<size_t>(global.insert_zone_length)
        - 1u
        - static_cast<size_t>(UNI_USLP_FECF_LENGTH);
    REQUIRE(required_sdu > 0);

    // Queue MAPA SDU to complete the frame
    std::vector<uint8_t> sdu(required_sdu);
    for (size_t i = 0; i < sdu.size(); ++i) sdu[i] = static_cast<uint8_t>(i & 0xFFu);
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);

    // Build frame
    std::vector<uint8_t> frame(64, 0x00);
    size_t out_len = frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame.data(), &out_len) == UNI_USLP_SUCCESS);
    REQUIRE(out_len == 64);

    // Validate Insert Zone content is present at offset PH(7) (VCF length=0 by default)
    const size_t insert_off = static_cast<size_t>(UNI_USLP_PRIMARY_HEADER_LENGTH);
    REQUIRE(std::memcmp(&frame[insert_off], in_sdu.data(), in_sdu.size()) == 0);

    // Accept frame -> expect INSERT.indication and MAPA SDU delivery
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

    REQUIRE(icap.called == true);
    REQUIRE(icap.vcid == VCID);
    REQUIRE(icap.data == in_sdu);

    REQUIRE(scap.called == true);
    REQUIRE(scap.vcid == VCID);
    REQUIRE(scap.map == MAP);
    REQUIRE(scap.sdu == sdu);
}

TEST_CASE("INSERT.request rejected on variable-length physical channel", "[uslp][insert][varlen]")
{
    uni_uslp_managed_params_t global{};
    global.physical_channel_name = "PC-VAR";
    global.max_frame_length = 2048;
    global.min_frame_length = 0;             // variable-length
    global.insert_zone_capability = true;    // even if capability is set, IZ only exists on fixed-length (§4.1.3)
    global.insert_zone_length = 8;
    global.fecf_capability = true;
    global.ocf_capability = false;
    global.truncated_frame_capable = false;
    global.max_sdu_length = 1024;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x3333, &global) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 2;

    uni_uslp_managed_params_t vc_params = global;
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc_params) == UNI_USLP_SUCCESS);

    std::vector<uint8_t> in_sdu(global.insert_zone_length, 0x5A);
    // Expect UNSUPPORTED since Insert Zone is only for fixed-length frames (§4.1.3)
    REQUIRE(uni_ccsds_uslp_send_insert(&ctx, VCID, in_sdu.data(), in_sdu.size()) == UNI_USLP_ERROR_UNSUPPORTED);
}