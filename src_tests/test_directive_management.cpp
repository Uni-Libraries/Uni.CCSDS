/**
 * @file test_directive_management.cpp
 * @brief Tests for COPs Management Service primitives:
 *        - Directive.request (USLP-84, §3.12.3.2)
 *        - Directive_Notify.indication (USLP-85, §3.12.3.3)
 *        - Async_Notify.indication (USLP-86, §3.12.3.4)
 *
 * Verifies:
 *  - Successful Directive.request for COP-1 (per-VC) and COP-P (per-MC/Port) with Directive_Notify callbacks
 *  - Coexistence restrictions (§2.2.5 b,d): Directive.request is UNSUPPORTED when VCF (per VC) or MCF (per MC) request services are present
 *  - Async_Notify.indication delivery to registered callback
 */

#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstdint>
#include <cstring>

namespace {

struct DirNotifyRec {
    bool is_cop1{};
    uint8_t vcid{};
    uint32_t port_id{};
    uint16_t directive_id{};
    uint8_t directive_type{};
    uint32_t directive_qualifier{};
    uni_uslp_directive_notify_type_t notify_type{};
    uint32_t notify_qualifier{};
};

struct DirNotifyCap {
    std::vector<DirNotifyRec> recs;
    size_t calls = 0;
};

static void dir_notify_cb(uni_uslp_context_t* ctx,
                          bool is_cop1,
                          uint8_t vcid,
                          uint32_t port_id,
                          uint16_t directive_id,
                          uint8_t directive_type,
                          uint32_t directive_qualifier,
                          uni_uslp_directive_notify_type_t notify_type,
                          uint32_t notify_qualifier,
                          void* user)
{
    (void)ctx;
    auto* cap = static_cast<DirNotifyCap*>(user);
    cap->calls++;
    cap->recs.push_back(DirNotifyRec{
        is_cop1, vcid, port_id,
        directive_id, directive_type, directive_qualifier,
        notify_type, notify_qualifier
    });
}

struct AsyncRec {
    bool is_cop1{};
    uint8_t vcid{};
    uint32_t port_id{};
    uint8_t notification_type{};
    uint32_t notification_qualifier{};
};

struct AsyncCap {
    std::vector<AsyncRec> recs;
    size_t calls = 0;
};

static void async_notify_cb(uni_uslp_context_t* ctx,
                            bool is_cop1,
                            uint8_t vcid,
                            uint32_t port_id,
                            uint8_t notification_type,
                            uint32_t notification_qualifier,
                            void* user)
{
    (void)ctx;
    auto* cap = static_cast<AsyncCap*>(user);
    cap->calls++;
    cap->recs.push_back(AsyncRec{
        is_cop1, vcid, port_id, notification_type, notification_qualifier
    });
}

/* Dummy VCF/MCF provider TX callbacks for coexistence checks */
static void vcf_tx_cb(uni_uslp_context_t* ctx,
                      uint8_t vcid,
                      const uint8_t* frame,
                      size_t frame_length,
                      void* user)
{
    (void)ctx; (void)vcid; (void)frame; (void)frame_length; (void)user;
}

static void mcf_tx_cb(uni_uslp_context_t* ctx,
                      uint32_t mcid,
                      const uint8_t* frame,
                      size_t frame_length,
                      void* user)
{
    (void)ctx; (void)mcid; (void)frame; (void)frame_length; (void)user;
}

} // namespace

TEST_CASE("Directive.request COP-1 delivers Directive_Notify QUEUED then SENT", "[uslp][directive][cop1]")
{
    // Minimal managed parameters
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 1024;
    p.min_frame_length = 0; // variable-length (not used directly here)
    p.fecf_capability = false;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;

    const uint16_t SCID = 0x4A4A;
    const uint8_t VCID = 5;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);

    DirNotifyCap cap{};
    REQUIRE(uni_ccsds_uslp_register_directive_notify_callback(&ctx, dir_notify_cb, &cap) == UNI_USLP_SUCCESS);

    const uint16_t directive_id = 0x1234;
    const uint8_t directive_type = 0x56;
    const uint32_t directive_qual = 0xABCDEFu;

    // No VCF.request registered on this VC => allowed
    REQUIRE(uni_ccsds_uslp_directive_request(&ctx, true, VCID, 0u, directive_id, directive_type, directive_qual) == UNI_USLP_SUCCESS);

    REQUIRE(cap.calls == 2);
    REQUIRE(cap.recs.size() == 2);

    // First: QUEUED
    {
        const auto& r = cap.recs[0];
        REQUIRE(r.is_cop1 == true);
        REQUIRE(r.vcid == VCID);
        REQUIRE(r.port_id == 0u);
        REQUIRE(r.directive_id == directive_id);
        REQUIRE(r.directive_type == directive_type);
        REQUIRE(r.directive_qualifier == directive_qual);
        REQUIRE(r.notify_type == UNI_USLP_DIR_NOTIFY_QUEUED);
        REQUIRE(r.notify_qualifier == 0u);
    }
    // Second: SENT
    {
        const auto& r = cap.recs[1];
        REQUIRE(r.is_cop1 == true);
        REQUIRE(r.vcid == VCID);
        REQUIRE(r.port_id == 0u);
        REQUIRE(r.directive_id == directive_id);
        REQUIRE(r.directive_type == directive_type);
        REQUIRE(r.directive_qualifier == directive_qual);
        REQUIRE(r.notify_type == UNI_USLP_DIR_NOTIFY_SENT);
        REQUIRE(r.notify_qualifier == 0u);
    }
}

TEST_CASE("Directive.request COP-1 is UNSUPPORTED when VCF.request exists on same VC (§2.2.5 b,d)", "[uslp][directive][cop1][coexist]")
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 512;
    p.min_frame_length = 0;
    const uint16_t SCID = 0x3030;
    const uint8_t VCID = 6;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);

    // Register VCF provider for this VC
    REQUIRE(uni_ccsds_uslp_register_vcf_tx_callback(&ctx, VCID, vcf_tx_cb, nullptr) == UNI_USLP_SUCCESS);

    // Now Directive.request for COP-1 on this VC shall be rejected as UNSUPPORTED
    REQUIRE(uni_ccsds_uslp_directive_request(&ctx, true, VCID, 0u, 1u, 2u, 3u) == UNI_USLP_ERROR_UNSUPPORTED);
}

TEST_CASE("Directive.request COP-P delivers Directive_Notify and respects MCF coexistence", "[uslp][directive][copp]")
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 512;
    p.min_frame_length = 0;
    const uint16_t SCID = 0x5151;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);

    // Case A: No MCF registered => success
    {
        DirNotifyCap cap{};
        REQUIRE(uni_ccsds_uslp_register_directive_notify_callback(&ctx, dir_notify_cb, &cap) == UNI_USLP_SUCCESS);

        const uint32_t port_id = 7u;
        const uint16_t directive_id = 0x55AA;
        const uint8_t directive_type = 0xCC;
        const uint32_t directive_qual = 0x010203u;

        REQUIRE(uni_ccsds_uslp_directive_request(&ctx, false, 0u, port_id, directive_id, directive_type, directive_qual) == UNI_USLP_SUCCESS);
        REQUIRE(cap.calls == 2);
        REQUIRE(cap.recs[0].is_cop1 == false);
        REQUIRE(cap.recs[0].port_id == port_id);
        REQUIRE(cap.recs[0].notify_type == UNI_USLP_DIR_NOTIFY_QUEUED);
        REQUIRE(cap.recs[1].notify_type == UNI_USLP_DIR_NOTIFY_SENT);
    }

    // Case B: MCF registered => UNSUPPORTED (coexistence restriction)
    REQUIRE(uni_ccsds_uslp_register_mcf_tx_callback(&ctx, mcf_tx_cb, nullptr) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_directive_request(&ctx, false, 0u, 9u, 1u, 1u, 1u) == UNI_USLP_ERROR_UNSUPPORTED);
}

TEST_CASE("Async_Notify.indication delivery to registered callback", "[uslp][directive][async]")
{
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 256;
    p.min_frame_length = 0;
    const uint16_t SCID = 0x2222;
    const uint8_t VCID = 9;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, SCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);

    AsyncCap cap{};
    REQUIRE(uni_ccsds_uslp_register_async_notify_callback(&ctx, async_notify_cb, &cap) == UNI_USLP_SUCCESS);

    const uint8_t nt = 0x5A;
    const uint32_t nq = 0xDEADBEEFu;

    // Emit VC-scoped async notify
    REQUIRE(uni_ccsds_uslp_async_notify(&ctx, true, VCID, 0u, nt, nq) == UNI_USLP_SUCCESS);

    REQUIRE(cap.calls == 1);
    REQUIRE(cap.recs.size() == 1);
    REQUIRE(cap.recs[0].is_cop1 == true);
    REQUIRE(cap.recs[0].vcid == VCID);
    REQUIRE(cap.recs[0].port_id == 0u);
    REQUIRE(cap.recs[0].notification_type == nt);
    REQUIRE(cap.recs[0].notification_qualifier == nq);
}