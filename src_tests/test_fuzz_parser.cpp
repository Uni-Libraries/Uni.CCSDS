/**
 * @file test_fuzz_parser.cpp
 * @brief Property/fuzz-style tests for USLP parser robustness
 *
 * Strategy:
 * 1) Generate valid frames via the public builder (Rule '111', variable-length, with/without FECF).
 * 2) Apply random mutations (bit/byte flips, truncations/expansions within buffer, random headers).
 * 3) Feed into accept() and assert that it returns a defined status (no crashes/UB).
 *
 * This focuses on parser safety and strict bounds checking, not on accepting malformed frames.
 *
 * References:
 * - CCSDS 732.1-B-3 §4.1/§4.3 frame format and validation
 * - Annex B (FECF)
 */

#include <catch2/catch_test_macros.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include "uni_crypto.h"

#include <vector>
#include <random>
#include <cstring>
#include <cstdint>

namespace {

struct Capture {
    bool called = false;
    uint8_t vcid = 0;
    uint8_t map = 0;
    std::vector<uint8_t> sdu;
};

void sdu_cb(uni_uslp_context_t* ctx,
            uint8_t vcid,
            uint8_t map_id,
            uni_uslp_service_type_t service_type,
            const uint8_t* sdu_data,
            size_t sdu_length,
            uni_uslp_verification_status_t verification_status, bool gap_detected,
            void* user)
{
    (void)ctx; (void)service_type; (void)gap_detected;
    auto* c = static_cast<Capture*>(user);
    c->called = true;
    c->vcid = vcid;
    c->map = map_id;
    c->sdu.assign(sdu_data, sdu_data + sdu_length);
}

static void make_valid_frame(uni_uslp_context_t& ctx,
                             uint8_t vcid,
                             uint8_t map_id,
                             const std::vector<uint8_t>& payload,
                             std::vector<uint8_t>& out_frame)
{
    REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, vcid, map_id, payload.data(), payload.size()) == UNI_USLP_SUCCESS);
    size_t cap = out_frame.size();
    REQUIRE(uni_ccsds_uslp_build_frame(&ctx, vcid, map_id, out_frame.data(), &cap) == UNI_USLP_SUCCESS);
    out_frame.resize(cap);
}

static void random_mutations(std::mt19937_64& rng,
                             std::vector<uint8_t>& frame,
                             size_t max_extra = 8)
{
    std::uniform_int_distribution<int> mode(0, 4);
    std::uniform_int_distribution<size_t> idx(0, frame.empty() ? 0 : frame.size() - 1);
    std::uniform_int_distribution<int> byteval(0, 255);
    std::uniform_int_distribution<size_t> extra(0, max_extra);

    int m = mode(rng);
    switch (m) {
        case 0: /* single byte flip */
            if (!frame.empty()) {
                size_t i = idx(rng);
                frame[i] ^= (uint8_t)(1u << (rng() % 8));
            }
            break;
        case 1: /* random byte overwrite */
            if (!frame.empty()) {
                size_t i = idx(rng);
                frame[i] = (uint8_t)byteval(rng);
            }
            break;
        case 2: /* truncate */
            if (frame.size() > 1) {
                frame.resize(frame.size() - 1);
            }
            break;
        case 3: /* duplicate one random byte (if room) */
            if (!frame.empty()) {
                size_t i = idx(rng);
                if (frame.size() < frame.capacity()) {
                    frame.insert(frame.begin() + (long)i, frame[i]);
                }
            }
            break;
        case 4: /* append some random bytes (bounded) */
        default:
        {
            size_t n = extra(rng);
            for (size_t k = 0; k < n; ++k) {
                frame.push_back((uint8_t)byteval(rng));
            }
            break;
        }
    }
}

} // namespace

TEST_CASE("Parser robustness against random mutations (variable-length, Rule '111')", "[uslp][fuzz][parser]")
{
    // Managed parameters for variable-length with FECF enabled
    uni_uslp_managed_params_t p{};
    p.max_frame_length = 2048;
    p.min_frame_length = 0;       // variable-length
    p.fecf_capability = true;
    p.ocf_capability = false;
    p.insert_zone_capability = false;
    p.truncated_frame_capable = false;
    p.max_sdu_length = 1024;

    uni_uslp_context_t ctx{};
    REQUIRE(uni_ccsds_uslp_init(&ctx, 0x4D4D, &p) == UNI_USLP_SUCCESS);

    const uint8_t VCID = 4;
    const uint8_t MAP  = 7;

    REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) == UNI_USLP_SUCCESS);
    REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);

    Capture cap{};
    REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VCID, MAP, sdu_cb, &cap) == UNI_USLP_SUCCESS);

    // Make a baseline valid frame
    std::vector<uint8_t> payload = {0,1,2,3,4,5,6,7,8,9,10};
    std::vector<uint8_t> frame(256, 0x00);
    make_valid_frame(ctx, VCID, MAP, payload, frame);

    // Sanity: valid frame verifies CRC and accepts
    REQUIRE(uni_crypto_crc16_ccitt_verify(frame.data(), frame.size()) == true);
    REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);

    // Fuzz: mutate copies and ensure accept() never crashes and returns defined statuses
    std::mt19937_64 rng(0xBADC0FFEEULL);
    const int trials = 500;
    for (int t = 0; t < trials; ++t) {
        std::vector<uint8_t> mutated = frame;
        random_mutations(rng, mutated);
        uni_uslp_status_t st = uni_ccsds_uslp_accept_frame(&ctx, mutated.data(), mutated.size());

        // Accept should either succeed or return a specific error code. We assert it is not "unknown".
        // Allowable failures include INVALID_FRAME, CRC_MISMATCH, BUFFER_TOO_SMALL, UNSUPPORTED.
        bool ok =
            (st == UNI_USLP_SUCCESS) ||
            (st == UNI_USLP_ERROR_NULL_POINTER) ||
            (st == UNI_USLP_ERROR_INVALID_PARAM) ||
            (st == UNI_USLP_ERROR_BUFFER_TOO_SMALL) ||
            (st == UNI_USLP_ERROR_INVALID_FRAME) ||
            (st == UNI_USLP_ERROR_CRC_MISMATCH) ||
            (st == UNI_USLP_ERROR_UNSUPPORTED) ||
            (st == UNI_USLP_ERROR_CONTEXT_FULL) ||
            (st == UNI_USLP_ERROR_NOT_FOUND) ||
            (st == UNI_USLP_ERROR_SDLS_FAILURE) ||
            (st == UNI_USLP_ERROR_TRUNCATED) ||
            (st == UNI_USLP_ERROR_SEQUENCE_GAP);
        REQUIRE(ok);
    }
}