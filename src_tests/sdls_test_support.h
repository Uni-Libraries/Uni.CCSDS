// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

/*
 * Shared setup for SDLS tests: SA profiles and a TX/RX helper.
 */

#pragma once

#include <memory>
#include <catch2/catch_test_macros.hpp>

// uni.CCSDS
#include "uni_ccsds_uslp_internal.h"

// stdlib
#include <cstdint>
#include <cstring>
#include <vector>

namespace sdls_test {

inline const uint8_t kKey256[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0};

/** HMAC-SHA-256, SN 8 octets, 16-octet MAC, strict anti-replay. */
inline uni_uslp_sdls_sa_config_t hmac_sa(uint16_t spi) {
    uni_uslp_sdls_sa_config_t sa{};
    sa.spi = spi;
    sa.suite = UNI_USLP_SDLS_SUITE_HMAC_SHA256;
    sa.iv_length = 0;
    sa.sn_length = 8;
    sa.mac_length = 16;
    sa.anti_replay_enabled = true;
    sa.replay_mode = UNI_USLP_SDLS_REPLAY_STRICT;
    sa.anti_replay_window = 64;
    return sa;
}

/** AES-GCM with the IV derived from an 8-octet SN field (IV not transmitted). */
inline uni_uslp_sdls_sa_config_t gcm_sa(uint16_t spi) {
    uni_uslp_sdls_sa_config_t sa = hmac_sa(spi);
    sa.suite = UNI_USLP_SDLS_SUITE_AES_GCM;
    return sa;
}

/** CCSDS 355.0-B-2 Annex E baseline: AES-GCM, 96-bit IV in the header, no SN field, 128-bit MAC. */
inline uni_uslp_sdls_sa_config_t gcm_baseline_sa(uint16_t spi) {
    uni_uslp_sdls_sa_config_t sa = gcm_sa(spi);
    sa.iv_length = UNI_USLP_SDLS_IV_LENGTH;
    sa.sn_length = 0;
    return sa;
}

/** VC configuration applying `tx_spi` and accepting `rx_spis`. */
inline uni_uslp_sdls_vc_config_t vc_config(uint16_t tx_spi, std::initializer_list<uint16_t> rx_spis) {
    uni_uslp_sdls_vc_config_t vc{};
    vc.enabled = true;
    vc.tx_spi = tx_spi;
    for (const uint16_t spi : rx_spis) {
        vc.rx_spis[vc.rx_spi_count++] = spi;
    }
    return vc;
}

/** Variable-length frames without FECF, so a tampered frame reaches SDLS. */
inline uni_uslp_managed_params_t varlen_params() {
    uni_uslp_managed_params_t p{};
    std::memset(&p, 0, sizeof(p));
    p.max_frame_length = 8192;
    p.max_sdu_length = 8192;
    return p;
}

/** One USLP context with SDLS on a VC, delivering MAPA SDUs of every MAP 0..15 to `received`. */
struct Endpoint {
    // The context is > 1 MiB: heap-allocate it (1 MiB default stack on Windows).
    std::unique_ptr<uni_uslp_context_t> ctx_owner = std::make_unique<uni_uslp_context_t>();
    uni_uslp_context_t& ctx = *ctx_owner;
    std::vector<uint8_t> work = std::vector<uint8_t>(16384);
    struct Delivery {
        uint8_t vcid;
        uint8_t map_id;
        std::vector<uint8_t> sdu;
        uni_uslp_verification_status_t ver;
    };
    std::vector<Delivery> received;

    static void on_sdu(uni_uslp_context_t*, uint8_t vcid, uint8_t map_id, uni_uslp_service_type_t, const uint8_t* data, size_t len,
                       uni_uslp_verification_status_t ver, bool, void* user) {
        static_cast<Endpoint*>(user)->received.push_back({vcid, map_id, std::vector<uint8_t>(data, data + len), ver});
    }

    explicit Endpoint(const uni_uslp_managed_params_t& p = varlen_params(), uint16_t scid = 0x6161, bool with_work_buffer = true) {
        REQUIRE(uni_ccsds_uslp_init(&ctx, scid, &p) == UNI_USLP_SUCCESS);
        REQUIRE(uni_ccsds_uslp_register_builtin_sdls(&ctx) == UNI_USLP_SUCCESS);
        if (with_work_buffer) {
            REQUIRE(uni_ccsds_uslp_set_work_buffer(&ctx, work.data(), work.size()) == UNI_USLP_SUCCESS);
        }
    }
    ~Endpoint() { (void)uni_ccsds_uslp_free(&ctx); }
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    void add_vc(uint8_t vcid, const uni_uslp_managed_params_t& p = varlen_params()) {
        REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, vcid, &p) == UNI_USLP_SUCCESS);
        for (uint8_t map = 0; map < 16; ++map) {
            REQUIRE(uni_ccsds_uslp_configure_map(&ctx, vcid, map, UNI_USLP_SERVICE_MAPA, &p) == UNI_USLP_SUCCESS);
            REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, vcid, map, &Endpoint::on_sdu, this) == UNI_USLP_SUCCESS);
        }
    }

    void add_sa(const uni_uslp_sdls_sa_config_t& sa, const uint8_t* key = kKey256, size_t key_len = sizeof(kKey256)) {
        REQUIRE(uni_ccsds_uslp_sdls_add_sa(&ctx, &sa, key, key_len) == UNI_USLP_SUCCESS);
    }

    void enable_sdls(uint8_t vcid, const uni_uslp_sdls_vc_config_t& vc) { REQUIRE(uni_ccsds_uslp_configure_sdls(&ctx, vcid, &vc) == UNI_USLP_SUCCESS); }

    /** Build one MAPA frame; returns the status and the frame. */
    uni_uslp_status_t build(uint8_t vcid, uint8_t map, const std::vector<uint8_t>& sdu, std::vector<uint8_t>& frame, size_t capacity = 16384) {
        REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, vcid, map, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
        frame.assign(capacity, 0);
        size_t len = frame.size();
        const auto st = uni_ccsds_uslp_build_frame(&ctx, vcid, map, frame.data(), &len);
        frame.resize(st == UNI_USLP_SUCCESS ? len : 0);
        return st;
    }

    std::vector<uint8_t> build_ok(uint8_t vcid, uint8_t map, const std::vector<uint8_t>& sdu) {
        std::vector<uint8_t> frame;
        REQUIRE(build(vcid, map, sdu, frame) == UNI_USLP_SUCCESS);
        return frame;
    }

    uni_uslp_status_t accept(const std::vector<uint8_t>& frame) { return uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()); }

    uni_uslp_sdls_stats_t stats(uint8_t vcid) const {
        uni_uslp_sdls_stats_t s{};
        REQUIRE(uni_ccsds_uslp_get_sdls_stats(&ctx, vcid, &s) == UNI_USLP_SUCCESS);
        return s;
    }

    uni_uslp_sdls_sa_t* sa(uint16_t spi) { return uni_ccsds_uslp_sdls_find_sa(&ctx, spi); }
};

/** Offset of the Security Header in a frame without VCF Count and Insert Zone. */
constexpr size_t kSecOffset = UNI_USLP_PRIMARY_HEADER_LENGTH;

/** Write `sn` big-endian into the 8-octet SN field of a frame protected by hmac_sa()/gcm_sa(). */
inline void patch_sn(std::vector<uint8_t>& frame, uint64_t sn) {
    for (size_t i = 0; i < 8; ++i) {
        frame[kSecOffset + 2 + i] = static_cast<uint8_t>(sn >> (8 * (7 - i)));
    }
}

inline uint64_t read_sn(const std::vector<uint8_t>& frame) {
    uint64_t sn = 0;
    for (size_t i = 0; i < 8; ++i) sn = (sn << 8) | frame[kSecOffset + 2 + i];
    return sn;
}

} // namespace sdls_test
