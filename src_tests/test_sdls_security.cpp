// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

/*
 * SDLS security properties (CCSDS 355.0-B-2) of the built-in engine
 *
 * Regression tests for the defects of the 2026-10 audit (plan.md):
 * - CCSDS-1: forged frames must not change the anti-replay state (§4.2.4.4 j)       — poc_antireplay
 * - CCSDS-2: Primary Header (VCID, MAP ID) and Security Header are authenticated    — poc_mapid
 * - CCSDS-3: transmit SN restore after restart (IV reuse protection)
 * - CCSDS-4: 16-bit SPI, SA selected by SPI
 * - CCSDS-5: STRICT_355 and SLIDING anti-replay modes
 * - CCSDS-6: distinct rejection codes and per-VC counters
 * - CCSDS-8: large frames without a transmit work buffer
 * - CCSDS-9: invalid configurations rejected at configuration time
 */

#include "sdls_test_support.h"

#include <random>

using namespace sdls_test;

namespace {

constexpr uint8_t kVc = 4;
constexpr uint16_t kSpi = 0x0A0B;

/** Snapshot of the receive anti-replay state of an SA. */
struct RxState {
    bool initialized;
    uint64_t sn;
    std::vector<uint64_t> bitmap;
    bool operator==(const RxState&) const = default;
};

RxState rx_state(const uni_uslp_sdls_sa_t* sa) {
    return {sa->rx_initialized, sa->rx_sn, std::vector<uint64_t>(std::begin(sa->rx_window_bitmap), std::end(sa->rx_window_bitmap))};
}

/** Transmitter and receiver with one SA on kVc. */
struct Link {
    Endpoint tx;
    Endpoint rx;
    explicit Link(const uni_uslp_sdls_sa_config_t& sa) {
        tx.add_vc(kVc);
        tx.add_sa(sa);
        tx.enable_sdls(kVc, vc_config(sa.spi, {}));
        rx.add_vc(kVc);
        rx.add_sa(sa);
        rx.enable_sdls(kVc, vc_config(0, {sa.spi}));
    }
};

std::vector<uint8_t> sdu_of(uint32_t index) { return {static_cast<uint8_t>(index), static_cast<uint8_t>(index >> 8), 0xC3, 0x3C}; }

} // namespace

TEST_CASE("CCSDS-1: forged frames with any SN do not block genuine frames", "[sdls][security][anti-replay]")
{
    for (const auto mode : {UNI_USLP_SDLS_REPLAY_STRICT, UNI_USLP_SDLS_REPLAY_SLIDING}) {
        for (const auto suite : {UNI_USLP_SDLS_SUITE_AES_GCM, UNI_USLP_SDLS_SUITE_HMAC_SHA256}) {
            auto sa = gcm_sa(kSpi);
            sa.suite = suite;
            sa.replay_mode = mode;
            Link link(sa);

            std::vector<std::vector<uint8_t>> genuine;
            for (uint32_t i = 0; i < 8; ++i) genuine.push_back(link.tx.build_ok(kVc, 1, sdu_of(i)));

            // Forgeries: a genuine frame with its SN rewritten (MAC no longer matches), before any genuine frame —
            // SN 1 would occupy the first genuine SN, SN 10^6 would push the window past every genuine frame.
            for (const uint64_t forged_sn : {uint64_t{1}, uint64_t{2}, uint64_t{1000000}, UINT64_MAX}) {
                auto forged = genuine[7];
                patch_sn(forged, forged_sn);
                const RxState before = rx_state(link.rx.sa(kSpi));
                CHECK(link.rx.accept(forged) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);
                CHECK(rx_state(link.rx.sa(kSpi)) == before);
            }

            REQUIRE(link.rx.accept(genuine[0]) == UNI_USLP_SUCCESS);

            // Forgeries after the window is initialized: ahead of it, far ahead, and a wrong tag on the next SN.
            for (const uint64_t forged_sn : {uint64_t{3}, uint64_t{4}, uint64_t{60}, uint64_t{1000000}}) {
                auto forged = genuine[1]; // genuine SN 2
                patch_sn(forged, forged_sn);
                const RxState before = rx_state(link.rx.sa(kSpi));
                CHECK(link.rx.accept(forged) != UNI_USLP_SUCCESS);
                CHECK(rx_state(link.rx.sa(kSpi)) == before);
            }
            auto wrong_tag = genuine[1];
            wrong_tag.back() ^= 0x5A;
            const RxState before = rx_state(link.rx.sa(kSpi));
            CHECK(link.rx.accept(wrong_tag) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);
            CHECK(rx_state(link.rx.sa(kSpi)) == before);

            for (uint32_t i = 1; i < 8; ++i) {
                CHECK(link.rx.accept(genuine[i]) == UNI_USLP_SUCCESS);
            }
            CHECK(link.rx.received.size() == 8);
        }
    }
}

TEST_CASE("CCSDS-2: rewriting VCID, MAP ID, SPI or SN in a frame fails verification", "[sdls][security][auth-mask]")
{
    for (const auto suite : {UNI_USLP_SDLS_SUITE_AES_GCM, UNI_USLP_SDLS_SUITE_AES_CCM, UNI_USLP_SDLS_SUITE_HMAC_SHA256}) {
        auto sa = gcm_sa(kSpi);
        sa.suite = suite;
        // A second SA with the same key, so a rewritten SPI still reaches MAC verification.
        auto sa2 = sa;
        sa2.spi = kSpi ^ 0x0001u;

        Endpoint tx;
        Endpoint rx;
        for (Endpoint* ep : {&tx, &rx}) {
            ep->add_vc(kVc);
            ep->add_vc(kVc + 1);
            ep->add_sa(sa);
            ep->add_sa(sa2);
        }
        tx.enable_sdls(kVc, vc_config(kSpi, {}));
        rx.enable_sdls(kVc, vc_config(0, {kSpi, sa2.spi}));
        rx.enable_sdls(kVc + 1, vc_config(0, {kSpi, sa2.spi}));

        // poc_mapid: a frame of MAP 2 whose header is rewritten to MAP 1 must not be delivered to MAP 1.
        auto map_rewritten = tx.build_ok(kVc, 2, {0x11, 0x22, 0x33});
        map_rewritten[3] = static_cast<uint8_t>((map_rewritten[3] & ~0x1Eu) | (1u << 1));
        CHECK(rx.accept(map_rewritten) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);

        auto vc_rewritten = tx.build_ok(kVc, 2, {0x11, 0x22, 0x33});
        vc_rewritten[3] ^= 0x20; // VCID LSB (bit 26): VCID 4 -> 5
        CHECK(rx.accept(vc_rewritten) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);

        auto spi_rewritten = tx.build_ok(kVc, 2, {0x11, 0x22, 0x33});
        spi_rewritten[kSecOffset + 1] ^= 0x01; // kSpi -> sa2.spi (same key)
        CHECK(rx.accept(spi_rewritten) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);

        auto sn_rewritten = tx.build_ok(kVc, 2, {0x11, 0x22, 0x33});
        patch_sn(sn_rewritten, read_sn(sn_rewritten) + 1);
        CHECK(rx.accept(sn_rewritten) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);

        CHECK(rx.received.empty());

        // A bit outside the default mask (Bypass flag) is not authenticated, as §4.2.2.6.2 j allows.
        auto outside_mask = tx.build_ok(kVc, 2, {0x11, 0x22, 0x33});
        outside_mask[6] ^= 0x80;
        CHECK(rx.accept(outside_mask) == UNI_USLP_SUCCESS);
        REQUIRE(rx.received.size() == 1);
        CHECK(rx.received[0].map_id == 2);
    }
}

TEST_CASE("CCSDS-2: a mission mask extends authentication to further Primary Header bits", "[sdls][security][auth-mask]")
{
    auto sa = gcm_sa(kSpi);
    uni_ccsds_uslp_sdls_default_auth_mask(sa.auth_mask);
    sa.auth_mask[6] |= 0x80; // Bypass flag
    Link link(sa);

    auto frame = link.tx.build_ok(kVc, 1, {1, 2, 3});
    frame[6] ^= 0x80;
    CHECK(link.rx.accept(frame) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);
    frame[6] ^= 0x80;
    CHECK(link.rx.accept(frame) == UNI_USLP_SUCCESS);
}

TEST_CASE("CCSDS-3: transmit SN must be restored after a reset before frames are protected again", "[sdls][security][sn-restore]")
{
    auto sa = gcm_sa(kSpi);
    sa.require_sn_restore = true;
    Endpoint tx;
    tx.add_vc(kVc);
    tx.add_sa(sa);
    tx.enable_sdls(kVc, vc_config(kSpi, {}));

    std::vector<uint8_t> frame;
    CHECK(tx.build(kVc, 1, {1}, frame) == UNI_USLP_ERROR_SDLS_SN_NOT_RESTORED);

    REQUIRE(uni_ccsds_uslp_sdls_set_tx_sn(&tx.ctx, kSpi, 0) == UNI_USLP_SUCCESS);
    for (uint64_t expected = 1; expected <= 3; ++expected) {
        CHECK(read_sn(tx.build_ok(kVc, 1, {1})) == expected);
    }
    uint64_t last = 0;
    REQUIRE(uni_ccsds_uslp_sdls_get_tx_sn(&tx.ctx, kSpi, &last) == UNI_USLP_SUCCESS);
    CHECK(last == 3);

    // Restart with the same key: refused until the persisted SN is restored; then the sequence (and IV) continues.
    REQUIRE(uni_ccsds_uslp_reset(&tx.ctx) == UNI_USLP_SUCCESS);
    CHECK(tx.build(kVc, 1, {1}, frame) == UNI_USLP_ERROR_SDLS_SN_NOT_RESTORED);
    REQUIRE(uni_ccsds_uslp_sdls_set_tx_sn(&tx.ctx, kSpi, last) == UNI_USLP_SUCCESS);
    CHECK(read_sn(tx.build_ok(kVc, 1, {1})) == 4);

    // Rewinding while no restore is pending would reuse IVs.
    CHECK(uni_ccsds_uslp_sdls_set_tx_sn(&tx.ctx, kSpi, 1) == UNI_USLP_ERROR_INVALID_PARAM);

    // A new key starts a new SN space.
    const uint8_t new_key[32] = {9, 8, 7, 6, 5, 4, 3, 2, 1};
    REQUIRE(uni_ccsds_uslp_sdls_rekey_sa(&tx.ctx, kSpi, new_key, sizeof(new_key)) == UNI_USLP_SUCCESS);
    CHECK(read_sn(tx.build_ok(kVc, 1, {1})) == 1);
}

TEST_CASE("CCSDS-3: a reset without require_sn_restore keeps the transmit SN", "[sdls][security][sn-restore]")
{
    Link link(gcm_sa(kSpi));
    CHECK(read_sn(link.tx.build_ok(kVc, 1, {1})) == 1);
    REQUIRE(uni_ccsds_uslp_reset(&link.tx.ctx) == UNI_USLP_SUCCESS);
    CHECK(read_sn(link.tx.build_ok(kVc, 1, {1})) == 2);
}

TEST_CASE("SDLS: the transmit SN never wraps into a reused IV", "[sdls][security][sn-exhausted]")
{
    auto sa = gcm_sa(kSpi);
    sa.sn_length = 1; // IV derived from a 1-octet SN field: 255 frames per key
    Endpoint tx;
    tx.add_vc(kVc);
    tx.add_sa(sa);
    tx.enable_sdls(kVc, vc_config(kSpi, {}));
    REQUIRE(uni_ccsds_uslp_sdls_set_tx_sn(&tx.ctx, kSpi, 254) == UNI_USLP_SUCCESS);
    std::vector<uint8_t> frame;
    CHECK(tx.build(kVc, 1, {1}, frame) == UNI_USLP_SUCCESS);
    CHECK(tx.build(kVc, 1, {1}, frame) == UNI_USLP_ERROR_SDLS_SN_EXHAUSTED);
}

TEST_CASE("CCSDS-4: 16-bit SPI selects the SA; unknown SPI is rejected", "[sdls][security][spi]")
{
    const uint16_t spi_a = 0x1234;
    const uint16_t spi_b = 0xFFFE;
    const uint8_t key_b[16] = {0xB0, 0xB1};
    auto sa_a = gcm_sa(spi_a);
    auto sa_b = hmac_sa(spi_b);

    Endpoint tx;
    tx.add_vc(kVc);
    tx.add_sa(sa_a);
    tx.add_sa(sa_b, key_b, sizeof(key_b));
    Endpoint rx;
    rx.add_vc(kVc);
    rx.add_sa(sa_a);
    rx.add_sa(sa_b, key_b, sizeof(key_b));
    rx.enable_sdls(kVc, vc_config(0, {spi_a, spi_b}));

    // The transmitter switches SA; the receiver follows the SPI without reconfiguration.
    tx.enable_sdls(kVc, vc_config(spi_a, {}));
    const auto frame_a = tx.build_ok(kVc, 1, {0xA});
    tx.enable_sdls(kVc, vc_config(spi_b, {}));
    const auto frame_b = tx.build_ok(kVc, 1, {0xB});
    CHECK(frame_b[kSecOffset] == 0xFF);
    CHECK(frame_b[kSecOffset + 1] == 0xFE);
    CHECK(rx.accept(frame_a) == UNI_USLP_SUCCESS);
    CHECK(rx.accept(frame_b) == UNI_USLP_SUCCESS);
    REQUIRE(rx.received.size() == 2);
    CHECK(rx.received[0].sdu == std::vector<uint8_t>{0xA});
    CHECK(rx.received[1].sdu == std::vector<uint8_t>{0xB});

    // An SPI the VC does not accept, even if the SA exists elsewhere in the context.
    rx.enable_sdls(kVc, vc_config(0, {spi_a}));
    CHECK(rx.accept(frame_b) == UNI_USLP_ERROR_SDLS_SA_NOT_FOUND);
    auto unknown = frame_a;
    unknown[kSecOffset] = 0x77;
    CHECK(rx.accept(unknown) == UNI_USLP_ERROR_SDLS_SA_NOT_FOUND);
    CHECK(rx.stats(kVc).sa_not_found == 2);
}

TEST_CASE("CCSDS-4: an SA restricted to MAP IDs rejects frames of other MAPs", "[sdls][security][spi]")
{
    auto sa = gcm_sa(kSpi);
    sa.map_ids = 1u << 3;
    Link link(sa);
    std::vector<uint8_t> frame;
    CHECK(link.tx.build(kVc, 2, {1}, frame) == UNI_USLP_ERROR_SDLS_SA_NOT_FOUND);
    REQUIRE(link.tx.build(kVc, 3, {1}, frame) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(frame) == UNI_USLP_SUCCESS);
}

TEST_CASE("CCSDS-5: STRICT anti-replay follows 355.0-B-2 §4.2.4.4 g-j", "[sdls][security][anti-replay]")
{
    auto sa = gcm_sa(kSpi);
    sa.replay_mode = UNI_USLP_SDLS_REPLAY_STRICT;
    sa.anti_replay_window = 10;
    Link link(sa);
    std::vector<std::vector<uint8_t>> f;
    for (uint32_t i = 0; i < 40; ++i) f.push_back(link.tx.build_ok(kVc, 1, sdu_of(i))); // f[i] has SN i + 1

    REQUIRE(link.rx.accept(f[0]) == UNI_USLP_SUCCESS); // managed SN 1
    CHECK(link.rx.accept(f[0]) == UNI_USLP_ERROR_SDLS_REPLAY);
    CHECK(link.rx.accept(f[11]) == UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW); // SN 12 > 1 + 10
    CHECK(link.rx.accept(f[10]) == UNI_USLP_SUCCESS);                   // SN 11 = 1 + 10, gap allowed
    CHECK(link.rx.accept(f[5]) == UNI_USLP_ERROR_SDLS_REPLAY);          // SN 6 <= managed 11: late frames rejected
    CHECK(link.rx.accept(f[11]) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(f[30]) == UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW);

    // Key management may set the managed SN (e.g. after a receiver restart).
    REQUIRE(uni_ccsds_uslp_sdls_set_rx_sn(&link.rx.ctx, kSpi, 30) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(f[29]) == UNI_USLP_ERROR_SDLS_REPLAY);
    CHECK(link.rx.accept(f[30]) == UNI_USLP_SUCCESS);

    const auto s = link.rx.stats(kVc);
    CHECK(s.frames_verified == 4);
    CHECK(s.replays == 3);
    CHECK(s.out_of_window == 2);
}

TEST_CASE("CCSDS-5: SLIDING anti-replay accepts reordered frames once", "[sdls][security][anti-replay]")
{
    auto sa = gcm_sa(kSpi);
    sa.replay_mode = UNI_USLP_SDLS_REPLAY_SLIDING;
    sa.anti_replay_window = 16;
    Link link(sa);
    std::vector<std::vector<uint8_t>> f;
    for (uint32_t i = 0; i < 40; ++i) f.push_back(link.tx.build_ok(kVc, 1, sdu_of(i)));

    REQUIRE(link.rx.accept(f[20]) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(f[10]) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(f[10]) == UNI_USLP_ERROR_SDLS_REPLAY);
    CHECK(link.rx.accept(f[4]) == UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW); // 16 behind the highest
    CHECK(link.rx.accept(f[39]) == UNI_USLP_SUCCESS);                 // no forward bound in SLIDING
    CHECK(link.rx.accept(f[20]) == UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW);
}

TEST_CASE("CCSDS-6: every rejection reason has its own status and counter", "[sdls][security][status]")
{
    Link link(gcm_sa(kSpi));
    const auto good = link.tx.build_ok(kVc, 1, {1, 2, 3, 4});

    auto bad_mac = good;
    bad_mac[bad_mac.size() - 3] ^= 0x01;
    CHECK(link.rx.accept(bad_mac) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);

    auto bad_spi = good;
    bad_spi[kSecOffset] ^= 0x40;
    CHECK(link.rx.accept(bad_spi) == UNI_USLP_ERROR_SDLS_SA_NOT_FOUND);

    // Shorter than SPI + SN + MAC: rewrite the Frame Length field to keep the Primary Header consistent.
    std::vector<uint8_t> too_short(good.begin(), good.begin() + kSecOffset + 12);
    const uint16_t c = static_cast<uint16_t>(too_short.size() - 1);
    too_short[4] = static_cast<uint8_t>(c >> 8);
    too_short[5] = static_cast<uint8_t>(c);
    CHECK(link.rx.accept(too_short) == UNI_USLP_ERROR_SDLS_LENGTH);

    REQUIRE(link.rx.accept(good) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(good) == UNI_USLP_ERROR_SDLS_REPLAY);
    auto far = link.tx.build_ok(kVc, 1, {5});
    REQUIRE(uni_ccsds_uslp_sdls_set_tx_sn(&link.tx.ctx, kSpi, 500) == UNI_USLP_SUCCESS);
    far = link.tx.build_ok(kVc, 1, {6});
    CHECK(link.rx.accept(far) == UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW);

    const auto s = link.rx.stats(kVc);
    CHECK(s.frames_verified == 1);
    CHECK(s.mac_failures == 1);
    CHECK(s.sa_not_found == 1);
    CHECK(s.length_errors == 1);
    CHECK(s.replays == 1);
    CHECK(s.out_of_window == 1);
    CHECK(s.other_errors == 0);

    CHECK(std::string(uni_ccsds_uslp_status_string(UNI_USLP_ERROR_SDLS_REPLAY)).find("REPLAY") != std::string::npos);

    REQUIRE(uni_ccsds_uslp_reset(&link.rx.ctx) == UNI_USLP_SUCCESS);
    CHECK(link.rx.stats(kVc).mac_failures == 0);
}

TEST_CASE("CCSDS-8: frames above 1 KiB are protected without a transmit work buffer", "[sdls][aead][large]")
{
    for (const auto suite : {UNI_USLP_SDLS_SUITE_AES_GCM, UNI_USLP_SDLS_SUITE_AES_CCM, UNI_USLP_SDLS_SUITE_HMAC_SHA256}) {
        auto sa = gcm_sa(kSpi);
        sa.suite = suite;
        Endpoint tx(varlen_params(), 0x6161, /*with_work_buffer=*/false);
        tx.add_vc(kVc);
        tx.add_sa(sa);
        tx.enable_sdls(kVc, vc_config(kSpi, {}));
        Endpoint rx;
        rx.add_vc(kVc);
        rx.add_sa(sa);
        rx.enable_sdls(kVc, vc_config(0, {kSpi}));

        for (const size_t len : {size_t{1140}, size_t{4096}}) {
            std::vector<uint8_t> sdu(len);
            for (size_t i = 0; i < len; ++i) sdu[i] = static_cast<uint8_t>(i * 7);
            REQUIRE(rx.accept(tx.build_ok(kVc, 1, sdu)) == UNI_USLP_SUCCESS);
            CHECK(rx.received.back().sdu == sdu);
        }
    }
}

TEST_CASE("SDLS on fixed-length frames pads the TFDZ before protection", "[sdls][fixed-length]")
{
    auto p = varlen_params();
    p.max_frame_length = 128;
    p.min_frame_length = 128;
    auto sa = gcm_sa(kSpi);

    Endpoint tx(p);
    tx.add_vc(kVc, p);
    tx.add_sa(sa);
    tx.enable_sdls(kVc, vc_config(kSpi, {}));
    Endpoint rx(p);
    rx.add_vc(kVc, p);
    rx.add_sa(sa);
    rx.enable_sdls(kVc, vc_config(0, {kSpi}));

    const std::vector<uint8_t> sdu = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto frame = tx.build_ok(kVc, 1, sdu);
    REQUIRE(frame.size() == 128);
    REQUIRE(rx.accept(frame) == UNI_USLP_SUCCESS);
    REQUIRE(rx.received.size() == 1);
    REQUIRE(rx.received[0].sdu.size() >= sdu.size());
    CHECK(std::vector<uint8_t>(rx.received[0].sdu.begin(), rx.received[0].sdu.begin() + 4) == sdu);
}

TEST_CASE("CCSDS-9: invalid SDLS configurations are rejected when configured", "[sdls][config]")
{
    Endpoint ep;
    ep.add_vc(kVc);
    const auto add = [&](const uni_uslp_sdls_sa_config_t& sa, size_t key_len = 32) {
        return uni_ccsds_uslp_sdls_add_sa(&ep.ctx, &sa, kKey256, key_len);
    };

    auto sa = gcm_sa(0);
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM); // reserved SPI 0
    sa.spi = 0xFFFF;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM); // reserved SPI 65535
    sa = gcm_sa(1);
    sa.mac_length = 12;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM); // GCM tags are 16 octets
    sa = gcm_sa(1);
    CHECK(add(sa, 20) == UNI_USLP_ERROR_INVALID_PARAM); // AES key length
    sa.iv_length = 8;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM);
    sa = gcm_sa(1);
    sa.iv_length = 0;
    sa.sn_length = 0;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM); // no IV source
    sa = gcm_sa(1);
    sa.sn_length = 9;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM);
    sa = gcm_sa(1);
    sa.anti_replay_window = UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW + 1;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM);
    sa = gcm_sa(1);
    uni_ccsds_uslp_sdls_default_auth_mask(sa.auth_mask);
    sa.auth_mask[3] &= static_cast<uint8_t>(~0x02u); // MAP ID bit missing (§4.2.2.6.2 c)
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM);
    sa = hmac_sa(1);
    sa.sn_length = 0;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM); // authentication needs an SN
    sa = hmac_sa(1);
    CHECK(add(sa, 8) == UNI_USLP_ERROR_INVALID_PARAM); // short HMAC key
    sa = gcm_sa(1);
    sa.suite = UNI_USLP_SDLS_SUITE_NULL;
    CHECK(add(sa) == UNI_USLP_ERROR_INVALID_PARAM); // clear mode cannot do anti-replay

    REQUIRE(add(gcm_sa(1)) == UNI_USLP_SUCCESS);
    CHECK(add(gcm_sa(1)) == UNI_USLP_ERROR_INVALID_PARAM); // duplicate SPI

    auto vc = vc_config(2, {1});
    CHECK(uni_ccsds_uslp_configure_sdls(&ep.ctx, kVc, &vc) == UNI_USLP_ERROR_SDLS_SA_NOT_FOUND);
    vc = vc_config(1, {1, 7});
    CHECK(uni_ccsds_uslp_configure_sdls(&ep.ctx, kVc, &vc) == UNI_USLP_ERROR_SDLS_SA_NOT_FOUND);
    vc = vc_config(1, {1});
    vc.rx_spi_count = UNI_USLP_SDLS_MAX_SPI_PER_VC + 1;
    CHECK(uni_ccsds_uslp_configure_sdls(&ep.ctx, kVc, &vc) == UNI_USLP_ERROR_INVALID_PARAM);
    vc = vc_config(1, {1});
    CHECK(uni_ccsds_uslp_configure_sdls(&ep.ctx, kVc, &vc) == UNI_USLP_SUCCESS);

    for (uint16_t spi = 2; spi <= UNI_USLP_SDLS_MAX_SA; ++spi) REQUIRE(add(gcm_sa(spi)) == UNI_USLP_SUCCESS);
    CHECK(add(gcm_sa(100)) == UNI_USLP_ERROR_CONTEXT_FULL);
    REQUIRE(uni_ccsds_uslp_sdls_remove_sa(&ep.ctx, 5) == UNI_USLP_SUCCESS);
    CHECK(add(gcm_sa(100)) == UNI_USLP_SUCCESS);
}

TEST_CASE("SDLS Annex E baseline profile round trip and anti-replay from the IV", "[sdls][aead][baseline]")
{
    Link link(gcm_baseline_sa(kSpi));
    std::vector<std::vector<uint8_t>> f;
    for (uint32_t i = 0; i < 4; ++i) f.push_back(link.tx.build_ok(kVc, 1, sdu_of(i)));
    REQUIRE(f[0].size() == kSecOffset + 14 + 1 + 4 + 16);
    CHECK(link.rx.accept(f[0]) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(f[2]) == UNI_USLP_SUCCESS);
    CHECK(link.rx.accept(f[1]) == UNI_USLP_ERROR_SDLS_REPLAY);
    CHECK(link.rx.accept(f[3]) == UNI_USLP_SUCCESS);
}

TEST_CASE("SDLS: mutated secured frames never crash and are never delivered", "[sdls][fuzz]")
{
    Link link(gcm_sa(kSpi));
    std::mt19937 rng(20261028u);
    for (int i = 0; i < 2000; ++i) {
        auto frame = link.tx.build_ok(kVc, 1, sdu_of(static_cast<uint32_t>(i)));
        const size_t flips = 1 + rng() % 4;
        for (size_t k = 0; k < flips; ++k) {
            const size_t pos = kSecOffset + rng() % (frame.size() - kSecOffset);
            frame[pos] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        const auto st = link.rx.accept(frame);
        CHECK(st != UNI_USLP_SUCCESS);
    }
    CHECK(link.rx.received.empty());
}
