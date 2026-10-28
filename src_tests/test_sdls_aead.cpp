// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025-2026 Uni-Libraries contributors

/*
 * SDLS AES-GCM / AES-CCM (authenticated encryption) tests for USLP
 *
 * References:
 * - CCSDS 732.1-B-3 §6 (SDLS integration with USLP)
 * - CCSDS 355.0-B-2 §4.2.3.2.2.3, §4.2.4.2.3.2 (AEAD: plaintext = Frame Data Field, AAD = preceding octets)
 *
 * Coverage:
 * - ApplySecurity encrypts the TFDF; ProcessSecurity decrypts and verifies the tag
 * - Anti-replay rejects duplicates; tampered ciphertext/tag fails MAC verification
 * - Separate TX/RX contexts sharing only the key
 * - SLIDING anti-replay window for diversity reception
 * - Known-answer check of the AAD composition against uni.crypto directly
 */

#include "sdls_test_support.h"

#include "uni_crypto.h"

using namespace sdls_test;

TEST_CASE("SDLS AES-GCM: encrypt/decrypt MAPA round-trip; tamper and replay detection", "[sdls][aead][aes-gcm]")
{
    for (const auto suite : {UNI_USLP_SDLS_SUITE_AES_GCM, UNI_USLP_SDLS_SUITE_AES_CCM}) {
        Endpoint ep;
        const uint8_t VC = 4, MAP = 2;
        ep.add_vc(VC);
        auto sa = gcm_sa(3);
        sa.suite = suite;
        ep.add_sa(sa);
        ep.enable_sdls(VC, vc_config(3, {3}));

        const std::vector<uint8_t> sdu = {0xBA, 0xAD, 0xF0, 0x0D, 0x12, 0x34, 0x56, 0x78};
        const auto frame = ep.build_ok(VC, MAP, sdu);

        // Header SPI(2) + SN(8), trailer 16; the TFDF is encrypted.
        REQUIRE(frame.size() == kSecOffset + 10 + 1 + sdu.size() + 16);
        CHECK(std::vector<uint8_t>(frame.begin() + kSecOffset + 11, frame.begin() + kSecOffset + 11 + sdu.size()) != sdu);

        REQUIRE(ep.accept(frame) == UNI_USLP_SUCCESS);
        REQUIRE(ep.received.size() == 1);
        CHECK(ep.received[0].sdu == sdu);
        CHECK(ep.received[0].ver == UNI_USLP_VERIF_SUCCESS);

        CHECK(ep.accept(frame) == UNI_USLP_ERROR_SDLS_REPLAY);

        auto tampered = ep.build_ok(VC, MAP, sdu);
        tampered.back() ^= 0x01; // tag
        CHECK(ep.accept(tampered) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);
        tampered.back() ^= 0x01;
        tampered[kSecOffset + 12] ^= 0x80; // ciphertext
        CHECK(ep.accept(tampered) == UNI_USLP_ERROR_SDLS_MAC_FAILURE);
        CHECK(ep.received.size() == 1);
    }
}

TEST_CASE("SDLS AES-GCM: MAPA secured frame round-trip using separate TX/RX contexts (key only shared)", "[sdls][aead][aes-gcm][no-reuse]")
{
    const uint8_t VC = 7, MAP = 3;
    Endpoint tx(varlen_params(), 0x6161, /*with_work_buffer=*/false);
    tx.add_vc(VC);
    tx.add_sa(gcm_sa(3));
    tx.enable_sdls(VC, vc_config(3, {}));

    Endpoint rx;
    rx.add_vc(VC);
    rx.add_sa(gcm_sa(3));
    rx.enable_sdls(VC, vc_config(0, {3}));

    const std::vector<uint8_t> sdu = {0xFE, 0xED, 0xFA, 0xCE, 0x12, 0x34, 0x56, 0x78, 0x9A};
    REQUIRE(rx.accept(tx.build_ok(VC, MAP, sdu)) == UNI_USLP_SUCCESS);
    REQUIRE(rx.received.size() == 1);
    CHECK(rx.received[0].sdu == sdu);
    CHECK(rx.received[0].ver == UNI_USLP_VERIF_SUCCESS);
}

TEST_CASE("SDLS sliding anti-replay window accepts late frames of a lagging diversity carrier once", "[sdls][aead][anti-replay]")
{
    // Several carriers of a diversity link deliver copies of the same secured frames; merged into one receiver, a
    // carrier that lags far behind still contributes frames the leading carrier lost, as long as the window covers
    // the lag. Duplicates are rejected either way. This is the SLIDING deviation from 355.0-B-2 §4.2.4.4 h.
    const uint8_t VC = 3, MAP = 1;
    Endpoint tx;
    tx.add_vc(VC);
    tx.add_sa(gcm_sa(3));
    tx.enable_sdls(VC, vc_config(3, {}));
    std::vector<std::vector<uint8_t>> frames;
    for (uint32_t index = 0; index < 1500; ++index) {
        frames.push_back(tx.build_ok(VC, MAP, {static_cast<uint8_t>(index), static_cast<uint8_t>(index >> 8), 0x5A}));
    }

    for (const uint16_t window : {uint16_t{64}, uint16_t{1024}}) {
        Endpoint rx;
        rx.add_vc(VC);
        auto sa = gcm_sa(3);
        sa.replay_mode = UNI_USLP_SDLS_REPLAY_SLIDING;
        sa.anti_replay_window = window;
        rx.add_sa(sa);
        rx.enable_sdls(VC, vc_config(0, {3}));

        const auto accept = [&](const std::size_t index) { return rx.accept(frames[index]); };
        REQUIRE(accept(1499) == UNI_USLP_SUCCESS);
        // 900 frames behind the newest one: inside a 1024 window, too old for 64.
        CHECK(accept(599) == (window > 900 ? UNI_USLP_SUCCESS : UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW));
        CHECK(accept(599) == (window > 900 ? UNI_USLP_ERROR_SDLS_REPLAY : UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW));
        CHECK(accept(1499) == UNI_USLP_ERROR_SDLS_REPLAY);
        // Beyond any window.
        CHECK(accept(99) == UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW);
        // Newer frames keep being accepted; the window slides with them.
        CHECK(accept(1498) == UNI_USLP_SUCCESS);
    }
}

TEST_CASE("SDLS AES-GCM: AAD is the masked Primary Header plus the Security Header with the IV zeroed", "[sdls][aead][kat]")
{
    // Recompute the tag of a built frame with uni.crypto directly, following 355.0-B-2 §4.2.2.6.2 and
    // §4.2.3.2.2.3 a independently of the engine: AAD = (PH & mask) || SPI || IV:=0 || SN.
    const uint8_t VC = 9, MAP = 5;
    Endpoint ep;
    ep.add_vc(VC);
    ep.add_sa(gcm_baseline_sa(0x0102));
    ep.enable_sdls(VC, vc_config(0x0102, {0x0102}));

    const std::vector<uint8_t> sdu = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    const auto frame = ep.build_ok(VC, MAP, sdu);
    const size_t hdr = 2 + 12;
    const size_t tfdf_len = 1 + sdu.size();
    REQUIRE(frame.size() == kSecOffset + hdr + tfdf_len + 16);

    // Security Header: SPI 0x0102, IV = 96-bit counter 1 (first frame of the SA).
    CHECK(frame[kSecOffset] == 0x01);
    CHECK(frame[kSecOffset + 1] == 0x02);
    for (size_t i = 0; i < 11; ++i) CHECK(frame[kSecOffset + 2 + i] == 0x00);
    CHECK(frame[kSecOffset + 13] == 0x01);

    uint8_t mask[UNI_USLP_SDLS_AUTH_MASK_LENGTH];
    uni_ccsds_uslp_sdls_default_auth_mask(mask);
    std::vector<uint8_t> aad;
    for (size_t i = 0; i < kSecOffset; ++i) aad.push_back(frame[i] & mask[i]);
    aad.push_back(0x01);
    aad.push_back(0x02);
    aad.insert(aad.end(), 12, 0x00);

    const uint8_t* iv = &frame[kSecOffset + 2];
    std::vector<uint8_t> plain(tfdf_len);
    REQUIRE(uni_crypto_aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, kKey256, sizeof(kKey256), iv, 12, aad.data(), aad.size(), &frame[kSecOffset + hdr],
                                    tfdf_len, &frame[kSecOffset + hdr + tfdf_len], 16, plain.data()) == UNI_CRYPTO_AEAD_SUCCESS);
    CHECK(std::vector<uint8_t>(plain.begin() + 1, plain.end()) == sdu);

    // The engine accepts it, and the anti-replay SN is the low 64 bits of the IV.
    REQUIRE(ep.accept(frame) == UNI_USLP_SUCCESS);
    CHECK(ep.sa(0x0102)->rx_sn == 1u);
}

TEST_CASE("SDLS Uni.CCSDS 1.x wire format: frames of a legacy transmitter are accepted", "[sdls][aead][legacy]")
{
    // Build a frame exactly as Uni.CCSDS 1.x ApplySecurity did, independently of the engine: Security Header =
    // SPI(1) || SN(8), IV = 0x00000000 || SN, AAD empty, plaintext = TFDF (header 0xE5: rule '111', UPID 5 = MAPA).
    const uint8_t VC = 21, MAP = 2;
    const uint8_t key128[16] = {0xA4, 0xE8, 0x10, 0x72, 0x3A, 0xC5, 0x6A, 0x12, 0x1C, 0x82, 0xF8, 0xFA, 0xE9, 0xA2, 0xC4, 0x3A};
    const std::vector<uint8_t> sdu = {0x10, 0x20, 0x30, 0x40, 0x50};

    const auto legacy_frame = [&](uint64_t sn) {
        std::vector<uint8_t> tfdf = {0xE5};
        tfdf.insert(tfdf.end(), sdu.begin(), sdu.end());
        const size_t total = kSecOffset + 9 + tfdf.size() + 16;
        uni_uslp_primary_header_t ph{};
        ph.tfvn = UNI_USLP_TFVN;
        ph.scid = 0x6161;
        ph.vcid = VC;
        ph.map_id = MAP;
        ph.frame_length = static_cast<uint16_t>(total - 1);
        std::vector<uint8_t> frame(total);
        size_t written = 0;
        REQUIRE(uni_ccsds_uslp_primary_header_pack(&ph, frame.data(), frame.size(), &written) == UNI_USLP_SUCCESS);
        frame[kSecOffset] = 7; // SPI
        uint8_t iv[12] = {};
        for (size_t i = 0; i < 8; ++i) {
            frame[kSecOffset + 1 + i] = static_cast<uint8_t>(sn >> (8 * (7 - i)));
            iv[4 + i] = frame[kSecOffset + 1 + i];
        }
        REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key128, sizeof(key128), iv, sizeof(iv), nullptr, 0, tfdf.data(), tfdf.size(),
                                        &frame[kSecOffset + 9], &frame[kSecOffset + 9 + tfdf.size()], 16) == UNI_CRYPTO_AEAD_SUCCESS);
        return frame;
    };

    Endpoint rx;
    rx.add_vc(VC);
    auto sa = gcm_sa(7);
    sa.format = UNI_USLP_SDLS_FORMAT_UNI_V1;
    sa.replay_mode = UNI_USLP_SDLS_REPLAY_SLIDING;
    rx.add_sa(sa, key128, sizeof(key128));
    rx.enable_sdls(VC, vc_config(0, {7}));

    REQUIRE(rx.accept(legacy_frame(0)) == UNI_USLP_SUCCESS); // 1.x transmitters started at SN 0
    REQUIRE(rx.accept(legacy_frame(1)) == UNI_USLP_SUCCESS);
    CHECK(rx.accept(legacy_frame(1)) == UNI_USLP_ERROR_SDLS_REPLAY);
    REQUIRE(rx.received.size() == 2);
    CHECK(rx.received[1].sdu == sdu);
    CHECK(rx.received[1].map_id == MAP);

    // The documented weakness of the format: the MAP ID is not authenticated.
    auto rewritten = legacy_frame(2);
    rewritten[3] = static_cast<uint8_t>((rewritten[3] & ~0x1Eu) | (1u << 1));
    CHECK(rx.accept(rewritten) == UNI_USLP_SUCCESS);
    CHECK(rx.received.back().map_id == 1);

    // The engine's own transmit side produces the same format.
    Endpoint tx;
    tx.add_vc(VC);
    tx.add_sa(sa, key128, sizeof(key128));
    tx.enable_sdls(VC, vc_config(7, {}));
    REQUIRE(uni_ccsds_uslp_sdls_set_tx_sn(&tx.ctx, 7, 99) == UNI_USLP_SUCCESS);
    const auto built = tx.build_ok(VC, MAP, sdu);
    CHECK(built == legacy_frame(100));

    // Formats cannot be mixed on one VC (the SPI field length must be known before the SA).
    rx.add_sa(gcm_sa(8));
    auto mixed = vc_config(0, {7, 8});
    CHECK(uni_ccsds_uslp_configure_sdls(&rx.ctx, VC, &mixed) == UNI_USLP_ERROR_INVALID_PARAM);
}
