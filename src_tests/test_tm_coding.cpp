// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

// stdlib
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

// catch
#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

// uni.ccsds
#include "uni_ccsds_tm.h"

TEST_CASE("TM randomizer table follows the CCSDS 131.0-B recurrence", "[tm][randomizer]") {
    std::array<std::uint8_t, UNI_CCSDS_TM_RANDOMIZER_PERIOD * 8U> bits{};
    for (std::size_t index = 0U; index < 8U; ++index) {
        bits[index] = 1U;
    }
    for (std::size_t index = 8U; index < bits.size(); ++index) {
        bits[index] = static_cast<std::uint8_t>(bits[index - 1U] ^ bits[index - 3U] ^ bits[index - 5U] ^ bits[index - 8U]);
    }
    const auto* sequence = uni_ccsds_tm_randomizer_sequence();
    for (std::size_t octet = 0U; octet < UNI_CCSDS_TM_RANDOMIZER_PERIOD; ++octet) {
        std::uint8_t expected = 0U;
        for (std::size_t bit = 0U; bit < 8U; ++bit) {
            expected = static_cast<std::uint8_t>((expected << 1U) | bits[octet * 8U + bit]);
        }
        CHECK(sequence[octet] == expected);
    }
    CHECK(sequence[0] == 0xFFU);
    CHECK(sequence[1] == 0x48U);
    CHECK(sequence[2] == 0x0EU);
    CHECK(sequence[3] == 0xC0U);
}

TEST_CASE("TM randomizer is its own inverse and repeats after its period", "[tm][randomizer]") {
    std::vector<std::uint8_t> frame(UNI_CCSDS_TM_RANDOMIZER_PERIOD + 3U, 0U);
    uni_ccsds_tm_randomize(frame.data(), frame.size());
    const auto* sequence = uni_ccsds_tm_randomizer_sequence();
    CHECK(frame[0] == sequence[0]);
    CHECK(frame[UNI_CCSDS_TM_RANDOMIZER_PERIOD] == sequence[0]);
    CHECK(frame[UNI_CCSDS_TM_RANDOMIZER_PERIOD + 2U] == sequence[2]);

    uni_ccsds_tm_randomize(frame.data(), frame.size());
    CHECK(frame == std::vector<std::uint8_t>(UNI_CCSDS_TM_RANDOMIZER_PERIOD + 3U, 0U));
}

TEST_CASE("TM convolutional encoder produces the code's impulse response", "[tm][convolutional]") {
    // Impulse response of G1 = 1111001b (171 octal) and G2 = 1011011b (133 octal), newest bit first.
    constexpr std::array<std::uint8_t, 7U> ExpectedC0{1U, 1U, 1U, 1U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 7U> ExpectedC1{1U, 0U, 1U, 1U, 0U, 1U, 1U};

    uni_ccsds_tm_conv_encoder_t plain{};
    uni_ccsds_tm_conv_encoder_init(&plain, false);
    uni_ccsds_tm_conv_encoder_t inverted{};
    uni_ccsds_tm_conv_encoder_init(&inverted, true);
    for (std::size_t step = 0U; step < ExpectedC0.size(); ++step) {
        const std::uint8_t bit = step == 0U ? 1U : 0U;
        const auto symbols = uni_ccsds_tm_conv_encoder_encode(&plain, bit);
        CHECK(symbols == static_cast<std::uint8_t>((ExpectedC0[step] << 1U) | ExpectedC1[step]));
        CHECK(uni_ccsds_tm_conv_encoder_encode(&inverted, bit) == static_cast<std::uint8_t>(symbols ^ 1U));
    }
    CHECK(plain.state == 0U);
}

TEST_CASE("TM inverse Q function inverts the Gaussian tail", "[tm][link_quality]") {
    for (const double p : {1e-9, 1e-4, 0.02, 0.1, 0.3, 0.5, 0.7, 0.99}) {
        const double x = uni_ccsds_tm_inverse_q(p);
        CHECK(0.5 * std::erfc(x / std::sqrt(2.0)) == Catch::Approx(p).epsilon(1e-9));
    }
    CHECK(std::isnan(uni_ccsds_tm_inverse_q(0.0)));
    CHECK(std::isnan(uni_ccsds_tm_inverse_q(1.0)));
}

TEST_CASE("TM Eb/N0 estimate follows the symbol error rate", "[tm][link_quality]") {
    // Eb/N0 = (Q^-1(Ps))^2 for R = 1/2; Q^-1(0.01) = 2.3263.
    CHECK(uni_ccsds_tm_ebn0_db_from_symbol_error_rate(0.01, 1000.0, 0.5) == Catch::Approx(10.0 * std::log10(2.3263478740 * 2.3263478740)).epsilon(1e-6));
    // A run without errors counts as half an error.
    CHECK(uni_ccsds_tm_ebn0_db_from_symbol_error_rate(0.0, 1000.0, 0.5) == uni_ccsds_tm_ebn0_db_from_symbol_error_rate(0.0005, 1000.0, 0.5));
    CHECK(std::isnan(uni_ccsds_tm_ebn0_db_from_symbol_error_rate(0.5, 1000.0, 0.5)));
    CHECK(std::isnan(uni_ccsds_tm_ebn0_db_from_symbol_error_rate(0.01, 0.0, 0.5)));
    CHECK(std::isnan(uni_ccsds_tm_ebn0_db_from_symbol_error_rate(0.01, 1000.0, 0.0)));
    CHECK(std::isnan(uni_ccsds_tm_ebn0_db_from_symbol_error_rate(std::nan(""), 1000.0, 0.5)));
}
