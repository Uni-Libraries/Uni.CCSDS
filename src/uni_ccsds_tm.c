// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <math.h>

// uni.ccsds
#include "uni_ccsds_tm.h"



//
// Consts
//

/** CCSDS 131.0-B-5 10.4: s[n + 8] = s[n + 7] ^ s[n + 5] ^ s[n + 3] ^ s[n], s[0..7] = 1, MSB first. */
static const uint8_t uni_ccsds_tm_randomizer[UNI_CCSDS_TM_RANDOMIZER_PERIOD] = {
    0xFF, 0x48, 0x0E, 0xC0, 0x9A, 0x0D, 0x70, 0xBC, 0x8E, 0x2C, 0x93, 0xAD,
    0xA7, 0xB7, 0x46, 0xCE, 0x5A, 0x97, 0x7D, 0xCC, 0x32, 0xA2, 0xBF, 0x3E,
    0x0A, 0x10, 0xF1, 0x88, 0x94, 0xCD, 0xEA, 0xB1, 0xFE, 0x90, 0x1D, 0x81,
    0x34, 0x1A, 0xE1, 0x79, 0x1C, 0x59, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C,
    0xB5, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E, 0x7C, 0x14, 0x21, 0xE3, 0x11,
    0x29, 0x9B, 0xD5, 0x63, 0xFD, 0x20, 0x3B, 0x02, 0x68, 0x35, 0xC2, 0xF2,
    0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xDD, 0x1B, 0x39, 0x6A, 0x5D, 0xF7, 0x30,
    0xCA, 0x8A, 0xFC, 0xF8, 0x28, 0x43, 0xC6, 0x22, 0x53, 0x37, 0xAA, 0xC7,
    0xFA, 0x40, 0x76, 0x04, 0xD0, 0x6B, 0x85, 0xE4, 0x71, 0x64, 0x9D, 0x6D,
    0x3D, 0xBA, 0x36, 0x72, 0xD4, 0xBB, 0xEE, 0x61, 0x95, 0x15, 0xF9, 0xF0,
    0x50, 0x87, 0x8C, 0x44, 0xA6, 0x6F, 0x55, 0x8F, 0xF4, 0x80, 0xEC, 0x09,
    0xA0, 0xD7, 0x0B, 0xC8, 0xE2, 0xC9, 0x3A, 0xDA, 0x7B, 0x74, 0x6C, 0xE5,
    0xA9, 0x77, 0xDC, 0xC3, 0x2A, 0x2B, 0xF3, 0xE0, 0xA1, 0x0F, 0x18, 0x89,
    0x4C, 0xDE, 0xAB, 0x1F, 0xE9, 0x01, 0xD8, 0x13, 0x41, 0xAE, 0x17, 0x91,
    0xC5, 0x92, 0x75, 0xB4, 0xF6, 0xE8, 0xD9, 0xCB, 0x52, 0xEF, 0xB9, 0x86,
    0x54, 0x57, 0xE7, 0xC1, 0x42, 0x1E, 0x31, 0x12, 0x99, 0xBD, 0x56, 0x3F,
    0xD2, 0x03, 0xB0, 0x26, 0x83, 0x5C, 0x2F, 0x23, 0x8B, 0x24, 0xEB, 0x69,
    0xED, 0xD1, 0xB3, 0x96, 0xA5, 0xDF, 0x73, 0x0C, 0xA8, 0xAF, 0xCF, 0x82,
    0x84, 0x3C, 0x62, 0x25, 0x33, 0x7A, 0xAC, 0x7F, 0xA4, 0x07, 0x60, 0x4D,
    0x06, 0xB8, 0x5E, 0x47, 0x16, 0x49, 0xD6, 0xD3, 0xDB, 0xA3, 0x67, 0x2D,
    0x4B, 0xBE, 0xE6, 0x19, 0x51, 0x5F, 0x9F, 0x05, 0x08, 0x78, 0xC4, 0x4A,
    0x66, 0xF5, 0x58,
};



//
// Private
//

static uint8_t uni_ccsds_tm_parity(uint32_t value) {
    value ^= value >> 4U;
    value ^= value >> 2U;
    value ^= value >> 1U;
    return (uint8_t)(value & 1U);
}



//
// Functions
//

const uint8_t* uni_ccsds_tm_randomizer_sequence(void) {
    return uni_ccsds_tm_randomizer;
}


void uni_ccsds_tm_randomize(uint8_t* frame, size_t frame_len) {
    for (size_t offset = 0U; offset < frame_len; offset += UNI_CCSDS_TM_RANDOMIZER_PERIOD) {
        const size_t remaining = frame_len - offset;
        const size_t chunk = remaining < UNI_CCSDS_TM_RANDOMIZER_PERIOD ? remaining : UNI_CCSDS_TM_RANDOMIZER_PERIOD;
        for (size_t index = 0U; index < chunk; ++index) {
            frame[offset + index] ^= uni_ccsds_tm_randomizer[index];
        }
    }
}


void uni_ccsds_tm_conv_encoder_init(uni_ccsds_tm_conv_encoder_t* encoder, bool invert_g2) {
    encoder->state = 0U;
    encoder->invert_g2 = invert_g2;
}


uint8_t uni_ccsds_tm_conv_encoder_encode(uni_ccsds_tm_conv_encoder_t* encoder, uint8_t bit) {
    // The newest bit enters bit 6 of a 7-bit window whose older six bits are the register state.
    const uint32_t window = ((uint32_t)(bit & 1U) << 6U) | encoder->state;
    const uint8_t c0 = uni_ccsds_tm_parity(window & UNI_CCSDS_TM_CONV_POLYNOMIAL_G1);
    const uint8_t c1 = (uint8_t)(uni_ccsds_tm_parity(window & UNI_CCSDS_TM_CONV_POLYNOMIAL_G2) ^ (encoder->invert_g2 ? 1U : 0U));
    encoder->state = (uint8_t)((window >> 1U) & 0x3FU);
    return (uint8_t)((c0 << 1U) | c1);
}


double uni_ccsds_tm_inverse_q(double p) {
    if (!(p > 0.0) || !(p < 1.0)) {
        return NAN;
    }
    // Lower-tail quantile x of the standard normal at probability q = 1 - p; Q^-1(p) = x.
    static const double a[] = {-3.969683028665376e+01, 2.209460984245205e+02,  -2.759285104469687e+02,
                               1.383577518672690e+02,  -3.066479806614716e+01, 2.506628277459239e+00};
    static const double b[] = {-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01};
    static const double c[] = {-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
                               -2.549732539343734e+00, 4.374664141464968e+00,  2.938163982698783e+00};
    static const double d[] = {7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00, 3.754408661907416e+00};
    const double low = 0.02425;
    const double sqrt2 = 1.41421356237309504880;
    const double two_pi = 6.28318530717958647693;

    // Evaluate on the smaller tail for accuracy: x(1 - p) = -x(p).
    const double tail = p < 1.0 - p ? p : 1.0 - p;
    double x = 0.0;
    if (tail < low) {
        const double r = sqrt(-2.0 * log(tail));
        x = (((((c[0] * r + c[1]) * r + c[2]) * r + c[3]) * r + c[4]) * r + c[5]) / ((((d[0] * r + d[1]) * r + d[2]) * r + d[3]) * r + 1.0);
    } else {
        const double q = tail - 0.5;
        const double r = q * q;
        x = (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0);
    }
    // x is the normal quantile of `tail` (negative); Q^-1(tail) = -x.
    double y = -x;
    // Halley refinement of Q(y) = tail.
    const double error = 0.5 * erfc(y / sqrt2) - tail;
    const double density = exp(-0.5 * y * y) / sqrt(two_pi);
    const double u = -error / density;
    y = y - u / (1.0 + 0.5 * y * u);
    return p <= 0.5 ? y : -y;
}


double uni_ccsds_tm_ebn0_db_from_symbol_error_rate(double symbol_error_rate, double symbols, double code_rate) {
    if (!isfinite(symbol_error_rate) || symbol_error_rate < 0.0 || !(symbols >= 1.0) || !(code_rate > 0.0)) {
        return NAN;
    }
    const double floor_rate = 0.5 / symbols;
    const double ps = symbol_error_rate > floor_rate ? symbol_error_rate : floor_rate;
    if (!(ps < 0.5)) {
        return NAN;
    }
    const double q = uni_ccsds_tm_inverse_q(ps);
    const double es_n0 = 0.5 * q * q;
    return 10.0 * log10(es_n0 / code_rate);
}
