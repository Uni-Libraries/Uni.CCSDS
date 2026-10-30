// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// Includes
//

// stdlib
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// uni.ccsds
#include "uni_ccsds_export.h"



//
// Defines
//

/** Attached Sync Marker for convolutionally coded and uncoded TM (CCSDS 131.0-B-5 9.3.3). */
#define UNI_CCSDS_TM_ASM                 (0x1ACFFC1DU)

/** Bits in the Attached Sync Marker. */
#define UNI_CCSDS_TM_ASM_BITS            (32U)

/** Period of the pseudo-randomizer sequence in octets. */
#define UNI_CCSDS_TM_RANDOMIZER_PERIOD   (255U)

/** Rate 1/2, K = 7 convolutional code generator G1 = 171 (octal), CCSDS 131.0-B-5 3.3. */
#define UNI_CCSDS_TM_CONV_POLYNOMIAL_G1  (0x79U)

/** Rate 1/2, K = 7 convolutional code generator G2 = 133 (octal), CCSDS 131.0-B-5 3.3. */
#define UNI_CCSDS_TM_CONV_POLYNOMIAL_G2  (0x5BU)



//
// Typedefs
//

/**
 * Rate 1/2, constraint length 7 convolutional encoder (CCSDS 131.0-B-5 3.3).
 * Initialize with uni_ccsds_tm_conv_encoder_init().
 */
typedef struct {
    /** Previous six input bits, newest in bit 5. */
    uint8_t state;

    /** Apply the inverter CCSDS specifies on the G2 output. */
    bool invert_g2;
} uni_ccsds_tm_conv_encoder_t;



//
// Functions
//

/**
 * The CCSDS TM pseudo-randomizer sequence (CCSDS 131.0-B-5 10.4), UNI_CCSDS_TM_RANDOMIZER_PERIOD
 * octets.
 *
 * Generator polynomial h(x) = x^8 + x^7 + x^5 + x^3 + 1, register set to all ones at the start of
 * every transfer frame, bits packed MSB first: the sequence starts 0xFF 0x48 0x0E 0xC0.
 *
 * @return a pointer to static storage
 */
UNI_CCSDS_EXPORT const uint8_t* uni_ccsds_tm_randomizer_sequence(void);

/**
 * XOR a frame with the pseudo-randomizer sequence, starting at the first octet of the frame. The
 * sequence repeats for frames longer than its period. Applying it twice restores the frame.
 */
UNI_CCSDS_EXPORT void uni_ccsds_tm_randomize(uint8_t* frame, size_t frame_len);

/** Start an encoder from the all-zero register state. */
UNI_CCSDS_EXPORT void uni_ccsds_tm_conv_encoder_init(uni_ccsds_tm_conv_encoder_t* encoder, bool invert_g2);

/**
 * Encode one information bit (only bit 0 of @p bit is used).
 *
 * @return the two channel symbols packed as `(c0 << 1) | c1`; c0 is transmitted first
 */
UNI_CCSDS_EXPORT uint8_t uni_ccsds_tm_conv_encoder_encode(uni_ccsds_tm_conv_encoder_t* encoder, uint8_t bit);

/**
 * Inverse of the Gaussian tail function Q(x) = 0.5 erfc(x / sqrt(2)).
 *
 * Acklam's rational approximation of the normal quantile (relative error below 1.2e-9), refined
 * by one Halley step on erfc.
 *
 * @return x, or NaN when @p p is outside (0, 1)
 */
UNI_CCSDS_EXPORT double uni_ccsds_tm_inverse_q(double p);

/**
 * Eb/N0 in dB estimated from the channel (coded) symbol error rate of a binary antipodal channel.
 *
 * Each coded bit is one BPSK symbol, or one quadrature of a Gray-mapped QPSK symbol, so its hard
 * decision errs with Ps = Q(sqrt(2 Es/N0)), Es being the energy per coded bit. Hence
 *   Es/N0 = (Q^-1(Ps))^2 / 2,   Eb/N0 = Es/N0 / R,
 * which for the K = 7, R = 1/2 code is Eb/N0 = (Q^-1(Ps))^2.
 *
 * Validity: Ps comes from re-encoding the decoder's output, so it is accurate only while the
 * decoder output is mostly right, about Eb/N0 > 2 dB (Ps < 0.1); below that decoder errors fit the
 * noise and Ps is underestimated (Eb/N0 overestimated). The upper end is set by the number of
 * symbols compared: a run without errors is reported as Ps = 0.5 / symbols (half an error), about
 * 12 dB for a 1.4 kB frame (2 x 11488 coded bits), so values near that limit are lower bounds.
 *
 * @param symbol_error_rate observed Ps, 0..1
 * @param symbols number of coded bits Ps was measured on
 * @param code_rate R of the code
 * @return Eb/N0 in dB, NaN when unknown (no symbols, Ps not finite, or Ps >= 0.5)
 */
UNI_CCSDS_EXPORT double uni_ccsds_tm_ebn0_db_from_symbol_error_rate(double symbol_error_rate, double symbols, double code_rate);

#ifdef __cplusplus
}
#endif
