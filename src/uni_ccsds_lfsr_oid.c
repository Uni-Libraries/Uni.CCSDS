// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

/**
 * @file lfsr_oid.c
 * @brief OID Transfer Frame LFSR Implementation
 * 
 * Implementation of 32-bit LFSR for OID Transfer Frame TFDF randomization
 * per CCSDS 732.1-B-3 Annex H.
 * 
 * The LFSR generates a pseudo-random sequence to fill the TFDF of OID Transfer
 * Frames. The LFSR is seeded at device startup and never restarted during
 * operation to ensure uniqueness of the generated sequence.
 * 
 * @author Uni-Libraries contributors
 * @date 2025
 * @copyright MIT License
 */

#include "uni_ccsds_uslp_internal.h"

/* ========================================================================== */
/* OID LFSR IMPLEMENTATION                                                    */
/* ========================================================================== */

/**
 * @brief Initialize OID LFSR
 * 
 * Initializes the OID LFSR with a non-zero seed value.
 * Per CCSDS 732.1-B-3 Annex H, the LFSR is seeded at device startup
 * and never restarted during operation.
 * 
 * @param lfsr_state Pointer to LFSR state variable
 * @param seed Initial seed value (must be non-zero)
 * @return Status code
 */
uni_uslp_status_t uni_ccsds_uslp_oid_lfsr_init(uint32_t *lfsr_state, uint32_t seed)
{
    UNI_USLP_CHECK_NULL(lfsr_state);
    
    /* Ensure seed is non-zero (LFSR requirement) */
    if (UNI_USLP_UNLIKELY(seed == 0)) {
        seed = UNI_USLP_OID_LFSR_INITIAL_SEED;
    }
    
    *lfsr_state = seed;
    return UNI_USLP_SUCCESS;
}

/**
 * @brief Generate next OID LFSR value
 * 
 * Generates the next 32-bit value from the OID LFSR using a primitive
 * polynomial for maximum period sequence generation.
 * 
 * Implementation uses Fibonacci LFSR configuration:
 * - Polynomial: x^32 + x^22 + x^2 + x^1 + 1 (0x80200003)
 * - Taps at positions 32, 22, 2, 1
 * - Maximum period: 2^32 - 1
 * 
 * Reference: CCSDS 732.1-B-3 Annex H
 * 
 * @param lfsr_state Pointer to LFSR state (updated)
 * @return Next 32-bit LFSR value
 */
uint32_t uni_ccsds_uslp_oid_lfsr_next(uint32_t *lfsr_state)
{
    if (UNI_USLP_UNLIKELY(lfsr_state == NULL)) {
        return 0;
    }
    
    uint32_t lfsr = *lfsr_state;
    
    /* Ensure LFSR state is never zero */
    if (UNI_USLP_UNLIKELY(lfsr == 0)) {
        lfsr = UNI_USLP_OID_LFSR_INITIAL_SEED;
    }
    
    /* Fibonacci LFSR implementation */
    /* Polynomial: x^32 + x^22 + x^2 + x^1 + 1 */
    /* Taps: bit 31 (MSB), bit 21, bit 1, bit 0 */
    uint32_t feedback = ((lfsr >> 31) ^ (lfsr >> 21) ^ (lfsr >> 1) ^ lfsr) & 1;
    
    /* Shift left and insert feedback bit */
    lfsr = (lfsr << 1) | feedback;
    
    /* Update state */
    *lfsr_state = lfsr;
    
    return lfsr;
}

/**
 * @brief Generate next OID LFSR byte
 * 
 * Generates the next byte from the OID LFSR. This function manages
 * the internal 32-bit LFSR state and extracts bytes sequentially.
 * 
 * @param lfsr_state Pointer to LFSR state
 * @param byte_position Byte position within 32-bit word (0-3)
 * @return Next LFSR byte value
 */
static uint8_t uni_ccsds_uslp_oid_lfsr_next_byte(uint32_t *lfsr_state, uint8_t *byte_position)
{
    static uint32_t current_word = 0;
    static uint8_t current_pos = 4;  /* Force new word generation */
    
    if (UNI_USLP_UNLIKELY(lfsr_state == NULL)) {
        return 0;
    }
    
    /* Generate new 32-bit word if needed */
    if (current_pos >= 4) {
        current_word = uni_ccsds_uslp_oid_lfsr_next(lfsr_state);
        current_pos = 0;
    }
    
    /* Extract byte (MSB first) */
    uint8_t byte_value = (uint8_t)((current_word >> (24 - (current_pos * 8))) & 0xFF);
    
    /* Update position */
    current_pos++;
    if (byte_position != NULL) {
        *byte_position = current_pos;
    }
    
    return byte_value;
}

/**
 * @brief Fill buffer with OID LFSR data
 * 
 * Fills a buffer with pseudo-random data from the OID LFSR.
 * Used to fill the TFDF of OID Transfer Frames.
 * 
 * @param lfsr_state Pointer to LFSR state
 * @param buffer Buffer to fill
 * @param length Number of bytes to fill
 * @return Status code
 */
uni_uslp_status_t uni_ccsds_uslp_oid_lfsr_fill(
    uint32_t *lfsr_state,
    uint8_t *buffer,
    size_t length
)
{
    UNI_USLP_CHECK_NULL(lfsr_state);
    UNI_USLP_CHECK_NULL(buffer);
    
    /* Fill buffer with LFSR bytes */
    for (size_t i = 0; i < length; i++) {
        buffer[i] = uni_ccsds_uslp_oid_lfsr_next_byte(lfsr_state, NULL);
    }
    
    return UNI_USLP_SUCCESS;
}

/**
 * @brief Alternative Galois LFSR implementation
 * 
 * Alternative implementation using Galois LFSR configuration.
 * This implementation may be more efficient on some architectures.
 * 
 * @param lfsr_state Pointer to LFSR state (updated)
 * @return Next 32-bit LFSR value
 */
static uint32_t uni_ccsds_uslp_oid_lfsr_next_galois(uint32_t *lfsr_state)
{
    if (UNI_USLP_UNLIKELY(lfsr_state == NULL)) {
        return 0;
    }
    
    uint32_t lfsr = *lfsr_state;
    
    /* Ensure LFSR state is never zero */
    if (UNI_USLP_UNLIKELY(lfsr == 0)) {
        lfsr = UNI_USLP_OID_LFSR_INITIAL_SEED;
    }
    
    /* Galois LFSR implementation */
    /* Extract LSB for feedback */
    uint32_t feedback = lfsr & 1;
    
    /* Shift right */
    lfsr >>= 1;
    
    /* Apply polynomial if feedback bit is set */
    if (feedback) {
        lfsr ^= UNI_USLP_OID_LFSR_POLYNOMIAL;
    }
    
    /* Update state */
    *lfsr_state = lfsr;
    
    return lfsr;
}

/**
 * @brief Get LFSR period information
 * 
 * Returns information about the LFSR period and current position.
 * Useful for testing and validation.
 * 
 * @param lfsr_state Current LFSR state
 * @param max_period Maximum theoretical period (out)
 * @param current_position Estimated current position (out)
 * @return Status code
 */
static uni_uslp_status_t uni_ccsds_uslp_oid_lfsr_get_period_info(
    uint32_t lfsr_state,
    uint64_t *max_period,
    uint64_t *current_position
)
{
    UNI_USLP_CHECK_NULL(max_period);
    
    /* Maximum period for 32-bit LFSR is 2^32 - 1 */
    *max_period = 0xFFFFFFFFULL;
    
    /* Current position is difficult to determine without tracking,
     * but we can provide the current state as an approximation */
    if (current_position != NULL) {
        *current_position = (uint64_t)lfsr_state;
    }
    
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* OID LFSR SELF-TEST                                                         */
/* ========================================================================== */

/**
 * @brief OID LFSR self-test
 * 
 * Performs self-test of OID LFSR implementation to verify:
 * - Non-zero output for non-zero input
 * - Sequence does not repeat immediately
 * - Both Fibonacci and Galois implementations work
 * 
 * @return true if self-test passes, false otherwise
 */
bool uni_ccsds_uslp_oid_lfsr_self_test(void)
{
    uint32_t lfsr_state1 = UNI_USLP_OID_LFSR_INITIAL_SEED;
    uint32_t lfsr_state2 = UNI_USLP_OID_LFSR_INITIAL_SEED;
    
    /* Test 1: Basic functionality */
    uint32_t value1 = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state1);
    if (value1 == 0 || value1 == UNI_USLP_OID_LFSR_INITIAL_SEED) {
        return false;
    }
    
    /* Test 2: State advancement */
    uint32_t value2 = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state1);
    if (value2 == value1 || value2 == 0) {
        return false;
    }
    
    /* Test 3: Galois implementation */
    uint32_t galois_value1 = uni_ccsds_uslp_oid_lfsr_next_galois(&lfsr_state2);
    if (galois_value1 == 0) {
        return false;
    }
    
    /* Test 4: Buffer fill */
    uint8_t buffer[16];
    uint32_t lfsr_state3 = UNI_USLP_OID_LFSR_INITIAL_SEED;
    uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state3, buffer, sizeof(buffer));
    if (status != UNI_USLP_SUCCESS) {
        return false;
    }
    
    /* Verify buffer is not all zeros */
    bool all_zeros = true;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    if (all_zeros) {
        return false;
    }
    
    /* Test 5: Period information */
    uint64_t max_period, current_position;
    status = uni_ccsds_uslp_oid_lfsr_get_period_info(lfsr_state1, &max_period, &current_position);
    if (status != UNI_USLP_SUCCESS || max_period != 0xFFFFFFFFULL) {
        return false;
    }
    
    /* Test 6: Zero state handling */
    uint32_t zero_state = 0;
    uint32_t zero_result = uni_ccsds_uslp_oid_lfsr_next(&zero_state);
    if (zero_result == 0 || zero_state == 0) {
        return false;
    }
    
    return true;
}
