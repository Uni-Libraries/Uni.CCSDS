// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

/**
 * @file uslp_primary_header.c
 * @brief USLP Primary Header pack/unpack and validation
 *
 * NOTE: This module provides initial scaffolding for USLP Primary Header handling.
 * The exact bit layout and packing order follow CCSDS 732.1-B-3 §4.1.2.
 * Implementation below currently validates parameters and stubs packing/unpacking
 * pending full bit-accurate mapping extracted from the Blue Book.
 *
 * Tracked TODO:
 * - Implement exact bit packing/unpacking per §4.1.2.2.x with MSB-first bit numbering.
 * - Cover VCF Count Length and variable VCF Count field encoding rules.
 * - Add unit tests with reference vectors from docs (once extracted).
 *
 * This file intentionally returns UNI_USLP_ERROR_UNSUPPORTED for pack/unpack
 * to compile and link the library while other core components are implemented.
 * It will be replaced with full implementation in subsequent steps.
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

//
// Includes
//

// stdlib
#include <string.h>

// uni.ccsds
#include "uni_ccsds_uslp_internal.h"

/* ========================================================================== */
/* INTERNAL HELPERS                                                           */
/* ========================================================================== */

static UNI_USLP_INLINE bool in_range_u8(uint8_t v, uint8_t max_inclusive) {
    return v <= max_inclusive;
}

/* Pack bits into a 56-bit field stored in uint64_t (MSB-first bit numbering).
 * start_bit: 0..55 where 0 is MSB of first octet, length: 1..32 (or more if needed)
 * Value is masked to 'length' bits.
 */
static UNI_USLP_INLINE void put_bits56(uint64_t *acc, uint32_t start_bit, uint32_t length, uint64_t value)
{
    /* Position from LSB side within 56-bit window */
    const uint32_t pos = 56u - start_bit - length;
    const uint64_t mask = (length >= 64u) ? UINT64_MAX : (((uint64_t)1u << length) - 1u);
    *acc |= ((value & mask) << pos);
}

/* Extract bits from a 56-bit field stored in uint64_t (MSB-first bit numbering). */
static UNI_USLP_INLINE uint64_t get_bits56(uint64_t acc, uint32_t start_bit, uint32_t length)
{
    const uint32_t pos = 56u - start_bit - length;
    const uint64_t mask = (length >= 64u) ? UINT64_MAX : (((uint64_t)1u << length) - 1u);
    return (acc >> pos) & mask;
}

/* ========================================================================== */
/* VALIDATION                                                                 */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_validate_primary_header(
    const uni_uslp_primary_header_t *header
)
{
    UNI_USLP_CHECK_NULL(header);

    /* TFVN must equal 0x0C (1100) for USLP per §4.1.2.2.1 */
    if (header->tfvn != UNI_USLP_TFVN) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* VCID range: 6 bits => 0..63 */
    if (!in_range_u8(header->vcid, (uint8_t)UNI_USLP_MAX_VCID)) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* MAP ID range: 4 bits => 0..15 */
    if (!in_range_u8(header->map_id, (uint8_t)UNI_USLP_MAX_MAP_ID)) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Frame Length lower bound check (upper bound not needed for uint16_t per §4.1.2.7) */
    if (header->frame_length < UNI_USLP_MIN_FRAME_LENGTH) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* VCF Count length 0..7 octets (Table 4-2) encoded on 3 bits */
    if (header->vcf_count_len > 7) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* If no VCF Count field present, count must be zero; otherwise leave range to packer/unpacker */
    if (header->vcf_count_len == 0 && header->vcf_count != 0u) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* PACK/UNPACK                                                                */
/* ========================================================================== */

/**
 * The exact bit mapping for the 4-octet Primary Header will be implemented
 * once the clause text is extracted verbatim. For now, we provide strict
 * parameter validation and return UNSUPPORTED to avoid silent misuse.
 */

uni_uslp_status_t uni_ccsds_uslp_primary_header_pack(
    const uni_uslp_primary_header_t *header,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *bytes_written
)
{
    UNI_USLP_CHECK_NULL(header);
    UNI_USLP_CHECK_NULL(buffer);
    UNI_USLP_CHECK_NULL(bytes_written);

    /* Validate fields per allowed ranges */
    uni_uslp_status_t st = uni_ccsds_uslp_validate_primary_header(header);
    if (st != UNI_USLP_SUCCESS) {
        return st;
    }

    /* Determine VCF Count octet length from vcf_count_len code (0..7 => 0..7 octets) */
    uint8_t vcf_octets = header->vcf_count_len & 0x7u;

    /* Enforce that vcf_count fits into indicated octet length (test expectation) */
    if (vcf_octets == 0) {
        /* Already validated that vcf_count must be zero when no field present */
    } else {
        unsigned shift_bits = (unsigned)vcf_octets * 8u;
        /* Max value that fits in vcf_octets bytes */
        uint64_t max_val = (shift_bits >= 64u) ? UINT64_MAX : ((1ULL << shift_bits) - 1ULL);
        if (header->vcf_count > max_val) {
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
    }

    /* Base header is 7 octets, plus VCF Count (0..7 octets) */
    size_t needed = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + (size_t)vcf_octets;
    if (buffer_size < needed) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    /* Build 56-bit base header per CCSDS 732.1-B-3 §4.1.2 (Figure 4-2) */
    uint64_t acc = 0;

    /* Bits 0–3: TFVN (4 bits) */
    put_bits56(&acc, 0, 4, header->tfvn & 0xFu);

    /* Bits 4–19: SCID (16 bits) */
    put_bits56(&acc, 4, 16, header->scid);

    /* Bit 20: Source-or-Destination Identifier (1 bit) */
    put_bits56(&acc, 20, 1, header->source_dest ? 1u : 0u);

    /* Bits 21–26: VCID (6 bits) */
    put_bits56(&acc, 21, 6, header->vcid & 0x3Fu);

    /* Bits 27–30: MAP ID (4 bits) */
    put_bits56(&acc, 27, 4, header->map_id & 0x0Fu);

    /* Bit 31: End of Frame Primary Header Flag (1 bit) */
    put_bits56(&acc, 31, 1, header->eof_ph_flag ? 1u : 0u);

    /* Bits 32–47: Frame Length (16 bits), C = total_octets_in_frame - 1 */
    put_bits56(&acc, 32, 16, header->frame_length);

    /* Bit 48: Bypass/Sequence Control Flag (1 bit) */
    put_bits56(&acc, 48, 1, header->bypass_flag ? 1u : 0u);

    /* Bit 49: Protocol Control Command Flag (1 bit) */
    put_bits56(&acc, 49, 1, header->cc_flag ? 1u : 0u);

    /* Bits 50–51: Spare (2 bits) set to '00' */
    put_bits56(&acc, 50, 2, 0u);

    /* Bit 52: OCF Flag (1 bit) */
    put_bits56(&acc, 52, 1, header->ocf_flag ? 1u : 0u);

    /* Bits 53–55: VCF Count Length (3 bits) */
    put_bits56(&acc, 53, 3, (uint64_t)(header->vcf_count_len & 0x7u));

    /* Emit the 7-octet base header (MSB-first) */
    for (size_t i = 0; i < 7; i++) {
        buffer[i] = (uint8_t)((acc >> (8u * (6u - i))) & 0xFFu);
    }

    /* Append VCF Count field (0..7 octets), MSB-first */
    for (uint8_t i = 0; i < vcf_octets; i++) {
        uint8_t shift = (uint8_t)(8u * (vcf_octets - 1u - i));
        buffer[7u + i] = (uint8_t)((header->vcf_count >> shift) & 0xFFu);
    }

    *bytes_written = needed;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_primary_header_unpack(
    const uint8_t *buffer,
    size_t buffer_size,
    uni_uslp_primary_header_t *header,
    size_t *bytes_read
)
{
    UNI_USLP_CHECK_NULL(buffer);
    UNI_USLP_CHECK_NULL(header);
    UNI_USLP_CHECK_NULL(bytes_read);

    if (buffer_size < (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    /* Load 7-octet base header into 56-bit accumulator (MSB-first) */
    uint64_t acc = 0;
    for (size_t i = 0; i < 7; i++) {
        acc = (acc << 8) | (uint64_t)buffer[i];
    }

    memset(header, 0, sizeof(*header));

    /* Extract fields per CCSDS 732.1-B-3 §4.1.2 (Figure 4-2) */
    header->tfvn        = (uint8_t)get_bits56(acc, 0, 4);
    header->scid        = (uint16_t)get_bits56(acc, 4, 16);
    header->source_dest = get_bits56(acc, 20, 1) ? true : false;
    header->vcid        = (uint8_t)get_bits56(acc, 21, 6);
    header->map_id      = (uint8_t)get_bits56(acc, 27, 4);
    header->eof_ph_flag = get_bits56(acc, 31, 1) ? true : false;
    header->frame_length= (uint16_t)get_bits56(acc, 32, 16);
    header->bypass_flag = get_bits56(acc, 48, 1) ? true : false;
    header->cc_flag     = get_bits56(acc, 49, 1) ? true : false;
    /* Bits 50–51 are spare '00' */
    header->ocf_flag    = get_bits56(acc, 52, 1) ? true : false;
    header->vcf_count_len = (uint8_t)get_bits56(acc, 53, 3);

    /* Determine VCF Count octet length */
    uint8_t vcf_octets = header->vcf_count_len & 0x7u;

    /* Ensure buffer has enough bytes for VCF Count */
    size_t need = 7u + (size_t)vcf_octets;
    if (buffer_size < need) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    /* Parse VCF Count (MSB-first) */
    uint64_t vcf = 0;
    for (uint8_t i = 0; i < vcf_octets; i++) {
        vcf = (vcf << 8) | (uint64_t)buffer[7u + i];
    }
    header->vcf_count = vcf;

    /* Validate header fields */
    uni_uslp_status_t st = uni_ccsds_uslp_validate_primary_header(header);
    if (st != UNI_USLP_SUCCESS) {
        return st;
    }

    *bytes_read = need;
    return UNI_USLP_SUCCESS;
}