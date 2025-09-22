/**
 * @file uslp_tfdf_header.c
 * @brief USLP TFDF Header pack/unpack and validation
 *
 * Implements the Transfer Frame Data Field (TFDF) Header handling per
 * CCSDS 732.1-B-3 §4.1.4.2, Figure 4-4 and Table 4-3.
 *
 * Fields:
 * - TFDZ Construction Rules (3 bits)      (§4.1.4.2.2, Table 4-3)
 * - UPID (5 bits)                         (§4.1.4.2.3)
 * - First Header/Last Valid Octet Pointer (16 bits, optional) (§4.1.4.2.4)
 *   Present only for Construction Rules: ‘000’, ‘001’, ‘010’.
 *   ‘000’ uses First Header Pointer (FHP) (§4.1.4.2.4.3, §4.1.4.2.4.4)
 *   ‘001’ and ‘010’ use Last Valid Octet Pointer (LVOP) (§4.1.4.2.4.5, §4.1.4.2.4.6)
 *
 * Encoding (single-octet base header):
 *   octet0 bits[0..2] = TFDZ Construction Rules (bit 0 = MSB)
 *   octet0 bits[3..7] = UPID (5 bits)
 * If pointer present: append two octets, MSB-first (big-endian).
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

#include "uni_ccsds_uslp_internal.h"

#include <string.h>

/* ========================================================================== */
/* VALIDATION                                                                 */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_validate_tfdf_header(
    const uni_uslp_tfdf_header_t *header
)
{
    UNI_USLP_CHECK_NULL(header);

    /* Construction rule range: 0..7 per Table 4-3 */
    if ((unsigned)header->construction_rule > 7u) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* UPID range: 5-bit value (0..31) per §4.1.4.2.3.1 */
    if (header->upid > 31u) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Pointer presence rules per §4.1.4.2.4.1:
       Present only for rules ‘000’, ‘001’, ‘010’. */
    switch (header->construction_rule) {
        case UNI_USLP_TFDZ_RULE_0:
            /* Packets spanning multiple frames: First Header Pointer required.
               Ensure LVOP is zero (ignored) to catch misuse. */
            if (header->last_valid_ptr != 0u) {
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            /* FHP can be 0..65535, no further constraint here. */
            break;

        case UNI_USLP_TFDZ_RULE_1:
        case UNI_USLP_TFDZ_RULE_2:
            /* Start/Continue of MAPA_SDU or VCA_SDU in fixed-length TFDZ:
               LVOP required. Ensure FHP unused is zero to catch misuse. */
            if (header->first_header_ptr != 0u) {
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            /* LVOP can be 0..65535, no further constraint here. */
            break;

        case UNI_USLP_TFDZ_RULE_3:
        case UNI_USLP_TFDZ_RULE_4:
        case UNI_USLP_TFDZ_RULE_5:
        case UNI_USLP_TFDZ_RULE_6:
        case UNI_USLP_TFDZ_RULE_7:
            /* No pointer present; ensure both are zero */
            if (header->first_header_ptr != 0u || header->last_valid_ptr != 0u) {
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            break;

        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }

    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* PACK/UNPACK                                                                */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_tfdf_header_pack(
    const uni_uslp_tfdf_header_t *header,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *bytes_written
)
{
    UNI_USLP_CHECK_NULL(header);
    UNI_USLP_CHECK_NULL(buffer);
    UNI_USLP_CHECK_NULL(bytes_written);

    uni_uslp_status_t st = uni_ccsds_uslp_validate_tfdf_header(header);
    if (st != UNI_USLP_SUCCESS) {
        return st;
    }

    const uint8_t rule = (uint8_t)header->construction_rule & 0x7u;
    const uint8_t upid = header->upid & 0x1Fu;

    /* Determine if the 16-bit pointer field is present (rules 000, 001, 010) */
    const bool pointer_present = (rule <= 2u);

    const size_t need = pointer_present ? 3u : 1u;
    if (buffer_size < need) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    /* First octet: [bits 0..2]=rule (MSBs), [bits 3..7]=UPID */
    buffer[0] = (uint8_t)((rule << 5) | upid);

    if (pointer_present) {
        uint16_t ptr = 0;
        if (rule == UNI_USLP_TFDZ_RULE_0) {
            /* First Header Pointer */
            ptr = header->first_header_ptr;
        } else {
            /* Last Valid Octet Pointer for 001 / 010 */
            ptr = header->last_valid_ptr;
        }
        buffer[1] = (uint8_t)((ptr >> 8) & 0xFFu);
        buffer[2] = (uint8_t)(ptr & 0xFFu);
    }

    *bytes_written = need;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_tfdf_header_unpack(
    const uint8_t *buffer,
    size_t buffer_size,
    uni_uslp_tfdf_header_t *header,
    size_t *bytes_read
)
{
    UNI_USLP_CHECK_NULL(buffer);
    UNI_USLP_CHECK_NULL(header);
    UNI_USLP_CHECK_NULL(bytes_read);

    UNI_USLP_CHECK_BUFFER_SIZE(buffer_size, 1u);

    const uint8_t b0 = buffer[0];
    const uint8_t rule = (uint8_t)((b0 >> 5) & 0x7u);
    const uint8_t upid = (uint8_t)(b0 & 0x1Fu);

    memset(header, 0, sizeof(*header));
    header->construction_rule = (uni_uslp_tfdz_construction_rule_t)rule;
    header->upid = upid;

    const bool pointer_present = (rule <= 2u);
    const size_t need = pointer_present ? 3u : 1u;
    if (buffer_size < need) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    if (pointer_present) {
        uint16_t ptr = (uint16_t)(((uint16_t)buffer[1] << 8) | (uint16_t)buffer[2]);
        if (rule == UNI_USLP_TFDZ_RULE_0) {
            header->first_header_ptr = ptr;
            header->last_valid_ptr = 0;
        } else {
            header->last_valid_ptr = ptr;
            header->first_header_ptr = 0;
        }
    } else {
        header->first_header_ptr = 0;
        header->last_valid_ptr = 0;
    }

    /* Validate decoded header */
    uni_uslp_status_t st = uni_ccsds_uslp_validate_tfdf_header(header);
    if (st != UNI_USLP_SUCCESS) {
        return st;
    }

    *bytes_read = need;
    return UNI_USLP_SUCCESS;
}