// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

/*
 * CCSDS Space Data Link Security (SDLS) built-in engine for USLP
 *
 * References:
 * - CCSDS 732.1-B-3 (USLP) §6 (SDLS option integration: placement and procedures)
 * - CCSDS 355.0-B-2 (Space Data Link Security Protocol)
 *
 * Implemented per integrator selections:
 * - Suites:
 *   - NULL: no Security Header/Trailer, passthrough
 *   - HMAC-SHA256 (auth-only): Header = SPI(1) || SN(8), Trailer = ICV (16)
 *   - AES-GCM/CCM (AEAD):      Header = SPI(1) || SN(8), IV = 12 bytes derived as 0x00000000 || SN_be_8,
 *                              Trailer = Tag (16)
 * - Integrity/confidentiality scope: TFDF only (Header + TFDZ); Primary Header, Insert Zone, OCF, FECF excluded.
 * - Anti-replay: Sliding window enabled when configured (default 64) using SN from header.
 *
 * Send path (USLP §6.4):
 *   Input to ApplySecurity: TFDF header + TFDZ
 *   Output: Security Header + protected TFDF’ + Security Trailer
 *
 * Receive path (USLP §6.5):
 *   Input to ProcessSecurity: Security Header + protected TFDF’ + Security Trailer
 *   Output: TFDF header + TFDZ (plaintext)
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "uni_ccsds_uslp_internal.h"
#include <uni_crypto.h>

/* ========== Helpers ========== */

static inline void be_store_u64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >>  8);
    out[7] = (uint8_t)(v >>  0);
}

static inline uint64_t be_load_u64(const uint8_t in[8])
{
    return ((uint64_t)in[0] << 56) |
           ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) |
           ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) |
           ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] <<  8) |
           ((uint64_t)in[7] <<  0);
}

/* Anti-replay window update. Returns true if acceptable (not replay/too old), false otherwise.
 *
 * Accepted SNs are recorded in a ring bitmap indexed by SN modulo the maximum window. An SN above
 * the highest one advances the window (clearing the slots it passes); an older SN is accepted
 * once as long as it lags the highest by less than the configured window. */
static bool sdls_bit_test_and_set(uint64_t* bitmap, uint64_t sn)
{
    const uint64_t slot = sn % UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW;
    const uint64_t mask = 1ull << (slot % 64u);
    uint64_t* word = &bitmap[slot / 64u];
    const bool was_set = (*word & mask) != 0u;
    *word |= mask;
    return was_set;
}

static void sdls_bit_clear(uint64_t* bitmap, uint64_t sn)
{
    const uint64_t slot = sn % UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW;
    bitmap[slot / 64u] &= ~(1ull << (slot % 64u));
}

static bool sdls_window_accept_and_update(uni_uslp_vc_state_t* vc, const uni_uslp_sdls_config_t* cfg, uint64_t sn)
{
    if (!cfg->anti_replay_enabled) {
        return true;
    }
    const uint64_t window = (cfg->anti_replay_window == 0u) ? 64u
                          : (cfg->anti_replay_window > UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW ? UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW
                                                                                            : cfg->anti_replay_window);
    uint64_t* bitmap = vc->sdls_rt.rx_window_bitmap;
    const size_t words = sizeof(vc->sdls_rt.rx_window_bitmap) / sizeof(vc->sdls_rt.rx_window_bitmap[0]);

    if (!vc->sdls_rt.rx_initialized) {
        vc->sdls_rt.rx_initialized = true;
        vc->sdls_rt.rx_highest_sn = sn;
        memset(bitmap, 0, words * sizeof(uint64_t));
        (void)sdls_bit_test_and_set(bitmap, sn);
        return true;
    }

    const uint64_t high = vc->sdls_rt.rx_highest_sn;
    if (sn > high) {
        const uint64_t advance = sn - high;
        if (advance >= UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW) {
            memset(bitmap, 0, words * sizeof(uint64_t));
        } else {
            for (uint64_t next = high + 1u; next < sn; ++next) {
                sdls_bit_clear(bitmap, next);
            }
            sdls_bit_clear(bitmap, sn);
        }
        vc->sdls_rt.rx_highest_sn = sn;
        (void)sdls_bit_test_and_set(bitmap, sn);
        return true;
    }
    if (high - sn >= window) {
        return false; /* too old */
    }
    return !sdls_bit_test_and_set(bitmap, sn); /* false: duplicate */
}

/* IV derivation for AEAD: 12 bytes = 0x00000000 || SN_be_8 */
static void sdls_derive_iv_from_sn(uint8_t out12[12], uint64_t sn)
{
    out12[0] = 0; out12[1] = 0; out12[2] = 0; out12[3] = 0;
    be_store_u64(&out12[4], sn);
}

/* Validate config coherence with integrator-selected profile, derive effective lengths. */
static uni_uslp_status_t sdls_validate_lengths(const uni_uslp_sdls_config_t* cfg,
                                               size_t* out_hdr_len,
                                               size_t* out_trl_len)
{
    if (!cfg || !out_hdr_len || !out_trl_len) return UNI_USLP_ERROR_INVALID_PARAM;

    switch (cfg->suite) {
        case UNI_USLP_SDLS_SUITE_NULL:
            *out_hdr_len = 0;
            *out_trl_len = 0;
            break;

        case UNI_USLP_SDLS_SUITE_HMAC_SHA256:
            /* Header = SPI(1) + SN(8), Trailer = ICV(mac_length) */
            if (!cfg->sec_header_present || !cfg->sec_trailer_present) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->sec_header_length != 9u) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->mac_length == 0) return UNI_USLP_ERROR_INVALID_PARAM;
            *out_hdr_len = cfg->sec_header_length;
            *out_trl_len = cfg->mac_length;
            break;

        case UNI_USLP_SDLS_SUITE_AES_GCM:
        case UNI_USLP_SDLS_SUITE_AES_CCM:
            /* Header = SPI(1) + SN(8), Trailer = Tag(mac_length), IV derivation fixed to 12 */
            if (!cfg->sec_header_present || !cfg->sec_trailer_present) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->sec_header_length != 9u) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->mac_length == 0) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->iv_length != 12u) return UNI_USLP_ERROR_INVALID_PARAM;
            *out_hdr_len = cfg->sec_header_length;
            *out_trl_len = cfg->mac_length;
            break;

        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }
    return UNI_USLP_SUCCESS;
}

/* Map suite -> crypto enums */
static inline uni_crypto_hmac_algorithm map_hmac_alg(void) {
    return UNI_CRYPTO_HMAC_ALG_SHA256;
}
static inline uni_crypto_aead_algorithm map_aead_alg(uni_uslp_sdls_suite_t suite) {
    return (suite == UNI_USLP_SDLS_SUITE_AES_GCM) ? UNI_CRYPTO_AEAD_ALG_AES_GCM : UNI_CRYPTO_AEAD_ALG_AES_CCM;
}

/* ========== Public API ========== */

uni_uslp_status_t uni_ccsds_uslp_register_builtin_sdls(uni_uslp_context_t* context)
{
    if (!context) return UNI_USLP_ERROR_NULL_POINTER;
    return uni_ccsds_uslp_register_sdls_callbacks(context,
                                            uni_ccsds_uslp_sdls_builtin_apply,
                                            uni_ccsds_uslp_sdls_builtin_process,
                                            NULL);
}

uni_uslp_status_t uni_ccsds_uslp_sdls_builtin_apply(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *input_frame,
    size_t input_length,
    uint8_t *output_frame,
    size_t *output_length,
    const uni_uslp_sdls_config_t *config,
    void *user_data
)
{
    (void)user_data;
    if (!context || !output_length) return UNI_USLP_ERROR_INVALID_PARAM;
    if (input_length > 0 && (!input_frame || !output_frame)) return UNI_USLP_ERROR_INVALID_PARAM;

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) return UNI_USLP_ERROR_INVALID_PARAM;

    size_t hdr_len = 0, trl_len = 0;
    uni_uslp_status_t st = sdls_validate_lengths(config, &hdr_len, &trl_len);
    if (st != UNI_USLP_SUCCESS) return st;

    /* NULL suite short-circuit */
    if (config->suite == UNI_USLP_SDLS_SUITE_NULL) {
        if (*output_length < input_length) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        if (input_length && output_frame != input_frame) {
            memmove(output_frame, input_frame, input_length);
        }
        *output_length = input_length;
        return UNI_USLP_SUCCESS;
    }

    /* Ensure total output capacity */
    if (*output_length < (hdr_len + input_length + trl_len)) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;

    /* Prepare Security Header in output region */
    uint8_t* out = output_frame;
    out[0] = config->spi;
    uint64_t sn = vc->sdls_rt.tx_sn;
    be_store_u64(&out[1], sn);

    switch (config->suite) {
        case UNI_USLP_SDLS_SUITE_HMAC_SHA256:
        {
            /* Compute ICV over plaintext TFDF (input_frame) first */
            uint8_t full_tag[32];
            int rc = uni_crypto_hmac_compute(map_hmac_alg(),
                                             config->key, config->key_length,
                                             input_frame, input_length,
                                             full_tag, sizeof(full_tag));
            if (rc != UNI_CRYPTO_HMAC_SUCCESS) return UNI_USLP_ERROR_SDLS_FAILURE;
            if (config->mac_length > sizeof(full_tag)) return UNI_USLP_ERROR_SDLS_FAILURE;

            /* Move plaintext TFDF into place after header, overlap-safe */
            if (input_length) {
                memmove(out + hdr_len, input_frame, input_length);
            }
            /* Append trailer (truncated tag) */
            memmove(out + hdr_len + input_length, full_tag, config->mac_length);

            /* Bump SN */
            vc->sdls_rt.tx_sn = sn + 1ull;

            *output_length = (size_t)(hdr_len + input_length + trl_len);
            return UNI_USLP_SUCCESS;
        }

        case UNI_USLP_SDLS_SUITE_AES_GCM:
        case UNI_USLP_SDLS_SUITE_AES_CCM:
        {
            /* AEAD over TFDF; IV derived from SN; AAD empty.
             * IMPORTANT: Avoid overlap between input_frame (TFDF located after SecHeader gap)
             * and output region (starts before input). Encrypt into a temporary buffer first,
             * then move into final output after the header. */
            uint8_t iv[12];
            sdls_derive_iv_from_sn(iv, sn);

            uint8_t tag_buf[16];
            if (trl_len > sizeof(tag_buf)) return UNI_USLP_ERROR_SDLS_FAILURE;

            /* Select temporary buffer for ciphertext */
            uint8_t* ct_tmp = NULL;
            bool ct_tmp_is_frame = false;
            uint8_t ct_small[1024]; /* stack scratch; fall back to context frame_buffer when larger */
            if (input_length <= sizeof(ct_small)) {
                ct_tmp = ct_small;
            } else if (context->frame_buffer && context->frame_buffer_size >= input_length) {
                ct_tmp = context->frame_buffer;
                ct_tmp_is_frame = true;
            } else {
                return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
            }

            int rc = uni_crypto_aead_encrypt(map_aead_alg(config->suite),
                                             config->key, config->key_length,
                                             iv, sizeof(iv),
                                             NULL, 0, /* AAD empty (TFDF-only scope) */
                                             input_frame, input_length,
                                             ct_tmp,
                                             tag_buf, trl_len);
            if (rc != UNI_CRYPTO_AEAD_SUCCESS) {
                /* zeroize scratch on failure */
                if (ct_tmp_is_frame && context->frame_buffer) {
                    uni_crypto_utils_zeroize(context->frame_buffer, input_length);
                } else {
                    uni_crypto_utils_zeroize(ct_small, sizeof(ct_small));
                }
                return UNI_USLP_ERROR_SDLS_FAILURE;
            }

            /* Move ciphertext into final location after header (overlap-safe) */
            if (input_length) {
                memmove(out + hdr_len, ct_tmp, input_length);
            }
            /* Append tag */
            memmove(out + hdr_len + input_length, tag_buf, trl_len);

            /* Zeroize scratch if used */
            if (ct_tmp_is_frame && context->frame_buffer) {
                uni_crypto_utils_zeroize(context->frame_buffer, input_length);
            } else {
                uni_crypto_utils_zeroize(ct_small, sizeof(ct_small));
            }

            /* Bump SN */
            vc->sdls_rt.tx_sn = sn + 1ull;

            *output_length = (size_t)(hdr_len + input_length + trl_len);
            return UNI_USLP_SUCCESS;
        }

        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }
}

uni_uslp_status_t uni_ccsds_uslp_sdls_builtin_process(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *input_frame,
    size_t input_length,
    uint8_t *output_frame,
    size_t *output_length,
    const uni_uslp_sdls_config_t *config,
    void *user_data,
    uint64_t *out_seq_num
)
{
    (void)user_data;
    if (!context || !output_length) return UNI_USLP_ERROR_INVALID_PARAM;
    if (input_length > 0 && (!input_frame || !output_frame)) return UNI_USLP_ERROR_INVALID_PARAM;

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) return UNI_USLP_ERROR_INVALID_PARAM;

    size_t hdr_len = 0, trl_len = 0;
    uni_uslp_status_t st = sdls_validate_lengths(config, &hdr_len, &trl_len);
    if (st != UNI_USLP_SUCCESS) return st;

    /* NULL suite short-circuit */
    if (config->suite == UNI_USLP_SDLS_SUITE_NULL) {
        if (*output_length < input_length) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        if (input_length && output_frame != input_frame) {
            memcpy(output_frame, input_frame, input_length);
        }
        *output_length = input_length;
        if (out_seq_num) *out_seq_num = 0;
        return UNI_USLP_SUCCESS;
    }

    /* Ensure frame long enough to include header and trailer */
    if (input_length < (hdr_len + trl_len)) return UNI_USLP_ERROR_INVALID_FRAME;

    /* Parse Security Header and Security Trailer pointers */
    const uint8_t* sec_hdr = input_frame;
    const uint8_t* protected_region = input_frame + hdr_len;
    size_t protected_len = input_length - hdr_len - trl_len;
    const uint8_t* sec_trl = protected_region + protected_len;

    /* Extract SPI and SN */
    if (hdr_len != 9u) return UNI_USLP_ERROR_INVALID_FRAME;
    const uint8_t spi = sec_hdr[0];
    (void)spi; /* In a full SA database, select by SPI; here config already provides SA */
    uint64_t sn = be_load_u64(&sec_hdr[1]);
    if (out_seq_num) *out_seq_num = sn;

    /* Anti-replay check */
    if (!sdls_window_accept_and_update(vc, config, sn)) {
        return UNI_USLP_ERROR_SDLS_FAILURE;
    }

    /* Validate output buffer */
    if (*output_length < protected_len) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    switch (config->suite) {
        case UNI_USLP_SDLS_SUITE_HMAC_SHA256:
        {
            /* Verify ICV over plaintext TFDF (protected_region is plaintext in auth-only suite) */
            int rc = uni_crypto_hmac_verify(map_hmac_alg(),
                                            config->key, config->key_length,
                                            protected_region, protected_len,
                                            sec_trl, trl_len);
            if (rc != UNI_CRYPTO_HMAC_SUCCESS) {
                return UNI_USLP_ERROR_SDLS_FAILURE;
            }
            /* Copy plaintext TFDF out */
            if (protected_len && output_frame != protected_region) {
                memcpy(output_frame, protected_region, protected_len);
            }
            *output_length = protected_len;
            return UNI_USLP_SUCCESS;
        }

        case UNI_USLP_SDLS_SUITE_AES_GCM:
        case UNI_USLP_SDLS_SUITE_AES_CCM:
        {
            /* Decrypt and authenticate with IV derived from SN; AAD empty */
            uint8_t iv[12];
            sdls_derive_iv_from_sn(iv, sn);

            int rc = uni_crypto_aead_decrypt(map_aead_alg(config->suite),
                                             config->key, config->key_length,
                                             iv, sizeof(iv),
                                             NULL, 0,
                                             protected_region, protected_len,
                                             sec_trl, trl_len,
                                             output_frame);
            if (rc != UNI_CRYPTO_AEAD_SUCCESS) {
                return UNI_USLP_ERROR_SDLS_FAILURE;
            }
            *output_length = protected_len;
            return UNI_USLP_SUCCESS;
        }

        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }
}
