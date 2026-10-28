// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025-2026 Uni-Libraries contributors

/*
 * CCSDS Space Data Link Security (SDLS) for USLP: Security Association table and built-in engine
 *
 * References:
 * - CCSDS 732.1-B-3 (USLP) §6 (SDLS option: Security Header/Trailer placement, procedures)
 * - CCSDS 355.0-B-2 (Space Data Link Security Protocol):
 *   §4.1.1 Security Header = SPI(2) || IV(iv_length) || SN(sn_length) (no Pad Length: no suite pads)
 *   §4.1.2 Security Trailer = MAC(mac_length)
 *   §4.2.2.6.2 authentication bit mask; §4.2.3 ApplySecurity; §4.2.4 ProcessSecurity
 *   Annex E baseline: AES-GCM, 256-bit key, 96-bit IV in the header, no SN field, 128-bit MAC
 *
 * Authentication Payload (§4.2.3.4 d, §4.2.4.4 a): the frame from the first Primary Header octet to the end of the
 * Transfer Frame Data Field, ANDed with the SA's mask:
 *   Primary Header      -> config.auth_mask (VCID and MAP ID always included, §4.2.2.6.2 b, c)
 *   Insert Zone         -> zeros (§4.2.2.6.2 g)
 *   Security Header     -> ones, except the IV field which is zeros (§4.2.2.6.2 h)
 *   Frame Data Field    -> ones (§4.2.2.6.2 i)
 * AEAD suites take everything before the Frame Data Field as AAD and the Frame Data Field as plaintext
 * (§4.2.3.2.2.3 a); HMAC takes the whole Authentication Payload.
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "uni_ccsds_uslp_internal.h"
#include <uni_crypto.h>

/* ========== Constants ========== */

/** Default anti-replay window when the configuration leaves it 0. */
#define SDLS_DEFAULT_WINDOW 64u

/** Largest AAD: longest Primary Header + Insert Zone + Security Header. */
#define SDLS_MAX_AAD_LENGTH (UNI_USLP_SDLS_AUTH_MASK_LENGTH + UNI_USLP_MAX_INSERT_ZONE_SIZE + UNI_USLP_SDLS_MAX_HEADER_LENGTH)

/** Length of the derived (not transmitted) AEAD IV. */
#define SDLS_DERIVED_IV_LENGTH 12u

/* ========== Helpers ========== */

/* Big-endian store of v into len octets; octets beyond the 64-bit value (len > 8) are zero. */
static void be_store(uint8_t* out, size_t len, uint64_t v)
{
    for (size_t i = 0; i < len; ++i) {
        out[len - 1u - i] = (i < 8u) ? (uint8_t)(v >> (8u * i)) : 0u;
    }
}

static uint64_t be_load(const uint8_t* in, size_t len)
{
    uint64_t v = 0;
    for (size_t i = 0; i < len; ++i) {
        v = (v << 8) | in[i];
    }
    return v;
}

static bool suite_is_aead(uni_uslp_sdls_suite_t suite)
{
    return suite == UNI_USLP_SDLS_SUITE_AES_GCM || suite == UNI_USLP_SDLS_SUITE_AES_CCM;
}

static uint64_t sdls_window(const uni_uslp_sdls_sa_config_t* cfg)
{
    if (cfg->anti_replay_window == 0u) return SDLS_DEFAULT_WINDOW;
    return cfg->anti_replay_window;
}

/* Largest SN an SA may transmit without reusing an IV or wrapping the SN field. With an IV derived from the SN field
 * the field width bounds the IV space; a transmitted IV is a 64-bit counter in its low octets. */
static uint64_t sdls_max_tx_sn(const uni_uslp_sdls_sa_config_t* cfg)
{
    if (cfg->sn_length > 0u && cfg->sn_length < 8u) {
        return (1ull << (8u * cfg->sn_length)) - 1u;
    }
    return UINT64_MAX;
}

/* VCID (bits 21..26) and MAP ID (bits 27..30) of the USLP Primary Header (732.1-B-3 §4.1.2). */
static const uint8_t k_required_mask[4] = {0x00u, 0x00u, 0x07u, 0xFEu};

void uni_ccsds_uslp_sdls_default_auth_mask(uint8_t mask[UNI_USLP_SDLS_AUTH_MASK_LENGTH])
{
    if (!mask) return;
    memset(mask, 0, UNI_USLP_SDLS_AUTH_MASK_LENGTH);
    memcpy(mask, k_required_mask, sizeof(k_required_mask));
}

/* SPI field length: 2 octets per §4.1.1.2.1, 1 octet in the Uni.CCSDS 1.x format. */
static size_t sdls_spi_length(uni_uslp_sdls_format_t format)
{
    return (format == UNI_USLP_SDLS_FORMAT_UNI_V1) ? 1u : UNI_USLP_SDLS_SPI_LENGTH;
}

size_t uni_ccsds_uslp_sdls_header_length(const uni_uslp_sdls_sa_config_t* config)
{
    return sdls_spi_length(config->format) + (size_t)config->iv_length + (size_t)config->sn_length;
}

/* ========== SA table ========== */

uni_uslp_sdls_sa_t* uni_ccsds_uslp_sdls_find_sa(uni_uslp_context_t* context, uint16_t spi)
{
    if (!context || spi == 0u) return NULL;
    for (size_t i = 0; i < UNI_USLP_SDLS_MAX_SA; ++i) {
        uni_uslp_sdls_sa_t* sa = &context->sdls_sa[i];
        if (sa->in_use && sa->config.spi == spi) return sa;
    }
    return NULL;
}

static const uni_uslp_sdls_sa_t* sdls_find_sa_const(const uni_uslp_context_t* context, uint16_t spi)
{
    return uni_ccsds_uslp_sdls_find_sa((uni_uslp_context_t*)context, spi);
}

/* Validate an SA configuration against 355.0-B-2 and the capabilities of the built-in engine (plan CCSDS-9: errors
 * surface when the SA is added, not on the first frame). */
static uni_uslp_status_t sdls_validate_config(const uni_uslp_sdls_sa_config_t* cfg)
{
    if (cfg->spi == 0u || cfg->spi == 0xFFFFu) return UNI_USLP_ERROR_INVALID_PARAM; /* reserved, §4.1.1.2.3 */
    if (cfg->format == UNI_USLP_SDLS_FORMAT_UNI_V1) {
        if (cfg->spi > 0xFFu || cfg->iv_length != 0u || cfg->sn_length != 8u) return UNI_USLP_ERROR_INVALID_PARAM;
        if (cfg->suite == UNI_USLP_SDLS_SUITE_NULL) return UNI_USLP_ERROR_INVALID_PARAM; /* 1.x NULL had no header at all */
    } else if (cfg->format != UNI_USLP_SDLS_FORMAT_355) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    if (cfg->sn_length > UNI_USLP_SDLS_MAX_SN_LENGTH) return UNI_USLP_ERROR_INVALID_PARAM;
    if (cfg->iv_length != 0u && cfg->iv_length != UNI_USLP_SDLS_IV_LENGTH) return UNI_USLP_ERROR_INVALID_PARAM;
    if (cfg->replay_mode != UNI_USLP_SDLS_REPLAY_STRICT && cfg->replay_mode != UNI_USLP_SDLS_REPLAY_SLIDING) return UNI_USLP_ERROR_INVALID_PARAM;
    if (cfg->anti_replay_window > UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW) return UNI_USLP_ERROR_INVALID_PARAM;
    if (cfg->mac_length > UNI_USLP_SDLS_MAX_MAC_LENGTH) return UNI_USLP_ERROR_INVALID_PARAM;
    if (uni_ccsds_uslp_sdls_header_length(cfg) > UNI_USLP_SDLS_MAX_HEADER_LENGTH) return UNI_USLP_ERROR_INVALID_PARAM;
    for (size_t i = 0; i < sizeof(k_required_mask); ++i) {
        if ((cfg->auth_mask[i] & k_required_mask[i]) != k_required_mask[i]) return UNI_USLP_ERROR_INVALID_PARAM; /* §4.2.2.6.2 b, c */
    }

    switch (cfg->suite) {
        case UNI_USLP_SDLS_SUITE_NULL:
            /* Clear mode: no MAC, so an SN check would protect nothing. */
            if (cfg->anti_replay_enabled) return UNI_USLP_ERROR_INVALID_PARAM;
            break;
        case UNI_USLP_SDLS_SUITE_HMAC_SHA256:
            if (cfg->iv_length != 0u) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->sn_length == 0u) return UNI_USLP_ERROR_INVALID_PARAM; /* §4.1.1.4.2: SN required for authentication */
            if (cfg->mac_length < 8u) return UNI_USLP_ERROR_INVALID_PARAM;
            break;
        case UNI_USLP_SDLS_SUITE_AES_GCM:
            if (cfg->mac_length != 16u) return UNI_USLP_ERROR_INVALID_PARAM; /* uni.crypto verifies full GCM tags only */
            if (cfg->iv_length == 0u && cfg->sn_length == 0u) return UNI_USLP_ERROR_INVALID_PARAM; /* no IV source */
            break;
        case UNI_USLP_SDLS_SUITE_AES_CCM:
            if (cfg->mac_length < 4u || cfg->mac_length > 16u || (cfg->mac_length % 2u) != 0u) return UNI_USLP_ERROR_INVALID_PARAM;
            if (cfg->iv_length == 0u && cfg->sn_length == 0u) return UNI_USLP_ERROR_INVALID_PARAM;
            break;
        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }
    return UNI_USLP_SUCCESS;
}

static uni_uslp_status_t sdls_validate_key(uni_uslp_sdls_suite_t suite, const uint8_t* key, size_t key_length)
{
    switch (suite) {
        case UNI_USLP_SDLS_SUITE_NULL:
            return UNI_USLP_SUCCESS;
        case UNI_USLP_SDLS_SUITE_HMAC_SHA256:
            return (key && key_length >= 16u && key_length <= 64u) ? UNI_USLP_SUCCESS : UNI_USLP_ERROR_INVALID_PARAM;
        case UNI_USLP_SDLS_SUITE_AES_GCM:
        case UNI_USLP_SDLS_SUITE_AES_CCM:
            return (key && (key_length == 16u || key_length == 24u || key_length == 32u)) ? UNI_USLP_SUCCESS : UNI_USLP_ERROR_INVALID_PARAM;
        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }
}

static void sdls_release_crypto(uni_uslp_sdls_sa_t* sa)
{
    uni_crypto_aead_ctx_free(&sa->aead);
    if (sa->hmac) {
        uni_crypto_hmac_free(sa->hmac);
        sa->hmac = NULL;
    }
    uni_crypto_utils_zeroize(sa->hmac_storage, sizeof(sa->hmac_storage));
}

/* Key the crypto context of an SA. The key bytes are not kept. */
static uni_uslp_status_t sdls_key_crypto(uni_uslp_sdls_sa_t* sa, const uint8_t* key, size_t key_length)
{
    switch (sa->config.suite) {
        case UNI_USLP_SDLS_SUITE_NULL:
            return UNI_USLP_SUCCESS;
        case UNI_USLP_SDLS_SUITE_HMAC_SHA256:
            if (uni_crypto_hmac_context_create_static(sa->hmac_storage, sizeof(sa->hmac_storage), &sa->hmac) != UNI_CRYPTO_HMAC_SUCCESS) {
                sa->hmac = NULL;
                return UNI_USLP_ERROR_SDLS_FAILURE;
            }
            if (uni_crypto_hmac_init(sa->hmac, UNI_CRYPTO_HMAC_ALG_SHA256, key, key_length) != UNI_CRYPTO_HMAC_SUCCESS) {
                sdls_release_crypto(sa);
                return UNI_USLP_ERROR_SDLS_FAILURE;
            }
            return UNI_USLP_SUCCESS;
        case UNI_USLP_SDLS_SUITE_AES_GCM:
        case UNI_USLP_SDLS_SUITE_AES_CCM: {
            const uni_crypto_aead_algorithm alg = (sa->config.suite == UNI_USLP_SDLS_SUITE_AES_GCM) ? UNI_CRYPTO_AEAD_ALG_AES_GCM
                                                                                                   : UNI_CRYPTO_AEAD_ALG_AES_CCM;
            return (uni_crypto_aead_ctx_init(&sa->aead, alg, key, key_length) == UNI_CRYPTO_AEAD_SUCCESS) ? UNI_USLP_SUCCESS
                                                                                                            : UNI_USLP_ERROR_SDLS_FAILURE;
        }
        default:
            return UNI_USLP_ERROR_INVALID_PARAM;
    }
}

static void sdls_reset_rx(uni_uslp_sdls_sa_t* sa)
{
    sa->rx_initialized = false;
    sa->rx_sn = 0u;
    memset(sa->rx_window_bitmap, 0, sizeof(sa->rx_window_bitmap));
}

uni_uslp_status_t uni_ccsds_uslp_sdls_add_sa(uni_uslp_context_t* context, const uni_uslp_sdls_sa_config_t* config, const uint8_t* key,
                                             size_t key_length)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(config);

    uni_uslp_sdls_sa_config_t cfg = *config;
    static const uint8_t zero_mask[UNI_USLP_SDLS_AUTH_MASK_LENGTH] = {0};
    if (memcmp(cfg.auth_mask, zero_mask, sizeof(zero_mask)) == 0) {
        uni_ccsds_uslp_sdls_default_auth_mask(cfg.auth_mask);
    }

    uni_uslp_status_t st = sdls_validate_config(&cfg);
    if (st != UNI_USLP_SUCCESS) return st;
    st = sdls_validate_key(cfg.suite, key, key_length);
    if (st != UNI_USLP_SUCCESS) return st;
    if (uni_ccsds_uslp_sdls_find_sa(context, cfg.spi)) return UNI_USLP_ERROR_INVALID_PARAM;

    uni_uslp_sdls_sa_t* sa = NULL;
    for (size_t i = 0; i < UNI_USLP_SDLS_MAX_SA; ++i) {
        if (!context->sdls_sa[i].in_use) {
            sa = &context->sdls_sa[i];
            break;
        }
    }
    if (!sa) return UNI_USLP_ERROR_CONTEXT_FULL;

    memset(sa, 0, sizeof(*sa));
    sa->config = cfg;
    st = sdls_key_crypto(sa, key, key_length);
    if (st != UNI_USLP_SUCCESS) {
        sdls_release_crypto(sa);
        memset(sa, 0, sizeof(*sa));
        return st;
    }
    sa->tx_sn = 0u;
    sa->tx_sn_restore_pending = cfg.require_sn_restore;
    sdls_reset_rx(sa);
    sa->in_use = true;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_remove_sa(uni_uslp_context_t* context, uint16_t spi)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_sdls_sa_t* sa = uni_ccsds_uslp_sdls_find_sa(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    sdls_release_crypto(sa);
    uni_crypto_utils_zeroize(sa, sizeof(*sa));
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_rekey_sa(uni_uslp_context_t* context, uint16_t spi, const uint8_t* key, size_t key_length)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_sdls_sa_t* sa = uni_ccsds_uslp_sdls_find_sa(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    uni_uslp_status_t st = sdls_validate_key(sa->config.suite, key, key_length);
    if (st != UNI_USLP_SUCCESS) return st;

    sdls_release_crypto(sa);
    st = sdls_key_crypto(sa, key, key_length);
    if (st != UNI_USLP_SUCCESS) {
        /* Leave no usable SA behind a failed rekey. */
        sdls_release_crypto(sa);
        uni_crypto_utils_zeroize(sa, sizeof(*sa));
        return st;
    }
    sa->tx_sn = 0u;
    sa->tx_sn_restore_pending = false;
    sdls_reset_rx(sa);
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_get_sa_config(const uni_uslp_context_t* context, uint16_t spi, uni_uslp_sdls_sa_config_t* out_config)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(out_config);
    const uni_uslp_sdls_sa_t* sa = sdls_find_sa_const(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    *out_config = sa->config;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_get_tx_sn(const uni_uslp_context_t* context, uint16_t spi, uint64_t* out_last_sn)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(out_last_sn);
    const uni_uslp_sdls_sa_t* sa = sdls_find_sa_const(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    *out_last_sn = sa->tx_sn;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_set_tx_sn(uni_uslp_context_t* context, uint16_t spi, uint64_t last_sn)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_sdls_sa_t* sa = uni_ccsds_uslp_sdls_find_sa(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    if (last_sn > sdls_max_tx_sn(&sa->config)) return UNI_USLP_ERROR_INVALID_PARAM;
    if (!sa->tx_sn_restore_pending && last_sn < sa->tx_sn) return UNI_USLP_ERROR_INVALID_PARAM; /* would reuse IVs */
    sa->tx_sn = last_sn;
    sa->tx_sn_restore_pending = false;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_set_rx_sn(uni_uslp_context_t* context, uint16_t spi, uint64_t managed_sn)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_sdls_sa_t* sa = uni_ccsds_uslp_sdls_find_sa(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    sdls_reset_rx(sa);
    sa->rx_initialized = true;
    sa->rx_sn = managed_sn;
    /* SLIDING: the managed SN counts as accepted, so it cannot be replayed. */
    const uint64_t slot = managed_sn % UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW;
    sa->rx_window_bitmap[slot / 64u] |= 1ull << (slot % 64u);
    return UNI_USLP_SUCCESS;
}

void uni_ccsds_uslp_sdls_reset_sessions(uni_uslp_context_t* context)
{
    for (size_t i = 0; i < UNI_USLP_SDLS_MAX_SA; ++i) {
        uni_uslp_sdls_sa_t* sa = &context->sdls_sa[i];
        if (!sa->in_use) continue;
        sdls_reset_rx(sa);
        if (sa->config.require_sn_restore) {
            sa->tx_sn_restore_pending = true;
        }
    }
}

void uni_ccsds_uslp_sdls_free_all(uni_uslp_context_t* context)
{
    for (size_t i = 0; i < UNI_USLP_SDLS_MAX_SA; ++i) {
        uni_uslp_sdls_sa_t* sa = &context->sdls_sa[i];
        if (!sa->in_use) continue;
        sdls_release_crypto(sa);
        uni_crypto_utils_zeroize(sa, sizeof(*sa));
    }
}

/* ========== Anti-replay (§4.2.4.4 f–j) ==========
 *
 * Split into a check that never changes state and a commit that runs only after the frame passed MAC verification
 * (§4.2.4.4 j). A forged frame therefore cannot occupy an SN or move the window. */

static uni_uslp_status_t sdls_replay_check(const uni_uslp_sdls_sa_t* sa, uint64_t sn)
{
    const uni_uslp_sdls_sa_config_t* cfg = &sa->config;
    if (!cfg->anti_replay_enabled || !sa->rx_initialized) {
        return UNI_USLP_SUCCESS;
    }
    const uint64_t window = sdls_window(cfg);
    const uint64_t managed = sa->rx_sn;

    if (cfg->replay_mode == UNI_USLP_SDLS_REPLAY_STRICT) {
        if (sn <= managed) return UNI_USLP_ERROR_SDLS_REPLAY;               /* §4.2.4.4 h */
        if (sn - managed > window) return UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW; /* §4.2.4.4 i */
        return UNI_USLP_SUCCESS;
    }

    /* SLIDING: managed = highest accepted SN */
    if (sn > managed) return UNI_USLP_SUCCESS;
    if (managed - sn >= window) return UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW; /* too old */
    const uint64_t slot = sn % UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW;
    const bool seen = (sa->rx_window_bitmap[slot / 64u] & (1ull << (slot % 64u))) != 0u;
    return seen ? UNI_USLP_ERROR_SDLS_REPLAY : UNI_USLP_SUCCESS;
}

static void sdls_bitmap_clear(uint64_t* bitmap, uint64_t sn)
{
    const uint64_t slot = sn % UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW;
    bitmap[slot / 64u] &= ~(1ull << (slot % 64u));
}

static void sdls_replay_commit(uni_uslp_sdls_sa_t* sa, uint64_t sn)
{
    const uni_uslp_sdls_sa_config_t* cfg = &sa->config;
    if (!cfg->anti_replay_enabled) {
        return;
    }
    uint64_t* bitmap = sa->rx_window_bitmap;

    if (cfg->replay_mode == UNI_USLP_SDLS_REPLAY_STRICT) {
        sa->rx_sn = sn; /* §4.2.4.4 j */
        sa->rx_initialized = true;
        return;
    }

    if (!sa->rx_initialized) {
        memset(sa->rx_window_bitmap, 0, sizeof(sa->rx_window_bitmap));
        sa->rx_sn = sn;
        sa->rx_initialized = true;
    } else if (sn > sa->rx_sn) {
        /* Advance: clear the slots the window passes over. */
        const uint64_t advance = sn - sa->rx_sn;
        if (advance >= UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW) {
            memset(sa->rx_window_bitmap, 0, sizeof(sa->rx_window_bitmap));
        } else {
            for (uint64_t next = sa->rx_sn + 1u; next <= sn; ++next) {
                sdls_bitmap_clear(bitmap, next);
            }
        }
        sa->rx_sn = sn;
    }
    const uint64_t slot = sn % UNI_USLP_SDLS_MAX_ANTI_REPLAY_WINDOW;
    bitmap[slot / 64u] |= 1ull << (slot % 64u);
}

/* ========== Authentication Payload ========== */

/* Write the masked Primary Header, zeroed Insert Zone and Security Header with a zeroed IV field to `aad`.
 * Returns the AAD length. `frame` starts at the first Primary Header octet; the Security Header follows the Insert
 * Zone. */
static size_t sdls_build_aad(const uni_uslp_sdls_sa_config_t* cfg, const uni_uslp_sdls_frame_layout_t* layout, const uint8_t* frame,
                             uint8_t aad[SDLS_MAX_AAD_LENGTH])
{
    if (cfg->format == UNI_USLP_SDLS_FORMAT_UNI_V1) {
        return 0u; /* 1.x: TFDF-only scope */
    }
    const size_t ph = layout->primary_header_length;
    const size_t iz = layout->insert_zone_length;
    const size_t hdr = uni_ccsds_uslp_sdls_header_length(cfg);

    for (size_t i = 0; i < ph; ++i) {
        aad[i] = (uint8_t)(frame[i] & cfg->auth_mask[i]);
    }
    memset(&aad[ph], 0, iz);
    memcpy(&aad[ph + iz], &frame[ph + iz], hdr);
    memset(&aad[ph + iz + sdls_spi_length(cfg->format)], 0, cfg->iv_length);
    return ph + iz + hdr;
}

static bool sdls_layout_supported(const uni_uslp_sdls_frame_layout_t* layout)
{
    return layout->primary_header_length <= UNI_USLP_SDLS_AUTH_MASK_LENGTH && layout->insert_zone_length <= UNI_USLP_MAX_INSERT_ZONE_SIZE;
}

/* AEAD IV: the transmitted IV field, or zero octets || SN field (big-endian) when the IV is not transmitted. */
static void sdls_aead_iv(const uni_uslp_sdls_sa_config_t* cfg, const uint8_t* sec_hdr, uint8_t iv[UNI_USLP_SDLS_IV_LENGTH])
{
    const size_t spi_len = sdls_spi_length(cfg->format);
    if (cfg->iv_length > 0u) {
        memcpy(iv, &sec_hdr[spi_len], UNI_USLP_SDLS_IV_LENGTH);
        return;
    }
    memset(iv, 0, SDLS_DERIVED_IV_LENGTH);
    memcpy(&iv[SDLS_DERIVED_IV_LENGTH - cfg->sn_length], &sec_hdr[spi_len], cfg->sn_length);
}

/* HMAC over AAD || TFDF into `mac` (full 32 octets). */
static uni_uslp_status_t sdls_hmac(uni_uslp_sdls_sa_t* sa, const uint8_t* aad, size_t aad_len, const uint8_t* tfdf, size_t tfdf_len,
                                   uint8_t mac[UNI_USLP_SDLS_MAX_MAC_LENGTH])
{
    if (!sa->hmac || uni_crypto_hmac_reset(sa->hmac) != UNI_CRYPTO_HMAC_SUCCESS ||
        uni_crypto_hmac_update(sa->hmac, aad, aad_len) != UNI_CRYPTO_HMAC_SUCCESS ||
        uni_crypto_hmac_update(sa->hmac, tfdf, tfdf_len) != UNI_CRYPTO_HMAC_SUCCESS ||
        uni_crypto_hmac_final(sa->hmac, mac, UNI_USLP_SDLS_MAX_MAC_LENGTH) != UNI_CRYPTO_HMAC_SUCCESS) {
        return UNI_USLP_ERROR_SDLS_FAILURE;
    }
    return UNI_USLP_SUCCESS;
}

/* ========== Built-in engine ========== */

uni_uslp_status_t uni_ccsds_uslp_register_builtin_sdls(uni_uslp_context_t* context)
{
    if (!context) return UNI_USLP_ERROR_NULL_POINTER;
    return uni_ccsds_uslp_register_sdls_callbacks(context, uni_ccsds_uslp_sdls_builtin_apply, uni_ccsds_uslp_sdls_builtin_process, NULL);
}

uni_uslp_status_t uni_ccsds_uslp_sdls_builtin_apply(uni_uslp_context_t* context, const uni_uslp_sdls_frame_layout_t* layout, uint16_t spi,
                                                    uint8_t* frame, size_t tfdf_length, void* user_data)
{
    (void)user_data;
    if (!context || !layout || !frame) return UNI_USLP_ERROR_NULL_POINTER;
    if (!sdls_layout_supported(layout)) return UNI_USLP_ERROR_UNSUPPORTED;

    uni_uslp_sdls_sa_t* sa = uni_ccsds_uslp_sdls_find_sa(context, spi);
    if (!sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    const uni_uslp_sdls_sa_config_t* cfg = &sa->config;
    if (sa->tx_sn_restore_pending) return UNI_USLP_ERROR_SDLS_SN_NOT_RESTORED;
    if (sa->tx_sn >= sdls_max_tx_sn(cfg)) return UNI_USLP_ERROR_SDLS_SN_EXHAUSTED;

    const size_t sec_off = layout->primary_header_length + layout->insert_zone_length;
    const size_t hdr_len = uni_ccsds_uslp_sdls_header_length(cfg);
    uint8_t* sec_hdr = &frame[sec_off];
    uint8_t* tfdf = &frame[sec_off + hdr_len];
    uint8_t* trailer = &tfdf[tfdf_length];

    /* §4.2.3.4 a–c: increment the managed SN and complete the Security Header. */
    const uint64_t sn = sa->tx_sn + 1u;
    const size_t spi_len = sdls_spi_length(cfg->format);
    be_store(sec_hdr, spi_len, cfg->spi);
    if (cfg->iv_length > 0u) {
        be_store(&sec_hdr[spi_len], cfg->iv_length, sn); /* 96-bit counter, 64-bit value */
    }
    be_store(&sec_hdr[spi_len + cfg->iv_length], cfg->sn_length, sn);

    if (cfg->suite == UNI_USLP_SDLS_SUITE_NULL) {
        memset(trailer, 0, cfg->mac_length);
        sa->tx_sn = sn;
        return UNI_USLP_SUCCESS;
    }

    uint8_t aad[SDLS_MAX_AAD_LENGTH];
    const size_t aad_len = sdls_build_aad(cfg, layout, frame, aad);

    uni_uslp_status_t st = UNI_USLP_SUCCESS;
    if (suite_is_aead(cfg->suite)) {
        uint8_t iv[UNI_USLP_SDLS_IV_LENGTH];
        sdls_aead_iv(cfg, sec_hdr, iv);
        /* Encrypt in place: no scratch buffer, any TFDF length (plan CCSDS-8). */
        const int rc = uni_crypto_aead_ctx_encrypt(&sa->aead, iv, sizeof(iv), aad, aad_len, tfdf, tfdf_length, tfdf, trailer, cfg->mac_length);
        if (rc != UNI_CRYPTO_AEAD_SUCCESS) st = UNI_USLP_ERROR_SDLS_FAILURE;
    } else {
        uint8_t mac[UNI_USLP_SDLS_MAX_MAC_LENGTH];
        st = sdls_hmac(sa, aad, aad_len, tfdf, tfdf_length, mac);
        if (st == UNI_USLP_SUCCESS) {
            memcpy(trailer, mac, cfg->mac_length); /* §4.2.3.4 f: keep the most significant octets */
        }
        uni_crypto_utils_zeroize(mac, sizeof(mac));
    }
    uni_crypto_utils_zeroize(aad, aad_len);
    if (st != UNI_USLP_SUCCESS) {
        uni_crypto_utils_zeroize(tfdf, tfdf_length + cfg->mac_length);
        return st;
    }

    sa->tx_sn = sn;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_sdls_builtin_process(uni_uslp_context_t* context, const uni_uslp_sdls_frame_layout_t* layout, const uint8_t* frame,
                                                      size_t protected_length, uint8_t* tfdf_out, size_t* tfdf_length, uni_uslp_sdls_rx_info_t* info,
                                                      void* user_data)
{
    (void)user_data;
    if (!context || !layout || !frame || !tfdf_out || !tfdf_length || !info) return UNI_USLP_ERROR_NULL_POINTER;
    memset(info, 0, sizeof(*info));
    info->verification = UNI_USLP_VERIF_SDLS_ERROR;
    if (!sdls_layout_supported(layout)) return UNI_USLP_ERROR_UNSUPPORTED;

    const size_t sec_off = layout->primary_header_length + layout->insert_zone_length;
    const uint8_t* sec_hdr = &frame[sec_off];

    /* §4.2.4.3: the SA named by the SPI must exist and be associated with this GVCID (and GMAP_ID). The SPI field length
     * follows from the wire format shared by the VC's SAs (checked by uni_ccsds_uslp_configure_sdls()). */
    const uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, layout->vcid);
    if (!vc || vc->sdls_config.rx_spi_count == 0u) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    const uni_uslp_sdls_sa_t* first_sa = uni_ccsds_uslp_sdls_find_sa(context, vc->sdls_config.rx_spis[0]);
    if (!first_sa) return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    const size_t spi_len = sdls_spi_length(first_sa->config.format);
    if (protected_length < spi_len) return UNI_USLP_ERROR_SDLS_LENGTH;
    const uint16_t spi = (uint16_t)be_load(sec_hdr, spi_len);
    info->spi = spi;

    bool associated = false;
    {
        for (uint8_t i = 0; i < vc->sdls_config.rx_spi_count && i < UNI_USLP_SDLS_MAX_SPI_PER_VC; ++i) {
            associated = associated || (vc->sdls_config.rx_spis[i] == spi);
        }
    }
    uni_uslp_sdls_sa_t* sa = associated ? uni_ccsds_uslp_sdls_find_sa(context, spi) : NULL;
    if (!sa || (sa->config.map_ids != 0u && (sa->config.map_ids & (1u << (layout->map_id & 0x0Fu))) == 0u)) {
        info->verification = UNI_USLP_VERIF_SDLS_ERROR;
        return UNI_USLP_ERROR_SDLS_SA_NOT_FOUND;
    }
    const uni_uslp_sdls_sa_config_t* cfg = &sa->config;

    const size_t hdr_len = uni_ccsds_uslp_sdls_header_length(cfg);
    const size_t trl_len = cfg->mac_length;
    if (protected_length < hdr_len + trl_len) return UNI_USLP_ERROR_SDLS_LENGTH;
    const size_t data_len = protected_length - hdr_len - trl_len;
    if (*tfdf_length < data_len) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    const uint8_t* data = &sec_hdr[hdr_len];
    const uint8_t* trailer = &data[data_len];

    /* §4.2.4.4 f: SN from the SN field, else from the low 64 bits of the transmitted IV. */
    uint64_t sn = 0u;
    if (cfg->sn_length > 0u) {
        sn = be_load(&sec_hdr[spi_len + cfg->iv_length], cfg->sn_length);
    } else if (cfg->iv_length > 0u) {
        sn = be_load(&sec_hdr[spi_len + cfg->iv_length - 8u], 8u);
    }
    info->sequence_number = sn;

    if (cfg->suite == UNI_USLP_SDLS_SUITE_NULL) {
        memcpy(tfdf_out, data, data_len);
        *tfdf_length = data_len;
        info->verification = UNI_USLP_VERIF_NOT_APPLICABLE;
        return UNI_USLP_SUCCESS;
    }

    /* §4.2.4.4 g–i without changing state; committed below only after the MAC verified (§4.2.4.4 j). */
    uni_uslp_status_t st = sdls_replay_check(sa, sn);
    if (st != UNI_USLP_SUCCESS) {
        info->verification = UNI_USLP_VERIF_REPLAY_REJECTED;
        return st;
    }

    uint8_t aad[SDLS_MAX_AAD_LENGTH];
    const size_t aad_len = sdls_build_aad(cfg, layout, frame, aad);

    if (suite_is_aead(cfg->suite)) {
        uint8_t iv[UNI_USLP_SDLS_IV_LENGTH];
        sdls_aead_iv(cfg, sec_hdr, iv);
        const int rc = uni_crypto_aead_ctx_decrypt(&sa->aead, iv, sizeof(iv), aad, aad_len, data, data_len, trailer, trl_len, tfdf_out);
        if (rc == UNI_CRYPTO_AEAD_EVERIFY) {
            st = UNI_USLP_ERROR_SDLS_MAC_FAILURE;
        } else if (rc != UNI_CRYPTO_AEAD_SUCCESS) {
            st = UNI_USLP_ERROR_SDLS_FAILURE;
        }
    } else {
        uint8_t mac[UNI_USLP_SDLS_MAX_MAC_LENGTH];
        st = sdls_hmac(sa, aad, aad_len, data, data_len, mac);
        if (st == UNI_USLP_SUCCESS && uni_crypto_utils_compare(mac, trailer, trl_len) != 0) {
            st = UNI_USLP_ERROR_SDLS_MAC_FAILURE;
        }
        uni_crypto_utils_zeroize(mac, sizeof(mac));
        if (st == UNI_USLP_SUCCESS) {
            memcpy(tfdf_out, data, data_len);
        }
    }
    uni_crypto_utils_zeroize(aad, aad_len);

    if (st != UNI_USLP_SUCCESS) {
        /* §4.2.4.4 e: discard; decrypted output of a failed AEAD verification must not leak. */
        uni_crypto_utils_zeroize(tfdf_out, data_len);
        info->verification = (st == UNI_USLP_ERROR_SDLS_MAC_FAILURE) ? UNI_USLP_VERIF_AUTH_FAILURE : UNI_USLP_VERIF_SDLS_ERROR;
        return st;
    }

    sdls_replay_commit(sa, sn);
    *tfdf_length = data_len;
    info->verification = UNI_USLP_VERIF_SUCCESS;
    return UNI_USLP_SUCCESS;
}
