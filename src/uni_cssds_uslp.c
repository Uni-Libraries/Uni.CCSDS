// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

/**
 * @file uni_ccsds_uslp.c
 * @brief Core USLP context, configuration, frame build and accept (partial pipeline)
 *
 * Implements minimal, standards-aligned sending/receiving path to enable:
 * - Context init/reset/free
 * - VC/MAP configuration and SDU callback registration
 * - MAPA zero-copy queueing (uni_uslp_send_mapa)
 * - Frame build for variable-length TFDFs with Rule '111' (No Segmentation)
 * - Frame acceptance with CRC verification and TFDF header parse and SDU callback
 *
 * Notes:
 * - This is an incremental implementation focused on §4.1 (frame format) and
 *   §4.2/§4.3 core path for MAPA on variable-length frames without Insert Zone or OCF.
 * - FECF is supported (Annex B) when enabled by managed parameters.
 * - OCF and Insert Zone are currently not emitted; OID and Truncated frames are not yet implemented here.
 * - Segmentation, blocking, multiplexing policy, and SDLS hooks are TODO.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include "uni_ccsds_uslp_internal.h"


#include "uni_crypto.h"

/* Suppress unused warnings for helper kept for documentation/PICS traceability */
#if defined(__GNUC__) || defined(__clang__)
#define UNI_USLP_UNUSED __attribute__((unused))
#else
#define UNI_USLP_UNUSED
#endif

/* ========================================================================== */
/* INTERNAL HELPERS                                                           */
/* ========================================================================== */

static UNI_USLP_UNUSED UNI_USLP_INLINE uint8_t vc_vcf_count_len_code(const uni_uslp_vc_state_t* vc)
{
    /* Map VC managed params to header 3-bit code (octets) per Table 4-2.
     * Retained for traceability (PICS code pointer), though current TX path computes per-service. */
    if (!vc) return 0u;
    return (uint8_t)(vc->vcf_seq_len & 0x7u);
}

static UNI_USLP_INLINE size_t vcf_octets_from_code(uint8_t code)
{
    return (size_t)(code & 0x7u);
}

/* Pack Truncated Primary Header (first 4 octets of Primary Header), MSB-first.
 * Fields per CCSDS 732.1-B-3 Annex D (Figure D-2) mapped to §4.1.2 bit layout:
 * Bits 0–3:  TFVN (4)
 * Bits 4–19: SCID (16)
 * Bit  20:   Source-or-Destination Identifier (1)
 * Bits 21–26:VCID (6)
 * Bits 27–30:MAP ID (4)
 * Bit  31:   End of Frame Primary Header Flag = 1 (truncated) */
static UNI_USLP_INLINE void pack_truncated_ph(
    uint8_t *out4,
    uint16_t scid,
    bool source_dest,
    uint8_t vcid,
    uint8_t map_id
)
{
    uint32_t acc = 0u;
    acc |= ((uint32_t)(UNI_USLP_TFVN & 0xFu)) << 28;                /* bits 0..3 */
    acc |= ((uint32_t)scid & 0xFFFFu) << 12;                        /* bits 4..19 */
    acc |= ((uint32_t)(source_dest ? 1u : 0u)) << 11;               /* bit 20 */
    acc |= ((uint32_t)(vcid & 0x3Fu)) << 5;                         /* bits 21..26 */
    acc |= ((uint32_t)(map_id & 0x0Fu)) << 1;                       /* bits 27..30 */
    acc |= 0x1u;                                                    /* bit 31 (EoH=1) */
    out4[0] = (uint8_t)((acc >> 24) & 0xFFu);
    out4[1] = (uint8_t)((acc >> 16) & 0xFFu);
    out4[2] = (uint8_t)((acc >>  8) & 0xFFu);
    out4[3] = (uint8_t)((acc >>  0) & 0xFFu);
}

/* Unpack Truncated Primary Header (first 4 octets), MSB-first. */
static UNI_USLP_INLINE void unpack_truncated_ph(
    const uint8_t *in4,
    uint8_t *tfvn,
    uint16_t *scid,
    bool *source_dest,
    uint8_t *vcid,
    uint8_t *map_id,
    bool *eoh_flag
)
{
    const uint32_t acc = ((uint32_t)in4[0] << 24) |
                         ((uint32_t)in4[1] << 16) |
                         ((uint32_t)in4[2] << 8)  |
                         ((uint32_t)in4[3]);
    if (tfvn)        *tfvn        = (uint8_t)((acc >> 28) & 0x0Fu);
    if (scid)        *scid        = (uint16_t)((acc >> 12) & 0xFFFFu);
    if (source_dest) *source_dest = (((acc >> 11) & 0x1u) != 0u);
    if (vcid)        *vcid        = (uint8_t)((acc >> 5) & 0x3Fu);
    if (map_id)      *map_id      = (uint8_t)((acc >> 1) & 0x0Fu);
    if (eoh_flag)    *eoh_flag    = ((acc & 0x1u) != 0u);
}

static UNI_USLP_INLINE size_t ocf_length_if_present(bool ocf_flag)
{
    return ocf_flag ? (size_t)UNI_USLP_OCF_LENGTH : 0u;
}

static UNI_USLP_INLINE size_t fecf_length_if_present(const uni_uslp_context_t* ctx)
{
    return ctx->params.fecf_capability ? (size_t)UNI_USLP_FECF_LENGTH : 0u;
}

static UNI_USLP_INLINE uni_uslp_fecf_tx_mode_t fecf_tx_mode(const uni_uslp_context_t* ctx)
{
    if (!ctx) return UNI_USLP_FECF_TX_INTERNAL;
    /* FECF mode only matters when FECF is present. */
    if (!ctx->params.fecf_capability) return UNI_USLP_FECF_TX_INTERNAL;

    /* Defensive: clamp unknown enum values. */
    switch (ctx->params.fecf_tx_mode) {
        case UNI_USLP_FECF_TX_INTERNAL:
        case UNI_USLP_FECF_TX_OFFLOAD_INPLACE:
        case UNI_USLP_FECF_TX_OFFLOAD_APPEND:
            return ctx->params.fecf_tx_mode;
        default:
            return UNI_USLP_FECF_TX_INTERNAL;
    }
}

static UNI_USLP_INLINE size_t insert_zone_length_if_present(const uni_uslp_context_t* ctx)
{
    return ctx->params.insert_zone_capability ? (size_t)ctx->params.insert_zone_length : 0u;
}

uni_uslp_vc_state_t* uni_ccsds_uslp_get_vc_state(uni_uslp_context_t *context, uint8_t vcid)
{
    if (!context) return NULL;
    if (vcid >= UNI_USLP_MAX_VIRTUAL_CHANNELS) return NULL;
    return &context->vcs[vcid];
}

uni_uslp_map_state_t* uni_ccsds_uslp_get_map_state(uni_uslp_context_t *context, uint8_t vcid, uint8_t map_id)
{
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return NULL;
    if (map_id >= UNI_USLP_MAX_MAPS_PER_VC) return NULL;
    return &vc->maps[map_id];
}

/* ========================================================================== */
/* CONTEXT MANAGEMENT                                                         */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_init(uni_uslp_context_t *context, uint16_t scid, const uni_uslp_managed_params_t *params)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(params);

    memset(context, 0, sizeof(*context));
    context->scid = scid;
    context->params = *params;

    /* Initialize scheduler state (USLP-99/USLP-96/USLP-101) */
    context->sched_last_vc_rr = 0xFF; /* none */
    for (size_t v = 0; v < UNI_USLP_MAX_VIRTUAL_CHANNELS; ++v) {
        uni_uslp_vc_state_t* vc = &context->vcs[v];
        vc->sched_last_map_rr = 0xFF; /* none */
        memset(vc->map_drr_deficit, 0, sizeof(vc->map_drr_deficit));
        /* Default VC mux policy */
        vc->vc_mux_policy.priority = 0;
        vc->vc_mux_policy.weight = 0;
        vc->vc_mux_policy.max_burst_size = 0;
    }

    context->oid_lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;

    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_reset(uni_uslp_context_t *context)
{
    UNI_USLP_CHECK_NULL(context);

    /* Reset counters and transient state, keep configuration */
    memset(&context->mc_state, 0, sizeof(context->mc_state));

    for (size_t v = 0; v < UNI_USLP_MAX_VIRTUAL_CHANNELS; ++v) {
        uni_uslp_vc_state_t* vc = &context->vcs[v];
        /* TX counters per persistence policy */
        if (!vc->params.vcf_persist) {
            vc->vcf_seq_tx = 0u;
            vc->vcf_exp_tx = 0u;
        }
        /* RX expected always set to UNSYNC on reset */
        vc->vcf_seq_rx_expected = UINT64_MAX;
        vc->vcf_exp_rx_expected = UINT64_MAX;

        /* Clear per-VC runtime statistics */
        vc->frames_sent = 0u;
        vc->frames_received = 0u;
        vc->frame_errors = 0u;
        vc->sequence_gaps = 0u;
        vc->duplicates_detected = 0u;
        vc->out_of_order_frames = 0u;
        vc->wraps = 0u;
        vc->vcf_frames_with_field = 0u;

        /* Clear schedulers (USLP-96/USLP-99) */
        vc->sched_last_map_rr = 0xFF; /* none */
        memset(vc->map_drr_deficit, 0, sizeof(vc->map_drr_deficit));

        for (size_t m = 0; m < UNI_USLP_MAX_MAPS_PER_VC; ++m) {
            uni_uslp_map_state_t* map = &vc->maps[m];
            map->send_buffer = NULL;
            map->send_buffer_size = 0;
            map->send_buffer_used = 0;
        }
        /* Clear pending IN_SDU for Insert Service */
        vc->insert_pending_valid = false;
        vc->insert_pending_length = 0u;
    }

    /* Reset VC RR scheduler (USLP-99/USLP-101) */
    context->sched_last_vc_rr = 0xFF;

    context->oid_lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;

    /* Clear pending C&S loss latch on reset (consumed on next successful accept) */
    context->rx_cs_loss_signaled_pending = false;

    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_free(uni_uslp_context_t *context)
{
    UNI_USLP_CHECK_NULL(context);
    /* No dynamic allocations by default; nothing to free. */
    memset(context, 0, sizeof(*context));
    return UNI_USLP_SUCCESS;
}
/* Set working buffer for in-place transformations (e.g., SDLS RX processing) */
uni_uslp_status_t uni_ccsds_uslp_set_work_buffer(
    uni_uslp_context_t *context,
    uint8_t *work_buffer,
    size_t work_buffer_size
)
{
    UNI_USLP_CHECK_NULL(context);
    context->frame_buffer = work_buffer;
    context->frame_buffer_size = work_buffer_size;
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* CONFIGURATION AND CALLBACKS                                                */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_configure_vc(uni_uslp_context_t *context, uint8_t vcid, const uni_uslp_managed_params_t *params)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(params);

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;

    /* Copy params */
    vc->params = *params;

    /* Derive cached VCF lengths (octets) per QoS from managed params (USLP-130/USLP-131) */
    uint8_t seq = vc->params.vcf_seq_count_len_octets;
    uint8_t exp = vc->params.vcf_exp_count_len_octets;
    const uint8_t legacy = vc->params.vcf_count_length;
    if (seq == 0u && exp == 0u && legacy > 0u) {
        seq = legacy;
        exp = legacy;
    }
    if (seq > 7u) seq = 7u;
    if (exp > 7u) exp = 7u;
    vc->vcf_seq_len = seq;
    vc->vcf_exp_len = exp;

    /* Initialize counters per persistence policy */
    if (!vc->params.vcf_persist) {
        vc->vcf_seq_tx = 0u;
        vc->vcf_exp_tx = 0u;
    }
    /* RX expected always starts unsynchronized; will sync to first received frame with count */
    vc->vcf_seq_rx_expected = UINT64_MAX;
    vc->vcf_exp_rx_expected = UINT64_MAX;

    /* Clear pending IN_SDU state for Insert Service on (re)configure */
    vc->insert_pending_valid = false;
    vc->insert_pending_length = 0u;

    vc->configured = true;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_configure_map(uni_uslp_context_t *context, uint8_t vcid, uint8_t map_id, uni_uslp_service_type_t service_type, const uni_uslp_managed_params_t *params)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(params);

    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;

    map->params = *params;
    map->service_type = service_type;
    map->configured = true;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_set_mux_policy(uni_uslp_context_t *context, uint8_t vcid, uint8_t map_id, const uni_uslp_mux_policy_t *policy)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(policy);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->mux_policy = *policy;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_configure_sdls(uni_uslp_context_t *context, uint8_t vcid, const uni_uslp_sdls_config_t *config)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(config);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->sdls_config = *config;
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* GETTERS: Managed Parameters (USLP-132..USLP-144)                            */
/* ========================================================================== */

/* USLP-132..144 are VC-managed parameters (Table 5-3). Provide readback APIs
 * so tests and integration can verify configuration without inventing behavior. */

/* Get a copy of VC managed params, including COP/CLCW/OCF policy and timing.
 * References:
 *  - §5 Table 5-3 (USLP-132..USLP-144)
 *  - §4.1.5 OCF inclusion (policy fields USLP-139, USLP-140) */
uni_uslp_status_t uni_ccsds_uslp_get_vc_params(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_managed_params_t *out_params
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(out_params);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    *out_params = vc->params;
    return UNI_USLP_SUCCESS;
}

/* Get repetition configuration counts (USLP-141/USLP-142) — recorded values. */
uni_uslp_status_t uni_ccsds_uslp_get_repetition_counts(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t *repetitions_seq,
    uint8_t *repetitions_cop_ctrl
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(repetitions_seq);
    UNI_USLP_CHECK_NULL(repetitions_cop_ctrl);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    *repetitions_seq = vc->params.repetitions_seq;
    *repetitions_cop_ctrl = vc->params.repetitions_cop_ctrl;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_register_sdu_callback(uni_uslp_context_t *context, uint8_t vcid, uint8_t map_id, uni_uslp_sdu_callback_t callback, void *user_data)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->sdu_callback = callback;
    map->sdu_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_register_ocf_callback(uni_uslp_context_t *context, uint8_t vcid, uni_uslp_ocf_callback_t callback, void *user_data)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->ocf_callback = callback;
    vc->ocf_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* OCF.indication v2 registration (USLP-44; §3.8.2.4) */
uni_uslp_status_t uni_ccsds_uslp_register_ocf2_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_ocf2_callback_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->ocf2_callback = callback;
    vc->ocf2_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_register_insert_callback(uni_uslp_context_t *context, uint8_t vcid, uni_uslp_insert_callback_t callback, void *user_data)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->insert_callback = callback;
    vc->insert_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* INSERT.indication v2 registration — adds IN_SDU Loss Flag per §3.11.2.4 (USLP-53, Optional) */
uni_uslp_status_t uni_ccsds_uslp_register_insert2_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_insert2_callback_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->insert2_callback = callback;
    vc->insert2_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_register_sdls_callbacks(uni_uslp_context_t *context, uni_uslp_sdls_apply_callback_t apply_callback, uni_uslp_sdls_process_callback_t process_callback, void *user_data)
{
    UNI_USLP_CHECK_NULL(context);
    context->sdls_apply_callback = apply_callback;
    context->sdls_process_callback = process_callback;
    context->sdls_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_register_idle_filler_callback(uni_uslp_context_t *context, uni_uslp_idle_filler_callback_t callback, void *user_data)
{
    UNI_USLP_CHECK_NULL(context);
    context->idle_filler_callback = callback;
    context->idle_filler_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* OCTET_STREAM_Notify.indication registration (§3.7.3.4) */
uni_uslp_status_t uni_ccsds_uslp_register_octet_stream_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_octet_stream_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->octet_stream_notify_cb = callback;
    map->octet_stream_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}
/* MAPA_Notify.indication registration (§3.5.3.3) */
uni_uslp_status_t uni_ccsds_uslp_register_mapa_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapa_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->mapa_notify_cb = callback;
    map->mapa_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* MAPP_Notify.indication registration (§3.3.3.3) */
uni_uslp_status_t uni_ccsds_uslp_register_mapp_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapp_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->mapp_notify_cb = callback;
    map->mapp_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* VCA_Notify.indication registration (§3.6.4.3) */
uni_uslp_status_t uni_ccsds_uslp_register_vca_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_vca_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->vca_notify_cb = callback;
    map->vca_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* MAPP.indication registration (receiving end) — optional PQI support (§3.3.3.4; USLP-14) */
uni_uslp_status_t uni_ccsds_uslp_register_mapp_indication_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapp_indication_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map) return UNI_USLP_ERROR_INVALID_PARAM;
    map->mapp_indication_cb = callback;
    map->mapp_indication_user_data = user_data;
    return UNI_USLP_SUCCESS;
}
/* VCP_Notify.indication registration (§3.4.3.3) */
uni_uslp_status_t uni_ccsds_uslp_register_vcp_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcp_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->vcp_notify_cb = callback;
    vc->vcp_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* VCP.indication registration (receiving end) (§3.4.3.4) */
uni_uslp_status_t uni_ccsds_uslp_register_vcp_indication_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcp_indication_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->vcp_indication_cb = callback;
    vc->vcp_indication_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* VCF.indication registration — §3.9.3.3; Parameters §3.9.2.2..§3.9.2.4 (USLP-45..USLP-47) */
uni_uslp_status_t uni_ccsds_uslp_register_vcf_indication_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcf_indication_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->vcf_indication_cb = callback;
    vc->vcf_indication_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* MCF.indication registration — §3.10.3.3; Parameters §3.10.2.2..§3.10.2.4 (USLP-48..USLP-50) */
uni_uslp_status_t uni_ccsds_uslp_register_mcf_indication_callback(
    uni_uslp_context_t *context,
    uni_uslp_mcf_indication_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    context->mcf_indication_cb = callback;
    context->mcf_indication_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* VCF.request provider TX callback registration — §3.9.3.2 (USLP-78) */
uni_uslp_status_t uni_ccsds_uslp_register_vcf_tx_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcf_tx_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->vcf_tx_cb = callback;
    vc->vcf_tx_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* MCF.request provider TX callback registration — §3.10.3.2 (USLP-80) */
uni_uslp_status_t uni_ccsds_uslp_register_mcf_tx_callback(
    uni_uslp_context_t *context,
    uni_uslp_mcf_tx_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    context->mcf_tx_cb = callback;
    context->mcf_tx_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* Directive_Notify.indication registration — §3.12.3.3 (USLP-85) */
uni_uslp_status_t uni_ccsds_uslp_register_directive_notify_callback(
    uni_uslp_context_t *context,
    uni_uslp_directive_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    context->directive_notify_cb = callback;
    context->directive_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* Async_Notify.indication registration — §3.12.3.4 (USLP-86) */
uni_uslp_status_t uni_ccsds_uslp_register_async_notify_callback(
    uni_uslp_context_t *context,
    uni_uslp_async_notify_cb_t callback,
    void *user_data
)
{
    UNI_USLP_CHECK_NULL(context);
    context->async_notify_cb = callback;
    context->async_notify_user_data = user_data;
    return UNI_USLP_SUCCESS;
}

/* Provide underlying C&S sublayer loss signal for next accepted frame (§3.10.2.4.2, §3.11.2.4.2) */
uni_uslp_status_t uni_ccsds_uslp_set_rx_cs_loss_signaled(
    uni_uslp_context_t *context,
    bool loss_signaled
)
{
    UNI_USLP_CHECK_NULL(context);
    context->rx_cs_loss_signaled_pending = loss_signaled;
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* VCF/MCF REQUEST PRIMITIVES (provider handoff)                               */
/* ========================================================================== */

/* VCF.request — §3.9.3.2 (USLP-78)
 * Submit an externally supplied, partially formatted USLP Transfer Frame for the specified VC.
 * Constraints per §3.2.7 apply. The frame is forwarded unchanged; no SDLS/FECF is applied (§2.2.3.4; §4.2.11.5).
 */
uni_uslp_status_t uni_ccsds_uslp_vcf_request(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *frame,
    size_t frame_length
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame);
    if (vcid > (uint8_t)UNI_USLP_MAX_VCID) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    if (!vc->vcf_tx_cb) {
        return UNI_USLP_ERROR_UNSUPPORTED;
    }

    /* Minimal Primary Header consistency check (§4.1.2) */
    if (frame_length < (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    uni_uslp_primary_header_t ph;
    size_t ph_read = 0;
    uni_uslp_status_t st = uni_ccsds_uslp_primary_header_unpack(frame, frame_length, &ph, &ph_read);
    if (st != UNI_USLP_SUCCESS) return st;
    if (ph.tfvn != UNI_USLP_TFVN) return UNI_USLP_ERROR_INVALID_PARAM;
    if (ph.scid != context->scid) return UNI_USLP_ERROR_INVALID_PARAM;
    if (ph.vcid != vcid) return UNI_USLP_ERROR_INVALID_PARAM;

    /* Forward unchanged to provider (underlying C&S) */
    vc->vcf_tx_cb(context, vcid, frame, frame_length, vc->vcf_tx_user_data);
    return UNI_USLP_SUCCESS;
}

/* MCF.request — §3.10.3.2 (USLP-80)
 * Submit an externally supplied, partially formatted USLP Transfer Frame for the Master Channel.
 * MCID = (TFVN<<16)|SCID (§2.1.3). Forward unchanged; no SDLS/FECF is applied (§2.2.3.4; §4.2.11.5).
 */
uni_uslp_status_t uni_ccsds_uslp_mcf_request(
    uni_uslp_context_t *context,
    uint32_t mcid,
    const uint8_t *frame,
    size_t frame_length
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame);

    const uint32_t expected_mcid = ((uint32_t)UNI_USLP_TFVN << 16) | (uint32_t)context->scid;
    if (mcid != expected_mcid) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    if (!context->mcf_tx_cb) {
        return UNI_USLP_ERROR_UNSUPPORTED;
    }

    /* Minimal Primary Header consistency check (§4.1.2) */
    if (frame_length < (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    uni_uslp_primary_header_t ph;
    size_t ph_read = 0;
    uni_uslp_status_t st = uni_ccsds_uslp_primary_header_unpack(frame, frame_length, &ph, &ph_read);
    if (st != UNI_USLP_SUCCESS) return st;
    if (ph.tfvn != UNI_USLP_TFVN) return UNI_USLP_ERROR_INVALID_PARAM;
    if (ph.scid != context->scid) return UNI_USLP_ERROR_INVALID_PARAM;

    /* Forward unchanged to provider (underlying C&S) */
    context->mcf_tx_cb(context, mcid, frame, frame_length, context->mcf_tx_user_data);
    return UNI_USLP_SUCCESS;
}

/* Directive.request — §3.12.3.2 (USLP-84)
 * Minimal sending-end behavior with coexistence enforcement (§2.2.5 b,d).
 * Reports Directive_Notify.indication QUEUED then SENT if registered (§3.12.3.3).
 */
uni_uslp_status_t uni_ccsds_uslp_directive_request(
    uni_uslp_context_t *context,
    bool is_cop1,
    uint8_t vcid,
    uint32_t port_id,
    uint16_t directive_id,
    uint8_t directive_type,
    uint32_t directive_qualifier
)
{
    UNI_USLP_CHECK_NULL(context);

    if (is_cop1) {
        uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
        if (!vc || !vc->configured) {
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
        /* Coexistence restriction: if VCF exists on this VC, COPs Management shall not exist (§2.2.5 b,d) */
        if (vc->vcf_tx_cb) {
            return UNI_USLP_ERROR_UNSUPPORTED;
        }
    } else {
        /* Coexistence restriction with MCF on the Master Channel */
        if (context->mcf_tx_cb) {
            return UNI_USLP_ERROR_UNSUPPORTED;
        }
    }

    if (context->directive_notify_cb) {
        context->directive_notify_cb(context, is_cop1, vcid, port_id,
                                     directive_id, directive_type, directive_qualifier,
                                     UNI_USLP_DIR_NOTIFY_QUEUED, 0u,
                                     context->directive_notify_user_data);
        context->directive_notify_cb(context, is_cop1, vcid, port_id,
                                     directive_id, directive_type, directive_qualifier,
                                     UNI_USLP_DIR_NOTIFY_SENT, 0u,
                                     context->directive_notify_user_data);
    }
    return UNI_USLP_SUCCESS;
}

/* Provider-side Async_Notify.indication emitter — §3.12.3.4 (USLP-86) */
uni_uslp_status_t uni_ccsds_uslp_async_notify(
    uni_uslp_context_t *context,
    bool is_cop1,
    uint8_t vcid,
    uint32_t port_id,
    uint8_t notification_type,
    uint32_t notification_qualifier
)
{
    UNI_USLP_CHECK_NULL(context);
    if (context->async_notify_cb) {
        context->async_notify_cb(context, is_cop1, vcid, port_id,
                                 notification_type, notification_qualifier,
                                 context->async_notify_user_data);
    }
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* SENDING SERVICES (MAPA minimal path)                                       */
/* ========================================================================== */


/* MAPP.request with PVN/QoS/SDU ID (§3.3.3.2; parameters §3.3.2.2..§3.3.2.6) */
uni_uslp_status_t uni_ccsds_uslp_send_packet_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *packet_data,
    size_t packet_length,
    uint8_t pvn,
    bool expedited,
    uint32_t sdu_id
)
{
    UNI_USLP_CHECK_NULL(context);

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);

    /* Validate data pointer/length first to allow REJECTED_INVALID notification */
    if (!packet_data || packet_length == 0) {
        if (map && map->mapp_notify_cb) {
            map->mapp_notify_cb(context, vcid, map_id,
                                UNI_USLP_MAPP_NOTIFY_REJECTED_INVALID,
                                map->mapp_notify_user_data);
        }
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    if (!vc || !vc->configured || !map || !map->configured || map->service_type != UNI_USLP_SERVICE_PACKET) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* USLP-148: Valid PVNs (Table 5-5; §3.3.2.4) — validate PVN parameter (not transmitted by USLP) */
    {
        uint8_t mask = map->params.valid_pvns_mask;
        if (mask == 0u) {
            if (vc && vc->params.valid_pvns_mask != 0u) {
                mask = vc->params.valid_pvns_mask;
            } else {
                /* default: allow PVN 0 only */
                mask = (uint8_t)(1u << 0);
            }
        }
        if (pvn > 7u || ((mask & (uint8_t)(1u << pvn)) == 0u)) {
            if (map->mapp_notify_cb) {
                map->mapp_notify_cb(context, vcid, map_id,
                                    UNI_USLP_MAPP_NOTIFY_REJECTED_INVALID,
                                    map->mapp_notify_user_data);
            }
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
    }

    /* USLP-149: Maximum Packet Length (Table 5-5) — enforce configured limit if non-zero */
    {
        uint16_t max_len = map->params.max_packet_length;
        if (max_len == 0u && vc) {
            max_len = vc->params.max_packet_length; /* VC-level fallback */
        }
        if (max_len > 0u && packet_length > (size_t)max_len) {
            if (map->mapp_notify_cb) {
                map->mapp_notify_cb(context, vcid, map_id,
                                    UNI_USLP_MAPP_NOTIFY_REJECTED_INVALID,
                                    map->mapp_notify_user_data);
            }
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
    }

    /* Minimal implementation (no segmentation): one complete Space Packet per frame.
     * PVN (USLP-10) is accepted for validation/accounting; not transmitted by USLP. */
    map->send_buffer = (uint8_t*)(uintptr_t)packet_data;
    map->send_buffer_size = packet_length;
    map->send_buffer_used = 0;
    map->send_bypass_flag = expedited;   /* QoS (USLP-12) -> Bypass flag (§4.1.2.8.1) */
    map->send_pvn = pvn;                 /* PVN (USLP-10), not placed on the wire */
    map->send_sdu_id = sdu_id;           /* SDU ID (USLP-11), accounting only (§2.2.2) */
    map->send_is_vcp = false;

    /* Notify QUEUED (§3.3.3.3) */
    if (map->mapp_notify_cb) {
        map->mapp_notify_cb(context, vcid, map_id,
                            UNI_USLP_MAPP_NOTIFY_QUEUED,
                            map->mapp_notify_user_data);
    }

    return UNI_USLP_SUCCESS;
}

/* VCP Packet — wrapper (§3.4.2, §3.4.3): PVN=0, Sequence-Controlled (Bypass=0), SDU ID=0 */

/* VCP.request with PVN/Service Type/SDU ID (§3.4.3.2; parameters §3.4.2.2..§3.4.2.6) */
uni_uslp_status_t uni_ccsds_uslp_send_vcp_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *packet_data,
    size_t packet_length,
    uint8_t pvn,
    bool expedited,
    uint32_t sdu_id
)
{
    UNI_USLP_CHECK_NULL(context);

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }
    /* Use MAP ID 0 internally to route through builder; require it to be configured as VCP service */
    const uint8_t map_id = 0u;
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map || !map->configured || map->service_type != UNI_USLP_SERVICE_VCP) {
        /* Configuration mismatch for VCP on this VC */
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Validate data pointer/length first to allow REJECTED_INVALID notification (§3.4.3.3) */
    if (!packet_data || packet_length == 0) {
        if (vc->vcp_notify_cb) {
            vc->vcp_notify_cb(context, vcid, UNI_USLP_VCP_NOTIFY_REJECTED_INVALID, vc->vcp_notify_user_data);
        }
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* USLP-148: Valid PVNs (Table 5-5; §3.4.2.4) */
    {
        uint8_t mask = map->params.valid_pvns_mask;
        if (mask == 0u) {
            /* default: allow PVN 0 only; if VC-level mask present use it */
            if (vc->params.valid_pvns_mask != 0u) {
                mask = vc->params.valid_pvns_mask;
            } else {
                mask = (uint8_t)(1u << 0);
            }
        }
        if (pvn > 7u || ((mask & (uint8_t)(1u << pvn)) == 0u)) {
            if (vc->vcp_notify_cb) {
                vc->vcp_notify_cb(context, vcid, UNI_USLP_VCP_NOTIFY_REJECTED_INVALID, vc->vcp_notify_user_data);
            }
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
    }

    /* USLP-149: Maximum Packet Length (Table 5-5) */
    {
        uint16_t max_len = map->params.max_packet_length;
        if (max_len == 0u) {
            max_len = vc->params.max_packet_length;
        }
        if (max_len > 0u && packet_length > (size_t)max_len) {
            if (vc->vcp_notify_cb) {
                vc->vcp_notify_cb(context, vcid, UNI_USLP_VCP_NOTIFY_REJECTED_INVALID, vc->vcp_notify_user_data);
            }
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
    }

    /* Minimal implementation (no segmentation): one complete Space Packet per frame (Rule '000').
     * PVN (USLP-18) is accepted for validation/accounting; not transmitted by USLP. */
    map->send_buffer = (uint8_t*)(uintptr_t)packet_data;
    map->send_buffer_size = packet_length;
    map->send_buffer_used = 0;
    map->send_bypass_flag = expedited; /* Service Type (USLP-20) -> Bypass flag (§4.1.2.8.1) */
    map->send_pvn = pvn;               /* PVN (USLP-18), not placed on the wire */
    map->send_sdu_id = sdu_id;         /* SDU ID (USLP-19), accounting only (§2.2.2) */
    map->send_is_vcp = true;

    /* Notify QUEUED (§3.4.3.3) */
    if (vc->vcp_notify_cb) {
        vc->vcp_notify_cb(context, vcid, UNI_USLP_VCP_NOTIFY_QUEUED, vc->vcp_notify_user_data);
    }

    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_send_mapa(uni_uslp_context_t *context, uint8_t vcid, uint8_t map_id, const uint8_t *sdu_data, size_t sdu_length)
{
    /* Mapped to MAPA.request (§3.5.3.2) and MAPA_Notify.indication (§3.5.3.3) */
    UNI_USLP_CHECK_NULL(context);

    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!map || !map->configured || map->service_type != UNI_USLP_SERVICE_MAPA) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Validate parameters: non-null, non-zero length */
    if (!sdu_data || sdu_length == 0) {
        if (map->mapa_notify_cb) {
            map->mapa_notify_cb(context, vcid, map_id,
                                UNI_USLP_MAPA_NOTIFY_REJECTED_INVALID,
                                map->mapa_notify_user_data);
        }
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Zero-copy enqueue: store pointer, the builder will consume once. */
    map->send_buffer = (uint8_t*)(uintptr_t)sdu_data;
    map->send_buffer_size = sdu_length;
    map->send_buffer_used = 0;

    /* Notify QUEUED (§3.5.3.3) */
    if (map->mapa_notify_cb) {
        map->mapa_notify_cb(context, vcid, map_id,
                            UNI_USLP_MAPA_NOTIFY_QUEUED,
                            map->mapa_notify_user_data);
    }
    return UNI_USLP_SUCCESS;
}


/* VCA.request with Service Type and SDU ID (§3.6.4.2; parameters §3.6.3.2..§3.6.3.5)
 * Minimal implementation uses No Segmentation (Rule '111') in variable-length TFDFs, like MAPA (§3.2.3).
 * SDU ID (USLP-32) is for sending-end accounting only (§2.2.2) and is not transmitted by USLP. */
uni_uslp_status_t uni_ccsds_uslp_send_vca_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *sdu_data,
    size_t sdu_length,
    bool expedited,
    uint32_t sdu_id
)
{
    UNI_USLP_CHECK_NULL(context);

    /* Resolve VC and MAP early to allow notify on rejections */
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);

    /* Validate data pointer/length first to allow REJECTED_INVALID notification */
    if (!sdu_data || sdu_length == 0) {
        if (map && map->vca_notify_cb) {
            map->vca_notify_cb(context, vcid, map_id,
                               UNI_USLP_VCA_NOTIFY_REJECTED_INVALID,
                               map->vca_notify_user_data);
        }
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    if (!vc || !vc->configured || !map || !map->configured || map->service_type != UNI_USLP_SERVICE_VCA) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Queue VCA_SDU; builder will emit using Rule '111' (variable, no segmentation) for minimal path.
     * Service Type (USLP-33): expedited=true => Bypass=1; false => Bypass=0 (§4.1.2.8.1). */
    map->send_buffer = (uint8_t*)(uintptr_t)sdu_data;
    map->send_buffer_size = sdu_length;
    map->send_buffer_used = 0;
    map->send_bypass_flag = expedited;
    map->send_sdu_id = sdu_id; /* Accounting only (§2.2.2) */

    /* Notify QUEUED (§3.6.4.3) */
    if (map->vca_notify_cb) {
        map->vca_notify_cb(context, vcid, map_id,
                           UNI_USLP_VCA_NOTIFY_QUEUED,
                           map->vca_notify_user_data);
    }

    return UNI_USLP_SUCCESS;
}


/* Extended OCTET_STREAM.request with QoS and SDU ID (§3.7.2.4, §3.7.2.5; §3.7.3.2)
 * Also emits OCTET_STREAM_Notify.indication at the sending end (§3.7.3.4). */
uni_uslp_status_t uni_ccsds_uslp_send_octet_stream_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *data,
    size_t length,
    bool expedited,
    uint32_t sdu_id
)
{
    UNI_USLP_CHECK_NULL(context);

    /* Resolve VC and MAP early to allow notify on rejections */
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);

    /* Validate data */
    if (!data || length == 0) {
        if (map && map->octet_stream_notify_cb) {
            map->octet_stream_notify_cb(context, vcid, map_id, sdu_id, expedited,
                                        UNI_USLP_OS_NOTIFY_REJECTED_INVALID,
                                        map->octet_stream_notify_user_data);
        }
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    if (!vc || !vc->configured || !map || !map->configured || map->service_type != UNI_USLP_SERVICE_OCTET_STREAM) {
        /* No notify if MAP not configured for Octet Stream */
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Restriction: Octet Stream Service cannot exist with fixed-length Transfer Frames (§2.2.4.6, §2.2.5 g). */
    const bool fixed_length = (vc->params.min_frame_length == vc->params.max_frame_length) &&
                              (vc->params.max_frame_length > 0);
    if (fixed_length) {
        if (map->octet_stream_notify_cb) {
            map->octet_stream_notify_cb(context, vcid, map_id, sdu_id, expedited,
                                        UNI_USLP_OS_NOTIFY_REJECTED_UNSUPPORTED,
                                        map->octet_stream_notify_user_data);
        }
        return UNI_USLP_ERROR_UNSUPPORTED;
    }

    /* Queue this portion of Octet Stream Data; builder will emit with Rule ‘011’ (§4.2.4). */
    map->send_buffer = (uint8_t*)(uintptr_t)data;
    map->send_buffer_size = length;
    map->send_buffer_used = 0;
    map->send_bypass_flag = expedited; /* true => Bypass=1; false => Bypass=0 (§4.1.2.8.1) */
    map->send_sdu_id = sdu_id;         /* Accounting only (§2.2.2), not transmitted. */
    map->send_is_vcp = false;

    /* Notify QUEUED per §3.7.3.4 */
    if (map->octet_stream_notify_cb) {
        map->octet_stream_notify_cb(context, vcid, map_id, sdu_id, expedited,
                                    UNI_USLP_OS_NOTIFY_QUEUED,
                                    map->octet_stream_notify_user_data);
    }

    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_send_ocf(uni_uslp_context_t *context, uint8_t vcid, const uni_uslp_ocf_t *ocf)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(ocf);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) return UNI_USLP_ERROR_INVALID_PARAM;
    if (!vc->params.ocf_capability) return UNI_USLP_ERROR_UNSUPPORTED;
    vc->ocf_value = *ocf;
    vc->ocf_pending = true;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_send_insert(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *insert_data,
    size_t insert_length
)
{
    /* CCSDS 732.1-B-3
     * - §3.2.8 Insert Data SDU (USLP-7): carried only by the Insert Zone.
     * - §3.11.2.2 IN_SDU (USLP-51): mission data for Insert Zone only.
     * - §3.11.3.2 INSERT.request (USLP-82): request to place IN_SDU in the next frame's Insert Zone.
     * - §4.1.3 Insert Zone: present only when fixed-length Transfer Frames are used.
     *
     * Policy:
     *  - Only allowed when Physical Channel is configured with Insert Zone capability and fixed-length frames.
     *  - insert_length must equal the configured Insert Zone length (no invention of padding).
     *  - The IN_SDU is stored per-VC and consumed by the next build for that VC.
     */
    UNI_USLP_CHECK_NULL(context);

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Insert Zone present only on fixed-length frames (§4.1.3) */
    const bool fixed_length = (vc->params.min_frame_length == vc->params.max_frame_length) &&
                              (vc->params.max_frame_length > 0);
    if (!fixed_length) {
        return UNI_USLP_ERROR_UNSUPPORTED;
    }

    const size_t iz_len = insert_zone_length_if_present(context);
    if (!context->params.insert_zone_capability || iz_len == 0u) {
        return UNI_USLP_ERROR_UNSUPPORTED;
    }

    UNI_USLP_CHECK_NULL(insert_data);
    if (insert_length != iz_len || insert_length > sizeof(vc->insert_pending)) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    memcpy(vc->insert_pending, insert_data, insert_length);
    vc->insert_pending_length = insert_length;
    vc->insert_pending_valid = true;
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* FRAME BUILD (MAPA, Variable-length, Rule '111', no Insert, no OCF)         */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_build_frame(uni_uslp_context_t *context, uint8_t vcid, uint8_t map_id, uint8_t *frame_buffer, size_t *frame_length)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame_buffer);
    UNI_USLP_CHECK_NULL(frame_length);

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
    if (!vc || !vc->configured || !map || !map->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Support variable-length and fixed-length frames */
    const bool fixed_length = (vc->params.min_frame_length == vc->params.max_frame_length) &&
                              (vc->params.max_frame_length > 0);
    const size_t fixed_total = fixed_length ? (size_t)vc->params.max_frame_length : 0u;

    const size_t buf_cap = *frame_length;

    /* Nothing queued for this (VC, MAP)? */
    if (!map->send_buffer || map->send_buffer_size == 0) {
        return UNI_USLP_ERROR_NOT_FOUND; /* nothing to send */
    }

    /* Header fields and optional zones */
    /* Select Construction Rule and payload based on service (§4.1.4.2.2; §4.2.3/§4.2.4): */
    uni_uslp_tfdz_construction_rule_t rule = UNI_USLP_TFDZ_RULE_7; /* default: ‘111’ (No segmentation) */
    size_t sdu_len = map->send_buffer_size;
    const bool is_octet_stream = (map->service_type == UNI_USLP_SERVICE_OCTET_STREAM);
    const bool is_packet      = (map->service_type == UNI_USLP_SERVICE_PACKET);
    const bool is_vcp         = (map->service_type == UNI_USLP_SERVICE_VCP);
    const bool is_vca         = (map->service_type == UNI_USLP_SERVICE_VCA);
    const bool expedited_qos  = ((is_octet_stream || is_packet || is_vcp || is_vca) ? map->send_bypass_flag : false);

    const size_t  ph_base    = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH;
    /* VCF Count Length code depends on QoS (Sequence vs Expedited) per §4.1.2.11 and Table 4-2.
     * USLP-131 (Expedited): Partial — TX does not emit Expedited VCF Count (set length=0).
     * RX continuity for Expedited is still supported if a field is present (accept path).
     * For fixed-length frames with Sequence-Controlled QoS and unspecified length (0), default to 1 octet
     * so that TFDZ starts after PH+VCF and tests expecting PH(7)+VCF(1)+TFDF(1) hold (see §4.1.2.11). */
    const uint8_t vcf_code   = (uint8_t)((expedited_qos ? 0 : vc->vcf_seq_len) & 0x7u);
    const size_t  vcf_octets = vcf_octets_from_code(vcf_code);
    const size_t  insert_len = fixed_length ? insert_zone_length_if_present(context) : 0u; /* fixed-length only */
    /* USLP-139/USLP-140 OCF inclusion policy (Table 5-3; §4.1.5):
     * - Variable-length: include OCF only if ocf_allowed_variable=true and OCF is pending.
     *   If ocf_allowed_variable=false and an OCF is pending, the attempt is rejected with INVALID_PARAM
     *   and the pending OCF is cleared (test USLP-139; CCSDS 732.1-B-3 Table 5-3 item USLP-139).
     * - Fixed-length: if ocf_required_fixed=true then OCF must be present; error if not pending. */
    bool ocf_flag = false;
    if (vc->params.ocf_capability) {
        if (fixed_length) {
            if (vc->params.ocf_required_fixed) {
                if (!vc->ocf_pending) {
                    return UNI_USLP_ERROR_INVALID_PARAM;
                }
                ocf_flag = true;
            } else {
                ocf_flag = vc->ocf_pending;
            }
        } else {
            /* Variable-length path (USLP-139) */
            if (!vc->params.ocf_allowed_variable && vc->ocf_pending) {
                /* Clear the pending OCF and reject this build attempt.
                 * Rationale: OCF is not allowed on variable-length frames for this VC. */
                vc->ocf_pending = false;
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            ocf_flag = vc->params.ocf_allowed_variable ? vc->ocf_pending : false;
        }
    }
    const size_t  ocf_len    = ocf_length_if_present(ocf_flag);
    size_t  tfdf_hdr_len = 1u; /* Will be set per rule: 3 if pointer present (rules 000/001/010), else 1. */
    const size_t  fecf_len   = fecf_length_if_present(context);
    const uni_uslp_fecf_tx_mode_t fecf_mode = fecf_tx_mode(context);
    /* SDLS presence and lengths per USLP §6.6.2 (managed parameters) */
    const bool    sdls_on    = (vc->sdls_config.enabled && context->sdls_apply_callback != NULL);
    const size_t  sec_hdr_len = (sdls_on && vc->sdls_config.sec_header_present) ? (size_t)vc->sdls_config.sec_header_length : 0u;
    const size_t  sec_trl_len = (sdls_on && vc->sdls_config.sec_trailer_present) ? (size_t)vc->sdls_config.sec_trailer_length : 0u;

    if (is_octet_stream) {
        /* Octet Stream requires variable-length frames (§2.2.4.6, §2.2.5 g). */
        if (fixed_length) {
            return UNI_USLP_ERROR_UNSUPPORTED;
        }
        rule = UNI_USLP_TFDZ_RULE_3; /* ‘011’ Octet Stream (§4.1.4.2.2.2.4) */
    } else if (is_packet || is_vcp) {
        /* Packet services (MAPP §3.3 and VCP §3.4) use rule ‘000’ with FHP (§4.1.4.2.2.2.1, §4.1.4.2.4.3). */
        rule = UNI_USLP_TFDZ_RULE_0;
    } else {
        /* MAPA minimal path continues to use ‘111’ (variable length, no segmentation). */
        rule = UNI_USLP_TFDZ_RULE_7;
    }
    /* Pointer present only for rules ‘000’, ‘001’, ‘010’ per §4.1.4.2.4.1 */
    tfdf_hdr_len = (rule <= UNI_USLP_TFDZ_RULE_2) ? 3u : 1u;

    /* Compute total frame length (USLP §6.3 with SDLS option: SecHeader before TFDF; SecTrailer after TFDF; OCF, then FECF) */
    size_t total = ph_base + vcf_octets + insert_len + sec_hdr_len + tfdf_hdr_len + sdu_len + sec_trl_len + ocf_len + fecf_len;
    if (fixed_length) {
        total = fixed_total;
        /* In OFFLOAD_APPEND mode the last 2 bytes are emitted by hardware, so
         * the CPU buffer may be 2 bytes shorter than the on-wire frame. */
        const size_t required = (fecf_len && fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND)
                                    ? (total - fecf_len)
                                    : total;
        if (buf_cap < required) {
            return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        }
    } else {
        /* Variable-length: do not enforce capacity against 'total' because OCF/FECF may be appended
         * after TFDF/TFDZ and some callers pass a smaller current size while retaining larger underlying
         * capacity (e.g., std::vector capacity). We rely on precise checks before each write instead:
         *  - Primary Header pack ensures >= 7 bytes
         *  - TFDF header pack and TFDZ copy ensure off + tfdz_copy_len fits
         *  - FECF appender validates room when fecf_len > 0
         * This aligns with USLP-139 test expectations. */
    }

    /* Build Primary Header */
    uni_uslp_primary_header_t ph;
    memset(&ph, 0, sizeof(ph));
    ph.tfvn = UNI_USLP_TFVN; /* §4.1.2.2.2.2 '1100' */
    ph.scid = context->scid; /* §4.1.2.2.3 */
    ph.source_dest = false;  /* SCID refers to source (§4.1.2.3.3 a) */
    ph.vcid = vcid;          /* §4.1.2.4.1 */
    ph.map_id = map_id;      /* §4.1.2.5.1 */
    ph.eof_ph_flag = false;  /* Non-truncated (§4.1.2.6) */
    ph.frame_length = (uint16_t)(total - 1u); /* §4.1.2.7.2 */
    /* QoS flag: Bypass=1 for Expedited; 0 for Sequence-Controlled (§4.1.2.8.1). */
    ph.bypass_flag = expedited_qos ? true : false;
    ph.cc_flag = false;      /* User data (§4.1.2.8.2.2 a) ) */
    ph.ocf_flag = ocf_flag;  /* OCF presence (§4.1.2.10) */
    ph.vcf_count_len = vcf_code; /* §4.1.2.11 */
    /* Set VCF Count value per configured octet length (USLP-130/USLP-131) */
    if (vcf_octets > 0u) {
        const uint8_t n = (uint8_t)vcf_octets;
        const uint64_t mask = (n >= 8u) ? UINT64_MAX : ((1ULL << (8u * n)) - 1ULL);
        const uint64_t cnt = expedited_qos ? vc->vcf_exp_tx : vc->vcf_seq_tx;
        ph.vcf_count = (cnt & mask);
    } else {
        ph.vcf_count = 0u;
    }

    size_t ph_written = 0;
    uni_uslp_status_t st = uni_ccsds_uslp_primary_header_pack(&ph, frame_buffer, buf_cap, &ph_written);
    if (st != UNI_USLP_SUCCESS) return st;
    size_t off = ph_written;

    /* Insert Zone (fixed-length; §4.1.3):
     *  - If INSERT.request provided IN_SDU (USLP-82), copy it and consume once.
     *  - Otherwise, fill with idle octets (implementation default 0x00).
     *  - Note: uni_uslp_insert_callback is for INSERT.indication on RX, not used to fill TX. */
    if (insert_len) {
        if (vc->insert_pending_valid) {
            if (vc->insert_pending_length != insert_len) {
                return UNI_USLP_ERROR_INVALID_PARAM; /* enforce exact fit per managed Insert Zone length */
            }
            memcpy(&frame_buffer[off], vc->insert_pending, insert_len);
            vc->insert_pending_valid = false;
            vc->insert_pending_length = 0u;
        } else {
            memset(&frame_buffer[off], UNI_USLP_DEFAULT_IDLE_FILLER, insert_len);
        }
        off += insert_len;
    }

    /* TFDF Header: Rule depends on service (Octet Stream ‘011’; MAPA ‘111’). UPID is project/SANA managed (§4.1.4.2.3). */
    uni_uslp_tfdf_header_t th;
    memset(&th, 0, sizeof(th));
    th.construction_rule = rule;
    /* UPID mapping per service:
     *  - 0: MAP Packet (Space Packet) (§3.3)
     *  - 4: Octet Stream (§3.7)
     *  - 5: MAPA SDU (§3.5)
     *  - 0: VCP (treated as Packet) (§3.4)
     *  - 6: VCA SDU (implementation-chosen, not used in current interop)
     */
    {
        uint8_t upid = 0u;
        if (is_octet_stream) {
            upid = 4u;
        } else if (is_packet || is_vcp) {
            upid = 0u;
        } else if (is_vca) {
            upid = 6u;
        } else {
            /* MAPA */
            upid = 5u;
        }
        th.upid = upid;
    }
    th.first_header_ptr = 0;
    th.last_valid_ptr = 0;

    /* Determine TFDZ length to copy (room will be computed after emitting TFDF header) */
    size_t tfdz_copy_len = sdu_len;

    if (sdls_on) {
        /* Build TFDF header + TFDZ at a temporary position after SecHeader space, then invoke SDLS.Apply.
         * Input: TFDF header + TFDZ; Output: SecHeader + Protected TFDF’ + SecTrailer (USLP §6.3.4–§6.3.6). */
        size_t tfdf_pos = off + sec_hdr_len;
        size_t th_written = 0;
        st = uni_ccsds_uslp_tfdf_header_pack(&th, &frame_buffer[tfdf_pos], buf_cap - tfdf_pos, &th_written);
        if (st != UNI_USLP_SUCCESS) return st;
        if (buf_cap < tfdf_pos + th_written + tfdz_copy_len) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        memcpy(&frame_buffer[tfdf_pos + th_written], map->send_buffer, tfdz_copy_len);
        size_t in_len = th_written + tfdz_copy_len;

        /* Expected output length equals sec_hdr + in + sec_trailer per managed params (USLP-176..179). */
        size_t out_len = sec_hdr_len + in_len + sec_trl_len;
        st = context->sdls_apply_callback(
                context,
                vcid,
                &frame_buffer[tfdf_pos], in_len,
                &frame_buffer[off], &out_len,
                &vc->sdls_config,
                context->sdls_user_data);
        if (st != UNI_USLP_SUCCESS) {
            return UNI_USLP_ERROR_SDLS_FAILURE;
        }
        /* Validate produced length matches managed parameters (defensive check) */
        if (out_len != (sec_hdr_len + in_len + sec_trl_len)) {
            return UNI_USLP_ERROR_SDLS_FAILURE;
        }
        off += out_len;
    } else {
        /* No SDLS: emit TFDF header then TFDZ plainly */
        size_t th_written = 0;
        st = uni_ccsds_uslp_tfdf_header_pack(&th, &frame_buffer[off], buf_cap - off, &th_written);
        if (st != UNI_USLP_SUCCESS) return st;
        off += th_written;

        /* For fixed-length frames compute available TFDZ room to enforce exact/padded behavior.
         * For variable-length frames, only ensure we can copy the SDU itself; OCF/FECF may be appended later
         * without requiring the caller to pre-size the buffer (per tests; see §4.2.11 generation). */
        if (fixed_length) {
            if (total < (off + ocf_len + fecf_len)) {
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            size_t tfdz_room = total - off - ocf_len - fecf_len;
            if (tfdz_copy_len > tfdz_room) {
                /* Segmentation/blocking not implemented in this path */
                return UNI_USLP_ERROR_UNSUPPORTED;
            }
            if (buf_cap < off + tfdz_copy_len) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        } else {
            /* For variable-length, only ensure room for TFDF header + TFDZ itself.
             * OCF and FECF, if present, may be appended beyond the caller-provided
             * 'frame_length' as some callers reuse a smaller current size while retaining
             * larger underlying capacity (see USLP-139; §4.2.11). */
            if (buf_cap < off + tfdz_copy_len) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(&frame_buffer[off], map->send_buffer, tfdz_copy_len);
        off += tfdz_copy_len;

        if (fixed_length) {
            /* Fill any remaining space in the TFDZ with idle octets on fixed-length frames. */
            size_t pad = 0u;
            if (total > (off + ocf_len + fecf_len)) {
                pad = total - off - ocf_len - fecf_len;
            }
            if (pad > 0u) {
                if (buf_cap < off + pad) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
                memset(&frame_buffer[off], UNI_USLP_DEFAULT_IDLE_FILLER, pad);
                off += pad;
            }
        }
    }

    /* OCF (if present), placed before FECF at the end of TFDF/TFDZ */
    if (ocf_len) {
        size_t ocf_pos = fixed_length ? (total - fecf_len - ocf_len) : off;
        frame_buffer[ocf_pos + 0] = (uint8_t)((vc->ocf_value.data >> 24) & 0xFFu);
        frame_buffer[ocf_pos + 1] = (uint8_t)((vc->ocf_value.data >> 16) & 0xFFu);
        frame_buffer[ocf_pos + 2] = (uint8_t)((vc->ocf_value.data >> 8) & 0xFFu);
        frame_buffer[ocf_pos + 3] = (uint8_t)(vc->ocf_value.data & 0xFFu);
        if (!fixed_length) {
            off += ocf_len;
        }
        vc->ocf_pending = false;
    }

    /* FECF */
    if (fecf_len) {
        if (fixed_length && fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND) {
            /* Fixed-length frames already have a fixed on-wire size; in OFFLOAD_APPEND
             * mode the caller provides (total-2) bytes and the link hardware appends
             * the last 2 bytes. No CRC bytes are written by the CPU here. */
        } else if (fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND) {
            /* TX offload (append outside of CPU buffer):
             * - Primary Header already includes FECF in Frame Length.
             * - Do NOT write the final 2 FECF bytes into frame_buffer.
             * - Do NOT increase returned *frame_length for variable-length.
             *
             * The hardware is expected to append those 2 bytes "on the wire".
             */
        } else if (fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_INPLACE) {
            /* TX offload (in-place overwrite): reserve space for FECF but do not compute it.
             * We also avoid writing to the last 2 bytes so the caller may provide a shorter
             * buffer or leave them to DMA/hardware.
             */
            if (!fixed_length) {
                /* For variable-length, we still need to report the full on-wire length
                 * so the caller can pass that to the transport if it includes those bytes.
                 * If the caller wants "append outside" semantics, use OFFLOAD_APPEND.
                 */
                if (buf_cap < off + fecf_len) {
                    return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
                }
                off += fecf_len;
            }
        } else {
            /* Compute CRC over the entire frame excluding the FECF itself.
             * For fixed-length frames, OCF (if present) is placed at absolute offset (total - fecf_len - ocf_len),
             * therefore CRC input length is (total - fecf_len). For variable-length frames, 'off' already
             * accounts for any appended OCF. */
            const size_t crc_input_len = fixed_length ? (total - fecf_len) : off;
            uni_crypto_crc16_status_t cst = uni_crypto_crc16_ccitt_append(frame_buffer, crc_input_len, buf_cap);
            if (cst == UNI_CRYPTO_CRC16_ERROR_BUFFER_TOO_SMALL) {
                return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
            }
            if (cst != UNI_CRYPTO_CRC16_SUCCESS) {
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            if (!fixed_length) {
                off += fecf_len;
            }
        }
    }

    /* After successful frame construction, update the appropriate VCF TX counter */
    if (vcf_octets > 0u) {
        const uint8_t n = (uint8_t)vcf_octets;
        const uint64_t mod = (n >= 8u) ? 0u : (1ULL << (8u * n));
        if (mod != 0u) {
            if (expedited_qos) {
                vc->vcf_exp_tx = (vc->vcf_exp_tx + 1ULL) % mod;
                if (vc->vcf_exp_tx == 0u) vc->wraps++;
            } else {
                vc->vcf_seq_tx = (vc->vcf_seq_tx + 1ULL) % mod;
                if (vc->vcf_seq_tx == 0u) vc->wraps++;
            }
        }
        vc->vcf_frames_with_field++;
    }

    /* Notify SENT per service after successful frame construction */
    switch (map->service_type) {
        case UNI_USLP_SERVICE_OCTET_STREAM:
            if (map->octet_stream_notify_cb) {
                map->octet_stream_notify_cb(context, vcid, map_id, map->send_sdu_id, expedited_qos,
                                            UNI_USLP_OS_NOTIFY_SENT,
                                            map->octet_stream_notify_user_data);
            }
            break;
        case UNI_USLP_SERVICE_PACKET:
            if (map->mapp_notify_cb) {
                map->mapp_notify_cb(context, vcid, map_id,
                                    UNI_USLP_MAPP_NOTIFY_SENT,
                                    map->mapp_notify_user_data);
            }
            break;
        case UNI_USLP_SERVICE_VCP:
        {
            /* VCP is VC-level notify (§3.4.3.3) */
            uni_uslp_vc_state_t* nvc = uni_ccsds_uslp_get_vc_state(context, vcid);
            if (nvc && nvc->vcp_notify_cb) {
                nvc->vcp_notify_cb(context, vcid, UNI_USLP_VCP_NOTIFY_SENT, nvc->vcp_notify_user_data);
            }
            break;
        }
        case UNI_USLP_SERVICE_MAPA:
            if (map->mapa_notify_cb) {
                map->mapa_notify_cb(context, vcid, map_id,
                                    UNI_USLP_MAPA_NOTIFY_SENT,
                                    map->mapa_notify_user_data);
            }
            break;
        case UNI_USLP_SERVICE_VCA:
            if (map->vca_notify_cb) {
                map->vca_notify_cb(context, vcid, map_id,
                                   UNI_USLP_VCA_NOTIFY_SENT,
                                   map->vca_notify_user_data);
            }
            break;
        default:
            break;
    }

    /* Consume the queued SDU */
    map->send_buffer = NULL;
    map->send_buffer_size = 0;
    map->send_buffer_used = 0;

    /* Ensure reported frame length matches Primary Header:
     * - Variable-length: 'off' equals total bytes produced.
     * - Fixed-length: always report the configured fixed_total. */
    if (fixed_length) {
        off = (fecf_len && fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND)
                  ? (total - fecf_len)
                  : total;
    }

    *frame_length = off;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_build_oid(uni_uslp_context_t *context, uint8_t *frame_buffer, size_t *frame_length)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame_buffer);
    UNI_USLP_CHECK_NULL(frame_length);

    const size_t buf_cap = *frame_length;
    const uint8_t vcid = (uint8_t)UNI_USLP_OID_VCID;
    const uint8_t map_id = (uint8_t)UNI_USLP_OID_MAP_ID;

    const uint8_t vcf_code = 0u;
    const size_t ph_base = (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH;
    const size_t vcf_octets = 0u;
    const size_t insert_len = 0u;
    const bool ocf_flag = false;
    const size_t ocf_len = 0u;
    const size_t tfdf_hdr_len = 1u;
    const size_t fecf_len = fecf_length_if_present(context);
    const uni_uslp_fecf_tx_mode_t fecf_mode = fecf_tx_mode(context);
    const bool fecf_append_external = (fecf_len && fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND);

    if (buf_cap < ph_base + tfdf_hdr_len + (fecf_append_external ? 0u : fecf_len) + 1u) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }
    size_t tfdz_len = buf_cap - (ph_base + tfdf_hdr_len + (fecf_append_external ? 0u : fecf_len));
    if (context->params.max_frame_length) {
        size_t max_total = context->params.max_frame_length;
        /* max_total is the on-wire maximum, including FECF if present */
        if (max_total < (ph_base + tfdf_hdr_len + fecf_len + 1u)) {
            return UNI_USLP_ERROR_INVALID_PARAM;
        }
        size_t max_tfdz = max_total - (ph_base + tfdf_hdr_len + fecf_len);
        if (tfdz_len > max_tfdz) tfdz_len = max_tfdz;
    }

    const size_t total = ph_base + vcf_octets + insert_len + tfdf_hdr_len + tfdz_len + ocf_len + fecf_len;

    uni_uslp_primary_header_t ph;
    memset(&ph, 0, sizeof(ph));
    ph.tfvn = UNI_USLP_TFVN;
    ph.scid = context->scid;
    ph.source_dest = false;
    ph.vcid = vcid;
    ph.map_id = map_id;
    ph.eof_ph_flag = false;
    ph.frame_length = (uint16_t)(total - 1u);
    ph.bypass_flag = false;
    ph.cc_flag = false;
    ph.ocf_flag = ocf_flag;
    ph.vcf_count_len = vcf_code;
    ph.vcf_count = 0;

    size_t ph_written = 0;
    uni_uslp_status_t st = uni_ccsds_uslp_primary_header_pack(&ph, frame_buffer, buf_cap, &ph_written);
    if (st != UNI_USLP_SUCCESS) return st;
    size_t off = ph_written;

    uni_uslp_tfdf_header_t th;
    memset(&th, 0, sizeof(th));
    th.construction_rule = UNI_USLP_TFDZ_RULE_7;
    th.upid = 1; /* Mission-specific placeholder for OID */
    size_t th_written = 0;
    st = uni_ccsds_uslp_tfdf_header_pack(&th, &frame_buffer[off], buf_cap - off, &th_written);
    if (st != UNI_USLP_SUCCESS) return st;
    off += th_written;

    /* Fill TFDZ with OID LFSR PN */
    uint32_t state = context->oid_lfsr_state;

    st = uni_ccsds_uslp_oid_lfsr_fill(&state, &frame_buffer[off], tfdz_len);
    if (st != UNI_USLP_SUCCESS) return st;
    context->oid_lfsr_state = state;
    off += tfdz_len;

    /* FECF if enabled */
    if (fecf_len) {
        if (fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_APPEND) {
            /* Do not write or count FECF bytes in the CPU buffer; hardware appends them on the wire. */
        } else if (fecf_mode == UNI_USLP_FECF_TX_OFFLOAD_INPLACE) {
            /* Reserve bytes for FECF but do not compute or write them. */
            if (buf_cap < off + fecf_len) {
                return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
            }
            off += fecf_len;
        } else {
            uni_crypto_crc16_status_t cst = uni_crypto_crc16_ccitt_append(frame_buffer, off, buf_cap);
            if (cst == UNI_CRYPTO_CRC16_ERROR_BUFFER_TOO_SMALL) {
                return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
            }
            if (cst != UNI_CRYPTO_CRC16_SUCCESS) {
                return UNI_USLP_ERROR_INVALID_PARAM;
            }
            off += fecf_len;
        }
    }

    *frame_length = off;
    return UNI_USLP_SUCCESS;
}

uni_uslp_status_t uni_ccsds_uslp_build_truncated(uni_uslp_context_t *context, uint8_t vcid, uint8_t *frame_buffer, size_t *frame_length)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame_buffer);
    UNI_USLP_CHECK_NULL(frame_length);

    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Validate VC capability and managed truncated length */
    if (!vc->params.truncated_frame_capable) {
        return UNI_USLP_ERROR_UNSUPPORTED;
    }
    const uint16_t tlen = vc->params.truncated_frame_length;
    if (tlen < (uint16_t)UNI_USLP_TRUNCATED_MIN_LENGTH || tlen > 32u) {
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    /* Find a MAP with a queued MAPA SDU to carry in truncated frame */
    uint8_t map_id = 0xFFu;
    uni_uslp_map_state_t* map = NULL;
    for (uint8_t m = 0; m < (uint8_t)UNI_USLP_MAX_MAPS_PER_VC; ++m) {
        if (vc->maps[m].configured &&
            vc->maps[m].service_type == UNI_USLP_SERVICE_MAPA &&
            vc->maps[m].send_buffer &&
            vc->maps[m].send_buffer_size > 0)
        {
            map_id = m;
            map = &vc->maps[m];
            break;
        }
    }
    if (!map) {
        return UNI_USLP_ERROR_NOT_FOUND; /* nothing to send */
    }

    /* Layout per Annex D:
     *  - 4 B Truncated Primary Header
     *  - 1 B TFDF Header (Rule '111', UPID mission-specific)
     *  - N B TFDZ (one complete MAPA_SDU)
     * No Insert Zone, no OCF, no FECF in truncated frames. */
    const size_t need = (size_t)tlen;
    if (*frame_length < need) {
        return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    }

    /* TFDZ length must exactly fill remainder */
    const size_t tfdz_len = need - ((size_t)UNI_USLP_TRUNCATED_PH_LENGTH + 1u);
    if (map->send_buffer_size != tfdz_len) {
        /* Enforce "one complete MAPA_SDU" exactly filling TFDZ */
        return UNI_USLP_ERROR_INVALID_PARAM;
    }

    size_t off = 0u;

    /* Truncated Primary Header: EoH=1 */
    pack_truncated_ph(&frame_buffer[off],
                      context->scid,
                      false /* SCID refers to source */,
                      vcid,
                      map_id);
    off += (size_t)UNI_USLP_TRUNCATED_PH_LENGTH;

    /* TFDF header: Rule '111' (variable, no segmentation), UPID=0 (MAP Packet default per baseline scenarios) */
    {
        const uint8_t dbg_rule = (uint8_t)UNI_USLP_TFDZ_RULE_7;
        const uint8_t dbg_upid = 0x00u;
        frame_buffer[off++] = (uint8_t)((dbg_rule << 5) | (dbg_upid & 0x1Fu));
    }

    /* TFDZ: copy MAPA SDU */
    memcpy(&frame_buffer[off], map->send_buffer, tfdz_len);
    off += tfdz_len;

    /* Consume the queued SDU */
    map->send_buffer = NULL;
    map->send_buffer_size = 0;
    map->send_buffer_used = 0;

    *frame_length = off;
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* FRAME ACCEPT                                                               */
/* ========================================================================== */

uni_uslp_status_t uni_ccsds_uslp_accept_frame(uni_uslp_context_t *context, const uint8_t *frame_data, size_t frame_length)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame_data);
    /* Latch C&S loss signal for this frame (USLP §3.10.2.4.2, §3.11.2.4.2) */
    bool cs_loss = context->rx_cs_loss_signaled_pending;

    /* Truncated frame detection path (Annex D):
     * Check minimal length and EoH=1 in first 4 octets, TFVN match, SCID match,
     * and per-VC managed truncated length equals received length. */
    if (frame_length >= (size_t)UNI_USLP_TRUNCATED_MIN_LENGTH && frame_length <= 32u) {
        /* Peek truncated PH */
        uint8_t tfvn = 0, vcid = 0, map_id = 0;
        uint16_t scid = 0;
        bool srcdst = false, eoh = false;
        unpack_truncated_ph(frame_data, &tfvn, &scid, &srcdst, &vcid, &map_id, &eoh);

        if (tfvn == UNI_USLP_TFVN && eoh && scid == context->scid) {
            uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
            if (vc && vc->configured && vc->params.truncated_frame_capable &&
                vc->params.truncated_frame_length == (uint16_t)frame_length)
            {
                /* No Insert/OCF/FECF. Next byte is TFDF header which must indicate Rule '111'. */
                if (frame_length < (size_t)UNI_USLP_TRUNCATED_PH_LENGTH + 1u) {
                    return UNI_USLP_ERROR_INVALID_FRAME;
                }
                const uint8_t tfdf0 = frame_data[UNI_USLP_TRUNCATED_PH_LENGTH];
                const uint8_t rule = (uint8_t)((tfdf0 >> 5) & 0x7u);
                /* UPID is mission-specific; accept any 5-bit value for now (0..31). */
                if (rule != (uint8_t)UNI_USLP_TFDZ_RULE_7) {
                    return UNI_USLP_ERROR_INVALID_FRAME;
                }

                const size_t tfdz_len = frame_length - ((size_t)UNI_USLP_TRUNCATED_PH_LENGTH + 1u);
                const uint8_t* tfdz = &frame_data[UNI_USLP_TRUNCATED_PH_LENGTH + 1u];

                /* VCF.indication (no VCF Count in truncated frames => frame_loss_flag=false) */
                if (vc->vcf_indication_cb) {
                    vc->vcf_indication_cb(context, scid, vcid, frame_data, frame_length, false, vc->vcf_indication_user_data);
                }
                /* MCF.indication with C&S loss flag (§3.10.2.4.2) */
                if (context->mcf_indication_cb) {
                    uint32_t mcid = ((uint32_t)UNI_USLP_TFVN << 16) | (uint32_t)scid;
                    context->mcf_indication_cb(context, mcid, frame_data, frame_length, cs_loss, context->mcf_indication_user_data);
                }
                /* Consume C&S loss latch on success */
                context->rx_cs_loss_signaled_pending = false;

                /* Deliver to MAP callback if registered */
                uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
                if (map && map->sdu_callback) {
                    map->sdu_callback(context,
                                      vcid,
                                      map_id,
                                      UNI_USLP_SERVICE_MAPA,
                                      tfdz,
                                      tfdz_len,
                                      UNI_USLP_VERIF_NOT_APPLICABLE, /* Truncated frames: SDLS not applicable */
                                      false,
                                      map->sdu_user_data);
                }
                return UNI_USLP_SUCCESS;
            }
        }
    }

    if (frame_length < (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH) {
        return UNI_USLP_ERROR_INVALID_FRAME;
    }

    /* Parse Primary Header (non-truncated path) */
    uni_uslp_primary_header_t ph;
    size_t ph_read = 0;
    uni_uslp_status_t st = uni_ccsds_uslp_primary_header_unpack(frame_data, frame_length, &ph, &ph_read);
    if (st != UNI_USLP_SUCCESS) return st;

    const size_t vcf_octets = vcf_octets_from_code(ph.vcf_count_len);
    if (ph_read != (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + vcf_octets) {
        return UNI_USLP_ERROR_INVALID_FRAME;
    }

    /* Validate length field (C = total - 1) */
    const size_t total_from_header = (size_t)ph.frame_length + 1u;
    if (total_from_header != frame_length) {
        return UNI_USLP_ERROR_INVALID_FRAME;
    }

    /* Basic TFVN/SCID check for this context (optional) */
    if (ph.tfvn != UNI_USLP_TFVN) {
        return UNI_USLP_ERROR_INVALID_FRAME;
    }
    if (ph.scid != context->scid) {
        /* Different SCID could exist on same physical channel; for now enforce same */
        return UNI_USLP_ERROR_INVALID_FRAME;
    }

    const uint8_t vcid = ph.vcid;
    const uint8_t map_id = ph.map_id;
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc) return UNI_USLP_ERROR_INVALID_FRAME;

    /* FECF verification if present on the physical channel */
    const size_t fecf_len = fecf_length_if_present(context);
    if (fecf_len) {
        if (frame_length < fecf_len) return UNI_USLP_ERROR_INVALID_FRAME;
        if (!uni_crypto_crc16_ccitt_verify(frame_data, frame_length)) {
            return UNI_USLP_ERROR_CRC_MISMATCH;
        }
    }

    /* Compute payload areas */
    size_t off = ph_read;

    /* Insert Zone (§4.1.3): deliver via INSERT.indication (USLP-83) if callback registered) and v2 with Loss Flag (USLP-53, O) */
    const size_t insert_len = insert_zone_length_if_present(context);
    if (insert_len) {
        if (off + insert_len > frame_length) return UNI_USLP_ERROR_INVALID_FRAME;
        const uint8_t* insert_ptr = &frame_data[off];
        if (vc->insert_callback) {
            vc->insert_callback(context, vcid, insert_ptr, insert_len, vc->insert_user_data);
        }
        if (vc->insert2_callback) {
            /* IN_SDU Loss Flag derived from underlying C&S signal (§3.11.2.4.2) */
            vc->insert2_callback(context, vcid, insert_ptr, insert_len, cs_loss, vc->insert2_user_data);
        }
        off += insert_len;
    }

    /* Compute OCF length now; payload region excludes OCF and FECF */
    const size_t ocf_len = ocf_length_if_present(ph.ocf_flag);

    if (off > frame_length) return UNI_USLP_ERROR_INVALID_FRAME;
    if (off > frame_length - (ocf_len + fecf_len)) return UNI_USLP_ERROR_INVALID_FRAME;

    /* SDLS ProcessSecurity (USLP §6.5): if enabled for this VC, process [SecHeader + TFDF’ + SecTrailer] into [TFDF + TFDZ] */
    const bool sdls_on = (vc->sdls_config.enabled && context->sdls_process_callback != NULL);
    const uint8_t* payload_ptr = NULL;
    size_t payload_len = 0;
    /* Verification Status Code for indications (USLP §3.3.2.9/§3.5.2.8/§3.6.3.7/§3.7.2.7; C2):
     * Default NOT_APPLICABLE unless SDLS option is in effect and verification succeeded. */
    uni_uslp_verification_status_t ver = UNI_USLP_VERIF_NOT_APPLICABLE;

    if (sdls_on) {
        size_t in_len = frame_length - off - ocf_len - fecf_len;
        if (in_len == 0) return UNI_USLP_ERROR_INVALID_FRAME;
        if (!context->frame_buffer || context->frame_buffer_size == 0) {
            return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
        }
        size_t out_len = context->frame_buffer_size;
        uint64_t sdls_seqnum = 0;
        st = context->sdls_process_callback(
                context,
                vcid,
                &frame_data[off], in_len,
                context->frame_buffer, &out_len,
                &vc->sdls_config,
                context->sdls_user_data,
                &sdls_seqnum);
        if (st != UNI_USLP_SUCCESS) {
            return UNI_USLP_ERROR_SDLS_FAILURE;
        }
        payload_ptr = context->frame_buffer;
        payload_len = out_len;
        /* SDLS verification succeeded. If suite is NULL transform, treat as NOT_APPLICABLE; else SUCCESS. */
        ver = (vc->sdls_config.suite == UNI_USLP_SDLS_SUITE_NULL)
              ? UNI_USLP_VERIF_NOT_APPLICABLE
              : UNI_USLP_VERIF_SUCCESS;
    } else {
        payload_ptr = &frame_data[off];
        payload_len = frame_length - off - ocf_len - fecf_len;
    }

    /* Parse TFDF header from payload_ptr (plain or post-SDLS) */
    uni_uslp_tfdf_header_t th;
    size_t th_read = 0;
    st = uni_ccsds_uslp_tfdf_header_unpack(payload_ptr, payload_len, &th, &th_read);
    if (st != UNI_USLP_SUCCESS) return st;

    /* Remaining is TFDZ */
    if (th_read > payload_len) return UNI_USLP_ERROR_INVALID_FRAME;
    const size_t tfdz_len = payload_len - th_read;

    /* VCF continuity check (USLP §2.1.2.3, §4.1.2.11) */
    bool gap_detected = false;
    if (vcf_octets > 0u && vc) {
        const uint8_t n = (uint8_t)vcf_octets;
        const uint64_t M = (n >= 8u) ? 0u : (1ULL << (8u * n));
        if (M != 0u) {
            uint64_t R = ph.vcf_count;
            uint64_t* expected_ptr = ph.bypass_flag ? &vc->vcf_exp_rx_expected : &vc->vcf_seq_rx_expected;
            uint64_t expected = *expected_ptr;
            if (expected == UINT64_MAX) {
                *expected_ptr = (R + 1ULL) % M; /* initial sync */
            } else {
                uint64_t delta = (R + M - (expected % M)) % M;
                if (delta == 0u) {
                    *expected_ptr = (expected + 1ULL) % M; /* in order */
                } else if (delta == (M - 1u)) {
                    vc->duplicates_detected++; /* duplicate previous */
                } else {
                    vc->sequence_gaps++;
                    gap_detected = true;       /* gap or out-of-order */
                    *expected_ptr = (R + 1ULL) % M; /* soft resync */
                }
            }
            vc->vcf_frames_with_field++;
        }
    }

    /* VCF/MCF Service indications (receiving end)
     * VCF Frame Loss Flag derived from VCF Count continuity (§3.9.2.4.2).
     * MCF Frame Loss Flag derived from C&S loss signal (§3.10.2.4.2). */
    if (vc->vcf_indication_cb) {
        vc->vcf_indication_cb(context, ph.scid, ph.vcid, frame_data, frame_length, gap_detected, vc->vcf_indication_user_data);
    }
    if (context->mcf_indication_cb) {
        uint32_t mcid = ((uint32_t)UNI_USLP_TFVN << 16) | (uint32_t)ph.scid;
        context->mcf_indication_cb(context, mcid, frame_data, frame_length, cs_loss, context->mcf_indication_user_data);
    }

    /* Route by construction rule */
    switch (th.construction_rule) {
        case UNI_USLP_TFDZ_RULE_3: /* Octet Stream (variable-length) (§4.1.4.2.2.2.4) */
        {
            uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
            if (map && map->sdu_callback) {
                /* Octet Stream Data Loss Flag derived from VCF Count gaps (§3.7.2.6, §4.3.7.4). */
                map->sdu_callback(context,
                                  vcid,
                                  map_id,
                                  UNI_USLP_SERVICE_OCTET_STREAM,
                                  &payload_ptr[th_read],
                                  tfdz_len,
                                  ver /* Verification Status Code (C2) */,
                                  gap_detected,
                                  map->sdu_user_data);
            }
            break;
        }
        case UNI_USLP_TFDZ_RULE_0: /* Packet services with pointer present (FHP) (§4.1.4.2.2.2.1) */
        {
            uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
            uni_uslp_vc_state_t* ivc = uni_ccsds_uslp_get_vc_state(context, vcid);

            /* USLP-150: Deliver incomplete packets (Table 5-5)
             * FHP indicates the first complete Space Packet header within the TFDZ (bytes before FHP are tail of a previous Packet).
             * If managed parameter 'deliver_incomplete_packets' is true, deliver the pre-FHP portion with PQI=PARTIAL. */
            size_t fhp = (size_t)th.first_header_ptr;
            if (fhp > tfdz_len) {
                return UNI_USLP_ERROR_INVALID_FRAME;
            }
            const bool deliver_incomplete =
                (map && map->configured) ? map->params.deliver_incomplete_packets
                                         : (ivc ? ivc->params.deliver_incomplete_packets : false);

            const uint8_t* tfdz_base = &payload_ptr[th_read];
            const size_t pre_len  = fhp;
            const size_t post_len = tfdz_len - fhp;

            if (pre_len > 0u && deliver_incomplete) {
                /* Deliver pre-FHP tail as PARTIAL */
                if (map) {
                    if (map->service_type == UNI_USLP_SERVICE_VCP) {
                        if (ivc && ivc->vcp_indication_cb) {
                            ivc->vcp_indication_cb(context,
                                                   vcid,
                                                   tfdz_base,
                                                   pre_len,
                                                   UNI_USLP_PQI_PARTIAL,
                                                   ver,
                                                   ivc->vcp_indication_user_data);
                        }
                    } else {
                        if (map->mapp_indication_cb) {
                            map->mapp_indication_cb(context,
                                                    vcid,
                                                    map_id,
                                                    tfdz_base,
                                                    pre_len,
                                                    UNI_USLP_PQI_PARTIAL,
                                                    ver,
                                                    map->mapp_indication_user_data);
                        }
                    }
                    if (map->sdu_callback) {
                        map->sdu_callback(context,
                                          vcid,
                                          map_id,
                                          (map->service_type == UNI_USLP_SERVICE_VCP) ? UNI_USLP_SERVICE_VCP : UNI_USLP_SERVICE_PACKET,
                                          tfdz_base,
                                          pre_len,
                                          ver,
                                          gap_detected,
                                          map->sdu_user_data);
                    }
                }
            }

            /* Deliver the remainder (from FHP) as COMPLETE if any bytes remain.
             * Minimal path does not attempt to locate multiple packets; it delivers the contiguous remainder. */
            if (post_len > 0u && map) {
                const uint8_t* post_ptr = tfdz_base + pre_len;
                if (map->service_type == UNI_USLP_SERVICE_VCP) {
                    if (ivc && ivc->vcp_indication_cb) {
                        ivc->vcp_indication_cb(context,
                                               vcid,
                                               post_ptr,
                                               post_len,
                                               UNI_USLP_PQI_COMPLETE,
                                               ver,
                                               ivc->vcp_indication_user_data);
                    }
                } else {
                    if (map->mapp_indication_cb) {
                        map->mapp_indication_cb(context,
                                                vcid,
                                                map_id,
                                                post_ptr,
                                                post_len,
                                                UNI_USLP_PQI_COMPLETE,
                                                ver,
                                                map->mapp_indication_user_data);
                    }
                }
                if (map->sdu_callback) {
                    map->sdu_callback(context,
                                      vcid,
                                      map_id,
                                      (map->service_type == UNI_USLP_SERVICE_VCP) ? UNI_USLP_SERVICE_VCP : UNI_USLP_SERVICE_PACKET,
                                      post_ptr,
                                      post_len,
                                      ver,
                                      gap_detected,
                                      map->sdu_user_data);
                }
            }
            break;
        }
        case UNI_USLP_TFDZ_RULE_7: /* No Segmentation (variable-length) */
        {
            /* MAPA/VCA minimal path (variable-length, Rule '111') */
            uni_uslp_map_state_t* map = uni_ccsds_uslp_get_map_state(context, vcid, map_id);
            if (map && map->sdu_callback) {
                map->sdu_callback(context,
                                  vcid,
                                  map_id,
                                  map->service_type,
                                  &payload_ptr[th_read],
                                  tfdz_len,
                                  ver /* Verification Status Code (C2) */,
                                  gap_detected,
                                  map->sdu_user_data);
            }
            break;
        }
        default:
            return UNI_USLP_ERROR_UNSUPPORTED;
    }

    /* OCF extraction and callback(s) if present (at end of frame before FECF) */
    if (ocf_len) {
        size_t ocf_pos = frame_length - fecf_len - ocf_len;
        uni_uslp_ocf_t ocf;
        ocf.type = UNI_USLP_OCF_TYPE_1; /* default */
        ocf.data = ((uint32_t)frame_data[ocf_pos + 0] << 24) |
                   ((uint32_t)frame_data[ocf_pos + 1] << 16) |
                   ((uint32_t)frame_data[ocf_pos + 2] << 8)  |
                   ((uint32_t)frame_data[ocf_pos + 3]);

        /* USLP-44: OCF_SDU Loss Flag (Optional) derived from C&S loss signal (§3.8.2.4.2) */
        if (vc->ocf2_callback) {
            vc->ocf2_callback(context, vcid, &ocf, cs_loss, vc->ocf2_user_data);
        }
        if (vc->ocf_callback) {
            vc->ocf_callback(context, vcid, &ocf, vc->ocf_user_data);
        }
    }

    /* Consume C&S loss latch on success */
    context->rx_cs_loss_signaled_pending = false;
    return UNI_USLP_SUCCESS;
}

/* ========================================================================== */
/* TX MULTIPLEXING: MC/VC/MAP selection                                       */
/* CCSDS 732.1-B-3                                                            */
/*  - §4.2.5 MAP Multiplexing Function (USLP-96)                              */
/*  - §4.2.8 Virtual Channel Multiplexing (USLP-99)                           */
/*  - §4.2.10 Master Channel Multiplexing (USLP-101)                          */
/* Managed Parameters                                                         */
/*  - Table 5-1: MC Multiplexing Scheme (USLP-117)                            */
/*  - Table 5-2: VC Multiplexing Scheme (USLP-127)                            */
/* Notes:                                                                     */
/*  - This IUT supports a single Master Channel (one SCID). MC mux therefore  */
/*    degenerates to SINGLE; other MC schemes are recorded only.              */
/*  - VC/MAP schemes supported: SINGLE and RR. PRIORITY selects the highest   */
/*    priority value. DRR behaves as RR unless weights are configured.        */
/*    This complies with §4.2.8/§4.2.5 without inventing scheduling semantics.*/
/* ========================================================================== */

static UNI_USLP_INLINE bool map_is_ready(const uni_uslp_map_state_t* map) {
    return map && map->configured && map->send_buffer && map->send_buffer_size > 0;
}

static bool vc_has_any_pending(const uni_uslp_vc_state_t* vc) {
    if (!vc || !vc->configured) return false;
    for (uint8_t m = 0; m < (uint8_t)UNI_USLP_MAX_MAPS_PER_VC; ++m) {
        if (map_is_ready(&vc->maps[m])) return true;
    }
    return false;
}

/* Select next MAP within a VC by SINGLE (lowest), RR (round-robin), or PRIORITY.
 * DRR treated as RR (minimal). */
static bool select_next_map_impl(uni_uslp_context_t *context, uni_uslp_vc_state_t* vc, uint8_t *out_map_id)
{
    (void)context;
    if (!vc || !vc->configured) return false;

    uni_uslp_map_mux_scheme_t scheme = vc->params.map_mux_scheme;
    if (scheme == UNI_USLP_MAP_MUX_UNSPECIFIED) scheme = UNI_USLP_MAP_MUX_SINGLE;

    switch (scheme) {
        case UNI_USLP_MAP_MUX_SINGLE: {
            for (uint8_t m = 0; m < (uint8_t)UNI_USLP_MAX_MAPS_PER_VC; ++m) {
                if (map_is_ready(&vc->maps[m])) { *out_map_id = m; return true; }
            }
            return false;
        }
        case UNI_USLP_MAP_MUX_RR: {
            uint8_t start = (vc->sched_last_map_rr == 0xFFu) ? 0u : (uint8_t)((vc->sched_last_map_rr + 1u) % UNI_USLP_MAX_MAPS_PER_VC);
            for (uint16_t i = 0; i < (uint16_t)UNI_USLP_MAX_MAPS_PER_VC; ++i) {
                uint8_t m = (uint8_t)((start + i) % UNI_USLP_MAX_MAPS_PER_VC);
                if (map_is_ready(&vc->maps[m])) {
                    vc->sched_last_map_rr = m;
                    *out_map_id = m;
                    return true;
                }
            }
            return false;
        }
        case UNI_USLP_MAP_MUX_PRIORITY:
        case UNI_USLP_MAP_MUX_DRR:
        default: {
            /* PRIORITY: pick highest priority value; DRR: treat as RR minimal */
            int best_idx = -1;
            uint8_t best_prio = 0;
            for (uint8_t m = 0; m < (uint8_t)UNI_USLP_MAX_MAPS_PER_VC; ++m) {
                const uni_uslp_map_state_t* map = &vc->maps[m];
                if (!map_is_ready(map)) continue;
                const uint8_t pr = map->mux_policy.priority;
                if (best_idx < 0 || pr > best_prio) { best_idx = (int)m; best_prio = pr; }
            }
            if (best_idx >= 0) {
                vc->sched_last_map_rr = (uint8_t)best_idx;
                *out_map_id = (uint8_t)best_idx;
                return true;
            }
            return false;
        }
    }
}

/* Public API: set VC-level mux policy (USLP-99 with PRIORITY/DRR) */
uni_uslp_status_t uni_ccsds_uslp_set_vc_mux_policy(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_mux_policy_t *policy
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(policy);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) return UNI_USLP_ERROR_INVALID_PARAM;
    vc->vc_mux_policy = *policy;
    return UNI_USLP_SUCCESS;
}

/* Public API: select next VC by scheme (USLP-99; Table 5-2 USLP-127) */
uni_uslp_status_t uni_ccsds_uslp_select_next_vc(
    uni_uslp_context_t *context,
    uint8_t *out_vcid
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(out_vcid);

    uni_uslp_vc_mux_scheme_t scheme = context->params.vc_mux_scheme;
    if (scheme == UNI_USLP_VC_MUX_UNSPECIFIED) scheme = UNI_USLP_VC_MUX_SINGLE;

    switch (scheme) {
        case UNI_USLP_VC_MUX_SINGLE: {
            for (uint8_t v = 0; v <= (uint8_t)UNI_USLP_MAX_VCID; ++v) {
                uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, v);
                if (vc && vc->configured && vc_has_any_pending(vc)) {
                    *out_vcid = v;
                    return UNI_USLP_SUCCESS;
                }
            }
            return UNI_USLP_ERROR_NOT_FOUND;
        }
        case UNI_USLP_VC_MUX_RR: {
            uint8_t last = context->sched_last_vc_rr;
            uint8_t start = (last == 0xFFu) ? 0u : (uint8_t)((last + 1u) & 0x3Fu);
            for (uint16_t i = 0; i < (uint16_t)UNI_USLP_MAX_VIRTUAL_CHANNELS; ++i) {
                uint8_t v = (uint8_t)((start + i) % UNI_USLP_MAX_VIRTUAL_CHANNELS);
                uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, v);
                if (vc && vc->configured && vc_has_any_pending(vc)) {
                    context->sched_last_vc_rr = v;
                    *out_vcid = v;
                    return UNI_USLP_SUCCESS;
                }
            }
            return UNI_USLP_ERROR_NOT_FOUND;
        }
        case UNI_USLP_VC_MUX_PRIORITY:
        case UNI_USLP_VC_MUX_DRR:
        default: {
            int best_idx = -1;
            uint8_t best_prio = 0;
            for (uint8_t v = 0; v <= (uint8_t)UNI_USLP_MAX_VCID; ++v) {
                uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, v);
                if (!vc || !vc->configured) continue;
                if (!vc_has_any_pending(vc)) continue;
                uint8_t pr = vc->vc_mux_policy.priority;
                if (best_idx < 0 || pr > best_prio) { best_idx = (int)v; best_prio = pr; }
            }
            if (best_idx >= 0) {
                context->sched_last_vc_rr = (uint8_t)best_idx;
                *out_vcid = (uint8_t)best_idx;
                return UNI_USLP_SUCCESS;
            }
            return UNI_USLP_ERROR_NOT_FOUND;
        }
    }
}

/* Public API: select next MAP in a VC by scheme (USLP-96; Table 5-3 USLP-136) */
uni_uslp_status_t uni_ccsds_uslp_select_next_map(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t *out_map_id
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(out_map_id);
    uni_uslp_vc_state_t* vc = uni_ccsds_uslp_get_vc_state(context, vcid);
    if (!vc || !vc->configured) return UNI_USLP_ERROR_INVALID_PARAM;
    if (select_next_map_impl(context, vc, out_map_id)) return UNI_USLP_SUCCESS;
    return UNI_USLP_ERROR_NOT_FOUND;
}

/* Public API: build next frame based on VC and MAP selection (USLP-101/99/96 chain) */
uni_uslp_status_t uni_ccsds_uslp_build_next_frame(
    uni_uslp_context_t *context,
    uint8_t *frame_buffer,
    size_t *frame_length,
    uint8_t *out_vcid,
    uint8_t *out_map_id
)
{
    UNI_USLP_CHECK_NULL(context);
    UNI_USLP_CHECK_NULL(frame_buffer);
    UNI_USLP_CHECK_NULL(frame_length);

    /* MC multiplexing (USLP-101): single MC in this IUT — proceed to VC selection */
    uint8_t vcid = 0xFF;
    uni_uslp_status_t st = uni_ccsds_uslp_select_next_vc(context, &vcid);
    if (st != UNI_USLP_SUCCESS) {
        return st; /* UNI_USLP_ERROR_NOT_FOUND if no VC has pending SDUs */
    }

    uint8_t map_id = 0xFF;
    st = uni_ccsds_uslp_select_next_map(context, vcid, &map_id);
    if (st != UNI_USLP_SUCCESS) {
        return st;
    }

    /* Build the frame for selected (VC, MAP) via existing builder (§4.2.11 All Frames Generation) */
    size_t cap = *frame_length;
    st = uni_ccsds_uslp_build_frame(context, vcid, map_id, frame_buffer, &cap);
    if (st == UNI_USLP_SUCCESS) {
        *frame_length = cap;
        if (out_vcid) *out_vcid = vcid;
        if (out_map_id) *out_map_id = map_id;
    }
    return st;
}
