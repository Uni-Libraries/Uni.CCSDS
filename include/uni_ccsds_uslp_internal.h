// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// Includes
//

// stdlib
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// uni.ccsds
#include "uni_ccsds_uslp.h"


/**
 * @brief Force inline attribute
 */
#if defined(__GNUC__) || defined(__clang__)
#define UNI_USLP_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
#define UNI_USLP_INLINE __forceinline
#else
#define UNI_USLP_INLINE inline
#endif


/**
 * @brief Likely branch hint
 */
#if defined(__GNUC__) || defined(__clang__)
#define UNI_USLP_LIKELY(x) __builtin_expect(!!(x), 1)
#define UNI_USLP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define UNI_USLP_LIKELY(x) (x)
#define UNI_USLP_UNLIKELY(x) (x)
#endif


/* ========================================================================== */
/* INTERNAL STRUCTURES                                                        */
/* ========================================================================== */

/**
 * @brief SDU Reassembly State
 */
typedef struct {
    bool     in_use;                    /**< Reassembly slot in use */
    uint8_t  vcid;                      /**< Virtual Channel ID */
    uint8_t  map_id;                    /**< MAP ID */
    uni_uslp_service_type_t service_type; /**< Service type */
    uint8_t  *sdu_buffer;               /**< SDU reassembly buffer */
    size_t   sdu_length;                /**< Current SDU length */
    size_t   sdu_capacity;              /**< SDU buffer capacity */
    uint32_t expected_sequence;         /**< Expected sequence number */
    bool     first_segment_received;    /**< First segment received */
    bool     gap_detected;              /**< Gap in sequence detected */
} uni_uslp_reassembly_state_t;

/**
 * @brief MAP Channel State
 */
typedef struct {
    bool     configured;                /**< MAP configured */
    uni_uslp_service_type_t service_type; /**< Service type */
    uni_uslp_managed_params_t params;   /**< MAP parameters */
    uni_uslp_mux_policy_t mux_policy;   /**< Multiplexing policy */
    
    /* Callbacks */
    uni_uslp_sdu_callback_t sdu_callback; /**< SDU callback */
    void    *sdu_user_data;             /**< SDU callback user data */
    uni_uslp_octet_stream_notify_cb_t octet_stream_notify_cb; /**< OCTET_STREAM_Notify.indication callback (§3.7.3.4) */
    void    *octet_stream_notify_user_data;                   /**< OCTET_STREAM_Notify user data */
    uni_uslp_mapa_notify_cb_t mapa_notify_cb;                 /**< MAPA_Notify.indication callback (§3.5.3.3) */
    void    *mapa_notify_user_data;                           /**< MAPA_Notify user data */
    uni_uslp_mapp_notify_cb_t mapp_notify_cb;                 /**< MAPP_Notify.indication callback (§3.3.3.3) */
    void    *mapp_notify_user_data;                           /**< MAPP_Notify user data */
    uni_uslp_vca_notify_cb_t vca_notify_cb;                   /**< VCA_Notify.indication callback (§3.6.4.3) */
    void    *vca_notify_user_data;                            /**< VCA_Notify user data */
    /* Optional MAPP.indication callback with PQI (§3.3.3.4; USLP-14) */
    uni_uslp_mapp_indication_cb_t mapp_indication_cb;         /**< MAPP.indication callback (receiving end) */
    void    *mapp_indication_user_data;                       /**< MAPP.indication user data */
    
    /* Sending state */
    uint8_t  *send_buffer;              /**< Send buffer */
    size_t   send_buffer_size;          /**< Send buffer size */
    size_t   send_buffer_used;          /**< Send buffer used */
    bool     send_bypass_flag;          /**< For Octet Stream/MAPP QoS: true=Expedited (Bypass=1), false=Sequence-Controlled (Bypass=0) */
    uint8_t  send_pvn;                  /**< For MAPP/VCP: Packet Version Number service parameter (USLP-10/USLP-18; not transmitted) */
    uint32_t send_sdu_id;               /**< Optional SDU ID for API accounting (§2.2.2; USLP-11/USLP-19/§3.7.2.4) */
    bool     send_is_vcp;               /**< Mark the current queued SDU as VCP-originated (affects notify/indication routing per §3.4) */
    
    /* Statistics */
    uint64_t sdus_sent;                 /**< SDUs sent count */
    uint64_t sdus_received;             /**< SDUs received count */
    uint64_t bytes_sent;                /**< Bytes sent count */
    uint64_t bytes_received;            /**< Bytes received count */
} uni_uslp_map_state_t;

/**
 * @brief Virtual Channel State
 *
 * VCF counters per §2.1.2.3 (Sequence-Controlled vs Expedited) and §4.1.2.11:
 * - Separate counters and expected values are maintained for Bypass=0 (SEQ) and Bypass=1 (EXP).
 * - Counter lengths (octets) are cached from managed params for fast access.
 */
typedef struct {
    bool     configured;                /**< VC configured */
    uni_uslp_managed_params_t params;   /**< VC parameters */
    
    /* VCF Counter configuration cache (octets 0..7) */
    uint8_t  vcf_seq_len;               /**< USLP-130: Sequence-Controlled VCF Count octets */
    uint8_t  vcf_exp_len;               /**< USLP-131: Expedited VCF Count octets */

    /* VCF TX counters (current values placed in Primary Header) */
    uint64_t vcf_seq_tx;                /**< Current SEQ TX counter (mod 2^(8*vcf_seq_len)) */
    uint64_t vcf_exp_tx;                /**< Current EXP TX counter (mod 2^(8*vcf_exp_len)) */

    /* VCF RX expected next values; UINT64_MAX indicates unsynchronized */
    uint64_t vcf_seq_rx_expected;       /**< Expected next SEQ value (or UNSYNC) */
    uint64_t vcf_exp_rx_expected;       /**< Expected next EXP value (or UNSYNC) */

    /* VC-level multiplexing policy (USLP-99 Virtual Channel Multiplexing, §4.2.8; USLP-127 Table 5-2) */
    uni_uslp_mux_policy_t vc_mux_policy; /**< Default {priority=0, weight=0, max_burst_size=0} */

    /* MAP multiplexing scheduler state (USLP-96 §4.2.5; Table 5-3 USLP-136) */
    uint8_t  sched_last_map_rr;          /**< Last served MAP ID for Round-Robin (-1/0xFF when none) */
    uint16_t map_drr_deficit[UNI_USLP_MAX_MAPS_PER_VC]; /**< Deficit counters for DRR (implementation-defined; may be unused) */

    /* MAP channels */
    uni_uslp_map_state_t maps[UNI_USLP_MAX_MAPS_PER_VC];
    
    /* Callbacks */
    uni_uslp_ocf_callback_t ocf_callback; /**< OCF callback */
    void    *ocf_user_data;             /**< OCF callback user data */
    /* OCF.indication v2 with OCF_SDU Loss Flag (USLP-44; §3.8.2.4) */
    uni_uslp_ocf2_callback_t ocf2_callback; /**< OCF v2 callback with Loss Flag */
    void    *ocf2_user_data;            /**< OCF v2 callback user data */
    uni_uslp_insert_callback_t insert_callback; /**< Insert callback (used for INSERT.indication on RX; may be used by TX to fill zone if no pending IN_SDU) */
    void    *insert_user_data;          /**< Insert callback user data */
    /* Optional INSERT.indication v2 with IN_SDU Loss Flag (§3.11.2.4; §3.11.3.3) */
    uni_uslp_insert2_callback_t insert2_callback; /**< INSERT.indication v2 callback (optional) */
    void    *insert2_user_data;         /**< INSERT.indication v2 user data */
    /* VCF Service indication (§3.9.3.3) — Parameters §3.9.2.2..§3.9.2.4 */
    uni_uslp_vcf_indication_cb_t vcf_indication_cb; /**< VCF.indication callback (optional) */
    void    *vcf_indication_user_data;  /**< VCF.indication user data */

    /* VCF.request provider TX callback (§3.9.3.2) */
    uni_uslp_vcf_tx_cb_t vcf_tx_cb;     /**< Provider handoff for externally-supplied frames on this VC */
    void    *vcf_tx_user_data;          /**< User data for VCF TX callback */
    
    /* VCP Service callbacks (VC-level) — CCSDS 732.1-B-3 §3.4.3
     * USLP-21: Notification Type (optional, sending end)
     * USLP-16..USLP-20: Parameters on request
     * USLP-22: Packet Quality Indicator (optional, receiving end; delivered as COMPLETE in this minimal implementation)
     * USLP-23: Verification Status Code (C2; when SDLS option enabled) */
    uni_uslp_vcp_notify_cb_t     vcp_notify_cb;           /**< VCP_Notify.indication callback (sending end) */
    void                         *vcp_notify_user_data;   /**< User data for VCP_Notify */
    uni_uslp_vcp_indication_cb_t vcp_indication_cb;       /**< VCP.indication callback (receiving end) */
    void                         *vcp_indication_user_data; /**< User data for VCP.indication */
    
    /* Insert Service pending IN_SDU for next fixed-length frame (USLP §3.2.8, §3.11; USLP-7, USLP-51, USLP-82)
     * When set via INSERT.request, builder consumes it once to populate Insert Zone (§4.1.3). */
    bool     insert_pending_valid;
    size_t   insert_pending_length;
    uint8_t  insert_pending[UNI_USLP_MAX_INSERT_ZONE_SIZE];

    /* OCF pending state for emission on next frame when enabled */
    bool     ocf_pending;               /**< OCF pending flag */
    uni_uslp_ocf_t ocf_value;           /**< OCF value to emit */
    
    /* SDLS configuration */
    uni_uslp_sdls_config_t sdls_config; /**< SDLS configuration */

    /* SDLS runtime (per VC) */
    struct {
        uint64_t tx_sn;                 /**< Transmit Sequence Number (monotonic, 64-bit) */
        uint64_t rx_highest_sn;         /**< Highest SN accepted so far (initially UINT64_MAX to mark unsynced -> set to 0xFFFFFFFFFFFFFFFF? Use 0 to start.) */
        uint64_t rx_window_bitmap;      /**< Sliding window bitmap (LSB = rx_highest_sn, next bit = -1, etc.), window size up to 64 */
        bool     rx_initialized;        /**< Anti-replay state initialized flag */
    } sdls_rt;

    /* Statistics */
    uint64_t frames_sent;               /**< Frames sent count */
    uint64_t frames_received;           /**< Frames received count */
    uint64_t frame_errors;              /**< Frame error count */
    uint64_t sequence_gaps;             /**< Sequence gap count (RX) */
    uint64_t duplicates_detected;       /**< Duplicate frames detected (RX) */
    uint64_t out_of_order_frames;       /**< Out-of-order frames (RX) beyond duplicate */
    uint64_t wraps;                     /**< TX/RX modulo wrap events observed */
    uint64_t vcf_frames_with_field;     /**< Frames with VCF Count present (TX/RX) */
} uni_uslp_vc_state_t;

/**
 * @brief Master Channel State
 */
typedef struct {
    uint8_t  mcf_count;                 /**< MCF Count */
    uint8_t  expected_mcf_count;        /**< Expected MCF Count (receive) */
    
    /* Statistics */
    uint64_t frames_sent;               /**< Frames sent count */
    uint64_t frames_received;           /**< Frames received count */
} uni_uslp_mc_state_t;

/**
 * @brief USLP Context Structure
 */
struct uni_uslp_context {
    /* Configuration */
    uint16_t scid;                      /**< Spacecraft ID */
    uni_uslp_managed_params_t params;   /**< Global parameters */
    
    /* Channel states */
    uni_uslp_mc_state_t mc_state;       /**< Master Channel state */
    uni_uslp_vc_state_t vcs[UNI_USLP_MAX_VIRTUAL_CHANNELS]; /**< VC states */
    
    /* Reassembly states */
    uni_uslp_reassembly_state_t reassembly[UNI_USLP_MAX_PENDING_SDUS];
    
    /* OID LFSR state */
    uint32_t oid_lfsr_state;            /**< OID LFSR state */
    
    /* Global callbacks */
    uni_uslp_idle_filler_callback_t idle_filler_callback; /**< Idle filler callback */
    void    *idle_filler_user_data;     /**< Idle filler user data */
    
    /* SDLS callbacks */
    uni_uslp_sdls_apply_callback_t sdls_apply_callback; /**< SDLS apply callback */
    uni_uslp_sdls_process_callback_t sdls_process_callback; /**< SDLS process callback */
    void    *sdls_user_data;            /**< SDLS user data */

    /* MCF Service indication (§3.10.3.3) — Parameters §3.10.2.2..§3.10.2.4 */
    uni_uslp_mcf_indication_cb_t mcf_indication_cb; /**< MCF.indication callback (optional) */
    void    *mcf_indication_user_data;  /**< MCF.indication user data */

    /* MCF.request provider TX callback (§3.10.3.2) — MC-level */
    uni_uslp_mcf_tx_cb_t mcf_tx_cb;     /**< Provider handoff for externally-supplied frames on the Master Channel */
    void    *mcf_tx_user_data;          /**< User data for MCF TX callback */

    /* COPs Management primitives (§3.12.3): Directive_Notify.indication and Async_Notify.indication */
    uni_uslp_directive_notify_cb_t directive_notify_cb; /**< Sending-end Directive_Notify.indication callback */
    void    *directive_notify_user_data;                 /**< User data for Directive_Notify */
    uni_uslp_async_notify_cb_t     async_notify_cb;      /**< Async_Notify.indication callback */
    void    *async_notify_user_data;                     /**< User data for Async_Notify */
    
    /* Underlying Synchronization and Channel Coding sublayer loss signal latch
     * Used to derive MCF Frame Loss Flag (§3.10.2.4.2) and IN_SDU Loss Flag (§3.11.2.4.2) for the next accepted frame. */
    bool     rx_cs_loss_signaled_pending;

    /* VC Multiplexing scheduler state (USLP-99 §4.2.8; USLP-101 §4.2.10) */
    uint8_t  sched_last_vc_rr;          /**< Last served VCID for Round-Robin (-1/0xFF when none) */
    
    /* Working buffers */
    uint8_t  *frame_buffer;             /**< Frame working buffer */
    size_t   frame_buffer_size;         /**< Frame buffer size */
    
    /* Global statistics */
    uint64_t total_frames_sent;         /**< Total frames sent */
    uint64_t total_frames_received;     /**< Total frames received */
    uint64_t total_frame_errors;        /**< Total frame errors */
    uint64_t oid_frames_sent;           /**< OID frames sent */
    uint64_t truncated_frames_sent;     /**< Truncated frames sent */
    uint64_t truncated_frames_received; /**< Truncated frames received */
};

/* ========================================================================== */
/* INTERNAL FUNCTION DECLARATIONS                                             */
/* ========================================================================== */

/**
 * @brief Validate Primary Header
 * 
 * @param header Primary header to validate
 * @return Status code
 */
uni_uslp_status_t uni_ccsds_uslp_validate_primary_header(
    const uni_uslp_primary_header_t *header
);

/**
 * @brief Validate TFDF Header
 * 
 * @param header TFDF header to validate
 * @return Status code
 */
uni_uslp_status_t uni_ccsds_uslp_validate_tfdf_header(
    const uni_uslp_tfdf_header_t *header
);

/**
 * @brief Get MAP state
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @return MAP state pointer or NULL
 */
uni_uslp_map_state_t* uni_ccsds_uslp_get_map_state(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id
);

/**
 * @brief Get VC state
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @return VC state pointer or NULL
 */
uni_uslp_vc_state_t* uni_ccsds_uslp_get_vc_state(
    uni_uslp_context_t *context,
    uint8_t vcid
);

/**
 * @brief Allocate reassembly state
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param service_type Service type
 * @return Reassembly state pointer or NULL
 */
uni_uslp_reassembly_state_t* uni_ccsds_uslp_alloc_reassembly_state(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_service_type_t service_type
);

/**
 * @brief Find reassembly state
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param service_type Service type
 * @return Reassembly state pointer or NULL
 */
uni_uslp_reassembly_state_t* uni_ccsds_uslp_find_reassembly_state(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_service_type_t service_type
);

/**
 * @brief Free reassembly state
 * 
 * @param context USLP context
 * @param state Reassembly state to free
 */
void uni_ccsds_uslp_free_reassembly_state(
    uni_uslp_context_t *context,
    uni_uslp_reassembly_state_t *state
);

/**
 * @brief Fill idle data
 * 
 * @param context USLP context
 * @param buffer Buffer to fill
 * @param length Length to fill
 */
void uni_ccsds_uslp_fill_idle(
    uni_uslp_context_t *context,
    uint8_t *buffer,
    size_t length
);

/**
 * @brief Update statistics
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param frames_sent Frames sent increment
 * @param frames_received Frames received increment
 * @param bytes_sent Bytes sent increment
 * @param bytes_received Bytes received increment
 * @param errors Error increment
 */
void uni_ccsds_uslp_update_statistics(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uint64_t frames_sent,
    uint64_t frames_received,
    uint64_t bytes_sent,
    uint64_t bytes_received,
    uint64_t errors
);

/* ========================================================================== */
/* INTERNAL MACROS                                                            */
/* ========================================================================== */

/**
 * @brief Check if parameter validation is enabled
 */
#define UNI_USLP_CHECK_PARAM(cond, ret) \
    do { if (UNI_USLP_UNLIKELY(!(cond))) return (ret); } while(0)

/**
 * @brief Check for null pointer
 */
#define UNI_USLP_CHECK_NULL(ptr) \
    UNI_USLP_CHECK_PARAM((ptr) != NULL, UNI_USLP_ERROR_NULL_POINTER)

/**
 * @brief Check buffer size
 */
#define UNI_USLP_CHECK_BUFFER_SIZE(size, min_size) \
    UNI_USLP_CHECK_PARAM((size) >= (min_size), UNI_USLP_ERROR_BUFFER_TOO_SMALL)

/**
 * @brief Check parameter range
 */
#define UNI_USLP_CHECK_RANGE(val, min_val, max_val) \
    UNI_USLP_CHECK_PARAM((val) >= (min_val) && (val) <= (max_val), UNI_USLP_ERROR_INVALID_PARAM)


#ifdef __cplusplus
}
#endif
