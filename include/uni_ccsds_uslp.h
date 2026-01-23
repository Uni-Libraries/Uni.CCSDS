// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

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

#include "uni_ccsds_export.h"



//
// Defines
//

/**
 * @brief Maximum number of Virtual Channels
 */
#define UNI_USLP_MAX_VIRTUAL_CHANNELS 64

/**
 * @brief Maximum number of MAPs per Virtual Channel
 */
#define UNI_USLP_MAX_MAPS_PER_VC 64

/** 
 * @brief USLP Transfer Frame Version Number (CCSDS 732.1-B-3 §4.1.2.2.1) 
 */
#define UNI_USLP_TFVN                   0x0C  /* 1100 binary */

/**
 * @brief Maximum Transfer Frame Length (CCSDS 732.1-B-3 §4.1.2.2.6) 
 */
#define UNI_USLP_MAX_FRAME_LENGTH       65535

/** 
 * @brief Minimum Transfer Frame Length 
 */
#define UNI_USLP_MIN_FRAME_LENGTH       5

/** 
 * @brief Primary Header Base Length (non-truncated, without VCF Count) per CCSDS 732.1-B-3 §4.1.2 
 */
#define UNI_USLP_PRIMARY_HEADER_LENGTH  7

/**
 * @brief TFDF Header Minimum Length (CCSDS 732.1-B-3 §4.1.4) 
 */
#define UNI_USLP_TFDF_HEADER_MIN_LENGTH 2

/**
 * @brief OCF Length (CCSDS 732.1-B-3 §4.1.5) 
 */
#define UNI_USLP_OCF_LENGTH             4

/**
 * @brief FECF Length (CCSDS 732.1-B-3 §4.1.6) 
 */
#define UNI_USLP_FECF_LENGTH            2

/** 
 * @brief Truncated Primary Header Length (CCSDS 732.1-B-3 Annex D, Figure D-2) 
 */
#define UNI_USLP_TRUNCATED_PH_LENGTH 4

/** 
 * @brief OID Transfer Frame VCID (CCSDS 732.1-B-3 Annex H) 
 */
#define UNI_USLP_OID_VCID               63

/**
 * @brief OID Transfer Frame MAP ID (CCSDS 732.1-B-3 Annex H) 
 */
#define UNI_USLP_OID_MAP_ID             0

/**
 * @brief Minimum Truncated Transfer Frame total length (PH=4 + TFDF hdr=1 + >=1) per Annex D 
 */
#define UNI_USLP_TRUNCATED_MIN_LENGTH   6

/**
 * @brief Backward-compat alias (deprecated): length of truncated Primary Header 
 */
#define UNI_USLP_TRUNCATED_FRAME_LENGTH UNI_USLP_TRUNCATED_PH_LENGTH

/** 
 * @brief Maximum Spacecraft ID (16 bits) per §4.1.2.2.3 
 */
#define UNI_USLP_MAX_SCID               65535

/**
 * @brief Maximum Virtual Channel ID (6 bits) 
 */
#define UNI_USLP_MAX_VCID               63

/**
 * @brief Maximum MAP ID (4 bits) per §4.1.2.5 
 */
#define UNI_USLP_MAX_MAP_ID             15

/**
 * @brief Maximum VCF Count (24 bits) 
 */
#define UNI_USLP_MAX_VCF_COUNT          16777215

/**
 * @brief Maximum MCF Count (8 bits) 
 */
#define UNI_USLP_MAX_MCF_COUNT          255

/**
 * @brief OID LFSR polynomial (CCSDS 732.1-B-3 Annex H)
 * 
 * 32-bit primitive polynomial for maximum period LFSR
 */
#define UNI_USLP_OID_LFSR_POLYNOMIAL 0x80200003

/**
 * @brief OID LFSR initial seed
 * 
 * Non-zero seed value for LFSR initialization
 */
#define UNI_USLP_OID_LFSR_INITIAL_SEED 0x12345678

/**
 * @brief Default idle filler octet
 * 
 * Default value for filling unused TFDZ space (confirmed: 0x00)
 */
#define UNI_USLP_DEFAULT_IDLE_FILLER 0x00

/**
 * @brief Maximum SDU size for reassembly
 */
#define UNI_USLP_MAX_SDU_SIZE 65536

/**
 * @brief Maximum number of pending SDUs for reassembly
 */
#define UNI_USLP_MAX_PENDING_SDUS 16

/**
 * @brief Default frame buffer size
 */
#define UNI_USLP_DEFAULT_FRAME_BUFFER_SIZE 8192

/**
 * @brief Maximum Insert Zone size
 */
#define UNI_USLP_MAX_INSERT_ZONE_SIZE 1024




//
// Enums
//

/**
 * @brief USLP Status Codes
 * 
 * All USLP functions return status codes for robust error handling.
 */
typedef enum {
    UNI_USLP_SUCCESS = 0,           /**< Operation successful */
    UNI_USLP_ERROR_NULL_POINTER,    /**< Null pointer argument */
    UNI_USLP_ERROR_INVALID_PARAM,   /**< Invalid parameter value */
    UNI_USLP_ERROR_BUFFER_TOO_SMALL,/**< Output buffer too small */
    UNI_USLP_ERROR_INVALID_FRAME,   /**< Invalid frame format */
    UNI_USLP_ERROR_CRC_MISMATCH,    /**< FECF CRC verification failed */
    UNI_USLP_ERROR_UNSUPPORTED,     /**< Unsupported feature */
    UNI_USLP_ERROR_CONTEXT_FULL,    /**< Context buffers full */
    UNI_USLP_ERROR_NOT_FOUND,       /**< Resource not found */
    UNI_USLP_ERROR_SDLS_FAILURE,    /**< SDLS operation failed */
    UNI_USLP_ERROR_TRUNCATED,       /**< Frame truncated */
    UNI_USLP_ERROR_SEQUENCE_GAP     /**< Sequence number gap detected */
} uni_uslp_status_t;


/**
 * @brief TFDF Construction Rules (CCSDS 732.1-B-3 §4.1.4.2.2, Table 4-3)
 */
typedef enum {
    UNI_USLP_TFDZ_RULE_0 = 0,  /**< Fixed TFDZ, no segmentation */
    UNI_USLP_TFDZ_RULE_1 = 1,  /**< Fixed TFDZ, segmentation */
    UNI_USLP_TFDZ_RULE_2 = 2,  /**< Variable TFDZ, no segmentation */
    UNI_USLP_TFDZ_RULE_3 = 3,  /**< Variable TFDZ, segmentation */
    UNI_USLP_TFDZ_RULE_4 = 4,  /**< Fixed TFDZ, blocking */
    UNI_USLP_TFDZ_RULE_5 = 5,  /**< Fixed TFDZ, blocking + segmentation */
    UNI_USLP_TFDZ_RULE_6 = 6,  /**< Variable TFDZ, blocking */
    UNI_USLP_TFDZ_RULE_7 = 7   /**< Variable TFDZ, blocking + segmentation */
} uni_uslp_tfdz_construction_rule_t;


/**
 * @brief OCF Types (CCSDS 732.1-B-3 §4.1.5)
 */
typedef enum {
    UNI_USLP_OCF_TYPE_1 = 1,   /**< Type-1 OCF (CLCW) */
    UNI_USLP_OCF_TYPE_2 = 2    /**< Type-2 OCF (PLCW/FSR) */
} uni_uslp_ocf_type_t;


/**
 * @brief Service Types (CCSDS 732.1-B-3 §3.2)
 *
 * Note: UNI_USLP_SERVICE_VCP is an internal discriminator for VC Packet Service (§3.4)
 * to allow distinct callbacks/notifications while reusing common Packet (Rule '000') handling.
 */
typedef enum {
    UNI_USLP_SERVICE_PACKET = 0,       /**< MAP Packet Service (MAPP) */
    UNI_USLP_SERVICE_VCA = 1,          /**< VCA_SDU Service */
    UNI_USLP_SERVICE_MAPA = 2,         /**< MAPA_SDU Service */
    UNI_USLP_SERVICE_OCTET_STREAM = 3, /**< Octet Stream Service */
    UNI_USLP_SERVICE_VCP = 4           /**< VC Packet Service (VCP, §3.4) — internal discriminator */
} uni_uslp_service_type_t;
/**
 * @brief COP in Effect (VC-level) — CCSDS 732.1-B-3 Table 5-3 (USLP-132)
 *
 * Indicates whether COP-1 is in effect on this Virtual Channel.
 * Note: COP-P is MC/Port scoped and thus not represented here.
 */
typedef enum {
    UNI_USLP_COP_NONE = 0, /**< No COP in effect on this VC */
    UNI_USLP_COP_1    = 1  /**< COP-1 in effect on this VC */
} uni_uslp_cop_in_effect_t;

/**
 * @brief MAP Multiplexing Scheme (VC-level) — Table 5-3 (USLP-136)
 *
 * Recorded as a managed parameter only; no scheduling/multiplexing behavior
 * is implemented in this minimal path.
 */
typedef enum {
    UNI_USLP_MAP_MUX_UNSPECIFIED = 0, /**< Unspecified/implementation-defined */
    UNI_USLP_MAP_MUX_SINGLE      = 1, /**< Single MAP only (no multiplexing) */
    UNI_USLP_MAP_MUX_PRIORITY    = 2, /**< Priority-based selection */
    UNI_USLP_MAP_MUX_RR          = 3, /**< Round-Robin */
    UNI_USLP_MAP_MUX_DRR         = 4  /**< Deficit Round-Robin */
} uni_uslp_map_mux_scheme_t;

/**
 * @brief SDLS Algorithm Suite (CCSDS 355.0-B-2; mapped to 732.1 §6 option)
 *
 * Note: Availability depends on 3rdparty/uni.crypto (mbedTLS) build.
 */
typedef enum {
    UNI_USLP_SDLS_SUITE_NULL = 0,      /**< Null transform (no auth/conf) */
    UNI_USLP_SDLS_SUITE_HMAC_SHA256 = 1, /**< Authentication-only (HMAC-SHA256), tag truncated to mac_length */
    UNI_USLP_SDLS_SUITE_AES_GCM = 2,   /**< AEAD AES-GCM (auth+conf) */
    UNI_USLP_SDLS_SUITE_AES_CCM = 3    /**< AEAD AES-CCM (auth+conf) */
} uni_uslp_sdls_suite_t;


/* Added: Verification Status Code enum (USLP §3.3.2.9, §3.5.2.8, §3.6.3.7, §3.7.2.7; C2)
 * Present on indication when SDLS option is enabled and processing succeeded; otherwise NOT_APPLICABLE. */
typedef enum {
    UNI_USLP_VERIF_NOT_APPLICABLE = 0,  /* SDLS not enabled or not applicable (e.g., truncated frames, NULL suite) */
    UNI_USLP_VERIF_SUCCESS = 1,         /* SDLS authentication/decryption verified */
    UNI_USLP_VERIF_AUTH_FAILURE = 2,    /* Authentication/tag verification failed (typically not delivered to callback) */
    UNI_USLP_VERIF_REPLAY_REJECTED = 3, /* Replayed or too-old sequence rejected (typically not delivered) */
    UNI_USLP_VERIF_SDLS_ERROR = 4       /* Other SDLS processing error (typically not delivered) */
} uni_uslp_verification_status_t;

/* Added: Packet Quality Indicator (USLP §3.3.2.8; optional).
 * Indicates whether the Packet delivered by MAPP.indication is complete or partial. */
typedef enum {
    UNI_USLP_PQI_COMPLETE = 0,  /* Packet delivered is complete */
    UNI_USLP_PQI_PARTIAL  = 1   /* Packet delivered is partial (segmentation) */
} uni_uslp_packet_quality_t;

/**
 * @brief Master Channel Multiplexing Scheme — Table 5-1 (USLP-117)
 *
 * Recorded managed parameter describing how Master Channels are multiplexed on a Physical Channel.
 * Note: This IUT operates a single MC (one SCID); thus this parameter is recorded for completeness.
 */
typedef enum {
    UNI_USLP_MC_MUX_UNSPECIFIED = 0, /**< Unspecified/implementation-defined */
    UNI_USLP_MC_MUX_SINGLE      = 1, /**< Single Master Channel (no multiplexing) */
    UNI_USLP_MC_MUX_PRIORITY    = 2, /**< Priority-based selection among MCs */
    UNI_USLP_MC_MUX_RR          = 3, /**< Round-Robin among MCs */
    UNI_USLP_MC_MUX_DRR         = 4  /**< Deficit Round-Robin among MCs */
} uni_uslp_mc_mux_scheme_t;

/**
 * @brief FECF generation mode on TX
 *
 * Controls whether the library computes/appends the FECF bytes when building frames.
 * Presence of FECF on the wire is still controlled by managed parameter
 * [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:402).
 */
typedef enum {
    /** Library computes and appends FECF bytes (CRC-16/CCITT). */
    UNI_USLP_FECF_TX_INTERNAL = 0,

    /**
     * Offload CRC computation: reserve FECF bytes in the output buffer and include
     * them in the Primary Header Frame Length, but do not write to those 2 bytes.
     *
     * Intended for hardware that overwrites the last 2 bytes (in-place CRC insertion).
     */
    UNI_USLP_FECF_TX_OFFLOAD_INPLACE = 1,

    /**
     * Offload CRC insertion outside of the CPU buffer: include FECF in the Primary
     * Header Frame Length, but do not output the 2 FECF bytes at all.
     *
     * Intended for DMA/SPI/FPGA pipelines that transmit the bytes produced by the
     * library and then append the CRC on the wire.
     *
     * Note: in this mode, [`uni_ccsds_uslp_build_frame()`](include/uni_ccsds_uslp.h:1706)
     * returns a frame length that is 2 bytes shorter than what the Primary Header
     * indicates. The final on-wire frame becomes self-consistent only after the
     * hardware appends the FECF.
     */
    UNI_USLP_FECF_TX_OFFLOAD_APPEND = 2
} uni_uslp_fecf_tx_mode_t;

/**
 * @brief VC Multiplexing Scheme — Table 5-2 (USLP-127)
 *
 * Describes how Virtual Channels are multiplexed on the Master Channel.
 * Used by the scheduler to select the next VC for transmission (USLP §4.2.8, §4.2.10).
 */
typedef enum {
    UNI_USLP_VC_MUX_UNSPECIFIED = 0, /**< Unspecified/implementation-defined (treated as SINGLE) */
    UNI_USLP_VC_MUX_SINGLE      = 1, /**< Single VC only (no multiplexing) */
    UNI_USLP_VC_MUX_PRIORITY    = 2, /**< Priority-based selection among VCs */
    UNI_USLP_VC_MUX_RR          = 3, /**< Round-Robin among VCs */
    UNI_USLP_VC_MUX_DRR         = 4  /**< Deficit Round-Robin among VCs */
} uni_uslp_vc_mux_scheme_t;




/**
 * @brief USLP Primary Header (CCSDS 732.1-B-3 §4.1.2)
 */
typedef struct {
    uint8_t  tfvn;            /**< Transfer Frame Version Number (4 bits) */
    uint16_t scid;            /**< Spacecraft ID (16 bits) */
    bool     source_dest;     /**< Source-or-Destination Identifier (1 bit): 0=SCID is source, 1=destination */
    uint8_t  vcid;            /**< Virtual Channel ID (6 bits) */
    uint8_t  map_id;          /**< MAP ID (4 bits) */
    bool     eof_ph_flag;     /**< End of Frame Primary Header Flag (1 bit) */
    uint16_t frame_length;    /**< Frame Length (16 bits), value C = total_octets_in_frame - 1 */
    bool     bypass_flag;     /**< Bypass/Sequence Control Flag (1 bit) */
    bool     cc_flag;         /**< Protocol Control Command Flag (1 bit) */
    bool     ocf_flag;        /**< Operational Control Field Flag (1 bit) */
    uint8_t  vcf_count_len;   /**< VCF Count Length (3 bits): 0..7 octets (Table 4-2) */
    uint64_t vcf_count;       /**< VCF Count (0..56 bits depending on vcf_count_len) */
} uni_uslp_primary_header_t;


/**
 * @brief TFDF Header (CCSDS 732.1-B-3 §4.1.4)
 */
typedef struct {
    uni_uslp_tfdz_construction_rule_t construction_rule; /**< TFDZ Construction Rule (3 bits) */
    uint8_t  upid;              /**< User Protocol ID (5 bits) */
    uint16_t first_header_ptr;  /**< First Header Pointer (11 bits) */
    uint16_t last_valid_ptr;    /**< Last Valid Data Octet Pointer (11 bits) */
} uni_uslp_tfdf_header_t;


/**
 * @brief Operational Control Field (CCSDS 732.1-B-3 §4.1.5)
 */
typedef struct {
    uni_uslp_ocf_type_t type;   /**< OCF Type */
    uint32_t data;              /**< OCF Data (32 bits) */
} uni_uslp_ocf_t;


/**
 * @brief Managed Parameters (CCSDS 732.1-B-3 §5)
 *
 * Notes on VCF counters per §2.1.2.3 and §4.1.2.11 (USLP-130/USLP-131):
 * - VCF counters are scoped per VC and per QoS class (Bypass=0 Sequence-Controlled, Bypass=1 Expedited).
 * - The Primary Header carries 0..7 octets of VCF Count depending on configuration.
 * - For backward compatibility, legacy vcf_count_length (single value) may be used to set both
 *   sequence and expedited lengths when the per-QoS fields are zero.
 */
typedef struct {
    /* Physical Channel Parameters */
    const char* physical_channel_name;  /**< Physical Channel Name (USLP-52; §3.11.2.3) */
    uint16_t max_frame_length;          /**< Maximum frame length */
    uint16_t min_frame_length;          /**< Minimum frame length */
    bool     truncated_frame_capable;   /**< Truncated frame capability */
    uint16_t truncated_frame_length;    /**< Truncated frame length */
    uint8_t  max_frames_per_cs_du;      /**< USLP-122: Max Frames per C&S DU (Table 5-1) — record-only; 0 => unspecified */
    uint8_t  max_repetitions_to_cs;     /**< USLP-123: Max ‘Repetitions’ to C&S (Table 5-1) — record-only; 0 => unspecified */
    
    /* Master Channel Parameters */
    uint8_t  mcf_count_length;          /**< MCF Count length (0..8 octets on wire; placeholder bits count here) */
    /* USLP-117: MC Multiplexing Scheme (Table 5-1) — recorded and used for scheduling on Physical Channel */
    uni_uslp_mc_mux_scheme_t mc_mux_scheme; /**< Master Channel multiplexing scheme (default SINGLE) */
    /* USLP-127: VC Multiplexing Scheme (Table 5-2) — used by scheduler to select next VC on the Master Channel (§4.2.8, §4.2.10) */
    uni_uslp_vc_mux_scheme_t vc_mux_scheme; /**< VC multiplexing scheme (default SINGLE; options: PRIORITY, RR, DRR) */
    
    /* Virtual Channel Parameters */
    uint8_t  vcf_count_length;          /**< Legacy: VCF Count length (octets) applied to both QoS if per-QoS unset */
    uint8_t  vcf_seq_count_len_octets;  /**< USLP-130: Sequence-Controlled VCF Count octets (0..7) */
    uint8_t  vcf_exp_count_len_octets;  /**< USLP-131: Expedited VCF Count octets (0..7) */
    bool     vcf_persist;               /**< Persist VCF TX counters across reset (default false) */
    uint8_t  vcf_duplicate_window;      /**< Duplicate detection window (history depth), default 1 */

    /* USLP-132..USLP-144 (Table 5-3 VC Managed Parameters) */
    uni_uslp_cop_in_effect_t  cop_in_effect;        /**< USLP-132: COP in Effect (VC scope): NONE or COP-1 */
    uint8_t   clcw_version;                          /**< USLP-133: CLCW Version (recorded; Type-1 OCF provider specific) */
    uint16_t  clcw_reporting_rate;                   /**< USLP-134: CLCW Reporting Rate (recorded; provider/mission units) */
    uni_uslp_map_mux_scheme_t map_mux_scheme;        /**< USLP-136: MAP Multiplexing Scheme — used by MAP scheduler (USLP-96) */
    bool      ocf_allowed_variable;                  /**< USLP-139: Inclusion of OCF Allowed on variable-length frames */
    bool      ocf_required_fixed;                    /**< USLP-140: Inclusion of OCF Required on fixed-length frames */
    uint8_t   repetitions_seq;                       /**< USLP-141: Repetitions (Sequence-Controlled); record only */
    uint8_t   repetitions_cop_ctrl;                  /**< USLP-142: Repetitions (COP control); record only */
    uint32_t  max_tfdf_completion_delay;             /**< USLP-143: Max TFDF completion delay; record only */
    uint32_t  max_inter_frame_delay;                 /**< USLP-144: Max delay between frames; record only */

    bool     ocf_capability;            /**< OCF capability */
    bool     insert_zone_capability;    /**< Insert Zone capability */
    uint16_t insert_zone_length;        /**< Insert Zone length */
    
    /* MAP Parameters */
    bool     fecf_capability;           /**< FECF capability (when true, FECF is present on the wire) */
    uni_uslp_fecf_tx_mode_t fecf_tx_mode; /**< FECF generation mode on TX (default: INTERNAL) */
    bool     segmentation_permitted;    /**< Segmentation permitted */
    bool     blocking_permitted;        /**< Blocking permitted */
    uint16_t max_sdu_length;            /**< Maximum SDU length */

    /* Packet Transfer Parameters — Table 5-5 (USLP-148..USLP-150) */
    uint8_t  valid_pvns_mask;         /**< USLP-148: Bitmask of valid Packet Version Numbers (PVN 0..7); 0 => default allow PVN 0 */
    uint16_t max_packet_length;       /**< USLP-149: Maximum Packet Length in octets; 0 => unlimited */
    bool     deliver_incomplete_packets; /**< USLP-150: If true, deliver incomplete packet portions indicated by FHP; default false */
} uni_uslp_managed_params_t;


/**
 * @brief Multiplexing Policy Configuration
 */
typedef struct {
    uint8_t  priority;                  /**< Channel priority (0-255) */
    uint16_t weight;                    /**< DRR weight */
    uint32_t max_burst_size;            /**< Maximum burst size */
} uni_uslp_mux_policy_t;


/**
 * @brief SDLS Configuration (CCSDS 355.0-B-2 §6.6; USLP §6.6.2)
 *
 * Note: Key pointers must remain valid for the lifetime of the context or until reconfigured.
 */
typedef struct {
    bool     enabled;                   /**< SDLS enabled (USLP-151) */
    uint8_t  spi;                       /**< Security Parameter Index (SDLS §3.4) */
    uint8_t  iv_length;                 /**< IV/Nonce length (bytes), per suite */
    uint8_t  mac_length;                /**< ICV/MAC length (bytes), per suite */
    bool     authentication_only;       /**< Auth-only mode (e.g., HMAC) */
    bool     encryption_enabled;        /**< Authenticated encryption enabled (AEAD) */

    /* Algorithm suite and keying (maps to CCSDS 355.0-B-2 algorithm profiles) */
    uni_uslp_sdls_suite_t suite;        /**< Selected transform suite */
    const uint8_t* key;                 /**< Pointer to key material (AES or HMAC key) */
    uint16_t key_length;                /**< Key length in bytes */

    /* Anti-replay configuration */
    bool     anti_replay_enabled;       /**< Enable sliding window anti-replay */
    uint8_t  anti_replay_window;        /**< Window size (entries, up to 64 recommended) */

    /* USLP Additional Managed Parameters with SDLS Option (§6.6.2; USLP-176..179) */
    bool     sec_header_present;        /**< Presence of Security Header (USLP-176) */
    bool     sec_trailer_present;       /**< Presence of Security Trailer (USLP-177) */
    uint8_t  sec_header_length;         /**< Security Header length in octets (USLP-178) */
    uint8_t  sec_trailer_length;        /**< Security Trailer length in octets (USLP-179) */
} uni_uslp_sdls_config_t;




//
// Typedefs
//

/**
 * @brief Forward declaration of USLP context
 */
typedef struct uni_uslp_context uni_uslp_context_t;


/**
 * @brief Service Data Unit callback function
 *
 * Includes Verification Status Code when SDLS option is enabled
 * (USLP §3.3.2.9, §3.5.2.8, §3.6.3.7, §3.7.2.7; C2).
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param service_type Service type
 * @param sdu_data SDU data buffer
 * @param sdu_length SDU data length
 * @param verification_status Verification Status Code (C2): NOT_APPLICABLE if SDLS not in effect; SUCCESS when SDLS verified
 * @param gap_detected Gap in sequence detected (Loss Flag derivation where applicable)
 * @param user_data User-provided data
 */
typedef void (*uni_uslp_sdu_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_service_type_t service_type,
    const uint8_t *sdu_data,
    size_t sdu_length,
    uni_uslp_verification_status_t verification_status,
    bool gap_detected,
    void *user_data
);

/**
 * @brief OCF callback function
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param ocf OCF data
 * @param user_data User-provided data
 */
typedef void (*uni_uslp_ocf_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_ocf_t *ocf,
    void *user_data
);

/**
 * OCF.indication v2 (USLP_MC_OCF.indication) with OCF_SDU Loss Flag — CCSDS 732.1-B-3 §3.8.2.4 (Optional).
 *
 * Loss Flag is derived from the underlying Synchronization and Channel Coding sublayer loss signal
 * per §3.8.2.4.2. Backward compatible: the legacy uni_uslp_ocf_callback_t remains supported.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID (GVCID low part)
 * @param ocf OCF data (32-bit)
 * @param ocf_sdu_loss_flag true if loss was signaled prior to this frame (per §3.8.2.4.2)
 * @param user_data User-provided pointer
 */
typedef void (*uni_uslp_ocf2_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_ocf_t *ocf,
    bool ocf_sdu_loss_flag,
    void *user_data
);
/**
 * @brief Insert Zone callback function
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param insert_data Insert Zone data
 * @param insert_length Insert Zone length
 * @param user_data User-provided data
 */
typedef void (*uni_uslp_insert_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *insert_data,
    size_t insert_length,
    void *user_data
);

/**
 * INSERT.indication v2 (receiving end) — §3.11.3.3 with IN_SDU Loss Flag (§3.11.2.4, optional).
 * Backward compatible: original uni_uslp_insert_callback_t remains supported.
 * Derivation per CCSDS 732.1-B-3 §3.11.2.4.2: from underlying Synchronization and Channel Coding sublayer signal.
 */
typedef void (*uni_uslp_insert2_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *insert_data,
    size_t insert_length,
    bool in_sdu_loss_flag,        /* Derived from C&S loss signal (§3.11.2.4.2) */
    void *user_data
);


/**
 * @brief Idle filler callback function
 * 
 * @param buffer Buffer to fill
 * @param length Length to fill
 * @param user_data User-provided data
 */
typedef void (*uni_uslp_idle_filler_callback_t)(
    uint8_t *buffer,
    size_t length,
    void *user_data
);

/**
 * @brief Notification type for OCTET_STREAM_Notify.indication (CCSDS 732.1-B-3 §3.7.3.4)
 *
 * This is an implementation-defined minimal set sufficient for testing and basic integration.
 * Projects may extend with mission-specific values.
 */
typedef enum {
    UNI_USLP_OS_NOTIFY_QUEUED = 0,            /**< Portion queued for transfer (sending end) */
    UNI_USLP_OS_NOTIFY_SENT    = 1,           /**< Portion sent (frame built/emitted by USLP entity) */
    UNI_USLP_OS_NOTIFY_REJECTED_UNSUPPORTED = 2, /**< Rejected due to configuration (e.g., fixed-length restriction) */
    UNI_USLP_OS_NOTIFY_REJECTED_INVALID     = 3  /**< Rejected due to invalid parameters */
} uni_uslp_octet_stream_notify_type_t;

/**
 * @brief OCTET_STREAM_Notify.indication callback (sending end) (§3.7.3.4)
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID (GMAP ID low part)
 * @param sdu_id SDU ID (sender-supplied, §3.7.2.4; accounting only)
 * @param expedited QoS (true=Expedited, false=Sequence-Controlled) (§3.7.2.5)
 * @param notify_type Notification Type (implementation-defined enum above)
 * @param user_data User-provided pointer
 */
typedef void (*uni_uslp_octet_stream_notify_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uint32_t sdu_id,
    bool expedited,
    uni_uslp_octet_stream_notify_type_t notify_type,
    void *user_data
);

/**
 * @brief Notification type for MAPA_Notify.indication (CCSDS 732.1-B-3 §3.5.3.3)
 *
 * Minimal set for this implementation: QUEUED, SENT, REJECTED_INVALID. REJECTED_UNSUPPORTED is reserved.
 */
typedef enum {
    UNI_USLP_MAPA_NOTIFY_QUEUED = 0,              /**< MAPA_SDU queued for transfer (sending end) */
    UNI_USLP_MAPA_NOTIFY_SENT   = 1,              /**< MAPA_SDU sent (frame built/emitted by USLP entity) */
    UNI_USLP_MAPA_NOTIFY_REJECTED_UNSUPPORTED = 2,/**< Rejected due to configuration (not used currently) */
    UNI_USLP_MAPA_NOTIFY_REJECTED_INVALID   = 3   /**< Rejected due to invalid parameters */
} uni_uslp_mapa_notify_type_t;

/**
 * @brief MAPA_Notify.indication callback (sending end) (§3.5.3.3)
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID (GMAP ID low part)
 * @param notify_type Notification Type
 * @param user_data User-provided pointer
 */
typedef void (*uni_uslp_mapa_notify_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapa_notify_type_t notify_type,
    void *user_data
);
/**
 * @brief Notification type for VCA_Notify.indication (CCSDS 732.1-B-3 §3.6.4.3)
 *
 * Minimal set for this implementation: QUEUED, SENT, REJECTED_INVALID, REJECTED_UNSUPPORTED.
 */
typedef enum {
    UNI_USLP_VCA_NOTIFY_QUEUED = 0,               /**< VCA_SDU queued for transfer (sending end) */
    UNI_USLP_VCA_NOTIFY_SENT   = 1,               /**< VCA_SDU sent (frame built/emitted by USLP entity) */
    UNI_USLP_VCA_NOTIFY_REJECTED_UNSUPPORTED = 2, /**< Rejected due to configuration/policy */
    UNI_USLP_VCA_NOTIFY_REJECTED_INVALID   = 3    /**< Rejected due to invalid parameters */
} uni_uslp_vca_notify_type_t;

/**
 * @brief VCA_Notify.indication callback (sending end) (§3.6.4.3)
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID (GMAP ID low part)
 * @param notify_type Notification Type
 * @param user_data User-provided pointer
 */
typedef void (*uni_uslp_vca_notify_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_vca_notify_type_t notify_type,
    void *user_data
);

/**
 * @brief Notification type for MAPP_Notify.indication (CCSDS 732.1-B-3 §3.3.3.3)
 *
 * Minimal set for this implementation: QUEUED, SENT, REJECTED_INVALID, REJECTED_UNSUPPORTED.
 */
typedef enum {
    UNI_USLP_MAPP_NOTIFY_QUEUED = 0,               /**< Packet SDU queued for transfer (sending end) */
    UNI_USLP_MAPP_NOTIFY_SENT   = 1,               /**< Packet SDU sent (frame built/emitted by USLP entity) */
    UNI_USLP_MAPP_NOTIFY_REJECTED_UNSUPPORTED = 2, /**< Rejected due to configuration/policy */
    UNI_USLP_MAPP_NOTIFY_REJECTED_INVALID   = 3    /**< Rejected due to invalid parameters */
} uni_uslp_mapp_notify_type_t;

/**
 * @brief MAPP_Notify.indication callback (sending end) (§3.3.3.3)
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID (GMAP ID low part)
 * @param notify_type Notification Type
 * @param user_data User-provided pointer
 */
typedef void (*uni_uslp_mapp_notify_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapp_notify_type_t notify_type,
    void *user_data
);

/**
 * @brief MAPP.indication callback (receiving end) with Packet Quality Indicator (§3.3.3.4, §3.3.2.8)
 *
 * Optional per-standard parameter PQI indicates whether the delivered Packet is complete or partial.
 * This implementation currently delivers complete packets (no segmentation), thus PQI=COMPLETE.
 * Verification Status Code is provided per §3.3.2.9 (C2) when SDLS is enabled, else NOT_APPLICABLE.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID (GMAP ID low part)
 * @param packet Pointer to the Packet SDU bytes
 * @param packet_length Packet length in bytes
 * @param pqi Packet Quality Indicator (USLP-14)
 * @param verification_status Verification Status Code (C2)
 * @param user_data User-provided pointer
 */
typedef void (*uni_uslp_mapp_indication_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *packet,
    size_t packet_length,
    uni_uslp_packet_quality_t pqi,
    uni_uslp_verification_status_t verification_status,
    void *user_data
);

/* VCP (Virtual Channel Packet) Service — §3.4
 * Notification Type is optional (USLP-21), provided at the sending end analogous to MAPP_Notify.
 * Indication delivers Packet with optional PQI (USLP-22) and Verification Status Code (USLP-23, C2).
 */

/* VCP_Notify.indication types (sending end) — minimal set analogous to MAPP/VCA */
typedef enum {
    UNI_USLP_VCP_NOTIFY_QUEUED = 0,               /* request accepted and queued */
    UNI_USLP_VCP_NOTIFY_SENT   = 1,               /* a frame carrying that Packet SDU has been built/emitted */
    UNI_USLP_VCP_NOTIFY_REJECTED_UNSUPPORTED = 2, /* rejected due to configuration/policy */
    UNI_USLP_VCP_NOTIFY_REJECTED_INVALID   = 3    /* rejected due to invalid parameters */
} uni_uslp_vcp_notify_type_t;

/* VCP_Notify.indication callback (sending end) (§3.4.3.3) */
typedef void (*uni_uslp_vcp_notify_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcp_notify_type_t notify_type,
    void *user_data
);

/* VCP.indication callback (receiving end) (§3.4.3.4) with optional PQI (USLP-22) and Verification Status (USLP-23, C2) */
typedef void (*uni_uslp_vcp_indication_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *packet,
    size_t packet_length,
    uni_uslp_packet_quality_t pqi,
    uni_uslp_verification_status_t verification_status,
    void *user_data
);

/* VCF Service — §3.9
 * VCF.indication callback (receiving end) — §3.9.3.3; Parameters §3.9.2.2–§3.9.2.4.
 * Frame Loss Flag derivation per §3.9.2.4.2 by examining VCF Count continuity.
 */
typedef void (*uni_uslp_vcf_indication_cb_t)(
    uni_uslp_context_t *context,
    uint16_t scid,                /* From Primary Header (§4.1.2.2.3) */
    uint8_t vcid,                 /* From Primary Header (§4.1.2.4.1) */
    const uint8_t *frame,         /* Entire USLP Transfer Frame (PH..FECF) */
    size_t frame_length,
    bool frame_loss_flag,         /* true if VCF Count gap detected for this VC/QoS */
    void *user_data
);

/* MCF Service — §3.10
 * MCF.indication callback (receiving end) — §3.10.3.3; Parameters §3.10.2.2–§3.10.2.4.
 * Frame Loss Flag derivation per §3.10.2.4.2 from underlying C&S loss signal.
 */
typedef void (*uni_uslp_mcf_indication_cb_t)(
    uni_uslp_context_t *context,
    uint32_t mcid,                /* MCID = (TFVN << 16) | SCID (§2.1.3, §4.1.2.2) */
    const uint8_t *frame,         /* Entire USLP Transfer Frame (PH..FECF) */
    size_t frame_length,
    bool frame_loss_flag,         /* true if C&S indicated loss prior to this frame */
    void *user_data
);


/* COPs Management Service — §3.12
 * Directive.request (§3.12.3.2), Directive_Notify.indication (§3.12.3.3), Async_Notify.indication (§3.12.3.4)
 * Parameters per §3.12.2 (USLP-54..USLP-60). This implementation exposes minimal, transport-agnostic
 * callbacks to deliver Notification Type/Qualifier values without inventing COP semantics. The values
 * are forwarded as numeric fields; projects may map them to COP-1 (per-VC) or COP-P (per-MC) specifics.
 */

/* Implementation-defined minimal set for Directive_Notify Notification Type (sending-end lifecycle). */
typedef enum {
    UNI_USLP_DIR_NOTIFY_QUEUED = 0,               /* Request accepted and queued for transfer */
    UNI_USLP_DIR_NOTIFY_SENT   = 1,               /* Directive transferred to underlying entity */
    UNI_USLP_DIR_NOTIFY_REJECTED_INVALID = 2,     /* Rejected due to invalid parameters */
    UNI_USLP_DIR_NOTIFY_REJECTED_UNSUPPORTED = 3  /* Rejected due to configuration/policy */
} uni_uslp_directive_notify_type_t;

/* Directive_Notify.indication callback (sending end) — §3.12.3.3
 *
 * - is_cop1=true  => target identified by (vcid) per USLP-54 (GVCID on SAP; SCID implied by context)
 * - is_cop1=false => target identified by (port_id) per USLP-55 (COP-P Port ID)
 * - directive_id/type/qualifier per USLP-56..USLP-58
 * - notify_type/notify_qualifier per USLP-59..USLP-60
 */
typedef void (*uni_uslp_directive_notify_cb_t)(
    uni_uslp_context_t *context,
    bool is_cop1,
    uint8_t vcid,
    uint32_t port_id,
    uint16_t directive_id,
    uint8_t directive_type,
    uint32_t directive_qualifier,
    uni_uslp_directive_notify_type_t notify_type,
    uint32_t notify_qualifier,
    void *user_data
);

/* Async_Notify.indication callback (receiving end) — §3.12.3.4
 *
 * Asynchronous notifications unrelated to an immediate Directive.request completion, e.g., COP state changes.
 * Parameters mirror USLP-59..USLP-60 with target scope (VC via GVCID or MC via Port ID).
 */
typedef void (*uni_uslp_async_notify_cb_t)(
    uni_uslp_context_t *context,
    bool is_cop1,
    uint8_t vcid,
    uint32_t port_id,
    uint8_t notification_type,
    uint32_t notification_qualifier,
    void *user_data
);
/**
 * @brief SDLS Apply Security callback (CCSDS 355.0-B-2 §3.3)
 * 
 * @param context USLP context
 * @param input_frame Input frame buffer
 * @param input_length Input frame length
 * @param output_frame Output frame buffer
 * @param output_length Output frame length (in/out)
 * @param config SDLS configuration
 * @param user_data User-provided data
 * @return Status code
 */
typedef uni_uslp_status_t (*uni_uslp_sdls_apply_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,                       /* VC context for per-SA state */
    const uint8_t *input_frame,         /* TFDF header + TFDZ (no OCF/FECF) */
    size_t input_length,
    uint8_t *output_frame,              /* Security Header + protected TFDF’ + Security Trailer */
    size_t *output_length,
    const uni_uslp_sdls_config_t *config,
    void *user_data
);


/**
 * @brief SDLS Process Security callback (CCSDS 355.0-B-2 §3.4)
 * 
 * @param context USLP context
 * @param input_frame Input frame buffer
 * @param input_length Input frame length
 * @param output_frame Output frame buffer
 * @param output_length Output frame length (in/out)
 * @param config SDLS configuration
 * @param user_data User-provided data
 * @return Status code
 */
typedef uni_uslp_status_t (*uni_uslp_sdls_process_callback_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,                       /* VC context for per-SA state */
    const uint8_t *input_frame,         /* Security Header + protected TFDF’ + Security Trailer */
    size_t input_length,
    uint8_t *output_frame,              /* TFDF header + TFDZ (no SDLS data) */
    size_t *output_length,
    const uni_uslp_sdls_config_t *config,
    void *user_data,
    uint64_t *out_seq_num               /* Parsed Sequence Number (for anti-replay) */
);

/* TX callbacks for VCF/MCF request provider bridging (USLP §3.9.3.2, §3.10.3.2)
 * The USLP entity, acting as provider for VCF/MCF.request, forwards externally-supplied
 * USLP Transfer Frames to the underlying C&amp;S sublayer (or test harness) via these callbacks.
 */
typedef void (*uni_uslp_vcf_tx_cb_t)(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *frame,
    size_t frame_length,
    void *user_data
);

typedef void (*uni_uslp_mcf_tx_cb_t)(
    uni_uslp_context_t *context,
    uint32_t mcid, /* MCID = (TFVN << 16) | SCID (§2.1.3) */
    const uint8_t *frame,
    size_t frame_length,
    void *user_data
);



/* ========================================================================== */
/* CONTEXT MANAGEMENT                                                         */
/* ========================================================================== */

/**
 * @brief Initialize USLP context
 * 
 * @param context Context to initialize
 * @param scid Spacecraft ID
 * @param params Managed parameters
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_init(
    uni_uslp_context_t *context,
    uint16_t scid,
    const uni_uslp_managed_params_t *params
);

/**
 * @brief Reset USLP context
 * 
 * @param context Context to reset
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_reset(uni_uslp_context_t *context);

/**
 * @brief Free USLP context resources
 *
 * @param context Context to free
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_free(uni_uslp_context_t *context);

/**
 * @brief Set working buffer for in-place transformations (e.g., SDLS ProcessSecurity on RX)
 *
 * CCSDS 732.1-B-3 §6.5 requires SDLS processing on the received frame prior to TFDF parsing.
 * To avoid heap allocation, the application provides a scratch buffer used by the USLP entity
 * to hold transformed slices (e.g., Security Header removal and decrypt/authenticate output).
 *
 * Thread-safety: The caller must ensure exclusive use of the context while operations are in flight.
 *
 * @param context USLP context
 * @param work_buffer Caller-provided buffer memory (may be NULL to clear)
 * @param work_buffer_size Size of the buffer in bytes
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_set_work_buffer(
    uni_uslp_context_t *context,
    uint8_t *work_buffer,
    size_t work_buffer_size
);

/* ========================================================================== */
/* CONFIGURATION                                                              */
/* ========================================================================== */

/**
 * @brief Configure Virtual Channel
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param params VC-specific parameters
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_configure_vc(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_managed_params_t *params
);

/**
 * @brief Configure MAP
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param service_type Service type
 * @param params MAP-specific parameters
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_configure_map(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_service_type_t service_type,
    const uni_uslp_managed_params_t *params
);

/**
 * @brief Set multiplexing policy
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param policy Multiplexing policy
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_set_mux_policy(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uni_uslp_mux_policy_t *policy
);

/**
 * @brief Configure SDLS
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param config SDLS configuration
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_configure_sdls(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_sdls_config_t *config
);

/* ========================================================================== */
/* GETTERS: Managed Parameters (USLP-132..USLP-144)                            */
/* ========================================================================== */

/**
 * Get a copy of VC managed parameters, including USLP-132..USLP-144 fields.
 * Returns UNI_USLP_ERROR_INVALID_PARAM if VC not configured.
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_get_vc_params(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_managed_params_t *out_params
);

/**
 * Get repetition configuration counts (USLP-141/USLP-142) for a VC.
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_get_repetition_counts(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t *repetitions_seq,
    uint8_t *repetitions_cop_ctrl
);

/* ========================================================================== */
/* CALLBACK REGISTRATION                                                      */
/* ========================================================================== */

/**
 * @brief Register SDU callback
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param callback Callback function
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_sdu_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_sdu_callback_t callback,
    void *user_data
);

/**
 * @brief Register OCF callback
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param callback Callback function
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_ocf_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_ocf_callback_t callback,
    void *user_data
);

/**
 * @brief Register OCF.indication v2 callback with OCF_SDU Loss Flag (USLP-44) — CCSDS 732.1-B-3 §3.8.2.4
 *
 * Optional Loss Flag parameter is derived from the underlying Synchronization and Channel Coding
 * sublayer loss signal per §3.8.2.4.2. Provide the signal before calling uni_ccsds_uslp_accept_frame()
 * via uni_ccsds_uslp_set_rx_cs_loss_signaled(); it is latched and consumed on the next successful accept.
 *
 * Backward compatible: the legacy OCF callback remains supported; this v2 adds the Loss Flag.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param callback OCF v2 callback (with Loss Flag)
 * @param user_data User pointer
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_ocf2_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_ocf2_callback_t callback,
    void *user_data
);

/**
 * @brief Register Insert Zone callback
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param callback Callback function
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_insert_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_insert_callback_t callback,
    void *user_data
);

/**
 * Register INSERT.indication v2 callback with IN_SDU Loss Flag (optional parameter per §3.11.2.4).
 *
 * CCSDS 732.1-B-3:
 *  - §3.11.2.2 IN_SDU (USLP-51)
 *  - §3.11.2.3 Physical Channel Name (USLP-52)
 *  - §3.11.2.4 IN_SDU Loss Flag (USLP-53, Optional): derived from underlying Synchronization and Channel Coding sublayer signal (§3.11.2.4.2).
 *  - §3.11.3.3 INSERT.indication primitive
 *
 * Backward compatible: the legacy INSERT.indication callback remains supported; this v2 adds the Loss Flag.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param callback INSERT.indication v2 callback
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_insert2_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_insert2_callback_t callback,
    void *user_data
);

/**
 * @brief Register idle filler callback
 * 
 * @param context USLP context
 * @param callback Callback function
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_idle_filler_callback(
    uni_uslp_context_t *context,
    uni_uslp_idle_filler_callback_t callback,
    void *user_data
);
/**
 * @brief Register OCTET_STREAM_Notify.indication callback (sending end) (§3.7.3.4)
 *
 * Notifies the user about events associated with the transfer of Octet Stream portions:
 *  - QUEUED: successfully enqueued by OCTET_STREAM.request
 *  - SENT: a frame carrying that portion has been built/emitted by the USLP entity
 *  - REJECTED_UNSUPPORTED: request rejected due to configuration (e.g., fixed-length restriction per §2.2.4.6/§2.2.5 g)
 *  - REJECTED_INVALID: request rejected due to invalid parameters
 *
 * Note: SDU ID is for accounting only (§2.2.2, §3.7.2.4) and is not transmitted across the link.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param callback Callback function
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_octet_stream_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_octet_stream_notify_cb_t callback,
    void *user_data
);

/**
 * @brief Register a sending-end MAPA_Notify.indication callback.
 *
 * The callback receives QUEUED, SENT, or REJECTED notifications for MAPA SDUs
 * queued through uni_ccsds_uslp_send_mapa(). Ref: CCSDS 732.1-B-3 §3.5.3.3.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param callback Notify callback
 * @param user_data Opaque pointer passed to the callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_mapa_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapa_notify_cb_t callback,
    void *user_data
);

/**
 * @brief Register SDLS callbacks
 *
 * @param context USLP context
 * @param apply_callback Apply Security callback
 * @param process_callback Process Security callback
 * @param user_data User data for callbacks
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_sdls_callbacks(
    uni_uslp_context_t *context,
    uni_uslp_sdls_apply_callback_t apply_callback,
    uni_uslp_sdls_process_callback_t process_callback,
    void *user_data
);

/**
 * @brief Register a sending-end MAPP_Notify.indication callback.
 *
 * The callback observes state changes for Packet SDUs queued with
 * uni_ccsds_uslp_send_packet_ex(). Ref: CCSDS 732.1-B-3 §3.3.3.3.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param callback Notify callback
 * @param user_data Opaque pointer passed to the callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_mapp_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapp_notify_cb_t callback,
    void *user_data
);

/**
 * @brief Register a sending-end VCA_Notify.indication callback.
 *
 * The callback tracks queue/send/reject outcomes for VCA SDUs submitted via
 * uni_ccsds_uslp_send_vca_ex(). Ref: CCSDS 732.1-B-3 §3.6.4.3.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param callback Notify callback
 * @param user_data Opaque pointer passed to the callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_vca_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_vca_notify_cb_t callback,
    void *user_data
);

/**
 * @brief Register an optional receiving-end MAPP.indication callback.
 *
 * When configured, Packet SDUs are delivered through this callback together with
 * PQI and verification status information. Ref: CCSDS 732.1-B-3 §3.3.3.4.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param callback Indication callback
 * @param user_data Opaque pointer passed to the callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_mapp_indication_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_mapp_indication_cb_t callback,
    void *user_data
);

/**
 * @brief Register a sending-end VCP_Notify.indication callback.
 *
 * The callback is raised for queue/send/reject results produced by
 * uni_ccsds_uslp_send_vcp_ex(). Ref: CCSDS 732.1-B-3 §3.4.3.3.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param callback Notify callback
 * @param user_data Opaque pointer passed to the callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_vcp_notify_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcp_notify_cb_t callback,
    void *user_data
);

/**
 * @brief Register VCP.indication callback (receiving end) (§3.4.3.4) with optional PQI (USLP-22) and Verification Status (USLP-23, C2)
 *
 * PQI is only meaningful if incomplete packet delivery is configured (Table 5-5). This minimal implementation
 * does not perform segmentation and therefore delivers complete Packets with PQI=COMPLETE by default.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param callback VCP.indication callback
 * @param user_data User data pointer
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_vcp_indication_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcp_indication_cb_t callback,
    void *user_data
);

/**
 * Register VCF.indication callback (receiving end) — §3.9.3.3.
 *
 * Parameters per §3.9.2:
 *  - USLP-45: USLP Frame (entire Transfer Frame)
 *  - USLP-46: GVCID (SCID + VCID conveyed by PH; SCID from §4.1.2.2.3, VCID from §4.1.2.4.1)
 *  - USLP-47: Frame Loss Flag (Optional): derived by examining VCF Count continuity (§3.9.2.4.2; §4.3.7.4).
 *
 * The Loss Flag will be true when a VCF Count gap is detected for the corresponding QoS (Bypass=0/1).
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID to bind the indication callback
 * @param callback VCF.indication callback
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_vcf_indication_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcf_indication_cb_t callback,
    void *user_data
);

/**
 * Register MCF.indication callback (receiving end) — §3.10.3.3.
 *
 * Parameters per §3.10.2:
 *  - USLP-48: USLP Frame (entire Transfer Frame)
 *  - USLP-49: MCID (TFVN + SCID; MCID = (TFVN << 16) | SCID) (§2.1.3; §4.1.2.2)
 *  - USLP-50: Frame Loss Flag (Optional): derived from underlying Synchronization and Channel Coding sublayer signal (§3.10.2.4.2; §4.3.10.3).
 *
 * Use uni_ccsds_uslp_set_rx_cs_loss_signaled() prior to uni_ccsds_uslp_accept_frame() to provide the C&S loss signal.
 *
 * @param context USLP context
 * @param callback MCF.indication callback
 * @param user_data User data for callback
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_mcf_indication_callback(
    uni_uslp_context_t *context,
    uni_uslp_mcf_indication_cb_t callback,
    void *user_data
);

/* ========================================================================== */
/* CALLBACKS: PROVIDER BRIDGING (VCF/MCF) AND COPs MANAGEMENT (Directive/Async) */
/* ========================================================================== */

/**
 * Register VCF.request provider TX callback — CCSDS 732.1-B-3 §3.9.3.2 (USLP-78).
 *
 * The USLP entity forwards externally supplied, partially formatted USLP Transfer Frames
 * for the specified VC to the underlying C&S sublayer (or test harness) via this callback.
 * See §3.2.7 for "partially formatted" constraints; frames shall not include OCF/FECF
 * inserted by the USLP entity (bypass §4.2.11.5 error-control encoding).
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID (GVCID low part; TFVN and SCID implied by context)
 * @param callback Provider TX callback
 * @param user_data Opaque user pointer
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_vcf_tx_callback(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uni_uslp_vcf_tx_cb_t callback,
    void *user_data
);

/**
 * Register MCF.request provider TX callback — CCSDS 732.1-B-3 §3.10.3.2 (USLP-80).
 *
 * The USLP entity forwards externally supplied, partially formatted USLP Transfer Frames
 * on the Master Channel (identified by MCID = (TFVN<<16)|SCID; §2.1.3) to the underlying
 * C&S sublayer via this callback.
 *
 * @param context USLP context
 * @param callback Provider TX callback
 * @param user_data Opaque user pointer
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_mcf_tx_callback(
    uni_uslp_context_t *context,
    uni_uslp_mcf_tx_cb_t callback,
    void *user_data
);

/**
 * Register Directive_Notify.indication callback — CCSDS 732.1-B-3 §3.12.3.3 (USLP-85).
 *
 * Notifies the sending-end user about events associated with Directive.request (§3.12.3.2).
 * Parameters mirror §3.12.2 (USLP-56..USLP-60). Values are forwarded as numeric fields
 * (no invented COP semantics).
 *
 * @param context USLP context
 * @param callback Directive_Notify.indication callback
 * @param user_data Opaque user pointer
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_directive_notify_callback(
    uni_uslp_context_t *context,
    uni_uslp_directive_notify_cb_t callback,
    void *user_data
);

/**
 * Register Async_Notify.indication callback — CCSDS 732.1-B-3 §3.12.3.4 (USLP-86).
 *
 * Delivers asynchronous notifications related to COPs Management.
 *
 * @param context USLP context
 * @param callback Async_Notify.indication callback
 * @param user_data Opaque user pointer
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_async_notify_callback(
    uni_uslp_context_t *context,
    uni_uslp_async_notify_cb_t callback,
    void *user_data
);

/* ========================================================================== */
/* SENDING SERVICES                                                           */
/* ========================================================================== */


/**
 * @brief Queue a Space Packet SDU on a MAP channel (MAPP.request).
 *
 * Validates PVN and length against managed parameters, captures QoS metadata,
 * raises MAPP_Notify.indication (QUEUED/REJECTED) when configured, and leaves the
 * payload for the frame builder to emit in a single TFDF. Ref: CCSDS 732.1-B-3 §3.3.3.2.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param packet_data Pointer to one complete Space Packet
 * @param packet_length Space Packet length in bytes
 * @param pvn Application PVN (accounting only; not transmitted)
 * @param expedited True for expedited QoS (Bypass=1), else sequence-controlled
 * @param sdu_id Optional accounting identifier (not transmitted)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_packet_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *packet_data,
    size_t packet_length,
    uint8_t pvn,
    bool expedited,
    uint32_t sdu_id
);


/**
 * @brief Queue a VC Packet (VCP.request) on the VC service endpoint.
 *
 * Internally uses MAP ID 0 to share the MAP build path, enforces PVN and length
 * constraints, records QoS metadata, and fires VCP_Notify.indication events when
 * registered. Ref: CCSDS 732.1-B-3 §3.4.3.2.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID providing VCP service (MAP 0 is assumed)
 * @param packet_data Pointer to one complete Space Packet
 * @param packet_length Space Packet length in bytes
 * @param pvn Application PVN (accounting only; not transmitted)
 * @param expedited True for expedited service (Bypass=1), else sequence-controlled
 * @param sdu_id Optional accounting identifier (not transmitted)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_vcp_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *packet_data,
    size_t packet_length,
    uint8_t pvn,
    bool expedited,
    uint32_t sdu_id
);

/**
 * @brief Send MAPA Service SDU
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param sdu_data SDU data
 * @param sdu_length SDU length
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_mapa(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *sdu_data,
    size_t sdu_length
);


/**
 * @brief Queue a VCA SDU (VCA.request) on a MAP channel.
 *
 * Applies minimal Rule ‘111’ behaviour (no segmentation), records QoS and SDU ID
 * metadata, and emits VCA_Notify.indication state transitions when enabled.
 * Ref: CCSDS 732.1-B-3 §3.6.4.2.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID providing VCA service
 * @param sdu_data Pointer to VCA SDU bytes
 * @param sdu_length SDU length in bytes
 * @param expedited True for expedited delivery (Bypass=1), else sequence-controlled
 * @param sdu_id Optional accounting identifier (not transmitted)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_vca_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *sdu_data,
    size_t sdu_length,
    bool expedited,
    uint32_t sdu_id
);


/**
 * @brief Queue an Octet Stream segment (OCTET_STREAM.request).
 *
 * Accepts variable-length data only, enforces fixed-length restrictions, stores
 * QoS metadata, and issues OCTET_STREAM_Notify.indication callbacks for queue,
 * rejection, and send events. Ref: CCSDS 732.1-B-3 §3.7.3.2.
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID configured for Octet Stream service
 * @param data Pointer to Octet Stream bytes
 * @param length Number of bytes to queue
 * @param expedited True for expedited delivery (Bypass=1), else sequence-controlled
 * @param sdu_id Optional accounting identifier (not transmitted)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_octet_stream_ex(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    const uint8_t *data,
    size_t length,
    bool expedited,
    uint32_t sdu_id
);

/**
 * @brief Send OCF data
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param ocf OCF data
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_ocf(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_ocf_t *ocf
);

/**
 * @brief Send Insert Zone data
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param insert_data Insert Zone data
 * @param insert_length Insert Zone length
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_send_insert(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *insert_data,
    size_t insert_length
);

/**
 * VCF.request — CCSDS 732.1-B-3 §3.9.3.2 (USLP-78).
 *
 * Submit an externally supplied, partially formatted USLP Transfer Frame for transmission
 * on the specified VC (GVCID low part). Constraints per §3.2.7 apply. The provider shall
 * forward the frame unchanged; SDLS and FECF generation are not applied by the USLP entity
 * for VCF.request (§2.2.3.4, §4.2.11.5).
 *
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param frame Pointer to frame bytes (PH..TFDF[’].. no OCF/FECF)
 * @param frame_length Length of the frame in octets
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_vcf_request(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *frame,
    size_t frame_length
);

/**
 * MCF.request — CCSDS 732.1-B-3 §3.10.3.2 (USLP-80).
 *
 * Submit an externally supplied, partially formatted USLP Transfer Frame for transmission
 * on the Master Channel identified by MCID = (TFVN<<16)|SCID (§2.1.3). Constraints per §3.2.7 apply.
 * The provider shall forward the frame unchanged; SDLS and FECF generation are not applied (§2.2.3.4, §4.2.11.5).
 *
 * @param context USLP context
 * @param mcid Master Channel ID (TFVN + SCID)
 * @param frame Pointer to frame bytes (PH..TFDF[’].. no OCF/FECF)
 * @param frame_length Length of the frame in octets
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_mcf_request(
    uni_uslp_context_t *context,
    uint32_t mcid,
    const uint8_t *frame,
    size_t frame_length
);

/**
 * Directive.request — CCSDS 732.1-B-3 §3.12.3.2 (USLP-84).
 *
 * Submit a COPs Management directive for either COP-1 (per VC) or COP-P (per MC/Port).
 * This minimal implementation enforces coexistence rules (§2.2.5 b,d) and reports
 * Directive_Notify.indication with QUEUED then SENT if a notify callback is registered.
 *
 * @param context USLP context
 * @param is_cop1 true => target is VC (COP-1; USLP-54), false => target is Port ID (COP-P; USLP-55)
 * @param vcid VCID when is_cop1=true; ignored otherwise
 * @param port_id Port ID when is_cop1=false; ignored otherwise
 * @param directive_id USLP-56
 * @param directive_type USLP-57
 * @param directive_qualifier USLP-58
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_directive_request(
    uni_uslp_context_t *context,
    bool is_cop1,
    uint8_t vcid,
    uint32_t port_id,
    uint16_t directive_id,
    uint8_t directive_type,
    uint32_t directive_qualifier
);

/**
 * Raise Async_Notify.indication — CCSDS 732.1-B-3 §3.12.3.4 (USLP-86).
 *
 * Provider-side API to deliver asynchronous notifications to the registered callback.
 *
 * @param context USLP context
 * @param is_cop1 true => VC scope, false => MC/Port scope
 * @param vcid VCID when is_cop1=true; ignored otherwise
 * @param port_id Port ID when is_cop1=false; ignored otherwise
 * @param notification_type USLP-59
 * @param notification_qualifier USLP-60
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_async_notify(
    uni_uslp_context_t *context,
    bool is_cop1,
    uint8_t vcid,
    uint32_t port_id,
    uint8_t notification_type,
    uint32_t notification_qualifier
);

/* ========================================================================== */
/* FRAME BUILDING                                                             */
/* ========================================================================== */

/**
 * @brief Build Transfer Frame
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param map_id MAP ID
 * @param frame_buffer Output frame buffer
 * @param frame_length Frame buffer size (in), actual frame length (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_build_frame(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t map_id,
    uint8_t *frame_buffer,
    size_t *frame_length
);

/**
 * Notes on FECF offload:
 *
 * If FECF is enabled (see [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436))
 * and TX mode is [`UNI_USLP_FECF_TX_OFFLOAD_APPEND`](include/uni_ccsds_uslp.h:327),
 * the builder counts the 2-byte FECF in the Primary Header Frame Length but does not
 * output those 2 bytes into `frame_buffer`.
 *
 * In that mode, `*frame_length` (bytes written to `frame_buffer`) will be 2 bytes
 * shorter than the length indicated by the Primary Header. The final on-wire frame
 * becomes self-consistent only after the hardware appends the FECF.
 */

/**
 * @brief Build OID Transfer Frame
 * 
 * @param context USLP context
 * @param frame_buffer Output frame buffer
 * @param frame_length Frame buffer size (in), actual frame length (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_build_oid(
    uni_uslp_context_t *context,
    uint8_t *frame_buffer,
    size_t *frame_length
);

/**
 * @brief Build Truncated Transfer Frame
 * 
 * @param context USLP context
 * @param vcid Virtual Channel ID
 * @param frame_buffer Output frame buffer
 * @param frame_length Frame buffer size (in), actual frame length (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_build_truncated(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t *frame_buffer,
    size_t *frame_length
);

/* ========================================================================== */
/* FRAME RECEPTION                                                            */
/* ========================================================================== */

/**
 * @brief Accept and process received Transfer Frame
 * 
 * @param context USLP context
 * @param frame_data Frame data buffer
 * @param frame_length Frame data length
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_accept_frame(
    uni_uslp_context_t *context,
    const uint8_t *frame_data,
    size_t frame_length
);

/**
 * Provide the underlying Synchronization and Channel Coding sublayer loss signal for the next accepted frame.
 *
 * CCSDS 732.1-B-3:
 *  - §3.10.2.4.2 (MCF Frame Loss Flag derivation from C&S signal)
 *  - §3.11.2.4.2 (IN_SDU Loss Flag derivation from C&S signal)
 *
 * Semantics: the flag is latched in the context and consumed by the next successful uni_ccsds_uslp_accept_frame() call.
 * After consumption, it is automatically cleared. Error returns do not consume/clear the flag.
 *
 * @param context USLP context
 * @param loss_signaled true if the C&S layer signaled loss prior to this frame
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_set_rx_cs_loss_signaled(
    uni_uslp_context_t *context,
    bool loss_signaled
);

/* ========================================================================== */
/* UTILITY FUNCTIONS                                                          */
/* ========================================================================== */


/**
 * @brief Generate next OID LFSR value (CCSDS 732.1-B-3 Annex H)
 * 
 * @param lfsr_state LFSR state (in/out)
 * @return Next LFSR value
 */
UNI_CCSDS_EXPORT uint32_t uni_ccsds_uslp_oid_lfsr_next(uint32_t *lfsr_state);

/**
 * @brief Pack non-truncated Primary Header to buffer (MSB-first bit numbering)
 *
 * Layout per CCSDS 732.1-B-3 §4.1.2 (Figure 4-2). Writes the 7-octet base header
 * plus VCF Count (0..7 octets) according to vcf_count_len.
 *
 * @param header Primary header structure
 * @param buffer Output buffer
 * @param buffer_size Output buffer size
 * @param bytes_written Bytes written to buffer (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_primary_header_pack(
    const uni_uslp_primary_header_t *header,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *bytes_written
);

/**
 * @brief Unpack non-truncated Primary Header from buffer (MSB-first bit numbering)
 *
 * Parses the 7-octet base header plus VCF Count as indicated by the header bits.
 *
 * @param buffer Input buffer
 * @param buffer_size Input buffer size
 * @param header Output header structure
 * @param bytes_read Bytes consumed from buffer (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_primary_header_unpack(
    const uint8_t *buffer,
    size_t buffer_size,
    uni_uslp_primary_header_t *header,
    size_t *bytes_read
);

/**
 * @brief Pack TFDF Header to buffer
 * 
 * @param header TFDF header structure
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param bytes_written Bytes written (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_tfdf_header_pack(
    const uni_uslp_tfdf_header_t *header,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *bytes_written
);

/**
 * @brief Unpack TFDF Header from buffer
 * 
 * @param buffer Input buffer
 * @param buffer_size Buffer size
 * @param header Output header structure
 * @param bytes_read Bytes read (out)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_tfdf_header_unpack(
    const uint8_t *buffer,
    size_t buffer_size,
    uni_uslp_tfdf_header_t *header,
    size_t *bytes_read
);




/**
 * @brief Initialize OID LFSR
 *
 * @param lfsr_state Pointer to LFSR state variable
 * @param seed Initial seed value (must be non-zero)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_oid_lfsr_init(uint32_t *lfsr_state, uint32_t seed);

/**
 * @brief Fill buffer with OID LFSR data
 *
 * @param lfsr_state Pointer to LFSR state
 * @param buffer Buffer to fill
 * @param length Number of bytes to fill
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_oid_lfsr_fill(
    uint32_t *lfsr_state,
    uint8_t *buffer,
    size_t length
);


/**
 * @brief OID LFSR self-test
 *
 * @return true if self-test passes, false otherwise
 */
UNI_CCSDS_EXPORT bool uni_ccsds_uslp_oid_lfsr_self_test(void);

/**
 * @brief Get status code description string
 *
 * @param status Status code
 * @return Status description string
 */
UNI_CCSDS_EXPORT const char* uni_ccsds_uslp_status_string(uni_uslp_status_t status);


/* ========================================================================== */
/* MULTIPLEXING SCHEDULER — TX side                                           */
/* CCSDS 732.1-B-3                                                            */
/*   - §4.2.5 MAP Multiplexing Function (USLP-96)                             */
/*   - §4.2.8 Virtual Channel Multiplexing (USLP-99)                          */
/*   - §4.2.10 Master Channel Multiplexing (USLP-101)                         */
/* Managed Parameters                                                         */
/*   - Table 5-1: MC Multiplexing Scheme (USLP-117)                           */
/*   - Table 5-2: VC Multiplexing Scheme (USLP-127)                           */
/* Notes: This IUT supports SINGLE and RR scheduling. PRIORITY/DRR selection  */
/*        are recognized; PRIORITY uses per-VC/per-MAP priority, DRR behaves  */
/*        as RR unless weights are set (map-level only, minimal).             */
/* ========================================================================== */

/**
 * @brief Set VC-level multiplexing policy (priority/weight/burst)
 *
 * Used by VC Multiplexing (USLP-99) when scheme is PRIORITY or DRR.
 *
 * @param context USLP context
 * @param vcid VCID
 * @param policy Policy parameters (priority/weight/burst)
 * @return Status code
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_set_vc_mux_policy(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uni_uslp_mux_policy_t *policy
);

/**
 * @brief Select next Virtual Channel with at least one ready MAP SDU per VC Mux Scheme
 *
 * Implements USLP-99 (§4.2.8). The scheme is taken from the Physical/Master channel
 * managed parameters (context->params.vc_mux_scheme; USLP-127).
 *
 * @param context USLP context
 * @param out_vcid Next VCID selected (valid when SUCCESS)
 * @return UNI_USLP_SUCCESS when a VC is selected, UNI_USLP_ERROR_NOT_FOUND if none ready
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_select_next_vc(
    uni_uslp_context_t *context,
    uint8_t *out_vcid
);

/**
 * @brief Select next MAP within a VC per MAP Multiplexing Scheme
 *
 * Implements USLP-96 (§4.2.5). The scheme is taken from the VC managed parameters
 * (vc->params.map_mux_scheme; Table 5-3 USLP-136).
 *
 * @param context USLP context
 * @param vcid VCID to select from
 * @param out_map_id Next MAP ID selected (valid when SUCCESS)
 * @return UNI_USLP_SUCCESS when a MAP is selected, UNI_USLP_ERROR_NOT_FOUND if none ready
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_select_next_map(
    uni_uslp_context_t *context,
    uint8_t vcid,
    uint8_t *out_map_id
);

/**
 * @brief Build next Transfer Frame according to MC/VC/MAP multiplexing
 *
 * Order: MC (single in this IUT; USLP-101 satisfied with SINGLE) -> VC (USLP-99)
 * -> MAP (USLP-96) -> build via uni_ccsds_uslp_build_frame().
 *
 * @param context USLP context
 * @param frame_buffer Output buffer
 * @param frame_length In: capacity, Out: bytes produced
 * @param out_vcid (optional) returns VCID selected
 * @param out_map_id (optional) returns MAP ID selected
 * @return UNI_USLP_SUCCESS if a frame was built, UNI_USLP_ERROR_NOT_FOUND if no SDU pending
 */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_build_next_frame(
    uni_uslp_context_t *context,
    uint8_t *frame_buffer,
    size_t *frame_length,
    uint8_t *out_vcid,
    uint8_t *out_map_id
);


/*
 * Built-in SDLS engine for USLP (CCSDS-355.0-B-2; USLP §6)
 *
 * Header/Trailer per project defaults (confirmed by integrator):
 *  - NULL: no Security Header/Trailer
 *  - HMAC-SHA256 (auth-only): Security Header = SPI(1) || SN(8) (big-endian),
 *                             Security Trailer = ICV (16 bytes, truncated SHA-256)
 *  - AES-GCM/CCM (AEAD):      Security Header = SPI(1) || SN(8) (big-endian),
 *                             IV = 12 bytes derived from SN as 0x00000000 || SN_be_8,
 *                             Security Trailer = AEAD Tag (16 bytes)
 *  - Integrity covers TFDF only (header+TFDZ). Insert/OCF/FECF excluded (USLP §6.3; SDLS §2.3.2.2).
 *  - Anti-replay window: sliding window (configurable, default 64) based on SN in Security Header.
 *
 * API:
 *  - Register built-in engine on a context via uni_ccsds_uslp_register_builtin_sdls().
 *  - The engine implements the sdls_apply/process callbacks wired by the core.
 */

/* Register the built-in SDLS engine callbacks on the context */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_register_builtin_sdls(uni_uslp_context_t* context);

/* Exposed for tests and advanced integration: built-in callbacks */
UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_sdls_builtin_apply(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *input_frame,
    size_t input_length,
    uint8_t *output_frame,
    size_t *output_length,
    const uni_uslp_sdls_config_t *config,
    void *user_data
);

UNI_CCSDS_EXPORT uni_uslp_status_t uni_ccsds_uslp_sdls_builtin_process(
    uni_uslp_context_t *context,
    uint8_t vcid,
    const uint8_t *input_frame,
    size_t input_length,
    uint8_t *output_frame,
    size_t *output_length,
    const uni_uslp_sdls_config_t *config,
    void *user_data,
    uint64_t *out_seq_num
);

#ifdef __cplusplus
}
#endif
