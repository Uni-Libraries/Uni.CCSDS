// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

//
// Includes
//

// uni.ccsds
#include "uni_ccsds_uslp_internal.h"


//
// Implementation
//

const char* uni_ccsds_uslp_status_string(uni_uslp_status_t status)
{
    switch (status) {
        case UNI_USLP_SUCCESS:               return "UNI_USLP_SUCCESS: Operation successful";
        case UNI_USLP_ERROR_NULL_POINTER:    return "UNI_USLP_ERROR_NULL_POINTER: Null pointer argument";
        case UNI_USLP_ERROR_INVALID_PARAM:   return "UNI_USLP_ERROR_INVALID_PARAM: Invalid parameter value";
        case UNI_USLP_ERROR_BUFFER_TOO_SMALL:return "UNI_USLP_ERROR_BUFFER_TOO_SMALL: Output buffer too small";
        case UNI_USLP_ERROR_INVALID_FRAME:   return "UNI_USLP_ERROR_INVALID_FRAME: Invalid frame format";
        case UNI_USLP_ERROR_CRC_MISMATCH:    return "UNI_USLP_ERROR_CRC_MISMATCH: FECF CRC verification failed";
        case UNI_USLP_ERROR_UNSUPPORTED:     return "UNI_USLP_ERROR_UNSUPPORTED: Unsupported feature";
        case UNI_USLP_ERROR_CONTEXT_FULL:    return "UNI_USLP_ERROR_CONTEXT_FULL: Context buffers full";
        case UNI_USLP_ERROR_NOT_FOUND:       return "UNI_USLP_ERROR_NOT_FOUND: Resource not found";
        case UNI_USLP_ERROR_SDLS_FAILURE:    return "UNI_USLP_ERROR_SDLS_FAILURE: SDLS operation failed";
        case UNI_USLP_ERROR_TRUNCATED:       return "UNI_USLP_ERROR_TRUNCATED: Frame truncated";
        case UNI_USLP_ERROR_SEQUENCE_GAP:    return "UNI_USLP_ERROR_SEQUENCE_GAP: Sequence number gap detected";
        default:                             return "UNI_USLP_ERROR_UNKNOWN: Unknown status code";
    }
}
