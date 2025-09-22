// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

/**
 * @file benchmarks/bench_uslp.c
 * @brief Simple encode/decode throughput benchmark for USLP MAPA frames
 *
 * Measures:
 * - Build throughput for variable-length Rule '111' frames with FECF ON
 * - Accept throughput for same frames
 *
 * Usage:
 *   bench_uslp [iterations] [payload_len]
 * Defaults:
 *   iterations = 100000
 *   payload_len = 46 (so that final frame ~ small)
 *
 * Notes:
 * - Uses clock() for portability (C11). Results are approximate.
 * - CCSDS references: 732.1-B-3 §4.1.2 (Primary Header), §4.1.4 (TFDF), Annex B (FECF)
 */

//
// Includes
//

// stdlib
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"




//
// Functions
//

static double seconds_now(void) {
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

int main(int argc, char** argv) {
    unsigned long iterations = 100000UL;
    size_t payload_len = 46;

    if (argc >= 2) {
        iterations = strtoul(argv[1], NULL, 10);
        if (iterations == 0) iterations = 1;
    }
    if (argc >= 3) {
        unsigned long pl = strtoul(argv[2], NULL, 10);
        if (pl > 0 && pl < 65500UL) payload_len = (size_t)pl;
    }

    // Managed params: variable-length frames, FECF enabled
    uni_uslp_managed_params_t p;
    memset(&p, 0, sizeof(p));
    p.max_frame_length = 4096;
    p.min_frame_length = 0;
    p.fecf_capability = true;
    p.truncated_frame_capable = false;
    p.insert_zone_capability = false;
    p.ocf_capability = false;
    p.segmentation_permitted = false;
    p.blocking_permitted = false;
    p.max_sdu_length = 4096;

    const uint16_t SCID = 0x4242;
    const uint8_t VCID = 2;
    const uint8_t MAP  = 1;

    uni_uslp_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (uni_ccsds_uslp_init(&ctx, SCID, &p) != UNI_USLP_SUCCESS) {
        fprintf(stderr, "init failed\n");
        return 1;
    }
    if (uni_ccsds_uslp_configure_vc(&ctx, VCID, &p) != UNI_USLP_SUCCESS) {
        fprintf(stderr, "configure_vc failed\n");
        return 1;
    }
    if (uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p) != UNI_USLP_SUCCESS) {
        fprintf(stderr, "configure_map failed\n");
        return 1;
    }

    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < payload_len; ++i) payload[i] = (uint8_t)(i & 0xFF);

    uint8_t frame[8192];
    size_t frame_len_cap = sizeof(frame);
    // Prepare one frame to feed accept in the accept loop
    if (uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, payload, payload_len) != UNI_USLP_SUCCESS) {
        fprintf(stderr, "send_mapa failed\n");
        free(payload);
        return 1;
    }
    size_t frame_len = frame_len_cap;
    if (uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame, &frame_len) != UNI_USLP_SUCCESS) {
        fprintf(stderr, "build_frame failed (prep)\n");
        free(payload);
        return 1;
    }

    // Build benchmark
    double t0 = seconds_now();
    for (unsigned long i = 0; i < iterations; ++i) {
        (void)uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, payload, payload_len);
        size_t out_len = frame_len_cap;
        if (uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame, &out_len) != UNI_USLP_SUCCESS) {
            fprintf(stderr, "build_frame failed at iter %lu\n", i);
            free(payload);
            return 1;
        }
    }
    double t1 = seconds_now();
    double build_sec = t1 - t0;

    // Accept benchmark
    double t2 = seconds_now();
    for (unsigned long i = 0; i < iterations; ++i) {
        if (uni_ccsds_uslp_accept_frame(&ctx, frame, frame_len) != UNI_USLP_SUCCESS) {
            fprintf(stderr, "accept_frame failed at iter %lu\n", i);
            free(payload);
            return 1;
        }
    }
    double t3 = seconds_now();
    double accept_sec = t3 - t2;

    double build_fps = iterations / (build_sec > 0.0 ? build_sec : 1e-9);
    double accept_fps = iterations / (accept_sec > 0.0 ? accept_sec : 1e-9);
    double bytes_per_frame = (double)frame_len;
    double build_MBps = (build_fps * bytes_per_frame) / (1024.0 * 1024.0);
    double accept_MBps = (accept_fps * bytes_per_frame) / (1024.0 * 1024.0);

    printf("USLP bench: iterations=%lu payload_len=%zu frame_len=%zu\n",
           iterations, payload_len, frame_len);
    printf("Build:  %.2f frames/s, %.2f MiB/s\n", build_fps, build_MBps);
    printf("Accept: %.2f frames/s, %.2f MiB/s\n", accept_fps, accept_MBps);

    free(payload);
    return 0;
}