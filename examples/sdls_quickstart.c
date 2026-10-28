// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

/*
 * SDLS quick start: protect a MAPA SDU with the CCSDS 355.0-B-2 Annex E baseline SA (AES-256-GCM, 96-bit IV in the
 * Security Header, 128-bit MAC), receive it, then show tamper and replay rejection.
 *
 * Built and run by ctest (uni_ccsds_example_sdls_quickstart), so it stays in sync with the API; docs/uslp_sdls.md
 * quotes it.
 */

#include <stdio.h>
#include <string.h>

#include "uni_ccsds_uslp.h"
#include "uni_ccsds_uslp_internal.h" /* context layout, to allocate contexts */
#include <uni_crypto_crc16.h>

static void on_sdu(uni_uslp_context_t* ctx, uint8_t vcid, uint8_t map, uni_uslp_service_type_t svc, const uint8_t* sdu, size_t len,
                   uni_uslp_verification_status_t ver, bool gap, void* user)
{
    (void)ctx; (void)vcid; (void)map; (void)svc; (void)gap;
    *(int*)user += 1;
    printf("SDU %zu octets, verification %d:", len, (int)ver);
    for (size_t i = 0; i < len; ++i) printf(" %02X", sdu[i]);
    printf("\n");
}

static int check(uni_uslp_status_t st, uni_uslp_status_t expected, const char* what)
{
    printf("%-8s -> %s\n", what, uni_ccsds_uslp_status_string(st));
    return st == expected ? 0 : 1;
}

/* Contexts are large (all VC/MAP state); keep them out of the stack. */
static uni_uslp_context_t tx;
static uni_uslp_context_t rx;

int main(void)
{
    enum { SCID = 0x2222, VCID = 2, MAP = 1, SPI = 0x0101 };
    /* Demo key only. Real keys come from key management and must never be committed. */
    static const uint8_t KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    static const uint8_t SDU[] = {'h', 'e', 'l', 'l', 'o'};
    static uint8_t rx_work[UNI_USLP_MAX_FRAME_LENGTH];

    uni_uslp_managed_params_t p;
    memset(&p, 0, sizeof(p));
    p.fecf_capability = true;     /* FECF (CRC-16) covers the whole frame, Security Header and Trailer included */
    p.fecf_check = true;
    p.max_sdu_length = 2048;
    p.vcf_seq_count_len_octets = 1;

    /* Security Association: Annex E baseline. auth_mask left zero -> §4.2.2.6.2 default (VCID + MAP ID). */
    uni_uslp_sdls_sa_config_t sa;
    memset(&sa, 0, sizeof(sa));
    sa.spi = SPI;
    sa.suite = UNI_USLP_SDLS_SUITE_AES_GCM;
    sa.iv_length = UNI_USLP_SDLS_IV_LENGTH;
    sa.sn_length = 0;
    sa.mac_length = 16;
    sa.anti_replay_enabled = true;
    sa.replay_mode = UNI_USLP_SDLS_REPLAY_STRICT;
    sa.anti_replay_window = 64;

    int failures = 0;
    int delivered = 0;

    /* Transmitter: the SA is applied on VCID 2. */
    uni_ccsds_uslp_init(&tx, SCID, &p);
    uni_ccsds_uslp_configure_vc(&tx, VCID, &p);
    uni_ccsds_uslp_configure_map(&tx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p);
    uni_ccsds_uslp_register_builtin_sdls(&tx);
    failures += check(uni_ccsds_uslp_sdls_add_sa(&tx, &sa, KEY, sizeof(KEY)), UNI_USLP_SUCCESS, "add SA");
    uni_uslp_sdls_vc_config_t tx_vc;
    memset(&tx_vc, 0, sizeof(tx_vc));
    tx_vc.enabled = true;
    tx_vc.tx_spi = SPI;
    failures += check(uni_ccsds_uslp_configure_sdls(&tx, VCID, &tx_vc), UNI_USLP_SUCCESS, "TX VC");

    /* Receiver: VCID 2 accepts the SA; the SA is selected by the SPI in each frame. */
    uni_ccsds_uslp_init(&rx, SCID, &p);
    uni_ccsds_uslp_configure_vc(&rx, VCID, &p);
    uni_ccsds_uslp_configure_map(&rx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &p);
    uni_ccsds_uslp_register_builtin_sdls(&rx);
    uni_ccsds_uslp_set_work_buffer(&rx, rx_work, sizeof(rx_work));
    uni_ccsds_uslp_register_sdu_callback(&rx, VCID, MAP, on_sdu, &delivered);
    failures += check(uni_ccsds_uslp_sdls_add_sa(&rx, &sa, KEY, sizeof(KEY)), UNI_USLP_SUCCESS, "add SA");
    uni_uslp_sdls_vc_config_t rx_vc;
    memset(&rx_vc, 0, sizeof(rx_vc));
    rx_vc.enabled = true;
    rx_vc.rx_spi_count = 1;
    rx_vc.rx_spis[0] = SPI;
    failures += check(uni_ccsds_uslp_configure_sdls(&rx, VCID, &rx_vc), UNI_USLP_SUCCESS, "RX VC");

    uint8_t frame[256];
    size_t flen = sizeof(frame);
    uni_ccsds_uslp_send_mapa(&tx, VCID, MAP, SDU, sizeof(SDU));
    failures += check(uni_ccsds_uslp_build_frame(&tx, VCID, MAP, frame, &flen), UNI_USLP_SUCCESS, "build");

    /* 1) Genuine frame: decrypted, verified, delivered with UNI_USLP_VERIF_SUCCESS. */
    failures += check(uni_ccsds_uslp_accept_frame(&rx, frame, flen), UNI_USLP_SUCCESS, "accept");
    /* 2) Replay of the same frame. */
    failures += check(uni_ccsds_uslp_accept_frame(&rx, frame, flen), UNI_USLP_ERROR_SDLS_REPLAY, "replay");

    /* 3) A new frame whose MAP ID is rewritten in transit (CRC recomputed, as an attacker would): the Primary Header
     *    is authenticated, so the MAC check fails and nothing reaches MAP 0. */
    flen = sizeof(frame);
    uni_ccsds_uslp_send_mapa(&tx, VCID, MAP, SDU, sizeof(SDU));
    uni_ccsds_uslp_build_frame(&tx, VCID, MAP, frame, &flen);
    frame[3] &= (uint8_t)~0x1Eu;
    uni_crypto_crc16_ccitt_append(frame, flen - 2u, flen);
    failures += check(uni_ccsds_uslp_accept_frame(&rx, frame, flen), UNI_USLP_ERROR_SDLS_MAC_FAILURE, "tamper");

    uni_uslp_sdls_stats_t stats;
    uni_ccsds_uslp_get_sdls_stats(&rx, VCID, &stats);
    printf("verified=%llu replays=%llu mac_failures=%llu\n", (unsigned long long)stats.frames_verified, (unsigned long long)stats.replays,
           (unsigned long long)stats.mac_failures);

    /* Contexts with SAs own crypto state: always free them. */
    uni_ccsds_uslp_free(&tx);
    uni_ccsds_uslp_free(&rx);
    return (failures == 0 && delivered == 1) ? 0 : 1;
}
