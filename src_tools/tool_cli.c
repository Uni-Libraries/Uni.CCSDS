// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors
//
// Unified Space Data Link Protocol (USLP) CLI utility
//
// Supported operations (see CCSDS 732.1-B-3):
//   * Build MAPA variable-length frames with optional FECF (§4.1.6, Annex B)
//   * Build truncated frames (Annex D, Figure D-2) carrying a single MAPA_SDU
//   * Accept and inspect frames, invoking SDU callbacks to display payload data
//
// Usage examples (hex payload/frame may contain optional whitespace):
//   uniuslp_cli build  --scid 0x4242 --vcid 2 --map 5 --payload deadbeef
//   uniuslp_cli build  --scid 0x1001 --vcid 3 --map 2 --payload ab --trunc
//   uniuslp_cli accept --scid 0x4242 --frame 0fbad00d...
//
// Additional help:
//   uniuslp_cli --help         (generic overview)
//   uniuslp_cli build --help   (build-specific guidance)
//   uniuslp_cli accept --help  (accept-specific guidance)
//   uniuslp_cli --version      (tool version)
//
// Exit codes follow sysexits(3)-style semantics so automation can distinguish
// usage errors from data issues or internal USLP failures.

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uni_ccsds.h"

#ifndef UNIUSLP_CLI_VERSION
#define UNIUSLP_CLI_VERSION "0.1.0-dev"
#endif

#define CLI_CONTEXT_BYTES       (16u * 1024u * 1024u)  /* opaque context storage (coarse upper bound) */
#define CLI_DEFAULT_MAX_FRAME   (4096u)          /* default managed max frame length */
#define CLI_TRUNCATED_MAX_FRAME (32u)

typedef enum {
    CLI_EXIT_SUCCESS      = 0,
    CLI_EXIT_USAGE        = 64,
    CLI_EXIT_DATA_ERROR   = 65,
    CLI_EXIT_USLP_FAILURE = 66,
    CLI_EXIT_SYSTEM_ERROR = 71
} cli_exit_code_t;

typedef enum {
    CLI_CMD_NONE = 0,
    CLI_CMD_BUILD,
    CLI_CMD_ACCEPT
} cli_command_t;

typedef struct {
    cli_command_t command;
    bool show_help;
    bool show_version;
    bool truncated;

    const char *payload_hex;
    const char *frame_hex;

    uint16_t scid;
    uint8_t vcid;
    uint8_t map_id;

    bool have_scid;
    bool have_vcid;
    bool have_map;
    bool have_payload;
    bool have_frame;
} cli_options_t;

static void print_usage(FILE *stream, const char *prog, cli_command_t focus);
static void print_version(FILE *stream, const char *prog);
static cli_exit_code_t parse_args(int argc, char **argv, cli_options_t *out);

static bool parse_u16(const char *text, uint16_t *out);
static bool parse_u8(const char *text, uint8_t max_value, uint8_t *out);
static int hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len);
static void bytes_to_hex(const uint8_t *data, size_t len);

static cli_exit_code_t run_build(const char *prog, const cli_options_t *opts);
static cli_exit_code_t run_accept(const char *prog, const cli_options_t *opts);

static void sdu_cb(
    uni_uslp_context_t *ctx,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_service_type_t service_type,
    const uint8_t *sdu_data,
    size_t sdu_length,
    uni_uslp_verification_status_t verification_status,
    bool gap_detected,
    void *user_data);

int main(int argc, char **argv)
{
    const char *prog = (argc > 0 && argv[0]) ? argv[0] : "uniuslp_cli";
    cli_options_t opts;
    cli_exit_code_t parse_rc = parse_args(argc, argv, &opts);

    if (parse_rc != CLI_EXIT_SUCCESS) {
        if (opts.show_help) {
            print_usage(stderr, prog, opts.command);
        }
        return parse_rc;
    }

    if (opts.show_help) {
        print_usage(stdout, prog, opts.command);
        return CLI_EXIT_SUCCESS;
    }

    if (opts.show_version) {
        print_version(stdout, prog);
        return CLI_EXIT_SUCCESS;
    }

    switch (opts.command) {
        case CLI_CMD_BUILD:
            return run_build(prog, &opts);
        case CLI_CMD_ACCEPT:
            return run_accept(prog, &opts);
        default:
            fprintf(stderr, "%s: no command specified (see --help)\n", prog);
            return CLI_EXIT_USAGE;
    }
}

static void print_usage(FILE *stream, const char *prog, cli_command_t focus)
{
    fprintf(
        stream,
        "Unified Space Data Link Protocol CLI (CCSDS 732.1-B-3)\n"
        "\n"
        "Usage:\n"
        "  %s build  --scid <hex|dec> --vcid <0..63> --map <0..15> --payload <hex>\n"
        "  %s build  --scid <hex|dec> --vcid <0..63> --map <0..15> --payload <hex> --trunc\n"
        "  %s accept --scid <hex|dec> --frame <hex>\n"
        "\n"
        "Options:\n"
        "  --help       Display this help (global or per-subcommand)\n"
        "  --version    Report tool version\n"
        "  --scid       Spacecraft identifier (Section 4.1.2.2.3)\n"
        "  --vcid       Virtual Channel identifier (Section 4.1.2.4)\n"
        "  --map        MAP identifier (Section 4.1.2.5)\n"
        "  --payload    Hex payload for MAPA_SDU; whitespace is ignored (§3.5.2)\n"
        "  --frame      Hex transfer frame for acceptance path\n"
        "  --trunc      Emit truncated frame per Annex D (MAPA only, no FECF/OCF)\n"
        "\n",
        prog,
        prog,
        prog
    );

    if (focus == CLI_CMD_BUILD) {
        fprintf(
            stream,
            "Build specifics:\n"
            "  - Default output includes FECF (§4.1.6). Use --trunc to generate the\n"
            "    four-octet truncated Primary Header + TFDF header described in Annex D.\n"
            "  - Payload length is validated against managed parameters; the CLI adjusts\n"
            "    max_frame_length automatically within the limits of §4.1.2.7.\n"
            "\n"
        );
    } else if (focus == CLI_CMD_ACCEPT) {
        fprintf(
            stream,
            "Accept specifics:\n"
            "  - Frames are validated against the provided SCID (§4.1.2.2.3).\n"
            "  - For payload inspection, SDU callbacks print MAP service data along with\n"
            "    verification status (Table 3-2) and gap detection indicators.\n"
            "  - Truncated frames (Annex D) are auto-detected when the first four octets\n"
            "    indicate End-of-Header and SCID matches the supplied value.\n"
            "\n"
        );
    }
}

static void print_version(FILE *stream, const char *prog)
{
    fprintf(stream, "%s %s\n", prog, UNIUSLP_CLI_VERSION);
}

static cli_exit_code_t parse_args(int argc, char **argv, cli_options_t *out)
{
    memset(out, 0, sizeof(*out));

    if (argc <= 1) {
        out->show_help = true;
        return CLI_EXIT_USAGE;
    }

    const char *first = argv[1];
    if (strcmp(first, "--help") == 0 || strcmp(first, "-h") == 0) {
        out->show_help = true;
        return CLI_EXIT_SUCCESS;
    }
    if (strcmp(first, "--version") == 0) {
        out->show_version = true;
        return CLI_EXIT_SUCCESS;
    }
    if (strcmp(first, "build") == 0) {
        out->command = CLI_CMD_BUILD;
    } else if (strcmp(first, "accept") == 0) {
        out->command = CLI_CMD_ACCEPT;
    } else {
        fprintf(stderr, "error: unknown command '%s'\n", first);
        out->show_help = true;
        return CLI_EXIT_USAGE;
    }

    for (int idx = 2; idx < argc; ++idx) {
        const char *arg = argv[idx];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            out->show_help = true;
            continue;
        }
        if (strcmp(arg, "--version") == 0) {
            out->show_version = true;
            continue;
        }
        if (strcmp(arg, "--scid") == 0) {
            if (out->have_scid) {
                fprintf(stderr, "error: --scid specified multiple times\n");
                return CLI_EXIT_USAGE;
            }
            if (++idx >= argc) {
                fprintf(stderr, "error: --scid requires a value\n");
                return CLI_EXIT_USAGE;
            }
            if (!parse_u16(argv[idx], &out->scid)) {
                fprintf(stderr, "error: invalid SCID '%s'\n", argv[idx]);
                return CLI_EXIT_USAGE;
            }
            out->have_scid = true;
            continue;
        }
        if (strcmp(arg, "--vcid") == 0) {
            if (out->command != CLI_CMD_BUILD) {
                fprintf(stderr, "error: --vcid is only valid with the build command\n");
                return CLI_EXIT_USAGE;
            }
            if (out->have_vcid) {
                fprintf(stderr, "error: --vcid specified multiple times\n");
                return CLI_EXIT_USAGE;
            }
            if (++idx >= argc) {
                fprintf(stderr, "error: --vcid requires a value\n");
                return CLI_EXIT_USAGE;
            }
            if (!parse_u8(argv[idx], 63u, &out->vcid)) {
                fprintf(stderr, "error: invalid VCID '%s'\n", argv[idx]);
                return CLI_EXIT_USAGE;
            }
            out->have_vcid = true;
            continue;
        }
        if (strcmp(arg, "--map") == 0) {
            if (out->command != CLI_CMD_BUILD) {
                fprintf(stderr, "error: --map is only valid with the build command\n");
                return CLI_EXIT_USAGE;
            }
            if (out->have_map) {
                fprintf(stderr, "error: --map specified multiple times\n");
                return CLI_EXIT_USAGE;
            }
            if (++idx >= argc) {
                fprintf(stderr, "error: --map requires a value\n");
                return CLI_EXIT_USAGE;
            }
            if (!parse_u8(argv[idx], 15u, &out->map_id)) {
                fprintf(stderr, "error: invalid MAP ID '%s'\n", argv[idx]);
                return CLI_EXIT_USAGE;
            }
            out->have_map = true;
            continue;
        }
        if (strcmp(arg, "--payload") == 0) {
            if (out->command != CLI_CMD_BUILD) {
                fprintf(stderr, "error: --payload is only valid with the build command\n");
                return CLI_EXIT_USAGE;
            }
            if (out->have_payload) {
                fprintf(stderr, "error: --payload specified multiple times\n");
                return CLI_EXIT_USAGE;
            }
            if (++idx >= argc) {
                fprintf(stderr, "error: --payload requires a value\n");
                return CLI_EXIT_USAGE;
            }
            out->payload_hex = argv[idx];
            out->have_payload = true;
            continue;
        }
        if (strcmp(arg, "--frame") == 0) {
            if (out->command != CLI_CMD_ACCEPT) {
                fprintf(stderr, "error: --frame is only valid with the accept command\n");
                return CLI_EXIT_USAGE;
            }
            if (out->have_frame) {
                fprintf(stderr, "error: --frame specified multiple times\n");
                return CLI_EXIT_USAGE;
            }
            if (++idx >= argc) {
                fprintf(stderr, "error: --frame requires a value\n");
                return CLI_EXIT_USAGE;
            }
            out->frame_hex = argv[idx];
            out->have_frame = true;
            continue;
        }
        if (strcmp(arg, "--trunc") == 0) {
            if (out->command != CLI_CMD_BUILD) {
                fprintf(stderr, "error: --trunc is only valid with the build command\n");
                return CLI_EXIT_USAGE;
            }
            out->truncated = true;
            continue;
        }

        if (arg[0] == '-') {
            fprintf(stderr, "error: unrecognised option '%s'\n", arg);
        } else {
            fprintf(stderr, "error: unexpected argument '%s'\n", arg);
        }
        return CLI_EXIT_USAGE;
    }

    if (out->show_help || out->show_version) {
        return CLI_EXIT_SUCCESS;
    }

    if (!out->have_scid) {
        fprintf(stderr, "error: --scid is required\n");
        return CLI_EXIT_USAGE;
    }

    if (out->command == CLI_CMD_BUILD) {
        if (!out->have_vcid) {
            fprintf(stderr, "error: --vcid is required for build\n");
            return CLI_EXIT_USAGE;
        }
        if (!out->have_map) {
            fprintf(stderr, "error: --map is required for build\n");
            return CLI_EXIT_USAGE;
        }
        if (!out->have_payload) {
            fprintf(stderr, "error: --payload is required for build\n");
            return CLI_EXIT_USAGE;
        }
    } else if (out->command == CLI_CMD_ACCEPT) {
        if (!out->have_frame) {
            fprintf(stderr, "error: --frame is required for accept\n");
            return CLI_EXIT_USAGE;
        }
    }

    return CLI_EXIT_SUCCESS;
}

static bool parse_u16(const char *text, uint16_t *out)
{
    if (!text || !*text) {
        return false;
    }
    char *end = NULL;
    int base = (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) ? 16 : 10;
    errno = 0;
    unsigned long value = strtoul(text, &end, base);
    if (errno != 0 || end == text || *end != '\0' || value > 0xFFFFul) {
        return false;
    }
    *out = (uint16_t)value;
    return true;
}

static bool parse_u8(const char *text, uint8_t max_value, uint8_t *out)
{
    if (!text || !*text) {
        return false;
    }
    char *end = NULL;
    int base = (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) ? 16 : 10;
    errno = 0;
    unsigned long value = strtoul(text, &end, base);
    if (errno != 0 || end == text || *end != '\0' || value > max_value) {
        return false;
    }
    *out = (uint8_t)value;
    return true;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len)
{
    if (!hex) {
        return -1;
    }
    size_t written = 0;
    int high_nibble = -1;

    for (const char *cursor = hex; *cursor; ++cursor) {
        unsigned char c = (unsigned char)*cursor;

        if (isspace(c)) {
            continue;
        }

        int value = -1;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            value = 10 + (c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            value = 10 + (c - 'A');
        } else {
            return -1;
        }

        if (high_nibble < 0) {
            high_nibble = value;
        } else {
            if (out) {
                out[written] = (uint8_t)((high_nibble << 4) | value);
            }
            written++;
            high_nibble = -1;
        }
    }

    if (high_nibble >= 0) {
        return -1; /* odd number of nibbles */
    }

    if (out_len) {
        *out_len = written;
    }
    return 0;
}

static void bytes_to_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static cli_exit_code_t run_build(const char *prog, const cli_options_t *opts)
{
    size_t payload_len = 0;
    if (hex_to_bytes(opts->payload_hex, NULL, &payload_len) != 0 || payload_len == 0) {
        fprintf(stderr, "%s: invalid payload hex\n", prog);
        return CLI_EXIT_DATA_ERROR;
    }

    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        fprintf(stderr, "%s: out of memory while allocating payload buffer\n", prog);
        return CLI_EXIT_SYSTEM_ERROR;
    }
    if (hex_to_bytes(opts->payload_hex, payload, &payload_len) != 0) {
        fprintf(stderr, "%s: failed to decode payload\n", prog);
        free(payload);
        return CLI_EXIT_DATA_ERROR;
    }

    uni_uslp_managed_params_t params;
    memset(&params, 0, sizeof(params));

    params.max_frame_length = CLI_DEFAULT_MAX_FRAME;
    params.min_frame_length = 0;
    params.truncated_frame_capable = opts->truncated;
    params.truncated_frame_length = 0;
    params.fecf_capability = !opts->truncated;
    params.ocf_capability = false;
    params.insert_zone_capability = false;
    params.segmentation_permitted = false;
    params.blocking_permitted = false;
    params.max_sdu_length = 65535;

    if (opts->truncated) {
        size_t truncated_length =
            (size_t)UNI_USLP_TRUNCATED_PH_LENGTH + 1u + payload_len;
        if (truncated_length < (size_t)UNI_USLP_TRUNCATED_MIN_LENGTH ||
            truncated_length > CLI_TRUNCATED_MAX_FRAME) {
            fprintf(
                stderr,
                "%s: truncated payload produces invalid length (%zu octets); "
                "Annex D frames must be between %u and %u octets inclusive\n",
                prog,
                truncated_length,
                (unsigned)UNI_USLP_TRUNCATED_MIN_LENGTH,
                (unsigned)CLI_TRUNCATED_MAX_FRAME
            );
            free(payload);
            return CLI_EXIT_DATA_ERROR;
        }
        params.truncated_frame_length = (uint16_t)truncated_length;
    } else {
        size_t overhead =
            (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH +
            1u +                             /* TFDF header (Rule '111') */
            UNI_USLP_FECF_LENGTH;
        size_t required_frame = payload_len + overhead;

        if (required_frame > (size_t)UNI_USLP_MAX_FRAME_LENGTH) {
            fprintf(
                stderr,
                "%s: payload too large (%zu octets) for USLP frame with default "
                "managed parameters\n",
                prog,
                payload_len
            );
            free(payload);
            return CLI_EXIT_DATA_ERROR;
        }

        if (required_frame > params.max_frame_length) {
            params.max_frame_length = (uint16_t)required_frame;
        }
    }

    unsigned char *ctx_storage = calloc(1u, CLI_CONTEXT_BYTES);
    if (!ctx_storage) {
        fprintf(stderr, "%s: unable to reserve context storage\n", prog);
        free(payload);
        return CLI_EXIT_SYSTEM_ERROR;
    }

    uni_uslp_context_t *ctx = (uni_uslp_context_t *)(void *)ctx_storage;
    uni_uslp_status_t st = uni_ccsds_uslp_init(ctx, opts->scid, &params);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: uni_ccsds_uslp_init failed (%s)\n",
            prog,
            uni_ccsds_uslp_status_string(st)
        );
        free(ctx_storage);
        free(payload);
        return CLI_EXIT_USLP_FAILURE;
    }

    st = uni_ccsds_uslp_configure_vc(ctx, opts->vcid, &params);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: configure VC %u failed (%s)\n",
            prog,
            (unsigned)opts->vcid,
            uni_ccsds_uslp_status_string(st)
        );
        uni_ccsds_uslp_free(ctx);
        free(ctx_storage);
        free(payload);
        return CLI_EXIT_USLP_FAILURE;
    }

    st = uni_ccsds_uslp_configure_map(ctx, opts->vcid, opts->map_id, UNI_USLP_SERVICE_MAPA, &params);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: configure MAP %u/%u failed (%s)\n",
            prog,
            (unsigned)opts->vcid,
            (unsigned)opts->map_id,
            uni_ccsds_uslp_status_string(st)
        );
        uni_ccsds_uslp_free(ctx);
        free(ctx_storage);
        free(payload);
        return CLI_EXIT_USLP_FAILURE;
    }

    st = uni_ccsds_uslp_send_mapa(ctx, opts->vcid, opts->map_id, payload, payload_len);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: uni_ccsds_uslp_send_mapa rejected payload (%s)\n",
            prog,
            uni_ccsds_uslp_status_string(st)
        );
        uni_ccsds_uslp_free(ctx);
        free(ctx_storage);
        free(payload);
        return CLI_EXIT_USLP_FAILURE;
    }

    size_t frame_capacity = opts->truncated
        ? (size_t)params.truncated_frame_length
        : (size_t)params.max_frame_length;

    uint8_t *frame = malloc(frame_capacity > 0 ? frame_capacity : CLI_DEFAULT_MAX_FRAME);
    if (!frame) {
        fprintf(stderr, "%s: unable to allocate frame buffer\n", prog);
        uni_ccsds_uslp_free(ctx);
        free(ctx_storage);
        free(payload);
        return CLI_EXIT_SYSTEM_ERROR;
    }

    size_t frame_len = frame_capacity;
    if (opts->truncated) {
        st = uni_ccsds_uslp_build_truncated(ctx, opts->vcid, frame, &frame_len);
    } else {
        st = uni_ccsds_uslp_build_frame(ctx, opts->vcid, opts->map_id, frame, &frame_len);
    }

    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: frame build failed (%s)\n",
            prog,
            uni_ccsds_uslp_status_string(st)
        );
        free(frame);
        uni_ccsds_uslp_free(ctx);
        free(ctx_storage);
        free(payload);
        return CLI_EXIT_USLP_FAILURE;
    }

    bytes_to_hex(frame, frame_len);

    free(frame);
    uni_ccsds_uslp_free(ctx);
    free(ctx_storage);
    free(payload);
    return CLI_EXIT_SUCCESS;
}

static cli_exit_code_t run_accept(const char *prog, const cli_options_t *opts)
{
    size_t frame_len = 0;
    if (hex_to_bytes(opts->frame_hex, NULL, &frame_len) != 0 || frame_len == 0) {
        fprintf(stderr, "%s: invalid frame hex input\n", prog);
        return CLI_EXIT_DATA_ERROR;
    }

    uint8_t *frame = malloc(frame_len);
    if (!frame) {
        fprintf(stderr, "%s: unable to allocate frame buffer\n", prog);
        return CLI_EXIT_SYSTEM_ERROR;
    }
    if (hex_to_bytes(opts->frame_hex, frame, &frame_len) != 0) {
        fprintf(stderr, "%s: failed to decode frame payload\n", prog);
        free(frame);
        return CLI_EXIT_DATA_ERROR;
    }

    uni_uslp_managed_params_t params;
    memset(&params, 0, sizeof(params));
    params.max_frame_length = (frame_len > CLI_DEFAULT_MAX_FRAME)
        ? (frame_len <= UNI_USLP_MAX_FRAME_LENGTH ? (uint16_t)frame_len : (uint16_t)CLI_DEFAULT_MAX_FRAME)
        : CLI_DEFAULT_MAX_FRAME;
    params.min_frame_length = 0;
    params.fecf_capability = true;
    params.truncated_frame_capable = false;
    params.insert_zone_capability = false;
    params.ocf_capability = false;
    params.segmentation_permitted = false;
    params.blocking_permitted = false;
    params.max_sdu_length = 65535;

    bool configure_truncated = false;
    uint8_t truncated_vcid = 0;
    uint8_t truncated_map = 0;

    if (frame_len >= (size_t)UNI_USLP_TRUNCATED_MIN_LENGTH &&
        frame_len <= CLI_TRUNCATED_MAX_FRAME) {
        const uint8_t *ph = frame;
        uint32_t word =
            ((uint32_t)ph[0] << 24) |
            ((uint32_t)ph[1] << 16) |
            ((uint32_t)ph[2] << 8)  |
            ((uint32_t)ph[3]);

        uint8_t tfvn = (uint8_t)((word >> 28) & 0x0Fu);
        uint16_t scid_guess = (uint16_t)((word >> 12) & 0xFFFFu);
        bool eoh = ((word & 0x1u) != 0u);

        if (tfvn == UNI_USLP_TFVN && eoh && scid_guess == opts->scid) {
            configure_truncated = true;
            truncated_vcid = (uint8_t)((word >> 5) & 0x3Fu);
            truncated_map = (uint8_t)((word >> 1) & 0x0Fu);
        }
    }

    if (configure_truncated) {
        params.truncated_frame_capable = true;
        params.truncated_frame_length = (uint16_t)frame_len;
        params.fecf_capability = false;
    }

    unsigned char *ctx_storage = calloc(1u, CLI_CONTEXT_BYTES);
    if (!ctx_storage) {
        fprintf(stderr, "%s: failed to allocate context storage\n", prog);
        free(frame);
        return CLI_EXIT_SYSTEM_ERROR;
    }

    uni_uslp_context_t *ctx = (uni_uslp_context_t *)(void *)ctx_storage;
    uni_uslp_status_t st = uni_ccsds_uslp_init(ctx, opts->scid, &params);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: uni_ccsds_uslp_init failed (%s)\n",
            prog,
            uni_ccsds_uslp_status_string(st)
        );
        free(ctx_storage);
        free(frame);
        return CLI_EXIT_USLP_FAILURE;
    }

    if (configure_truncated) {
        uni_uslp_managed_params_t vc_params = params;
        st = uni_ccsds_uslp_configure_vc(ctx, truncated_vcid, &vc_params);
        if (st == UNI_USLP_SUCCESS) {
            (void)uni_ccsds_uslp_configure_map(
                ctx,
                truncated_vcid,
                truncated_map,
                UNI_USLP_SERVICE_MAPA,
                &vc_params
            );
        }
    }

    for (uint8_t vc = 0; vc < (uint8_t)UNI_USLP_MAX_VIRTUAL_CHANNELS; ++vc) {
        for (uint8_t map = 0; map < (uint8_t)UNI_USLP_MAX_MAPS_PER_VC; ++map) {
            (void)uni_ccsds_uslp_register_sdu_callback(ctx, vc, map, sdu_cb, NULL);
        }
    }

    st = uni_ccsds_uslp_accept_frame(ctx, frame, frame_len);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(
            stderr,
            "%s: accept failed (%s)\n",
            prog,
            uni_ccsds_uslp_status_string(st)
        );
        uni_ccsds_uslp_free(ctx);
        free(ctx_storage);
        free(frame);
        return CLI_EXIT_USLP_FAILURE;
    }

    uni_ccsds_uslp_free(ctx);
    free(ctx_storage);
    free(frame);
    return CLI_EXIT_SUCCESS;
}

static void sdu_cb(
    uni_uslp_context_t *ctx,
    uint8_t vcid,
    uint8_t map_id,
    uni_uslp_service_type_t service_type,
    const uint8_t *sdu_data,
    size_t sdu_length,
    uni_uslp_verification_status_t verification_status,
    bool gap_detected,
    void *user_data)
{
    (void)ctx;
    (void)user_data;

    fprintf(
        stdout,
        "SDU callback: VC=%u MAP=%u service=%u verification=%u gap=%s len=%zu\n",
        (unsigned)vcid,
        (unsigned)map_id,
        (unsigned)service_type,
        (unsigned)verification_status,
        gap_detected ? "true" : "false",
        sdu_length
    );
    bytes_to_hex(sdu_data, sdu_length);
}