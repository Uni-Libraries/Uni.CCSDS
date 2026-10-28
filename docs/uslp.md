# USLP

## 1. API overview
- Context lifecycle:
  - `uni_ccsds_uslp_init()`, `uni_ccsds_uslp_reset()`, `uni_ccsds_uslp_free()`
  - Scratch buffer for RX transforms: `uni_ccsds_uslp_set_work_buffer()`
- Configuration:
  - VC: `uni_ccsds_uslp_configure_vc()`, MAP: `uni_ccsds_uslp_configure_map()`
  - SDLS: Security Associations `uni_ccsds_uslp_sdls_add_sa()`, per‑VC `uni_ccsds_uslp_configure_sdls()`, built‑in engine `uni_ccsds_uslp_register_builtin_sdls()` — see [uslp_sdls.md](uslp_sdls.md)
- Queue SDUs:
  - MAPA: `uni_ccsds_uslp_send_mapa()`, Packet: `uni_ccsds_uslp_send_packet_ex()`, VCP: `uni_ccsds_uslp_send_vcp_ex()`, VCA: `uni_ccsds_uslp_send_vca_ex()`, Octet Stream: `uni_ccsds_uslp_send_octet_stream_ex()`
- Build/accept frames:
  - Build: `uni_ccsds_uslp_build_frame()`, Truncated: `uni_ccsds_uslp_build_truncated()`
  - Accept: `uni_ccsds_uslp_accept_frame()`
- Helpers:
  - Primary Header pack/unpack: `uni_ccsds_uslp_primary_header_pack()`, `uni_ccsds_uslp_primary_header_unpack()`
  - TFDF header helpers: `uni_ccsds_uslp_tfdf_header_pack()`, `uni_ccsds_uslp_tfdf_header_unpack()`
  - CRC append/verify: `uni_crypto_crc16_ccitt_append()`, `uni_crypto_crc16_ccitt_verify()`

## 2. Memory model and lifetime
- The library does not allocate; all buffers are supplied by the caller. The crypto backend (Mbed TLS) may allocate
  when an SDLS Security Association is keyed; call `uni_ccsds_uslp_free()` on every context that had SAs.
- TX queueing is zero‑copy: send APIs store pointers to your SDU; keep the SDU buffer alive until build returns.
- Build path writes into a caller‑supplied frame buffer; pass capacity via *frame_length; on success it returns produced bytes.
- RX path can run fully allocation‑free. If SDLS is enabled, set an RX scratch buffer via `uni_ccsds_uslp_set_work_buffer()` large enough for “TFDF header + TFDZ”.
- Parser returns pointers into your input buffer (zero‑copy); they become invalid when the input buffer goes out of scope.
- Maximum frame length on wire: `UNI_USLP_MAX_FRAME_LENGTH` (65535). VCID 0..`UNI_USLP_MAX_VCID` (63), MAP ID 0..`UNI_USLP_MAX_MAP_ID` (15), SCID 0..`UNI_USLP_MAX_SCID`.
- Alignment: byte‑addressable; structures are packed to octet boundaries and serialized MSB‑first.
- Custom allocator hooks: not required by the library itself. A custom SDLS engine can carry allocator hooks in the callback user_data.

## 3. Thread‑safety and security
- One thread per context. A context is not internally synchronized; use external locking if accessed concurrently.
- Separate contexts are independent.
- Secrets: SAs keep only the key schedule (the caller's key bytes are not retained); it is zeroized by `uni_ccsds_uslp_sdls_remove_sa()` and `uni_ccsds_uslp_free()`. Temporary AAD/MAC buffers are zeroized (src/uni_ccsds_uslp_sdls.c).
- Constant‑time: relies on the underlying crypto backend (mbedTLS via uni.crypto). Do not branch on secret‑dependent values in custom callbacks.
- Key/nonce lifetime: AEAD IVs are either transmitted counters or derived from the SN field; the transmitter refuses to wrap (`UNI_USLP_ERROR_SDLS_SN_EXHAUSTED`) and, with `require_sn_restore`, to restart without its persisted SN — see [uslp_sdls.md](uslp_sdls.md).

# 4. Errors and return codes
All public APIs return a `uni_uslp_status_t` code. Common results:
- UNI_USLP_ERROR_INVALID_FRAME: malformed/truncated frame fields
- UNI_USLP_ERROR_BUFFER_TOO_SMALL: insufficient output/scratch capacity
- UNI_USLP_ERROR_CRC_MISMATCH: FECF failed
- UNI_USLP_ERROR_INVALID_PARAM: bad IDs or inconsistent configuration
- UNI_USLP_ERROR_UNSUPPORTED: feature/combination not enabled
- UNI_USLP_ERROR_SDLS_SA_NOT_FOUND / _MAC_FAILURE / _REPLAY / _OUT_OF_WINDOW / _LENGTH: SDLS rejection by reason (counted per VC, `uni_ccsds_uslp_get_sdls_stats()`)
- UNI_USLP_ERROR_SDLS_SN_NOT_RESTORED / _SN_EXHAUSTED: transmit SN protection
- UNI_USLP_ERROR_SDLS_FAILURE: crypto backend failure
Use `uni_ccsds_uslp_status_string()` to print messages.


# 5. Performance and correctness notes
- Time complexity is O(frame_len) for build and accept; no hidden quadratic copies.
- Avoid copies by:
  - Supplying SDUs that stay valid until the build completes (zero‑copy queueing)
  - Reusing the same frame buffer across transmissions
  - Providing an RX scratch buffer as large as the largest TFDF (SDLS decrypts into it); transmit protection is in place and needs no scratch buffer
- Endianness/bit ordering: on‑the‑wire fields are MSB‑first; pack/unpack helpers handle host endianness.
- CRC: polynomial `0x1021`, initial value `0xFFFF`.

# 6. Configuration and limits
- Frame length: up to `UNI_USLP_MAX_FRAME_LENGTH`. Truncated frames length per VC (§Annex D), 6..32 bytes in this implementation.
- VC/MAP IDs: VCID 0..63, MAP 0..15. SCID 0..65535.
- VCF count: 0..7 octets (Table 4‑2). Sequence‑controlled and expedited lengths are configured independently.
- FECF: CRC‑16/CCITT computed over all fields except FECF itself; when SDLS is enabled, the Security Header and Trailer are covered by FECF (USLP §6.3.8).
- SDLS: up to 16 SAs per context, 8 SPIs per VC, anti‑replay window up to 4096 frames, Security Header ≤ 64 octets. Profiles, anti‑replay modes and limits are in [uslp_sdls.md](uslp_sdls.md).
- Key/SA rotation: `uni_ccsds_uslp_sdls_rekey_sa()` (restarts the SN space); rotate before the SN field is exhausted.


## 7. Examples

### 7.1 Build a USLP frame (MAPA, CRC‑16 FECF)
Functions used: `uni_ccsds_uslp_init()` `uni_ccsds_uslp_configure_vc()` `uni_ccsds_uslp_configure_map()` `uni_ccsds_uslp_send_mapa()` `uni_ccsds_uslp_build_frame()` `uni_crypto_crc16_ccitt_verify()`

```c
#include <stdio.h>
#include <string.h>
#include "uni_ccsds_uslp.h"
#include "uni_ccsds_uslp_internal.h" // to instantiate the context struct

static void die(const char* msg, uni_uslp_status_t st) {
    fprintf(stderr, "%s: %s\n", msg, uni_ccsds_uslp_status_string(st));
    _Exit(1);
}

int main(void) {
    // Application payload (MAPA SDU)
    static const uint8_t payload[] = { 0xDE,0xAD,0xBE,0xEF };

    // 1) Create and initialize context with SCID and physical channel defaults
    uni_uslp_context_t ctx;
    uni_uslp_managed_params_t phys = {0};
    phys.fecf_capability = true;     // Enable FECF (Annex B)
    phys.insert_zone_capability = false;
    phys.max_frame_length = 256;     // Variable-length frames up to 256
    phys.min_frame_length = 0;
    uni_uslp_status_t st = uni_ccsds_uslp_init(&ctx, /*SCID=*/0x4242, &phys);
    if (st != UNI_USLP_SUCCESS) die("init", st);

    // 2) Configure VC and MAP for MAPA service (variable length, no segmentation)
    const uint8_t VCID = 2, MAP = 5;
    uni_uslp_managed_params_t vc = phys;
    vc.vcf_seq_count_len_octets = 1;   // 1-octet VCF sequence counter on TX (Bypass=0)
    st = uni_ccsds_uslp_configure_vc(&ctx, VCID, &vc);
    if (st != UNI_USLP_SUCCESS) die("configure_vc", st);

    uni_uslp_managed_params_t map = phys;
    map.max_sdu_length = 200;
    st = uni_ccsds_uslp_configure_map(&ctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map);
    if (st != UNI_USLP_SUCCESS) die("configure_map", st);

    // 3) Queue SDU, then build one frame into caller-supplied buffer
    st = uni_ccsds_uslp_send_mapa(&ctx, VCID, MAP, payload, sizeof(payload));
    if (st != UNI_USLP_SUCCESS) die("send_mapa", st);

    uint8_t frame[256];
    size_t frame_len = sizeof(frame);
    st = uni_ccsds_uslp_build_frame(&ctx, VCID, MAP, frame, &frame_len);
    if (st != UNI_USLP_SUCCESS) die("build_frame", st);

    // 4) Optionally verify FECF locally (builder already appended it)
    if (!uni_crypto_crc16_ccitt_verify(frame, frame_len)) {
        fprintf(stderr, "CRC verify failed unexpectedly\n");
        return 2;
    }

    printf("Built frame (%zu bytes):", frame_len);
    for (size_t i=0;i<frame_len;i++) printf(" %02X", frame[i]);
    printf("\n");
    return 0;
}
```

### 7.2 Parse a received frame (header fields, payload, and errors)
Functions used: `uni_ccsds_uslp_primary_header_unpack()` `uni_ccsds_uslp_tfdf_header_unpack()` `uni_ccsds_uslp_accept_frame()`

```c
#include <stdio.h>
#include <string.h>
#include "uni_ccsds_uslp.h"
#include "uni_ccsds_uslp_internal.h"

static void on_sdu(uni_uslp_context_t* ctx, uint8_t vcid, uint8_t map_id,
                   uni_uslp_service_type_t svc, const uint8_t* sdu, size_t len,
                   uni_uslp_verification_status_t ver, bool gap, void* ud) {
    (void)ctx;(void)ud;
    printf("[RX] (vc=%u map=%u svc=%d ver=%d gap=%d) SDU:", vcid, map_id, (int)svc, (int)ver, gap);
    for (size_t i=0;i<len;i++) printf(" %02X", sdu[i]);
    printf("\n");
}

int main(void) {
    // Frame received from channel (example from section 7.1)
    uint8_t frame[64]; size_t flen = 0;
    // ... fill frame[] and flen from the link ...

    // 1) Peek and validate Primary Header
    uni_uslp_primary_header_t ph={0};
    size_t ph_read=0;
    uni_uslp_status_t st = uni_ccsds_uslp_primary_header_unpack(frame, flen, &ph, &ph_read);
    if (st != UNI_USLP_SUCCESS) { fprintf(stderr, "Bad PH: %s\n", uni_ccsds_uslp_status_string(st)); return 1; }
    if (ph.tfvn != UNI_USLP_TFVN) { fprintf(stderr, "TFVN mismatch\n"); return 1; }
    printf("SCID=0x%04X VCID=%u MAP=%u C=%u Bypass=%u VCFoctets=%u\n",
           ph.scid, ph.vcid, ph.map_id, ph.frame_length, ph.bypass_flag, ph.vcf_count_len);

    // 2) Full accept with validation and callback delivery
    uni_uslp_context_t ctx;
    uni_uslp_managed_params_t phys = {0};
    phys.fecf_capability=true;
    uni_ccsds_uslp_init(&ctx, ph.scid, &phys);
    // Register callback for this (VC,MAP)
    uni_ccsds_uslp_register_sdu_callback(&ctx, ph.vcid, ph.map_id, on_sdu, NULL);
    st = uni_ccsds_uslp_accept_frame(&ctx, frame, flen);
    if (st != UNI_USLP_SUCCESS) {
        fprintf(stderr, "accept_frame: %s\n", uni_ccsds_uslp_status_string(st));
        return 2;
    }
    return 0;
}
```

### 7.3 SDLS
The SDLS API (Security Associations, per‑VC configuration, built‑in and custom engines) and a complete example are in
[uslp_sdls.md](uslp_sdls.md). The example source, [examples/sdls_quickstart.c](../examples/sdls_quickstart.c), is
compiled and run by ctest.

## 8. Quick Start

[examples/sdls_quickstart.c](../examples/sdls_quickstart.c) builds an AES‑256‑GCM protected frame with FECF, accepts
it, and shows replay and tamper rejection. Build the library and run it:

```bash
cmake -S . -B build && cmake --build build -j
ctest --test-dir build -R uni_ccsds_example_sdls_quickstart --output-on-failure
```
