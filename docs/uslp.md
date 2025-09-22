# USLP

## 1. API overview
- Context lifecycle:
  - [uni_ccsds_uslp_init()](include/uni_ccsds_uslp.h:911), [uni_ccsds_uslp_reset()](include/uni_ccsds_uslp.h:923), [uni_ccsds_uslp_free()](include/uni_ccsds_uslp.h:931)
  - Scratch buffer for RX transforms: [uni_ccsds_uslp_set_work_buffer()](include/uni_ccsds_uslp.h:947)
- Configuration:
  - VC: [uni_ccsds_uslp_configure_vc()](include/uni_ccsds_uslp.h:965), MAP: [uni_ccsds_uslp_configure_map()](include/uni_ccsds_uslp.h:981)
  - SDLS: [uni_ccsds_uslp_configure_sdls()](include/uni_ccsds_uslp.h:1013), register built‑in engine: [uni_ccsds_uslp_register_builtin_sdls()](include/uni_ccsds_uslp.h:2009)
- Queue SDUs:
  - MAPA: [uni_ccsds_uslp_send_mapa()](include/uni_ccsds_uslp.h:1511), Packet: [uni_ccsds_uslp_send_packet_ex()](include/uni_ccsds_uslp.h:1463), VCP: [uni_ccsds_uslp_send_vcp_ex()](include/uni_ccsds_uslp.h:1491), VCA: [uni_ccsds_uslp_send_vca_ex()](include/uni_ccsds_uslp.h:1536), Octet Stream: [uni_ccsds_uslp_send_octet_stream_ex()](include/uni_ccsds_uslp.h:1563)
- Build/accept frames:
  - Build: [uni_ccsds_uslp_build_frame()](include/uni_ccsds_uslp.h:1706), Truncated: [uni_ccsds_uslp_build_truncated()](include/uni_ccsds_uslp.h:1737)
  - Accept: [uni_ccsds_uslp_accept_frame()](include/uni_ccsds_uslp.h:1756)
- Helpers:
  - Primary Header pack/unpack: [uni_ccsds_uslp_primary_header_pack()](include/uni_ccsds_uslp.h:1806), [uni_ccsds_uslp_primary_header_unpack()](include/uni_ccsds_uslp.h:1824)
  - TFDF header helpers: [uni_ccsds_uslp_tfdf_header_pack()](include/uni_ccsds_uslp.h:1840), [uni_ccsds_uslp_tfdf_header_unpack()](include/uni_ccsds_uslp.h:1856)
  - CRC append/verify: [uni_crypto_crc16_ccitt_append()](3rdparty/uni.crypto/include/uni_crypto_crc16.h:96), [uni_crypto_crc16_ccitt_verify()](3rdparty/uni.crypto/include/uni_crypto_crc16.h:81)

## 2. Memory model and lifetime
- No dynamic allocation by default; all buffers are supplied by the caller.
- TX queueing is zero‑copy: send APIs store pointers to your SDU; keep the SDU buffer alive until build returns.
- Build path writes into a caller‑supplied frame buffer; pass capacity via *frame_length; on success it returns produced bytes.
- RX path can run fully allocation‑free. If SDLS is enabled, set an RX scratch buffer via [uni_ccsds_uslp_set_work_buffer()](include/uni_ccsds_uslp.h:947) large enough for “TFDF header + TFDZ”.
- Parser returns pointers into your input buffer (zero‑copy); they become invalid when the input buffer goes out of scope.
- Maximum frame length on wire: [UNI_USLP_MAX_FRAME_LENGTH](include/uni_ccsds_uslp.h:44) (65535). VCID 0..[UNI_USLP_MAX_VCID](include/uni_ccsds_uslp.h:104) (63), MAP ID 0..[UNI_USLP_MAX_MAP_ID](include/uni_ccsds_uslp.h:109) (15), SCID 0..[UNI_USLP_MAX_SCID](include/uni_ccsds_uslp.h:99).
- Alignment: byte‑addressable; structures are packed to octet boundaries and serialized MSB‑first.
- Custom allocator hooks: not required because the library does not allocate. If you write a custom SDLS engine, carry malloc/free‑like hooks in the callback user_data and use them for any temporary buffers.

## 3. Thread‑safety and security
- One thread per context. A context is not internally synchronized; use external locking if accessed concurrently.
- Separate contexts are independent.
- Secrets: built‑in SDLS avoids long‑lived intermediate copies and zeroizes temporary buffers (see [src/uslp_sdls.c](src/uslp_sdls.c:272)).
- Constant‑time: relies on the underlying crypto backend (mbedTLS via uni.crypto). Do not branch on secret‑dependent values in custom callbacks.
- Key/nonce lifetime: keys live in your configuration struct; zeroize when rotating. Nonces for AEAD are derived from the 64‑bit Sequence Number (SN) per USLP §6 (IV = 0x00000000 || SN_be_8), preventing reuse until wrap.

# 4. Errors and return codes
All public APIs return a [uni_uslp_status_t](include/uni_ccsds_uslp.h:174) code. Common results:
- UNI_USLP_ERROR_INVALID_FRAME: malformed/truncated frame fields
- UNI_USLP_ERROR_BUFFER_TOO_SMALL: insufficient output/scratch capacity
- UNI_USLP_ERROR_CRC_MISMATCH: FECF failed
- UNI_USLP_ERROR_INVALID_PARAM: bad IDs or inconsistent configuration
- UNI_USLP_ERROR_UNSUPPORTED: feature/combination not enabled
- UNI_USLP_ERROR_SDLS_FAILURE: SDLS tag mismatch, nonce/IV issue, or anti‑replay rejection
Use [uni_ccsds_uslp_status_string()](include/uni_ccsds_uslp.h:1903) to print messages.


# 5. Performance and correctness notes
- Time complexity is O(frame_len) for build and accept; no hidden quadratic copies.
- Avoid copies by:
  - Supplying SDUs that stay valid until the build completes (zero‑copy queueing)
  - Reusing the same frame buffer across transmissions
  - Providing a large RX scratch buffer to avoid fallback to smaller stack temporary regions
- Endianness/bit ordering: on‑the‑wire fields are MSB‑first; pack/unpack helpers handle host endianness.
- CRC: polynomial [0x1021](3rdparty/uni.crypto/include/uni_crypto_crc16.h:22), initial value [0xFFFF](3rdparty/uni.crypto/include/uni_crypto_crc16.h:23).

# 6. Configuration and limits
- Frame length: up to [UNI_USLP_MAX_FRAME_LENGTH](include/uni_ccsds_uslp.h:44). Truncated frames length per VC (§Annex D), 6..32 bytes in this implementation.
- VC/MAP IDs: VCID 0..63, MAP 0..15. SCID 0..65535.
- VCF count: 0..7 octets (Table 4‑2). Sequence‑controlled and expedited lengths are configured independently.
- FECF: CRC‑16/CCITT computed over all fields except FECF itself; when SDLS is enabled, the Security Header and Trailer are covered by FECF (USLP §6.3.8).
- SDLS nonce/IV: IV = 0x00000000 || SN_be_8 (12 octets). Never reuse IV under the same key. On SN rollover, rotate key and reset anti‑replay window.
- Anti‑replay: sliding window (default 64). Duplicate or too‑old frames are rejected by SDLS processing.
- Key/SA rotation: rotate on mission policy or earlier if SN approaches wrap; zeroize retired keys.


## 7. Examples

### 7.1 Build a USLP frame (MAPA, CRC‑16 FECF)
Functions used: [uni_ccsds_uslp_init()](include/uni_ccsds_uslp.h:911) [uni_ccsds_uslp_configure_vc()](include/uni_ccsds_uslp.h:965) [uni_ccsds_uslp_configure_map()](include/uni_ccsds_uslp.h:981) [uni_ccsds_uslp_send_mapa()](include/uni_ccsds_uslp.h:1511) [uni_ccsds_uslp_build_frame()](include/uni_ccsds_uslp.h:1706) [uni_crypto_crc16_ccitt_verify()](3rdparty/uni.crypto/include/uni_crypto_crc16.h:81)

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
Functions used: [uni_ccsds_uslp_primary_header_unpack()](include/uni_ccsds_uslp.h:1824) [uni_ccsds_uslp_tfdf_header_unpack()](include/uni_ccsds_uslp.h:1856) [uni_ccsds_uslp_accept_frame()](include/uni_ccsds_uslp.h:1756)

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

### 7.3 SDLS AES‑CCM‑128 protect/verify
Built‑in engine usage (recommended). Functions used: [uni_ccsds_uslp_register_builtin_sdls()](include/uni_ccsds_uslp.h:2009) [uni_ccsds_uslp_configure_sdls()](include/uni_ccsds_uslp.h:1013) [uni_ccsds_uslp_set_work_buffer()](include/uni_ccsds_uslp.h:947)

```c
// Example key (demo only; DO NOT use in production)
static const uint8_t AES128_KEY[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};

uni_uslp_context_t ctx;
uni_uslp_managed_params_t phys = {0};
phys.fecf_capability = true;
uni_ccsds_uslp_init(&ctx, /*SCID=*/0x1001, &phys);

// Register built‑in SDLS engine once per context
uni_ccsds_uslp_register_builtin_sdls(&ctx);

// Configure SDLS on VCID 2 with AES‑CCM‑128, 16‑byte tag, anti‑replay window 64
uni_uslp_sdls_config_t sdls = {0};
sdls.enabled = true;
sdls.suite = UNI_USLP_SDLS_SUITE_AES_CCM;
sdls.spi = 0x42;
sdls.key = AES128_KEY;
sdls.key_length = sizeof(AES128_KEY);
sdls.iv_length = 12;            // IV = 0x00000000 || SN_be_8
sdls.mac_length = 16;           // AEAD tag length
sdls.authentication_only = false;
sdls.encryption_enabled = true;
sdls.anti_replay_enabled = true;
sdls.anti_replay_window = 64;
sdls.sec_header_present = true; sdls.sec_trailer_present = true;
sdls.sec_header_length = 9;     // SPI(1)+SN(8)
sdls.sec_trailer_length = 16;   // ICV/tag
uni_ccsds_uslp_configure_sdls(&ctx, /*VCID=*/2, &sdls);

// Provide RX scratch buffer (required when SDLS is enabled)
static uint8_t rx_scratch[1024];
uni_ccsds_uslp_set_work_buffer(&ctx, rx_scratch, sizeof(rx_scratch));
```

### 7.4 End‑to‑end: USLP + SDLS (TX and RX), tag verify and replay protection
Functions used: [uni_ccsds_uslp_send_mapa()](include/uni_ccsds_uslp.h:1511) [uni_ccsds_uslp_build_frame()](include/uni_ccsds_uslp.h:1706) [uni_ccsds_uslp_accept_frame()](include/uni_ccsds_uslp.h:1756)

```c
#include <stdio.h>
#include <string.h>
#include "uni_ccsds_uslp.h"
#include "uni_ccsds_uslp_internal.h"

static void rx_cb(uni_uslp_context_t* c, uint8_t vcid, uint8_t map,
                  uni_uslp_service_type_t svc, const uint8_t* sdu, size_t len,
                  uni_uslp_verification_status_t ver, bool gap, void* ud) {
    (void)c;(void)ud;(void)gap;
    printf("[RX ver=%d] SDU (%zu B):", (int)ver, len);
    for(size_t i=0;i<len;i++) printf(" %02X", sdu[i]);
    printf("\n");
}

int main(void) {
    const uint8_t VCID=2, MAP=1; // same VC/MAP on TX and RX sides
    static const uint8_t PLAINTEXT[] = { 0x01,0x02,0x03,0x04,0x05 };
    static const uint8_t KEY[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

    // TX side
    uni_uslp_context_t tx;
    uni_uslp_managed_params_t phys = (uni_uslp_managed_params_t){0};
    phys.fecf_capability = true;
    uni_ccsds_uslp_init(&tx, /*SCID=*/0x2222, &phys);
    uni_uslp_managed_params_t vc = phys; vc.vcf_seq_count_len_octets = 1;
    uni_ccsds_uslp_configure_vc(&tx, VCID, &vc);
    uni_uslp_managed_params_t map = phys; map.max_sdu_length = 2048;
    uni_ccsds_uslp_configure_map(&tx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map);
    uni_ccsds_uslp_register_builtin_sdls(&tx);
    uni_uslp_sdls_config_t sd = {0};
    sd.enabled=true; sd.suite=UNI_USLP_SDLS_SUITE_AES_CCM; sd.key=KEY; sd.key_length=16;
    sd.iv_length=12; sd.mac_length=16; sd.sec_header_present=sd.sec_trailer_present=true;
    sd.sec_header_length=9; sd.sec_trailer_length=16; sd.anti_replay_enabled=true; sd.anti_replay_window=64;
    uni_ccsds_uslp_configure_sdls(&tx, VCID, &sd);
    uni_ccsds_uslp_send_mapa(&tx, VCID, MAP, PLAINTEXT, sizeof(PLAINTEXT));
    uint8_t frame[256]; size_t flen=sizeof(frame);
    uni_uslp_status_t st = uni_ccsds_uslp_build_frame(&tx, VCID, MAP, frame, &flen);
    if (st != UNI_USLP_SUCCESS) { fprintf(stderr,"TX build: %s\n", uni_ccsds_uslp_status_string(st)); return 1; }

    // RX side
    uni_uslp_context_t rx;
    uni_ccsds_uslp_init(&rx, /*SCID=*/0x2222, &phys);
    uni_ccsds_uslp_configure_vc(&rx, VCID, &vc);
    uni_ccsds_uslp_configure_map(&rx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &map);
    uni_ccsds_uslp_register_builtin_sdls(&rx);
    uni_ccsds_uslp_configure_sdls(&rx, VCID, &sd); // same SA/key
    static uint8_t scratch[1024]; uni_ccsds_uslp_set_work_buffer(&rx, scratch, sizeof(scratch));
    uni_ccsds_uslp_register_sdu_callback(&rx, VCID, MAP, rx_cb, NULL);

    // 1) Happy path — decrypt and verify
    st = uni_ccsds_uslp_accept_frame(&rx, frame, flen);
    if (st != UNI_USLP_SUCCESS) { fprintf(stderr,"RX accept (good): %s\n", uni_ccsds_uslp_status_string(st)); return 2; }

    // 2) Tamper — flip 1 bit in AEAD tag: expect UNI_USLP_ERROR_SDLS_FAILURE
    frame[flen-1] ^= 0x01;
    st = uni_ccsds_uslp_accept_frame(&rx, frame, flen);
    printf("Tamper accept -> %s\n", uni_ccsds_uslp_status_string(st)); // should report SDLS failure
    frame[flen-1] ^= 0x01; // restore

    // 3) Replay — re‑send the same frame: expect anti‑replay rejection
    st = uni_ccsds_uslp_accept_frame(&rx, frame, flen);
    printf("Replay accept -> %s\n", uni_ccsds_uslp_status_string(st)); // SDLS failure (replay window)
    return 0;
}
```

### 7.5 Optional: custom SDLS engine with OpenSSL AES‑CCM‑128
Register your own Apply/Process callbacks via [uni_ccsds_uslp_register_sdls_callbacks()](include/uni_ccsds_uslp.h:1212). Minimal AES‑CCM‑128 example (no dynamic allocation; IV derived from SN per USLP §6):

```c
#include <openssl/evp.h>
typedef struct { /* optional hooks & replay state per VC */
    uint64_t rx_highest_sn;
    uint64_t rx_bitmap; // LSB = highest seen
} sdls_vc_state;

static int window_accept(sdls_vc_state* s, uint8_t W, uint64_t sn) {
    if (W==0||W>64) W=64;
    if (!s->rx_bitmap) { s->rx_highest_sn=sn; s->rx_bitmap=1ull; return 1; }
    if (sn > s->rx_highest_sn) {
        uint64_t d = sn - s->rx_highest_sn;
       s->rx_bitmap = (d>=64)?1ull:(s->rx_bitmap<<d)|1ull;
        s->rx_highest_sn = sn;
        return 1;
    } else {
        uint64_t off = s->rx_highest_sn - sn;
        if (off >= W) return 0;
        uint64_t mask = 1ull<<off;
        if (s->rx_bitmap & mask) return 0;
        s->rx_bitmap |= mask;
        return 1;
    }
}

static void iv_from_sn(uint8_t iv[12], uint64_t sn){ memset(iv,0,4); for(int i=0;i<8;i++) iv[4+i]=(uint8_t)(sn>>(56-8*i)); }

static uni_uslp_status_t sdls_apply_openssl(uni_uslp_context_t* ctx, uint8_t vcid,
    const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len,
    const uni_uslp_sdls_config_t* cfg, void* user_data) {
    (void)ctx;(void)user_data;(void)vcid;
    if (cfg->suite != UNI_USLP_SDLS_SUITE_AES_CCM) return UNI_USLP_ERROR_INVALID_PARAM;
    if (*out_len < (size_t)(cfg->sec_header_length + in_len + cfg->sec_trailer_length)) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    uint64_t sn = 0; /* keep SN in your per‑VC state; increment per TX */
    out[0]=cfg->spi; for (int i=0;i<8;i++) out[1+i]=(uint8_t)(sn>>(56-8*i));
    uint8_t iv[12]; iv_from_sn(iv, sn);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int ok = c && EVP_EncryptInit_ex(c, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1
               && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, cfg->iv_length, NULL) == 1
               && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, cfg->mac_length, NULL) == 1
               && EVP_EncryptInit_ex(c, NULL, NULL, cfg->key, iv) == 1;
    int len=0; ok = ok && EVP_EncryptUpdate(c, NULL, &len, NULL, (int)in_len) == 1;
    ok = ok && EVP_EncryptUpdate(c, NULL, &len, NULL, 0) == 1; // AAD = none
    ok = ok && EVP_EncryptUpdate(c, out + cfg->sec_header_length, &len, in, (int)in_len) == 1;
    ok = ok && EVP_EncryptFinal_ex(c, NULL, &len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, cfg->mac_length,
                                   out + cfg->sec_header_length + in_len) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return UNI_USLP_ERROR_SDLS_FAILURE;
    *out_len = (size_t)(cfg->sec_header_length + in_len + cfg->sec_trailer_length);
    return UNI_USLP_SUCCESS;
}

static uni_uslp_status_t sdls_process_openssl(uni_uslp_context_t* ctx, uint8_t vcid,
    const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len,
    const uni_uslp_sdls_config_t* cfg, void* user_data, uint64_t* out_sn) {
    (void)ctx;
    sdls_vc_state* state = (sdls_vc_state*)user_data; (void)vcid;
    if (cfg->suite != UNI_USLP_SDLS_SUITE_AES_CCM || cfg->sec_header_length != 9) return UNI_USLP_ERROR_INVALID_PARAM;
    if (in_len < (size_t)(cfg->sec_header_length + cfg->sec_trailer_length)) return UNI_USLP_ERROR_INVALID_FRAME;
    const uint8_t* sh = in;
    uint64_t sn = 0; for(int i=0;i<8;i++) sn = (sn<<8) | sh[1+i];
    if (out_sn) *out_sn = sn;
    if (!window_accept(state, cfg->anti_replay_window, sn)) return UNI_USLP_ERROR_SDLS_FAILURE;
    const uint8_t* ct = in + cfg->sec_header_length;
    size_t ct_len = in_len - cfg->sec_header_length - cfg->sec_trailer_length;
    const uint8_t* tag = in + in_len - cfg->sec_trailer_length;
    if (*out_len < ct_len) return UNI_USLP_ERROR_BUFFER_TOO_SMALL;
    uint8_t iv[12]; iv_from_sn(iv, sn);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    int ok = c && EVP_DecryptInit_ex(c, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1
               && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, cfg->iv_length, NULL) == 1
               && EVP_DecryptInit_ex(c, NULL, NULL, cfg->key, iv) == 1
               && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, cfg->mac_length, (void*)tag) == 1;
    int len=0; ok = ok && EVP_DecryptUpdate(c, NULL, &len, NULL, (int)ct_len) == 1;
    ok = ok && EVP_DecryptUpdate(c, NULL, &len, NULL, 0) == 1; // AAD = none
    ok = ok && EVP_DecryptUpdate(c, out, &len, ct, (int)ct_len) == 1;
    ok = ok && EVP_DecryptFinal_ex(c, NULL, &len) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return UNI_USLP_ERROR_SDLS_FAILURE;
    *out_len = ct_len;
    return UNI_USLP_SUCCESS;
}
```

## 8. Quick Start


This minimal program builds a protected frame (AES‑CCM‑128 + FECF), then parses and verifies it.

```c
#include <stdio.h>
#include "uni_ccsds_uslp.h"
#include "uni_ccsds_uslp_internal.h"

static void rx(uni_uslp_context_t* c, uint8_t vcid, uint8_t map, uni_uslp_service_type_t svc,
               const uint8_t* sdu, size_t len, uni_uslp_verification_status_t ver, bool gap, void* ud) {
    (void)c;(void)ud;(void)gap;(void)svc;
    printf("Verified SDU (%zu B):", len); for(size_t i=0;i<len;i++) printf(" %02X", sdu[i]); printf("\n");
}
int main(void){
  const uint8_t VCID=2, MAP=1; const uint16_t SCID=0x6001;
  static const uint8_t KEY[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  static const uint8_t SDU[]={ 'h','e','l','l','o' };
  uni_uslp_context_t tx, rxctx; uni_uslp_managed_params_t p={0}; p.fecf_capability=true;
  uni_ccsds_uslp_init(&tx, SCID, &p); uni_ccsds_uslp_init(&rxctx, SCID, &p);
  uni_uslp_managed_params_t v=p; v.vcf_seq_count_len_octets=1;
  uni_ccsds_uslp_configure_vc(&tx, VCID, &v); uni_ccsds_uslp_configure_vc(&rxctx, VCID, &v);
  uni_uslp_managed_params_t m=p; m.max_sdu_length=2048;
  uni_ccsds_uslp_configure_map(&tx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &m);
  uni_ccsds_uslp_configure_map(&rxctx, VCID, MAP, UNI_USLP_SERVICE_MAPA, &m);
  uni_ccsds_uslp_register_builtin_sdls(&tx); uni_ccsds_uslp_register_builtin_sdls(&rxctx);
  uni_uslp_sdls_config_t cfg={0}; cfg.enabled=true; cfg.suite=UNI_USLP_SDLS_SUITE_AES_CCM; cfg.key=KEY; cfg.key_length=16;
  cfg.iv_length=12; cfg.mac_length=16; cfg.sec_header_present=cfg.sec_trailer_present=true; cfg.sec_header_length=9; cfg.sec_trailer_length=16;
  cfg.anti_replay_enabled=true; cfg.anti_replay_window=64;
  uni_ccsds_uslp_configure_sdls(&tx, VCID, &cfg); uni_ccsds_uslp_configure_sdls(&rxctx, VCID, &cfg);
  static uint8_t scratch[1024]; uni_ccsds_uslp_set_work_buffer(&rxctx, scratch, sizeof(scratch));
  uni_ccsds_uslp_register_sdu_callback(&rxctx, VCID, MAP, rx, NULL);
  uni_ccsds_uslp_send_mapa(&tx, VCID, MAP, SDU, sizeof(SDU));
  uint8_t frame[256]; size_t fl=sizeof(frame);
  uni_uslp_status_t st=uni_ccsds_uslp_build_frame(&tx, VCID, MAP, frame, &fl);
  if(st!=UNI_USLP_SUCCESS){ fprintf(stderr,"build: %s\n", uni_ccsds_uslp_status_string(st)); return 1; }
  st=uni_ccsds_uslp_accept_frame(&rxctx, frame, fl);
  if(st!=UNI_USLP_SUCCESS){ fprintf(stderr,"accept: %s\n", uni_ccsds_uslp_status_string(st)); return 2; }
  return 0;
}
```

Compile and run (Linux/macOS)
- Build library: cmake -S . -B build && cmake --build build -j
- Build quick start:
  - gcc -std=c11 -I include -I 3rdparty/uni.crypto/include quickstart.c -o quickstart \
    build/libuni_ccsds.a build/3rdparty/uni.crypto/libuni_crypto.a -lmbedcrypto
- Run: ./quickstart

