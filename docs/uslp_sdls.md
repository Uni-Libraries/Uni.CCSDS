# SDLS for USLP (CCSDS 355.0-B-2)

Uni.CCSDS implements the Space Data Link Security option of USLP (CCSDS 732.1-B-3 §6) with a built-in
ProcessSecurity / ApplySecurity engine and a Security Association (SA) table. This page describes the model, the
supported profiles, the receive procedure, the PICS of the SDLS part and every deviation from CCSDS 355.0-B-2.

Version 2.0.0 of the library changed the SDLS API and the default wire format; see "Migration from 1.x" at the end
of this page.

## Model

```
context ── SA table (up to UNI_USLP_SDLS_MAX_SA = 16, looked up by 16-bit SPI)
             └─ SA: config, keyed crypto context, transmit SN, receive anti-replay state
         └─ VC 0..63 ── uni_uslp_sdls_vc_config_t { tx_spi, rx_spis[≤8] } ── SDLS statistics
```

- `uni_ccsds_uslp_sdls_add_sa()` validates the SA configuration and the key, keys the crypto backend once (the key
  bytes are not retained) and adds the SA. `uni_ccsds_uslp_sdls_remove_sa()` and `uni_ccsds_uslp_free()` zeroize
  the key schedule. Contexts with SAs **must** be released with `uni_ccsds_uslp_free()`.
- `uni_ccsds_uslp_configure_sdls()` names the SA applied on transmit (`tx_spi`, §4.2.3.2.1) and the SAs accepted on
  receive (`rx_spis`, §4.2.4.3 a). It fails for unknown SPIs and for SAs of different wire formats on one VC.
- An SA may be restricted to MAP IDs (`map_ids`, GMAP_ID association §4.2.2.2.1).
- Transmit SN management (§4.2.3.4 a): the first frame carries SN 1. `uni_ccsds_uslp_sdls_get_tx_sn()` returns the
  last transmitted SN for persistence; `uni_ccsds_uslp_sdls_set_tx_sn()` restores it. With `require_sn_restore`
  ApplySecurity is refused (`UNI_USLP_ERROR_SDLS_SN_NOT_RESTORED`) after `add_sa` and after every
  `uni_ccsds_uslp_reset()` until the SN is restored or the SA rekeyed (`uni_ccsds_uslp_sdls_rekey_sa()`), which
  prevents IV reuse when a transmitter restarts with the same key. While no restore is pending the SN can only move
  forward. A transmitter refuses to wrap the SN (`UNI_USLP_ERROR_SDLS_SN_EXHAUSTED`).
- `uni_ccsds_uslp_reset()` keeps keys and transmit SNs, clears the receive anti-replay state and the SDLS
  statistics.

## Profiles

Security Header = SPI (2 octets) ‖ IV (`iv_length`) ‖ SN (`sn_length`); Security Trailer = MAC (`mac_length`).
No suite pads, so there is no Pad Length field.

| Profile | Suite | `iv_length` | `sn_length` | `mac_length` | Header | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Annex E baseline (TM/AOS) | AES-GCM, 256-bit key | 12 | 0 | 16 | 14 | IV is a 96-bit counter; its low 64 bits are the anti-replay SN |
| IV derived from SN | AES-GCM / AES-CCM | 0 | 1..8 | 16 (GCM), 4..16 (CCM) | 2 + SN | IV = zero octets ‖ SN field; the SN field width bounds the frames per key |
| IV and SN transmitted | AES-GCM / AES-CCM | 12 | 1..8 | as above | 14 + SN | IV and SN carry the same counter |
| Authentication | HMAC-SHA-256 (16..64-octet key) | 0 | 1..8 | 8..32 (truncated) | 2 + SN | |
| Clear mode | NULL | 0/12 | 0..8 | 0..32 | as configured | No cryptography, no anti-replay; indications report `NOT_APPLICABLE`. Development only (§4.2.2.4 note) |
| Uni.CCSDS 1.x (`UNI_USLP_SDLS_FORMAT_UNI_V1`) | AES-GCM/CCM, HMAC | 0 | 8 | as above | 9 | Legacy, see deviations D4 |

### Authentication mask and AAD (§4.2.2.6.2, §4.2.3.2.2.3)

The Authentication Payload runs from the first octet of the Primary Header to the end of the Transfer Frame Data
Field (the USLP TFDF), ANDed with the mask:

| Region | Mask |
| --- | --- |
| Primary Header (incl. VCF Count) | `auth_mask` (≤ 14 octets). Default from `uni_ccsds_uslp_sdls_default_auth_mask()`: VCID and MAP ID bits set, everything else clear. The VCID and MAP ID bits are mandatory |
| Insert Zone | all zeros |
| Security Header | all ones except the IV field (zeros) |
| Frame Data Field | all ones |

AEAD suites take the octets before the Frame Data Field as AAD and the Frame Data Field as plaintext; HMAC takes the
whole Authentication Payload. OCF and FECF are outside SDLS; the FECF covers the protected frame.

## Receive procedure

ProcessSecurity on a VC with SDLS enabled:

1. Read the SPI (field length from the VC's wire format). Unknown SPI, SPI not in `rx_spis` of the VC, or MAP ID not
   allowed by the SA → `UNI_USLP_ERROR_SDLS_SA_NOT_FOUND` (§4.2.4.3).
2. Frame shorter than header + trailer → `UNI_USLP_ERROR_SDLS_LENGTH`.
3. Extract the SN (SN field, else low 64 bits of the IV) and check it **without changing state**:
   `UNI_USLP_ERROR_SDLS_REPLAY` or `UNI_USLP_ERROR_SDLS_OUT_OF_WINDOW` (§4.2.4.4 f–i).
4. Verify the MAC / decrypt → `UNI_USLP_ERROR_SDLS_MAC_FAILURE` (§4.2.4.4 d, e). Decrypted output of a failed
   verification is zeroized.
5. Only now update the anti-replay state (§4.2.4.4 j) and deliver the TFDF.

Every outcome is counted per VC (`uni_ccsds_uslp_get_sdls_stats()`). The SN check precedes the MAC check so that
duplicates (common with diversity reception) are rejected without decryption; because it does not change state, a
forged frame can neither occupy a sequence number nor move the window.

Anti-replay modes:

- `UNI_USLP_SDLS_REPLAY_STRICT` (default): reject SN ≤ managed SN (§4.2.4.4 h) and SN > managed SN + window
  (§4.2.4.4 i); the managed SN becomes the received one.
- `UNI_USLP_SDLS_REPLAY_SLIDING`: deviation D2.

The managed SN is unset after `add_sa`, `rekey` and `reset`; the first frame that passes MAC verification sets it,
unless key management sets it with `uni_ccsds_uslp_sdls_set_rx_sn()`.

Operational note on STRICT: a gap larger than the window (e.g. the frames transmitted between two passes over a
station) makes every later frame `OUT_OF_WINDOW` until SA management moves the managed SN
(`uni_ccsds_uslp_sdls_set_rx_sn()`) or the context is reset. This is the 355.0-B-2 behaviour; size the window for the
largest expected gap (at most 4096 frames) or resynchronize per pass.

## Example

[`examples/sdls_quickstart.c`](../examples/sdls_quickstart.c) (built and run by ctest as
`uni_ccsds_example_sdls_quickstart`) sets up the Annex E baseline SA on both ends, sends a frame, and shows replay
and header-tamper rejection:

```c
uni_uslp_sdls_sa_config_t sa = {0};          /* auth_mask zero -> §4.2.2.6.2 default */
sa.spi = 0x0101;
sa.suite = UNI_USLP_SDLS_SUITE_AES_GCM;
sa.iv_length = UNI_USLP_SDLS_IV_LENGTH;      /* 96-bit IV in the header */
sa.sn_length = 0;                            /* anti-replay SN = low 64 bits of the IV */
sa.mac_length = 16;
sa.anti_replay_enabled = true;
sa.replay_mode = UNI_USLP_SDLS_REPLAY_STRICT;
sa.anti_replay_window = 64;

uni_ccsds_uslp_register_builtin_sdls(&ctx);
uni_ccsds_uslp_sdls_add_sa(&ctx, &sa, key, 32);

uni_uslp_sdls_vc_config_t vc = {0};
vc.enabled = true;
vc.tx_spi = 0x0101;                          /* transmit side */
vc.rx_spi_count = 1; vc.rx_spis[0] = 0x0101; /* receive side */
uni_ccsds_uslp_configure_sdls(&ctx, VCID, &vc);
/* ... build / accept frames ... */
uni_ccsds_uslp_free(&ctx);                   /* releases crypto state, zeroizes key schedules */
```

## Custom engines

`uni_ccsds_uslp_register_sdls_callbacks()` replaces the built-in engine (e.g. with an HSM). The callbacks receive
the whole frame and its layout (`uni_uslp_sdls_frame_layout_t`): ApplySecurity writes the Security Header, protects
the TFDF in place and appends the trailer, using the header and trailer lengths of the SA named by `tx_spi`
(`uni_ccsds_uslp_sdls_get_sa_config()`); ProcessSecurity selects the SA by SPI, verifies and returns the plaintext
TFDF and a `uni_uslp_sdls_rx_info_t`. Return the specific `UNI_USLP_ERROR_SDLS_*` code so the per-reason statistics
stay meaningful.

## PICS (SDLS part, CCSDS 355.0-B-2 Annex A)

| Feature | Reference | Support | Notes |
| --- | --- | --- | --- |
| Security Header SPI 16 bit | §4.1.1.2 | Y | 1-octet SPI only in the UNI_V1 legacy format (D4) |
| Initialization Vector field | §4.1.1.3 | Y | 0 or 12 octets |
| Sequence Number field | §4.1.1.4 | Y | 0..8 octets |
| Pad Length field | §4.1.1.5 | N | No implemented suite pads (always 0 octets) |
| Security Trailer (MAC) | §4.1.2 | Y | |
| SA per GVCID / GMAP_ID | §4.2.2.2 | Y | `rx_spis`, `tx_spi`, `map_ids` |
| Authenticated encryption | §4.2.2.4 c | Y | AES-GCM, AES-CCM |
| Authentication | §4.2.2.4 a | Y | HMAC-SHA-256. AES-CMAC (Annex E TC baseline) is not implemented (D5) |
| Encryption only | §4.2.2.4 b | N | (D5) |
| Authentication bit mask | §4.2.2.6.2 | Y | Configurable over the Primary Header; fixed elsewhere as the standard requires |
| AEAD AAD / plaintext split | §4.2.3.2.2.3 a | Y | |
| Anti-replay check and update | §4.2.4.4 f–j | Y | STRICT mode; SLIDING is D2 |
| SA verification | §4.2.4.3 | Y | |
| Report exceptions | §4.2.4.3 b, §4.2.4.4 e, h, i | Y | Distinct status codes and per-VC counters |
| Archive rejected frames | §4.2.4.4 e note | N | The caller sees the rejected frame and may archive it |
| Key management, SA management procedures | 355.1-B-1 | N | `add/remove/rekey_sa`, `set_tx_sn`, `set_rx_sn` are the local hooks a key-management layer would drive |

## Deviations from CCSDS 355.0-B-2

| ID | Deviation | Why | Where |
| --- | --- | --- | --- |
| D1 | The anti-replay check (without state change) runs before MAC verification; the standard lists MAC first | Rejects duplicates without decryption (diversity reception produces many); the outcome for every frame is the same except which reason is reported for a frame that is both replayed and forged (`REPLAY`) | `uni_ccsds_uslp_sdls_builtin_process()` |
| D2 | `UNI_USLP_SDLS_REPLAY_SLIDING` accepts a lower SN once if it lags the highest accepted SN by less than the window, and accepts any higher SN (no §4.2.4.4 i bound) | Copies of one frame stream arriving from several carriers/stations are not in SN order; opt-in per SA | `sdls_replay_check()` |
| D3 | If the managed (receive) SN was never set, the first frame that passes MAC verification initializes it | 355.0-B-2 leaves initialization to SA management (355.1); without it a receiver joining a pass could never synchronize | `uni_ccsds_uslp_sdls_set_rx_sn()` sets it explicitly |
| D4 | `UNI_USLP_SDLS_FORMAT_UNI_V1`: 1-octet SPI, AAD empty, HMAC over the TFDF only — Primary and Security Headers are **not** authenticated | Receiving spacecraft that fly Uni.CCSDS 1.x; must not be used for new missions. In addition, 1.x transmitters kept the SN per VC: SAs that share a key across VCs reuse GCM nonces on board — a property of those spacecraft that the ground cannot fix | `sdls_build_aad()`, `sdls_spi_length()` |
| D5 | Not implemented: encryption-only SAs, AES-CMAC, padding / Pad Length, Extended Procedures (355.1) | Not needed by current missions | — |
| D6 | When the IV is transmitted, only its low 64 bits serve as the anti-replay SN | A 64-bit counter cannot wrap in the life of a key; the high IV octets are authenticated as the GCM nonce | `uni_ccsds_uslp_sdls_builtin_process()` |

Interoperability with NASA CryptoLib (plan item CCSDS-7): the Annex E header layout and the §4.2.2.6.2 mask are
implemented, but a USLP frame exchange with CryptoLib is not possible — CryptoLib (checked at commit `dbcb115`,
2026-10) implements ApplySecurity/ProcessSecurity for TC, TM and AOS frames only, not for USLP.

## Migration from 1.x

| 1.x | 2.x |
| --- | --- |
| `uni_uslp_sdls_config_t` per VC with key pointer, `sec_header_length` = 9, `spi` 8 bit | `uni_uslp_sdls_sa_config_t` added once with `uni_ccsds_uslp_sdls_add_sa()` (key copied into the key schedule), VC refers to it with `uni_uslp_sdls_vc_config_t` |
| `UNI_USLP_ERROR_SDLS_FAILURE` for every rejection | `UNI_USLP_ERROR_SDLS_SA_NOT_FOUND`, `_MAC_FAILURE`, `_REPLAY`, `_OUT_OF_WINDOW`, `_LENGTH`, `_SN_NOT_RESTORED`, `_SN_EXHAUSTED` (`_FAILURE` remains for backend errors) |
| Callbacks received only the TFDF | Callbacks receive the whole frame and its layout |
| Anti-replay state per VC, updated before MAC verification | Per SA, updated only after verification |
| First transmitted SN 0 | First transmitted SN 1 |
| `uni_ccsds_uslp_free()` optional | Required for contexts with SAs |

To keep receiving a 1.x transmitter, configure its SA with `format = UNI_USLP_SDLS_FORMAT_UNI_V1`, `sn_length = 8`,
`iv_length = 0` and, to reproduce the 1.x behaviour, `replay_mode = UNI_USLP_SDLS_REPLAY_SLIDING`.
