
# USLP FAQ

This FAQ describes practical, end-to-end sequences for sending and receiving a **custom payload** using this library’s USLP framing implementation.

---

## USLP services overview (what to use and when)

In USLP, the “service” determines how your SDU is represented inside the TFDF/TFDZ for a given (VCID, MAP ID). In this library you select the service when configuring a MAP via `uni_ccsds_uslp_configure_map()` and `uni_uslp_service_type_t`, and then you queue SDUs using the corresponding `send_*` API.

### Data-carrying services (typical application payload)

| Service | When to use | Queue API |
|---|---|---|
| Packet service (MAPP) `UNI_USLP_SERVICE_PACKET` | Your application data is already in **CCSDS Space Packets** and you want USLP to carry whole packets (and optionally validate PVN/length against managed parameters). | `uni_ccsds_uslp_send_packet_ex()` |
| VC Packet service (VCP) `UNI_USLP_SERVICE_VCP` | You want to send **Space Packets at VC scope** (not MAP multiplexed). In this IUT it reuses the MAP build path internally and is exposed as a separate service for distinct notifications/callbacks. | `uni_ccsds_uslp_send_vcp_ex()` |
| MAPA SDU service `UNI_USLP_SERVICE_MAPA` | Your payload is **opaque application bytes** (custom format) and you just want to deliver those bytes end-to-end. This is the recommended default for “custom payload” in this FAQ. | `uni_ccsds_uslp_send_mapa()` |
| VCA SDU service `UNI_USLP_SERVICE_VCA` | You want to send VCA SDUs (often used as application-defined records) with optional expedited/sequence-controlled QoS. Choose this when your mission/application defines VCA SDU semantics and you want it distinct from MAPA. | `uni_ccsds_uslp_send_vca_ex()` |
| Octet Stream service `UNI_USLP_SERVICE_OCTET_STREAM` | You have a **stream** of bytes where you want the library to emit “portions” (chunks) and optionally observe send/queue events via notify callbacks. Use this for continuous data feeds rather than discrete records/packets. | `uni_ccsds_uslp_send_octet_stream_ex()` |

### Control/management-related services (not “custom payload”)

These are part of USLP framing and are implemented in this library, but they are typically used for link/control-plane behaviors rather than application payload delivery:

- OCF insertion (Operational Control Field): queue via `uni_ccsds_uslp_send_ocf()`, receive via `uni_ccsds_uslp_register_ocf_callback()` or `uni_ccsds_uslp_register_ocf2_callback()`.
- Insert Zone: queue via `uni_ccsds_uslp_send_insert()`, receive via `uni_ccsds_uslp_register_insert_callback()` or `uni_ccsds_uslp_register_insert2_callback()`.
- VCF/MCF “frame services” (delivering whole Transfer Frames upward, and/or forwarding partially-formatted frames downward): see `uni_ccsds_uslp_register_vcf_indication_callback()`, `uni_ccsds_uslp_register_mcf_indication_callback()`, `uni_ccsds_uslp_vcf_request()`, `uni_ccsds_uslp_mcf_request()`.
- COPs Management directives/notifications: submit via `uni_ccsds_uslp_directive_request()` and observe via `uni_ccsds_uslp_register_directive_notify_callback()` / `uni_ccsds_uslp_register_async_notify_callback()`.

---

Unless stated otherwise, the examples assume you carry your custom payload as a **MAPA SDU** (i.e., bytes delivered via the MAPA service), using:

- TX/RX context: `uni_uslp_context_t`
- Physical/VC/MAP configuration: `uni_ccsds_uslp_init()`, `uni_ccsds_uslp_configure_vc()`, `uni_ccsds_uslp_configure_map()`
- Enqueue SDU: `uni_ccsds_uslp_send_mapa()`
- Build/parse frames: `uni_ccsds_uslp_build_frame()`, `uni_ccsds_uslp_accept_frame()`

Notes (important for correct integration):

- **Zero-copy TX queueing**: send APIs store pointers to your SDU; keep the SDU buffer valid until the corresponding build completes (documented in [`docs/uslp.md`](docs/uslp.md:20)).
- **RX delivery is zero-copy**: callbacks receive pointers into the input frame buffer; keep that frame buffer valid until callbacks return (documented in [`docs/uslp.md`](docs/uslp.md:20)).
- SDLS is optional. If SDLS is enabled for a VC, RX requires a scratch buffer via `uni_ccsds_uslp_set_work_buffer()` (documented in [`docs/uslp.md`](docs/uslp.md:20)).

---

## How does the receiver know whether a frame is encrypted?

In this library, “encrypted” means **SDLS is enabled on the receiving VC**.

- The **Primary Header** contains VCID and MAP ID (demultiplexing inputs). You can parse it up-front using `uni_ccsds_uslp_primary_header_unpack()`.
- Whether SDLS (and thus authenticated encryption) is applied is a **managed/configured property** of that VC, set by the receiver with `uni_ccsds_uslp_configure_sdls()` and the VCID.
- There is **no explicit “encrypted=yes/no” bit in the USLP Primary Header**; both ends must be configured consistently for the same VC (suite/key/SPI, header/trailer sizes).

On-wire hints and practical consequences:

- When SDLS is used, the TFDF region begins with a **Security Header** whose presence/size is part of the SDLS option (`SPI(2) || IV || SN`, lengths from the SA selected by the SPI; see [uslp_sdls.md](uslp_sdls.md)).
- However, the receiver should not “guess” encryption by heuristics. It should decide based on its VC configuration.
- If the receiver expects SDLS but receives an unprotected frame (or mismatched SDLS parameters), `uni_ccsds_uslp_accept_frame()` will fail (commonly `UNI_USLP_ERROR_SDLS_SA_NOT_FOUND` or `UNI_USLP_ERROR_SDLS_MAC_FAILURE`).
- If the receiver does not enable SDLS but receives an SDLS-protected frame, TFDF parsing will interpret the Security Header as TFDF data and typically return an error (commonly `UNI_USLP_ERROR_INVALID_FRAME`).

Also note: “SDLS present” does not necessarily mean “encrypted”. SDLS can be authentication-only depending on the SA suite (`uni_uslp_sdls_sa_config_t.suite`: HMAC-SHA-256 authenticates only). That mode selection is likewise determined by configuration rather than an explicit Primary Header flag.

---

## What information is available before decryption (SDLS processing)?

You can separate the received bytes into:

1. **Always available before SDLS** (because it is outside the protected TFDF content):
   - Primary Header fields (TFVN, SCID, VCID, MAP ID, Bypass flag, OCF flag, VCF Count length/value, etc.) using `uni_ccsds_uslp_primary_header_unpack()`.
   - Insert Zone presence/length is determined by managed parameters (e.g., `uni_uslp_managed_params_t.insert_zone_length`). The Insert Zone bytes themselves are not part of SDLS protection in this implementation.
   - OCF presence is indicated by `uni_uslp_primary_header_t.ocf_flag`; the OCF bytes are not SDLS-protected (they are outside TFDF).
   - FECF (if enabled) is at the end of the frame and can be checked for raw corruption prior to attempting higher-layer parsing.

2. **Conditionally available “in the clear” when SDLS is enabled** (profile-dependent):
   - The SDLS **Security Header** fields (e.g., SPI and Sequence Number) are typically not encrypted and can be read before decryption. The library uses these to select/check security processing and to enforce anti-replay before delivering SDUs.

3. **Not available until after SDLS succeeds**:
   - The TFDF header and all TFDF/TFDZ user data, including:
     - TFDF construction rule, UPID, First Header Pointer, Last Valid Pointer (see `uni_uslp_tfdf_header_t`)
     - The application SDU bytes delivered to callbacks

Practical integration pattern:

- If you need to make routing decisions **before** calling the library, parse only the Primary Header with `uni_ccsds_uslp_primary_header_unpack()` to obtain (SCID, VCID, MAP ID), then dispatch the frame to the correct context and call `uni_ccsds_uslp_accept_frame()` which performs SDLS processing (if configured) and then TFDF parsing.

---

## FECF (CRC-16) and offloading CRC to FPGA/modem

USLP frames may carry an optional **Frame Error Control Field (FECF)** of 2 octets (CRC-16/CCITT). In this library the presence of FECF is controlled by the **physical-channel managed parameter** `uni_uslp_managed_params_t.fecf_capability` (passed to `uni_ccsds_uslp_init()` and stored in the context).

TX generation behavior (CPU vs hardware) is controlled by `uni_uslp_managed_params_t.fecf_tx_mode` and `uni_uslp_fecf_tx_mode_t`.

### TX behavior (building frames)

- If `uni_uslp_managed_params_t.fecf_capability` is **true** and `uni_uslp_managed_params_t.fecf_tx_mode` is `UNI_USLP_FECF_TX_INTERNAL`, `uni_ccsds_uslp_build_frame()` computes and appends a CRC-16 over the whole frame except the FECF itself.
- If `uni_uslp_managed_params_t.fecf_capability` is **false**, no FECF bytes are present and the Primary Header `Frame Length` reflects that.

Practical offload patterns:

1. **Hardware overwrites the last 2 bytes in-place** (“CRC insertion” block).
   - Set `uni_uslp_managed_params_t.fecf_capability` **true**.
   - Set `uni_uslp_managed_params_t.fecf_tx_mode` to `UNI_USLP_FECF_TX_OFFLOAD_INPLACE`.
   - The library will:
     - include the 2-byte FECF in the Primary Header Frame Length
     - reserve those 2 bytes in the returned buffer length
     - **not write** the CRC bytes (hardware overwrites them)

2. **Hardware appends the 2 CRC bytes on the wire (outside the CPU buffer)**.
   - Set `uni_uslp_managed_params_t.fecf_capability` **true**.
   - Set `uni_uslp_managed_params_t.fecf_tx_mode` to `UNI_USLP_FECF_TX_OFFLOAD_APPEND`.
   - The library will:
     - include the 2-byte FECF in the Primary Header Frame Length
     - **not output** those 2 bytes into your `frame_buffer`
     - return `*frame_length` that is 2 bytes shorter than the Primary Header length
   - Your hardware/driver must append the 2-byte CRC after transmitting the CPU-provided bytes.

### RX behavior (accepting frames)

- If `uni_uslp_managed_params_t.fecf_capability` is **true**, `uni_ccsds_uslp_accept_frame()` verifies the CRC and returns `UNI_USLP_ERROR_CRC_MISMATCH` on failure.
- If it is **false**, no CRC verification is performed and the parser treats the received bytes as having no FECF.

Important interoperability note:

- This library currently treats FECF as **either present and verified** or **absent**. If your modem/FPGA verifies CRC and then *strips* the final 2 bytes, it must also ensure the Primary Header length and the receiver’s `uni_uslp_managed_params_t.fecf_capability` setting match the stripped representation; otherwise `uni_ccsds_uslp_accept_frame()` will reject the frame as inconsistent.

For details on CRC coverage and the SDLS interaction (FECF covers Security Header/Trailer when SDLS is enabled), see [`docs/uslp.md`](docs/uslp.md:57).

---

## 1) Sequence to send an unencrypted custom payload

1. **Initialize a TX context** with physical-channel defaults.
   - Allocate a `uni_uslp_context_t` instance and a base `uni_uslp_managed_params_t`.
   - Set required physical/MAP parameters such as:
     - `uni_uslp_managed_params_t.max_frame_length` (and optionally `uni_uslp_managed_params_t.min_frame_length`)
     - Enable/disable FECF as appropriate for your link via `uni_uslp_managed_params_t.fecf_capability`
   - Call `uni_ccsds_uslp_init()` with your SCID.

2. **Configure the target Virtual Channel (VC)**.
   - Prepare VC-scoped parameters (typically derived from your physical defaults).
   - For sequence-controlled traffic (Bypass=0), configure a VCF counter length (example field): `uni_uslp_managed_params_t.vcf_seq_count_len_octets`.
   - Call `uni_ccsds_uslp_configure_vc()` with the chosen VCID.

3. **Configure the target MAP** for “custom payload bytes”.
   - Choose a MAP ID and configure that (VC, MAP) as MAPA service: `UNI_USLP_SERVICE_MAPA`.
   - Ensure your MAP allows the SDU sizes you intend to send via `uni_uslp_managed_params_t.max_sdu_length`.
   - Call `uni_ccsds_uslp_configure_map()`.

4. **(Optional) Register a sending-end notify callback** to observe queue/send outcomes.
   - MAPA notify API: `uni_ccsds_uslp_register_mapa_notify_callback()`.

5. **Queue the payload**.
   - Call `uni_ccsds_uslp_send_mapa()` with your payload pointer/length.
   - Ensure it returns `UNI_USLP_SUCCESS` (or handle errors via `uni_ccsds_uslp_status_string()`).

6. **Build one Transfer Frame** into a caller-provided buffer.
   - Call `uni_ccsds_uslp_build_frame()`.
   - On success (`UNI_USLP_SUCCESS`), send the produced `frame_buffer[0..frame_length)` bytes using your link/radio/transport.

---

## 2) Sequence to send and receive an unencrypted custom payload

This is a “loopback” style description: build on the TX side, then feed the same frame bytes into the RX side.

### TX side

Perform the steps from **“send an unencrypted custom payload”** above.

### RX side

1. **Initialize and configure an RX context** consistently with the sender.
   - Create an RX `uni_uslp_context_t`.
   - Call `uni_ccsds_uslp_init()` using the same SCID (and compatible physical/MAP managed parameters).
   - Call `uni_ccsds_uslp_configure_vc()` for the VCID you expect.
   - Call `uni_ccsds_uslp_configure_map()` for the (VCID, MAP ID) you expect, using `UNI_USLP_SERVICE_MAPA`.

2. **Register an SDU callback** for that (VCID, MAP ID).
   - Implement a `uni_uslp_sdu_callback_t`.
   - Register it with `uni_ccsds_uslp_register_sdu_callback()`.

3. **Accept received frames**.
   - For each received frame buffer, call `uni_ccsds_uslp_accept_frame()`.
   - If it returns `UNI_USLP_SUCCESS`, your callback should be invoked with the delivered SDU.

4. **Interpret verification status for unencrypted frames**.
   - When SDLS is not in effect, the callback parameter `uni_uslp_verification_status_t` will be `UNI_USLP_VERIF_NOT_APPLICABLE`.

---

## 3) Sequence to send an encrypted custom payload

Encrypted payloads use the USLP SDLS option on a VC.

1. **Initialize TX context and configure VC/MAP**.
   - Perform steps 1–3 from **“send an unencrypted custom payload”**.

2. **Register the built-in SDLS engine** (recommended).
   - Call `uni_ccsds_uslp_register_builtin_sdls()` once per context.

3. **Add a Security Association and enable SDLS on the target VC** (details: [uslp_sdls.md](uslp_sdls.md)).
   - Fill a `uni_uslp_sdls_sa_config_t`: `spi` (16 bit), `suite`, `iv_length`/`sn_length`/`mac_length`, anti-replay mode
     and window; leave `auth_mask` zero for the CCSDS 355.0-B-2 default.
   - Add it with `uni_ccsds_uslp_sdls_add_sa(ctx, &sa, key, key_length)` — the key is turned into a key schedule and
     not retained.
   - Fill a `uni_uslp_sdls_vc_config_t` with `enabled = true` and `tx_spi = sa.spi`, and apply it with
     `uni_ccsds_uslp_configure_sdls()`. Configuration errors are reported here, not on the first frame.

4. **Queue the payload and build a frame**.
   - Queue payload via `uni_ccsds_uslp_send_mapa()`.
   - Build via `uni_ccsds_uslp_build_frame()`.
   - On success (`UNI_USLP_SUCCESS`), transmit the resulting frame bytes.

---

## 4) Sequence to send and receive an encrypted custom payload

### TX side

Perform the steps from **“send an encrypted custom payload”** above.

### RX side

1. **Initialize and configure an RX context** consistently with the sender.
   - Call `uni_ccsds_uslp_init()`, `uni_ccsds_uslp_configure_vc()`, and `uni_ccsds_uslp_configure_map()` for the expected VC/MAP.

2. **Enable SDLS on the RX context**.
   - Call `uni_ccsds_uslp_register_builtin_sdls()`, add the same SA (same SPI, profile and key) with
     `uni_ccsds_uslp_sdls_add_sa()`, and configure the VC with `rx_spis = { sa.spi }`. The receiver selects the SA by
     the SPI of each frame.

3. **Provide an RX work (scratch) buffer**.
   - SDLS RX processing requires a caller-supplied buffer for transformations.
   - Call `uni_ccsds_uslp_set_work_buffer()`.

4. **Register an SDU callback** for that (VCID, MAP ID).
   - Implement a `uni_uslp_sdu_callback_t` and register it via `uni_ccsds_uslp_register_sdu_callback()`.

5. **Accept received frames**.
   - Call `uni_ccsds_uslp_accept_frame()`.
   - On success (`UNI_USLP_SUCCESS`), the callback receives the decrypted SDU and a verification status.

6. **Handle authentication/decryption failures and anti-replay**.
   - If SDLS verification fails, `uni_ccsds_uslp_accept_frame()` returns the reason (`UNI_USLP_ERROR_SDLS_SA_NOT_FOUND`,
     `_MAC_FAILURE`, `_REPLAY`, `_OUT_OF_WINDOW`, `_LENGTH`), the frame is discarded and the per-VC counters
     (`uni_ccsds_uslp_get_sdls_stats()`) are incremented.
   - When SDLS is in effect and processing succeeds, the callback verification status `uni_uslp_verification_status_t` should be `UNI_USLP_VERIF_SUCCESS`.

---

## Appendix: using a different service than MAPA

If “custom payload” in your project means a different USLP service, the sequence is the same except for the “queue SDU” step and (sometimes) the callback type:

- Packet SDU: `uni_ccsds_uslp_send_packet_ex()`
- VCA SDU: `uni_ccsds_uslp_send_vca_ex()`
- Octet Stream portion: `uni_ccsds_uslp_send_octet_stream_ex()`

Frame building and reception still use `uni_ccsds_uslp_build_frame()` and `uni_ccsds_uslp_accept_frame()`.
