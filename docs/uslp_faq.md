
# USLP FAQ

This FAQ describes practical, end-to-end sequences for sending and receiving a **custom payload** using this library’s USLP framing implementation.

---

## USLP services overview (what to use and when)

In USLP, the “service” determines how your SDU is represented inside the TFDF/TFDZ for a given (VCID, MAP ID). In this library you select the service when configuring a MAP via [`uni_ccsds_uslp_configure_map()`](include/uni_ccsds_uslp.h:981) and [`uni_uslp_service_type_t`](include/uni_ccsds_uslp.h:220), and then you queue SDUs using the corresponding `send_*` API.

### Data-carrying services (typical application payload)

| Service | When to use | Queue API |
|---|---|---|
| Packet service (MAPP) [`UNI_USLP_SERVICE_PACKET`](include/uni_ccsds_uslp.h:221) | Your application data is already in **CCSDS Space Packets** and you want USLP to carry whole packets (and optionally validate PVN/length against managed parameters). | [`uni_ccsds_uslp_send_packet_ex()`](include/uni_ccsds_uslp.h:1463) |
| VC Packet service (VCP) [`UNI_USLP_SERVICE_VCP`](include/uni_ccsds_uslp.h:225) | You want to send **Space Packets at VC scope** (not MAP multiplexed). In this IUT it reuses the MAP build path internally and is exposed as a separate service for distinct notifications/callbacks. | [`uni_ccsds_uslp_send_vcp_ex()`](include/uni_ccsds_uslp.h:1491) |
| MAPA SDU service [`UNI_USLP_SERVICE_MAPA`](include/uni_ccsds_uslp.h:223) | Your payload is **opaque application bytes** (custom format) and you just want to deliver those bytes end-to-end. This is the recommended default for “custom payload” in this FAQ. | [`uni_ccsds_uslp_send_mapa()`](include/uni_ccsds_uslp.h:1511) |
| VCA SDU service [`UNI_USLP_SERVICE_VCA`](include/uni_ccsds_uslp.h:222) | You want to send VCA SDUs (often used as application-defined records) with optional expedited/sequence-controlled QoS. Choose this when your mission/application defines VCA SDU semantics and you want it distinct from MAPA. | [`uni_ccsds_uslp_send_vca_ex()`](include/uni_ccsds_uslp.h:1536) |
| Octet Stream service [`UNI_USLP_SERVICE_OCTET_STREAM`](include/uni_ccsds_uslp.h:224) | You have a **stream** of bytes where you want the library to emit “portions” (chunks) and optionally observe send/queue events via notify callbacks. Use this for continuous data feeds rather than discrete records/packets. | [`uni_ccsds_uslp_send_octet_stream_ex()`](include/uni_ccsds_uslp.h:1563) |

### Control/management-related services (not “custom payload”)

These are part of USLP framing and are implemented in this library, but they are typically used for link/control-plane behaviors rather than application payload delivery:

- OCF insertion (Operational Control Field): queue via [`uni_ccsds_uslp_send_ocf()`](include/uni_ccsds_uslp.h:1581), receive via [`uni_ccsds_uslp_register_ocf_callback()`](include/uni_ccsds_uslp.h:1074) or [`uni_ccsds_uslp_register_ocf2_callback()`](include/uni_ccsds_uslp.h:1096).
- Insert Zone: queue via [`uni_ccsds_uslp_send_insert()`](include/uni_ccsds_uslp.h:1596), receive via [`uni_ccsds_uslp_register_insert_callback()`](include/uni_ccsds_uslp.h:1112) or [`uni_ccsds_uslp_register_insert2_callback()`](include/uni_ccsds_uslp.h:1136).
- VCF/MCF “frame services” (delivering whole Transfer Frames upward, and/or forwarding partially-formatted frames downward): see [`uni_ccsds_uslp_register_vcf_indication_callback()`](include/uni_ccsds_uslp.h:1336), [`uni_ccsds_uslp_register_mcf_indication_callback()`](include/uni_ccsds_uslp.h:1358), [`uni_ccsds_uslp_vcf_request()`](include/uni_ccsds_uslp.h:1617), [`uni_ccsds_uslp_mcf_request()`](include/uni_ccsds_uslp.h:1637).
- COPs Management directives/notifications: submit via [`uni_ccsds_uslp_directive_request()`](include/uni_ccsds_uslp.h:1660) and observe via [`uni_ccsds_uslp_register_directive_notify_callback()`](include/uni_ccsds_uslp.h:1419) / [`uni_ccsds_uslp_register_async_notify_callback()`](include/uni_ccsds_uslp.h:1435).

---

Unless stated otherwise, the examples assume you carry your custom payload as a **MAPA SDU** (i.e., bytes delivered via the MAPA service), using:

- TX/RX context: [`uni_uslp_context_t`](include/uni_ccsds_uslp.h:463)
- Physical/VC/MAP configuration: [`uni_ccsds_uslp_init()`](include/uni_ccsds_uslp.h:911), [`uni_ccsds_uslp_configure_vc()`](include/uni_ccsds_uslp.h:965), [`uni_ccsds_uslp_configure_map()`](include/uni_ccsds_uslp.h:981)
- Enqueue SDU: [`uni_ccsds_uslp_send_mapa()`](include/uni_ccsds_uslp.h:1511)
- Build/parse frames: [`uni_ccsds_uslp_build_frame()`](include/uni_ccsds_uslp.h:1706), [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756)

Notes (important for correct integration):

- **Zero-copy TX queueing**: send APIs store pointers to your SDU; keep the SDU buffer valid until the corresponding build completes (documented in [`docs/uslp.md`](docs/uslp.md:20)).
- **RX delivery is zero-copy**: callbacks receive pointers into the input frame buffer; keep that frame buffer valid until callbacks return (documented in [`docs/uslp.md`](docs/uslp.md:20)).
- SDLS is optional. If SDLS is enabled for a VC, RX requires a scratch buffer via [`uni_ccsds_uslp_set_work_buffer()`](include/uni_ccsds_uslp.h:947) (documented in [`docs/uslp.md`](docs/uslp.md:20)).

---

## How does the receiver know whether a frame is encrypted?

In this library, “encrypted” means **SDLS is enabled on the receiving VC**.

- The **Primary Header** contains VCID and MAP ID (demultiplexing inputs). You can parse it up-front using [`uni_ccsds_uslp_primary_header_unpack()`](include/uni_ccsds_uslp.h:1824).
- Whether SDLS (and thus authenticated encryption) is applied is a **managed/configured property** of that VC, set by the receiver with [`uni_ccsds_uslp_configure_sdls()`](include/uni_ccsds_uslp.h:1013) and the VCID.
- There is **no explicit “encrypted=yes/no” bit in the USLP Primary Header**; both ends must be configured consistently for the same VC (suite/key/SPI, header/trailer sizes).

On-wire hints and practical consequences:

- When SDLS is used, the TFDF region begins with a **Security Header** whose presence/size is part of the SDLS option (in this project’s built-in profile: `SPI(1) || SN(8)` as described near [`uni_ccsds_uslp_register_builtin_sdls()`](include/uni_ccsds_uslp.h:1990)).
- However, the receiver should not “guess” encryption by heuristics. It should decide based on its VC configuration.
- If the receiver expects SDLS but receives an unprotected frame (or mismatched SDLS parameters), [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756) will fail (commonly [`UNI_USLP_ERROR_SDLS_FAILURE`](include/uni_ccsds_uslp.h:184)).
- If the receiver does not enable SDLS but receives an SDLS-protected frame, TFDF parsing will interpret the Security Header as TFDF data and typically return an error (commonly [`UNI_USLP_ERROR_INVALID_FRAME`](include/uni_ccsds_uslp.h:179)).

Also note: “SDLS present” does not necessarily mean “encrypted”. SDLS can be authentication-only depending on configuration fields like [`uni_uslp_sdls_config_t.authentication_only`](include/uni_ccsds_uslp.h:434) and [`uni_uslp_sdls_config_t.encryption_enabled`](include/uni_ccsds_uslp.h:435). That mode selection is likewise determined by configuration rather than an explicit Primary Header flag.

---

## What information is available before decryption (SDLS processing)?

You can separate the received bytes into:

1. **Always available before SDLS** (because it is outside the protected TFDF content):
   - Primary Header fields (TFVN, SCID, VCID, MAP ID, Bypass flag, OCF flag, VCF Count length/value, etc.) using [`uni_ccsds_uslp_primary_header_unpack()`](include/uni_ccsds_uslp.h:1824).
   - Insert Zone presence/length is determined by managed parameters (e.g., [`uni_uslp_managed_params_t.insert_zone_length`](include/uni_ccsds_uslp.h:399)). The Insert Zone bytes themselves are not part of SDLS protection in this implementation.
   - OCF presence is indicated by [`uni_uslp_primary_header_t.ocf_flag`](include/uni_ccsds_uslp.h:326); the OCF bytes are not SDLS-protected (they are outside TFDF).
   - FECF (if enabled) is at the end of the frame and can be checked for raw corruption prior to attempting higher-layer parsing.

2. **Conditionally available “in the clear” when SDLS is enabled** (profile-dependent):
   - The SDLS **Security Header** fields (e.g., SPI and Sequence Number) are typically not encrypted and can be read before decryption. The library uses these to select/check security processing and to enforce anti-replay before delivering SDUs.

3. **Not available until after SDLS succeeds**:
   - The TFDF header and all TFDF/TFDZ user data, including:
     - TFDF construction rule, UPID, First Header Pointer, Last Valid Pointer (see [`uni_uslp_tfdf_header_t`](include/uni_ccsds_uslp.h:335))
     - The application SDU bytes delivered to callbacks

Practical integration pattern:

- If you need to make routing decisions **before** calling the library, parse only the Primary Header with [`uni_ccsds_uslp_primary_header_unpack()`](include/uni_ccsds_uslp.h:1824) to obtain (SCID, VCID, MAP ID), then dispatch the frame to the correct context and call [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756) which performs SDLS processing (if configured) and then TFDF parsing.

---

## FECF (CRC-16) and offloading CRC to FPGA/modem

USLP frames may carry an optional **Frame Error Control Field (FECF)** of 2 octets (CRC-16/CCITT). In this library the presence of FECF is controlled by the **physical-channel managed parameter** [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:402) (passed to [`uni_ccsds_uslp_init()`](include/uni_ccsds_uslp.h:911) and stored in the context).

TX generation behavior (CPU vs hardware) is controlled by [`uni_uslp_managed_params_t.fecf_tx_mode`](include/uni_ccsds_uslp.h:437) and [`uni_uslp_fecf_tx_mode_t`](include/uni_ccsds_uslp.h:302).

### TX behavior (building frames)

- If [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436) is **true** and [`uni_uslp_managed_params_t.fecf_tx_mode`](include/uni_ccsds_uslp.h:437) is [`UNI_USLP_FECF_TX_INTERNAL`](include/uni_ccsds_uslp.h:305), [`uni_ccsds_uslp_build_frame()`](include/uni_ccsds_uslp.h:1741) computes and appends a CRC-16 over the whole frame except the FECF itself.
- If [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436) is **false**, no FECF bytes are present and the Primary Header `Frame Length` reflects that.

Practical offload patterns:

1. **Hardware overwrites the last 2 bytes in-place** (“CRC insertion” block).
   - Set [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436) **true**.
   - Set [`uni_uslp_managed_params_t.fecf_tx_mode`](include/uni_ccsds_uslp.h:437) to [`UNI_USLP_FECF_TX_OFFLOAD_INPLACE`](include/uni_ccsds_uslp.h:313).
   - The library will:
     - include the 2-byte FECF in the Primary Header Frame Length
     - reserve those 2 bytes in the returned buffer length
     - **not write** the CRC bytes (hardware overwrites them)

2. **Hardware appends the 2 CRC bytes on the wire (outside the CPU buffer)**.
   - Set [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436) **true**.
   - Set [`uni_uslp_managed_params_t.fecf_tx_mode`](include/uni_ccsds_uslp.h:437) to [`UNI_USLP_FECF_TX_OFFLOAD_APPEND`](include/uni_ccsds_uslp.h:327).
   - The library will:
     - include the 2-byte FECF in the Primary Header Frame Length
     - **not output** those 2 bytes into your `frame_buffer`
     - return `*frame_length` that is 2 bytes shorter than the Primary Header length
   - Your hardware/driver must append the 2-byte CRC after transmitting the CPU-provided bytes.

### RX behavior (accepting frames)

- If [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436) is **true**, [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1804) verifies the CRC and returns [`UNI_USLP_ERROR_CRC_MISMATCH`](include/uni_ccsds_uslp.h:180) on failure.
- If it is **false**, no CRC verification is performed and the parser treats the received bytes as having no FECF.

Important interoperability note:

- This library currently treats FECF as **either present and verified** or **absent**. If your modem/FPGA verifies CRC and then *strips* the final 2 bytes, it must also ensure the Primary Header length and the receiver’s [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436) setting match the stripped representation; otherwise [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1804) will reject the frame as inconsistent.

For details on CRC coverage and the SDLS interaction (FECF covers Security Header/Trailer when SDLS is enabled), see [`docs/uslp.md`](docs/uslp.md:57).

---

## 1) Sequence to send an unencrypted custom payload

1. **Initialize a TX context** with physical-channel defaults.
   - Allocate a [`uni_uslp_context_t`](include/uni_ccsds_uslp.h:463) instance and a base [`uni_uslp_managed_params_t`](include/uni_ccsds_uslp.h:361).
   - Set required physical/MAP parameters such as:
     - [`uni_uslp_managed_params_t.max_frame_length`](include/uni_ccsds_uslp.h:364) (and optionally [`uni_uslp_managed_params_t.min_frame_length`](include/uni_ccsds_uslp.h:365))
     - Enable/disable FECF as appropriate for your link via [`uni_uslp_managed_params_t.fecf_capability`](include/uni_ccsds_uslp.h:436)
   - Call [`uni_ccsds_uslp_init()`](include/uni_ccsds_uslp.h:911) with your SCID.

2. **Configure the target Virtual Channel (VC)**.
   - Prepare VC-scoped parameters (typically derived from your physical defaults).
   - For sequence-controlled traffic (Bypass=0), configure a VCF counter length (example field): [`uni_uslp_managed_params_t.vcf_seq_count_len_octets`](include/uni_ccsds_uslp.h:380).
   - Call [`uni_ccsds_uslp_configure_vc()`](include/uni_ccsds_uslp.h:965) with the chosen VCID.

3. **Configure the target MAP** for “custom payload bytes”.
   - Choose a MAP ID and configure that (VC, MAP) as MAPA service: [`UNI_USLP_SERVICE_MAPA`](include/uni_ccsds_uslp.h:223).
   - Ensure your MAP allows the SDU sizes you intend to send via [`uni_uslp_managed_params_t.max_sdu_length`](include/uni_ccsds_uslp.h:405).
   - Call [`uni_ccsds_uslp_configure_map()`](include/uni_ccsds_uslp.h:981).

4. **(Optional) Register a sending-end notify callback** to observe queue/send outcomes.
   - MAPA notify API: [`uni_ccsds_uslp_register_mapa_notify_callback()`](include/uni_ccsds_uslp.h:1195).

5. **Queue the payload**.
   - Call [`uni_ccsds_uslp_send_mapa()`](include/uni_ccsds_uslp.h:1511) with your payload pointer/length.
   - Ensure it returns [`UNI_USLP_SUCCESS`](include/uni_ccsds_uslp.h:175) (or handle errors via [`uni_ccsds_uslp_status_string()`](include/uni_ccsds_uslp.h:1903)).

6. **Build one Transfer Frame** into a caller-provided buffer.
   - Call [`uni_ccsds_uslp_build_frame()`](include/uni_ccsds_uslp.h:1706).
   - On success ([`UNI_USLP_SUCCESS`](include/uni_ccsds_uslp.h:175)), send the produced `frame_buffer[0..frame_length)` bytes using your link/radio/transport.

---

## 2) Sequence to send and receive an unencrypted custom payload

This is a “loopback” style description: build on the TX side, then feed the same frame bytes into the RX side.

### TX side

Perform the steps from **“send an unencrypted custom payload”** above.

### RX side

1. **Initialize and configure an RX context** consistently with the sender.
   - Create an RX [`uni_uslp_context_t`](include/uni_ccsds_uslp.h:463).
   - Call [`uni_ccsds_uslp_init()`](include/uni_ccsds_uslp.h:911) using the same SCID (and compatible physical/MAP managed parameters).
   - Call [`uni_ccsds_uslp_configure_vc()`](include/uni_ccsds_uslp.h:965) for the VCID you expect.
   - Call [`uni_ccsds_uslp_configure_map()`](include/uni_ccsds_uslp.h:981) for the (VCID, MAP ID) you expect, using [`UNI_USLP_SERVICE_MAPA`](include/uni_ccsds_uslp.h:223).

2. **Register an SDU callback** for that (VCID, MAP ID).
   - Implement a [`uni_uslp_sdu_callback_t`](include/uni_ccsds_uslp.h:482).
   - Register it with [`uni_ccsds_uslp_register_sdu_callback()`](include/uni_ccsds_uslp.h:1057).

3. **Accept received frames**.
   - For each received frame buffer, call [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756).
   - If it returns [`UNI_USLP_SUCCESS`](include/uni_ccsds_uslp.h:175), your callback should be invoked with the delivered SDU.

4. **Interpret verification status for unencrypted frames**.
   - When SDLS is not in effect, the callback parameter [`uni_uslp_verification_status_t`](include/uni_ccsds_uslp.h:267) will be [`UNI_USLP_VERIF_NOT_APPLICABLE`](include/uni_ccsds_uslp.h:268).

---

## 3) Sequence to send an encrypted custom payload

Encrypted payloads use the USLP SDLS option on a VC.

1. **Initialize TX context and configure VC/MAP**.
   - Perform steps 1–3 from **“send an unencrypted custom payload”**.

2. **Register the built-in SDLS engine** (recommended).
   - Call [`uni_ccsds_uslp_register_builtin_sdls()`](include/uni_ccsds_uslp.h:2009) once per context.

3. **Configure SDLS on the target VC**.
   - Fill a [`uni_uslp_sdls_config_t`](include/uni_ccsds_uslp.h:429) and set at minimum:
     - Enable SDLS via [`uni_uslp_sdls_config_t.enabled`](include/uni_ccsds_uslp.h:430)
     - Select a suite (e.g. [`UNI_USLP_SDLS_SUITE_AES_CCM`](include/uni_ccsds_uslp.h:261)) via [`uni_uslp_sdls_config_t.suite`](include/uni_ccsds_uslp.h:438)
     - Provide key material via [`uni_uslp_sdls_config_t.key`](include/uni_ccsds_uslp.h:439) and [`uni_uslp_sdls_config_t.key_length`](include/uni_ccsds_uslp.h:440)
     - Configure Security Header/Trailer presence and lengths via:
       - [`uni_uslp_sdls_config_t.sec_header_present`](include/uni_ccsds_uslp.h:447), [`uni_uslp_sdls_config_t.sec_header_length`](include/uni_ccsds_uslp.h:449)
       - [`uni_uslp_sdls_config_t.sec_trailer_present`](include/uni_ccsds_uslp.h:448), [`uni_uslp_sdls_config_t.sec_trailer_length`](include/uni_ccsds_uslp.h:450)
     - (Recommended) Enable anti-replay via [`uni_uslp_sdls_config_t.anti_replay_enabled`](include/uni_ccsds_uslp.h:443) and configure [`uni_uslp_sdls_config_t.anti_replay_window`](include/uni_ccsds_uslp.h:444)
   - Apply it to the VC using [`uni_ccsds_uslp_configure_sdls()`](include/uni_ccsds_uslp.h:1013).

4. **Queue the payload and build a frame**.
   - Queue payload via [`uni_ccsds_uslp_send_mapa()`](include/uni_ccsds_uslp.h:1511).
   - Build via [`uni_ccsds_uslp_build_frame()`](include/uni_ccsds_uslp.h:1706).
   - On success ([`UNI_USLP_SUCCESS`](include/uni_ccsds_uslp.h:175)), transmit the resulting frame bytes.

---

## 4) Sequence to send and receive an encrypted custom payload

### TX side

Perform the steps from **“send an encrypted custom payload”** above.

### RX side

1. **Initialize and configure an RX context** consistently with the sender.
   - Call [`uni_ccsds_uslp_init()`](include/uni_ccsds_uslp.h:911), [`uni_ccsds_uslp_configure_vc()`](include/uni_ccsds_uslp.h:965), and [`uni_ccsds_uslp_configure_map()`](include/uni_ccsds_uslp.h:981) for the expected VC/MAP.

2. **Enable SDLS on the RX context**.
   - Call [`uni_ccsds_uslp_register_builtin_sdls()`](include/uni_ccsds_uslp.h:2009).
   - Call [`uni_ccsds_uslp_configure_sdls()`](include/uni_ccsds_uslp.h:1013) with the same [`uni_uslp_sdls_config_t`](include/uni_ccsds_uslp.h:429) parameters (suite/key/SPI and header/trailer sizes must match what the sender uses).

3. **Provide an RX work (scratch) buffer**.
   - SDLS RX processing requires a caller-supplied buffer for transformations.
   - Call [`uni_ccsds_uslp_set_work_buffer()`](include/uni_ccsds_uslp.h:947).

4. **Register an SDU callback** for that (VCID, MAP ID).
   - Implement a [`uni_uslp_sdu_callback_t`](include/uni_ccsds_uslp.h:482) and register it via [`uni_ccsds_uslp_register_sdu_callback()`](include/uni_ccsds_uslp.h:1057).

5. **Accept received frames**.
   - Call [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756).
   - On success ([`UNI_USLP_SUCCESS`](include/uni_ccsds_uslp.h:175)), the callback receives the decrypted SDU and a verification status.

6. **Handle authentication/decryption failures and anti-replay**.
   - If SDLS verification fails (tag mismatch, replay rejection, etc.), [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756) returns [`UNI_USLP_ERROR_SDLS_FAILURE`](include/uni_ccsds_uslp.h:184) and the SDU is typically not delivered to callbacks.
   - When SDLS is in effect and processing succeeds, the callback verification status [`uni_uslp_verification_status_t`](include/uni_ccsds_uslp.h:267) should be [`UNI_USLP_VERIF_SUCCESS`](include/uni_ccsds_uslp.h:269).

---

## Appendix: using a different service than MAPA

If “custom payload” in your project means a different USLP service, the sequence is the same except for the “queue SDU” step and (sometimes) the callback type:

- Packet SDU: [`uni_ccsds_uslp_send_packet_ex()`](include/uni_ccsds_uslp.h:1463)
- VCA SDU: [`uni_ccsds_uslp_send_vca_ex()`](include/uni_ccsds_uslp.h:1536)
- Octet Stream portion: [`uni_ccsds_uslp_send_octet_stream_ex()`](include/uni_ccsds_uslp.h:1563)

Frame building and reception still use [`uni_ccsds_uslp_build_frame()`](include/uni_ccsds_uslp.h:1706) and [`uni_ccsds_uslp_accept_frame()`](include/uni_ccsds_uslp.h:1756).
