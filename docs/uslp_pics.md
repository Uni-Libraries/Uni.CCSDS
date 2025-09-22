# Protocol Implementation Conformance Statement (PICS)
Unified Space Data Link Protocol — CCSDS 732.1-B-3 (June 2024)

## A2.1 General Information

### A2.1.1 Identification of PICS

| Field | Value |
|---|---|
| Date of Statement (DD/MM/YYYY) | 22/09/2025 |
| PICS Serial Number | N/A |
| System Conformance Statement cross-reference | N/A |

### A2.1.2 Identification of Implementation Under Test (IUT)

| Implementation name | uni.CCSDS |
| Implementation version | 0.1.0-dev |
| Special Configuration | N/A |
| Other Information | N/A |

### A2.1.3 Identification of Supplier

TODO

### A2.1.4 Identification of Specification


## A.2.2 Requirements List

| Column | Meaning |
|---|---|
| Status | M=Mandatory, O=Optional, C#=Conditional, O.n=At least one in group |
| Support | Y=Supported, N=Not supported, N/A=Not applicable |
| Code | Key implementation pointers (clickable) |

### Table A-1: USLP Service Data Units

| Item | Description | Ref | Status | Support | Notes / Code |
|---|---|---|---|---|---|
| USLP-1 | Packet SDU | §3.2.2 | M | Y | Send API [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:812); Build [uni_ccsds_uslp_build_frame()](src/uslp.c:1199); Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1692) (Rule ‘000’) |
| USLP-2 | MAPA SDU | §3.2.3 | M | Y | Send API [uni_ccsds_uslp_send_mapa()](src/uslp.c:985) |
| USLP-3 | VCA SDU | §3.2.4 | M | Y | Send API [uni_ccsds_uslp_send_vca_ex()](src/uslp.c:1023); Build [uni_ccsds_uslp_build_frame()](src/uslp.c:1199) (Rule ‘111’ minimal path); Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1913) |
| USLP-4 | Octet Stream SDU | §3.2.5 | M | Y | Send API [uni_ccsds_uslp_send_octet_stream_ex()](src/uslp.c:1074); Build [uni_ccsds_uslp_build_frame()](src/uslp.c:1199); Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1913) |
| USLP-5 | OCF_SDU | §3.2.6 | M | Y | Build [uni_ccsds_uslp_build_frame()](src/uslp.c:417); Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:759); Send [uni_ccsds_uslp_send_ocf()](src/uslp.c:421) |
| USLP-6 | USLP Transfer Frame | §3.2.7 | M | Y | PH pack [uni_ccsds_uslp_primary_header_pack()](src/uslp_primary_header.c:117); TFDF [uni_ccsds_uslp_tfdf_header_pack()](src/uslp_tfdf_header.c:96) |
| USLP-7 | Insert Data SDU | §3.2.8 | M | Y | Fixed-length Insert Zone only; API [uni_ccsds_uslp_send_insert()](src/uslp.c:661); Build [uni_ccsds_uslp_build_frame()](src/uslp.c:819); Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1249) |

### Table A-2a: MAP Packet Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-8 | Packet | §3.3.2.2 | M | Y | TFDF Rule ‘000’ with FHP; one complete Space Packet per frame. Build [uni_ccsds_uslp_build_frame()](src/uslp.c:588) |
| USLP-9 | GMAP ID | §3.3.2.3 | M | Y | PH MAP ID field; VCID in PH. PH pack [uni_ccsds_uslp_primary_header_pack()](src/uslp_primary_header.c:117) |
| USLP-10 | PVN | §3.3.2.4 | M | Y | API parameter in [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:407); not transmitted by USLP |
| USLP-11 | SDU ID | §3.3.2.5 | M | Y | API parameter in [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:812); accounting only (§2.2.2) |
| USLP-12 | QoS | §3.3.2.6 | M | Y | Expedited/Sequence via Bypass flag in build path [uni_ccsds_uslp_build_frame()](src/uslp.c:1332) set from [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:842) |
| USLP-13 | Notification Type | §3.3.2.7 | O | Y | MAPP_Notify.indication (sending end). Register [uni_ccsds_uslp_register_mapp_notify_callback()](include/uni_ccsds_uslp.h:328); QUEUED in [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:890); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:1461); test [src_tests/test_packet_service.cpp](src_tests/test_packet_service.cpp:103) |
| USLP-14 | Packet Quality Indicator | §3.3.2.8 | O | Y | Delivered via MAPP.indication (receiving end). Register [uni_ccsds_uslp_register_mapp_indication_callback()](include/uni_ccsds_uslp.h:345); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1379) with PQI=COMPLETE (no segmentation); test [src_tests/test_packet_service.cpp](src_tests/test_packet_service.cpp:257) |
| USLP-15 | Verification Status Code | §3.3.2.9 | C2 | Y | Delivered via Verification Status Code on indication; Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1208) |

### Table A-2b: VCP Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-16 | Packet | §3.4.2.2 | M | Y | Send API [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:902); Build [uni_ccsds_uslp_build_frame()](src/uslp.c:1199) Rule ‘000’; Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1692) |
| USLP-17 | GVCID | §3.4.2.3 | M | Y | PH SCID/VCID fields; pack [uni_ccsds_uslp_primary_header_pack()](src/uslp_primary_header.c:117) |
| USLP-18 | PVN | §3.4.2.4 | M | Y | API parameter in [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:540); not transmitted by USLP |
| USLP-19 | SDU ID | §3.4.2.5 | M | Y | API parameter in [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:540); accounting only (§2.2.2) |
| USLP-20 | Service Type | §3.4.2.6 | M | Y | Expedited/Sequence via PH Bypass flag (§4.1.2.8.1) set from [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:540) and applied in [uni_ccsds_uslp_build_frame()](src/uslp.c:845) |
| USLP-21 | Notification Type | §3.4.2.7 | O | Y | Register [uni_ccsds_uslp_register_vcp_notify_callback()](src/uslp.c:532); QUEUED in [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:967); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:1461) |
| USLP-22 | Packet Quality Indicator | §3.4.2.8 | O | Y | Delivered via VCP.indication: register [uni_ccsds_uslp_register_vcp_indication_callback()](src/uslp.c:447); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1410) with PQI=COMPLETE (no segmentation) |
| USLP-23 | Verification Status Code | §3.4.2.9 | C2 | Y | Delivered via VCP.indication when SDLS option enabled; Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1414) |

### Table A-2c: MAPA Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-24 | MAPA_SDU | §3.5.2.2 | M | Y | Rule ‘111’ only |
| USLP-25 | GMAP ID | §3.5.2.3 | M | Y | PH MAP ID field |
| USLP-26 | SDU ID | §3.5.2.4 | M | Y | API only |
| USLP-27 | QoS | §3.5.2.5 | M | N | No COP/QoS; builder enforces PH.Bypass=0 for MAPA; test [src_tests/test_vcf_exp_counters.cpp](src_tests/test_vcf_exp_counters.cpp:229) |
| USLP-28 | MAPA_SDU Loss Flag | §3.5.2.7 | O | Y | Derived from VCF Count continuity in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1094) (Seq QoS; §3.5.2.7 via §4.3.7.4) |
| USLP-29 | Verification Status Code | §3.5.2.8 | C2 | Y | Delivered via Verification Status Code on indication; Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1094) |

### Table A-2d: VCA Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-30 | VCA_SDU | §3.6.3.2 | M | Y | Variable-length, Rule ‘111’ (No Segmentation) minimal path |
| USLP-31 | GVCID | §3.6.3.3 | M | Y | PH VCID and MAP ID fields |
| USLP-32 | SDU ID | §3.6.3.4 | M | Y | API parameter in [uni_ccsds_uslp_send_vca_ex()](src/uslp.c:1020); accounting only (§2.2.2) |
| USLP-33 | Service Type | §3.6.3.5 | M | Y | expedited parameter maps to PH Bypass flag (§4.1.2.8.1) |
| USLP-34 | Notification Type | §3.6.3.6 | O | Y | Register [uni_ccsds_uslp_register_vca_notify_callback()](src/uslp.c:463); QUEUED in [uni_ccsds_uslp_send_vca_ex()](src/uslp.c:1058); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:1493) |
| USLP-35 | Verification Status Code | §3.6.3.7 | C2 | Y | Delivered via Verification Status Code on indication; Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:2034) |

### Table A-2e: MAP Octet Stream Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-36 | Octet Stream Data | §3.7.2.2 | M | Y | TFDZ Rule ‘011’ build/accept; Build [uni_ccsds_uslp_build_frame()](src/uslp.c:417); Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:759) |
| USLP-37 | GMAP ID | §3.7.2.3 | M | Y | PH MAP ID field |
| USLP-38 | SDU ID | §3.7.2.4 | M | Y | API parameter in [uni_ccsds_uslp_send_octet_stream_ex()](src/uslp.c:374) (sending-end accounting per §2.2.2) |
| USLP-39 | QoS | §3.7.2.5 | M | Y | Expedited/Sequence via Bypass flag in build path [uni_ccsds_uslp_build_frame()](src/uslp.c:417) set from [uni_ccsds_uslp_send_octet_stream_ex()](src/uslp.c:374) |
| USLP-40 | Octet Stream Data Loss Flag | §3.7.2.6 | O | Y | Derived from VCF Count continuity in [uni_ccsds_uslp_accept_frame()](src/uslp.c:882) |
| USLP-41 | Verification Status Code | §3.7.2.7 | C2 | Y | Delivered via Verification Status Code on indication; Accept [uni_ccsds_uslp_accept_frame()](src/uslp.c:1077) |

### Table A-2f: USLP_MC_OCF Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-42 | OCF_SDU | §3.8.2.2 | M | Y | Raw 32-bit |
| USLP-43 | GVCID | §3.8.2.3 | M | Y | PH VCID |
| USLP-44 | OCF_SDU Loss Flag | §3.8.2.4 | O | Y | Derived from C&S loss signal (§3.8.2.4.2) set by [uni_ccsds_uslp_set_rx_cs_loss_signaled()](include/uni_ccsds_uslp.h:1004); delivered via OCF.indication v2: register [uni_ccsds_uslp_register_ocf2_callback()](src/uslp.c:372); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:2056) |

### Table A-2g: VCF Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-45 | USLP Frame | §3.9.2.2 | M | Y | Delivered via VCF.indication; register [uni_ccsds_uslp_register_vcf_indication_callback()](include/uni_ccsds_uslp.h:438); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1609) and truncated path [uni_ccsds_uslp_accept_frame()](src/uslp.c:1434) |
| USLP-46 | GVCID | §3.9.2.3 | M | Y | SCID/VCID from PH (§4.1.2.2.3/§4.1.2.4.1); passed to VCF.indication in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1609) and [uni_ccsds_uslp_accept_frame()](src/uslp.c:1434) |
| USLP-47 | Frame Loss Flag | §3.9.2.4 | O | Y | Derived from VCF Count continuity (§3.9.2.4.2; §4.3.7.4); computed in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1579) and provided to VCF.indication at [uni_ccsds_uslp_accept_frame()](src/uslp.c:1609) |

### Table A-2h: MCF Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-48 | USLP Frame | §3.10.2.2 | M | Y | Delivered via MCF.indication; register [uni_ccsds_uslp_register_mcf_indication_callback()](include/uni_ccsds_uslp.h:460); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1613) and truncated path [uni_ccsds_uslp_accept_frame()](src/uslp.c:1438) |
| USLP-49 | MCID | §3.10.2.3 | M | Y | MCID=(TFVN<<16)|SCID per §2.1.3; computed/passed in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1612) and [uni_ccsds_uslp_accept_frame()](src/uslp.c:1438) |
| USLP-50 | Frame Loss Flag | §3.10.2.4 | O | Y | Derived from underlying C&S loss signal (§3.10.2.4.2; §4.3.10.3); set via [uni_ccsds_uslp_set_rx_cs_loss_signaled()](include/uni_ccsds_uslp.h:814), consumed in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1612) and [uni_ccsds_uslp_accept_frame()](src/uslp.c:1438) |

### Table A-2i: Insert Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-51 | IN_SDU | §3.11.2.2 | M | Y | Insert Zone only; provided via [uni_ccsds_uslp_send_insert()](src/uslp.c:661) |
| USLP-52 | Physical Channel Name | §3.11.2.3 | M | Y | Managed parameter field [uni_uslp_managed_params_t](include/uni_ccsds_uslp_structs.h:76) |
| USLP-53 | IN_SDU Loss Flag | §3.11.2.4 | O | Y | Derived from C&S loss signal (§3.11.2.4.2); provided via INSERT.indication v2 [uni_ccsds_uslp_register_insert2_callback()](include/uni_ccsds_uslp.h:221); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1518); source set by [uni_ccsds_uslp_set_rx_cs_loss_signaled()](include/uni_ccsds_uslp.h:814) |

### Table A-2j: COPs Management Service Parameters

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-54 | GVCID (COP-1) | §3.12.2.2.1 | O.1 | Y | Supported via Directive.request is_cop1=true; VCID parameter validated. API [uni_ccsds_uslp_directive_request()](src/uslp.c:662) |
| USLP-55 | Port ID (COP-P) | §3.12.2.2.2 | O.1 | Y | Supported via Directive.request is_cop1=false; Port ID parameter forwarded. API [uni_ccsds_uslp_directive_request()](src/uslp.c:662) |
| USLP-56 | Directive ID | §3.12.2.3 | M | Y | Parameter in [uni_ccsds_uslp_directive_request()](src/uslp.c:662); delivered via Directive_Notify |
| USLP-57 | Directive Type | §3.12.2.4 | M | Y | Parameter in [uni_ccsds_uslp_directive_request()](src/uslp.c:662); delivered via Directive_Notify |
| USLP-58 | Directive Qualifier | §3.12.2.5 | M | Y | Parameter in [uni_ccsds_uslp_directive_request()](src/uslp.c:662); delivered via Directive_Notify |
| USLP-59 | Notification Type | §3.12.2.6 | M | Y | Delivered via Directive_Notify.indication; register [uni_ccsds_uslp_register_directive_notify_callback()](include/uni_ccsds_uslp.h:521); emitted in [uni_ccsds_uslp_directive_request()](src/uslp.c:690) |
| USLP-60 | Notification Qualifier | §3.12.2.7 | M | Y | Delivered via Directive_Notify.indication; register [uni_ccsds_uslp_register_directive_notify_callback()](include/uni_ccsds_uslp.h:521); emitted in [uni_ccsds_uslp_directive_request()](src/uslp.c:690) |

### Table A-3: Service Primitives

| Item | Primitive | Ref | Status | Support | Notes / Code |
|---|---|---|---|---|---|
| USLP-61 | MAPP.request | §3.3.3.2 | M | Y | API [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:812) |
| USLP-62 | MAPP_Notify.indication | §3.3.3.3 | M | Y | Register [uni_ccsds_uslp_register_mapp_notify_callback()](src/uslp.c:482); QUEUED in [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:880); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:1461) |
| USLP-63 | MAPP.indication | §3.3.3.4 | M | Y | Delivered in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1913) (Rule ‘000’) |
| USLP-64 | VCP.request | §3.4.3.2 | M | Y | API [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:902) |
| USLP-65 | VCP_Notify.indication | §3.4.3.3 | M | Y | Register [uni_ccsds_uslp_register_vcp_notify_callback()](src/uslp.c:532); QUEUED in [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:967); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:1461) |
| USLP-66 | VCP.indication | §3.4.3.4 | M | Y | Register [uni_ccsds_uslp_register_vcp_indication_callback()](src/uslp.c:447); delivered in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1404) (Rule ‘000’) |
| USLP-67 | MAPA.request | §3.5.3.2 | M | Y | API [uni_ccsds_uslp_send_mapa()](src/uslp.c:292) |
| USLP-68 | MAPA_Notify.indication | §3.5.3.3 | M | Y | Register [uni_ccsds_uslp_register_mapa_notify_callback()](src/uslp.c:356); QUEUED/REJECTED_INVALID in [uni_ccsds_uslp_send_mapa()](src/uslp.c:384); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:503) |
| USLP-69 | MAPA.indication | §3.5.3.4 | M | Y | Delivered in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1913) (Rule ‘111’) |
| USLP-70 | VCA.request | §3.6.4.2 | M | Y | API [uni_ccsds_uslp_send_vca_ex()](src/uslp.c:1023) |
| USLP-71 | VCA_Notify.indication | §3.6.4.3 | M | Y | Register [uni_ccsds_uslp_register_vca_notify_callback()](src/uslp.c:498); QUEUED in [uni_ccsds_uslp_send_vca_ex()](src/uslp.c:1055); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:1461) |
| USLP-72 | VCA.indication | §3.6.4.4 | M | Y | Delivered in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1913) (Rule ‘111’) |
| USLP-73 | OCTET_STREAM.request | §3.7.3.2 | M | Y | [uni_ccsds_uslp_send_octet_stream_ex()](src/uslp.c:1074) |
| USLP-74 | OCTET_STREAM.indication | §3.7.3.3 | M | Y | Delivered in [uni_ccsds_uslp_accept_frame()](src/uslp.c:910) (Rule ‘011’) |
| USLP-75 | OCTET_STREAM_Notify.indication | §3.7.3.4 | M | Y | Register [uni_ccsds_uslp_register_octet_stream_notify_callback()](src/uslp.c:340); QUEUED/REJECTED in [uni_ccsds_uslp_send_octet_stream_ex()](src/uslp.c:420); SENT in [uni_ccsds_uslp_build_frame()](src/uslp.c:710) |
| USLP-76 | USLP_MC_OCF.request | §3.8.3.2 | M | Y | [uni_ccsds_uslp_send_ocf()](src/uslp.c:327) |
| USLP-77 | USLP_MC_OCF.indication | §3.8.3.3 | M | Y | [uni_ccsds_uslp_accept_frame()](src/uslp.c:661) |
| USLP-78 | VCF.request | §3.9.3.2 | M | Y | API [uni_ccsds_uslp_vcf_request()](src/uslp.c:584); provider register [uni_ccsds_uslp_register_vcf_tx_callback()](include/uni_ccsds_uslp.h:484); tests [src_tests/test_vcf_mcf_request.cpp](src_tests/test_vcf_mcf_request.cpp) |
| USLP-79 | VCF.indication | §3.9.3.3 | M | Y | Register [uni_ccsds_uslp_register_vcf_indication_callback()](include/uni_ccsds_uslp.h:438); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1609) and truncated [uni_ccsds_uslp_accept_frame()](src/uslp.c:1434) |
| USLP-80 | MCF.request | §3.10.3.2 | M | Y | API [uni_ccsds_uslp_mcf_request()](src/uslp.c:624); provider register [uni_ccsds_uslp_register_mcf_tx_callback()](include/uni_ccsds_uslp.h:503); tests [src_tests/test_vcf_mcf_request.cpp](src_tests/test_vcf_mcf_request.cpp) |
| USLP-81 | MCF.indication | §3.10.3.3 | M | Y | Register [uni_ccsds_uslp_register_mcf_indication_callback()](include/uni_ccsds_uslp.h:460); invoked in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1613) and truncated [uni_ccsds_uslp_accept_frame()](src/uslp.c:1438); loss flag source [uni_ccsds_uslp_set_rx_cs_loss_signaled()](include/uni_ccsds_uslp.h:814) |
| USLP-82 | INSERT.request | §3.11.3.2 | M | Y | API [uni_ccsds_uslp_send_insert()](src/uslp.c:661) |
| USLP-83 | INSERT.indication | §3.11.3.3 | M | Y | Delivered via Insert callback [uni_ccsds_uslp_register_insert_callback()](src/uslp.c:323); extraction in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1249) |
| USLP-84 | Directive.request | §3.12.3.2 | M | Y | API [uni_ccsds_uslp_directive_request()](src/uslp.c:662); coexistence enforcement per §2.2.5 b,d; tests [src_tests/test_directive_management.cpp](src_tests/test_directive_management.cpp) |
| USLP-85 | Directive_Notify.indication | §3.12.3.3 | M | Y | Register [uni_ccsds_uslp_register_directive_notify_callback()](include/uni_ccsds_uslp.h:521); invoked in [uni_ccsds_uslp_directive_request()](src/uslp.c:690) |
| USLP-86 | Async_Notify.indication | §3.12.3.4 | M | Y | Register [uni_ccsds_uslp_register_async_notify_callback()](include/uni_ccsds_uslp.h:537); provider emit [uni_ccsds_uslp_async_notify()](src/uslp.c:704); tests [src_tests/test_directive_management.cpp](src_tests/test_directive_management.cpp) |

### Table A-4: USLP Protocol Data Unit

| Item | Component | Ref | Status | Support | Notes / Code |
|---|---|---|---|---|---|
| USLP-87 | USLP Transfer Frame | §4.1.1 | M | Y | — |
| USLP-88 | Transfer Frame Primary Header | §4.1.2 | M | Y | Pack [uni_ccsds_uslp_primary_header_pack()](src/uslp_primary_header.c:117); Unpack [uni_ccsds_uslp_primary_header_unpack()](src/uslp_primary_header.c:209) |
| USLP-89 | Transfer Frame Insert Zone | §4.1.3 | M | Y | Build/Accept: [uni_ccsds_uslp_build_frame()](src/uslp.c:819), [uni_ccsds_uslp_accept_frame()](src/uslp.c:1249) |
| USLP-90 | Transfer Frame Data Field | §4.1.4 | M | Y | TFDF: [uni_ccsds_uslp_tfdf_header_pack()](src/uslp_tfdf_header.c:96) |
| USLP-91 | Operational Control Field | §4.1.5 | M | Y | Include/extract in build/accept |
| USLP-92 | Frame Error Control Field | §4.1.6 | M | Y | CRC append [uni_crypto_crc16_ccitt_append()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:85); verify [uni_crypto_crc16_ccitt_verify()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:76) |

### Table A-5: Protocol Procedures

| Item | Procedure | Ref | Status | Support | Notes / Code |
|---|---|---|---|---|---|
| USLP-93 | MAPP Processing Function | §4.2.2 | M | Y | Build path [uni_ccsds_uslp_build_frame()](src/uslp.c:1314) selects Rule ‘000’ for Packet; request API [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:823); tests [src_tests/test_packet_service.cpp](src_tests/test_packet_service.cpp:78) |
| USLP-94 | MAPA_SDU Generation Function | §4.2.3 | M | Y | Build path [uni_ccsds_uslp_build_frame()](src/uslp.c:350) (Rule ‘111’) |
| USLP-95 | MAP Octet Stream Processing | §4.2.4 | M | Y | Build path (Rule ‘011’) [uni_ccsds_uslp_build_frame()](src/uslp.c:417) |
| USLP-96 | MAP Multiplexing Function | §4.2.5 | M | Y | TX selection [uni_ccsds_uslp_select_next_map()](src/uslp.c:2263); scheduler [select_next_map_impl()](src/uslp.c:2139); tests [src_tests/test_multiplexing.cpp](src_tests/test_multiplexing.cpp) |
| USLP-97 | VC Packet Processing | §4.2.6 | M | Y | Request [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:921); Build Rule ‘000’ [uni_ccsds_uslp_build_frame()](src/uslp.c:1314); Accept triggers VCP.indication [uni_ccsds_uslp_accept_frame()](src/uslp.c:2028); tests [src_tests/test_vcp_service.cpp](src_tests/test_vcp_service.cpp:95) |
| USLP-98 | Virtual Channel Generation Function | §4.2.7 | M | Y | Primary Header/VCF/OCF composition [uni_ccsds_uslp_build_frame()](src/uslp.c:1341); VCF counter update [uni_ccsds_uslp_build_frame()](src/uslp.c:1479); OCF gate (policy) [uni_ccsds_uslp_build_frame()](src/uslp.c:1278); No COP semantics (VCF per USLP-130/USLP-131 only) |
| USLP-99 | Virtual Channel Multiplexing | §4.2.8 | M | Y | TX selection [uni_ccsds_uslp_select_next_vc()](src/uslp.c:2204); managed scheme [uni_uslp_vc_mux_scheme_t](include/uni_ccsds_uslp_enums.h:143); tests [src_tests/test_multiplexing.cpp](src_tests/test_multiplexing.cpp) |
| USLP-100 | Master Channel Generation | §4.2.9 | M | Y | Single MC: generation realized by [uni_ccsds_uslp_build_next_frame()](src/uslp.c:2278) with PH SCID assignment in [uni_ccsds_uslp_build_frame()](src/uslp.c:1345); tests [src_tests/test_master_channel_generation.cpp](src_tests/test_master_channel_generation.cpp) |
| USLP-101 | Master Channel Multiplexing | §4.2.10 | M | Y | Single MC (SINGLE); chain [uni_ccsds_uslp_build_next_frame()](src/uslp.c:2278) composes MC→VC→MAP; managed [uni_uslp_mc_mux_scheme_t](include/uni_ccsds_uslp_enums.h:129) |
| USLP-102 | All Frames Generation | §4.2.11 | M | Y | Insert, FECF: [uni_ccsds_uslp_build_frame()](src/uslp.c:350) |
| USLP-103 | MAPP Extraction Function | §4.3.2 | M | Y | Accept Rule ‘000’: pre/post-FHP delivery via MAPP.indication [uni_ccsds_uslp_accept_frame()](src/uslp.c:1998) and [uni_ccsds_uslp_accept_frame()](src/uslp.c:2038); tests [src_tests/test_packet_service.cpp](src_tests/test_packet_service.cpp:386) |
| USLP-104 | MAPA_SDU Extraction Function | §4.3.3 | M | Y | Rule ‘111’ minimal path extraction [uni_ccsds_uslp_accept_frame()](src/uslp.c:2066); tests [src_tests/test_multiplexing.cpp](src_tests/test_multiplexing.cpp:210) and [src_tests/test_mapa_loss_flag.cpp](src_tests/test_mapa_loss_flag.cpp:1) |
| USLP-105 | MAP Octet Stream Extraction | §4.3.4 | M | Y | Accept path (Rule ‘011’) [uni_ccsds_uslp_accept_frame()](src/uslp.c:910) |
| USLP-106 | MAP Demultiplexing | §4.3.5 | M | Y | RX demux by PH MAP ID and TFDF rule in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1725); see case handling for Rules '011','000','111' |
| USLP-107 | VC Packet Extraction | §4.3.6 | M | Y | VCP.indication on Rule ‘000’ [uni_ccsds_uslp_accept_frame()](src/uslp.c:2028); tests [src_tests/test_vcp_service.cpp](src_tests/test_vcp_service.cpp:157) |
| USLP-108 | Virtual Channel Reception | §4.3.7 | M | Y | Decommutation: [uni_ccsds_uslp_accept_frame()](src/uslp.c:661) |
| USLP-109 | VC Demultiplexing | §4.3.8 | M | Y | RX demux by PH SCID/VCID; VCF.indication line in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1938) |
| USLP-110 | Master Channel Reception | §4.3.9 | M | Y | OCF extract in accept |
| USLP-111 | Master Channel Demultiplexing | §4.3.10 | M | Y | RX demux to MCF by MCID derived from SCID at [uni_ccsds_uslp_accept_frame()](src/uslp.c:1941) |
| USLP-112 | All Frames Reception | §4.3.11 | M | Y | FECF verify; truncated support |

### Table A-6a: Managed Parameters — Physical Channel (Table 5-1)

| Item | Parameter | Status | Support | Notes |
|---|---|---|---|---|
| USLP-113 | Physical Channel Name | M | Y | String field in config |
| USLP-114 | Transfer Frame Type (Physical) | M | Y | Fixed/Variable enum |
| USLP-115 | Transfer Frame Length | M | Y | Used for fixed-length |
| USLP-116 | TFVN (‘1100’) | M | Y | Enforced in validate [uni_ccsds_uslp_validate_primary_header()](src/uslp_primary_header.c:68) |
| USLP-117 | MC Multiplexing Scheme | M | Y | Managed param [uni_uslp_managed_params_t.mc_mux_scheme](include/uni_ccsds_uslp_structs.h:86); enum [uni_uslp_mc_mux_scheme_t](include/uni_ccsds_uslp_enums.h:129); used in [uni_ccsds_uslp_build_next_frame()](src/uslp.c:2278) (SINGLE in this IUT) |
| USLP-118 | Presence of Insert Zone | M | Y | Fixed-length only |
| USLP-119 | Insert Zone Length | M | Y | — |
| USLP-120 | Presence of FECF | M | Y | Optional |
| USLP-122 | Max Frames per C&S DU | M | Y | Recorded-only; no C&S interface; managed field [uni_uslp_managed_params_t](include/uni_ccsds_uslp_structs.h:82) |
| USLP-123 | Max ‘Repetitions’ to C&S | M | Y | Recorded-only; no C&S interface; managed field [uni_uslp_managed_params_t](include/uni_ccsds_uslp_structs.h:83) |

### Table A-6b: Managed Parameters — Master Channel (Table 5-2)

| Item | Parameter | Status | Support | Notes |
|---|---|---|---|---|
| USLP-124 | MC Transfer Frame Type | M | Y | Inferred from Physical |
| USLP-125 | SCID | M | Y | 16-bit PH field |
| USLP-126 | VCIDs | M | Y | Field only; no mux |
| USLP-127 | VC Multiplexing Scheme | M | Y | Managed param [uni_uslp_managed_params_t.vc_mux_scheme](include/uni_ccsds_uslp_structs.h:88); enum [uni_uslp_vc_mux_scheme_t](include/uni_ccsds_uslp_enums.h:143); used by [uni_ccsds_uslp_select_next_vc()](src/uslp.c:2204) |

### Table A-6c: Managed Parameters — Virtual Channel (Table 5-3)

| Item | Parameter | Status | Support | Notes |
|---|---|---|---|---|
| USLP-128 | VC Transfer Frame Type | M | Y | — |
| USLP-129 | VCID | M | Y | — |
| USLP-130 | VCF Count Length (Seq) | M | Y | TX encode (1..7 octets) and RX continuity; [vc_vcf_count_len_code()](src/uslp.c:37), [uni_ccsds_uslp_build_frame()](src/uslp.c:350), [uni_ccsds_uslp_accept_frame()](src/uslp.c:661); tests: [test_vcf_counters.cpp](src_tests/test_vcf_counters.cpp) |
| USLP-131 | VCF Count Length (Exp) | M | Partial | RX continuity if present; TX omits expedited VCF Count (PH.vcf_count_len=0) when Bypass=1; code [uni_ccsds_uslp_build_frame()](src/uslp.c:1268); tests [src_tests/test_vcf_exp_counters.cpp](src_tests/test_vcf_exp_counters.cpp:133), [src_tests/test_octet_stream.cpp](src_tests/test_octet_stream.cpp:125) |
| USLP-132 | COP in Effect | M | Y | VC managed parameter [uni_uslp_managed_params_t.cop_in_effect](include/uni_ccsds_uslp_structs.h:91); enum [uni_uslp_cop_in_effect_t](include/uni_ccsds_uslp_enums.h:61); defaults NONE; no COP semantics implemented |
| USLP-133 | CLCW Version | M | Y | VC managed parameter [uni_uslp_managed_params_t.clcw_version](include/uni_ccsds_uslp_structs.h:92); recorded value; Type-1 OCF provider/mission specific |
| USLP-134 | CLCW Reporting Rate | M | Y | VC managed parameter [uni_uslp_managed_params_t.clcw_reporting_rate](include/uni_ccsds_uslp_structs.h:93); recorded value; units mission-defined |
| USLP-135 | MAP IDs | M | Y | — |
| USLP-136 | MAP Multiplexing Scheme | O | Y | VC managed parameter [uni_uslp_managed_params_t.map_mux_scheme](include/uni_ccsds_uslp_structs.h:101); enum [uni_uslp_map_mux_scheme_t](include/uni_ccsds_uslp_enums.h:85); used by [uni_ccsds_uslp_select_next_map()](src/uslp.c:2263) |
| USLP-137 | Truncated Frame Length | M | Y | [uni_ccsds_uslp_build_truncated()](src/uslp.c:674) |
| USLP-138 | SDU Type | M | Partial | MAPA and Octet Stream on MAP channels; tests [src_tests/test_octet_stream.cpp](src_tests/test_octet_stream.cpp:125) |
| USLP-139 | Inclusion of OCF Allowed (var) | M | Y | VC managed parameter [uni_uslp_managed_params_t.ocf_allowed_variable](include/uni_ccsds_uslp_structs.h:95); enforced in [uni_ccsds_uslp_build_frame()](src/uslp.c:1185) (variable-length gate) |
| USLP-140 | Inclusion of OCF Required (fix) | M | Y | VC managed parameter [uni_uslp_managed_params_t.ocf_required_fixed](include/uni_ccsds_uslp_structs.h:96); enforced in [uni_ccsds_uslp_build_frame()](src/uslp.c:1190) (fixed-length requirement) |
| USLP-141 | Repetitions (Seq) | M | Y | VC managed parameter [uni_uslp_managed_params_t.repetitions_seq](include/uni_ccsds_uslp_structs.h:97); record-only; getter [uni_ccsds_uslp_get_repetition_counts()](src/uslp.c:1078) |
| USLP-142 | Repetitions (COP ctrl) | M | Y | VC managed parameter [uni_uslp_managed_params_t.repetitions_cop_ctrl](include/uni_ccsds_uslp_structs.h:98); record-only; getter [uni_ccsds_uslp_get_repetition_counts()](src/uslp.c:1078) |
| USLP-143 | Max TFDF completion delay | M | Y | VC managed parameter [uni_uslp_managed_params_t.max_tfdf_completion_delay](include/uni_ccsds_uslp_structs.h:99); record-only (timing not enforced) |
| USLP-144 | Max delay between frames | M | Y | VC managed parameter [uni_uslp_managed_params_t.max_inter_frame_delay](include/uni_ccsds_uslp_structs.h:100); record-only (timing not enforced) |

### Table A-6d: Managed Parameters — MAP Channel (Table 5-4)

| Item | Parameter | Status | Support | Notes |
|---|---|---|---|---|
| USLP-145 | MAP ID | M | Y | — |
| USLP-146 | SDU Type | M | Y | MAPA_SDU and Octet Stream Data |
| USLP-147 | UPID supported | M | Y | TFDF UPID field |

### Table A-6e: Managed Parameters — Packet Transfer (Table 5-5)

| Item | Parameter | Status | Support | Notes |
|---|---|---|---|---|
| USLP-148 | Valid PVNs | M | Y | Enforced in [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:479) and [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:577); managed via [uni_uslp_managed_params_t](include/uni_ccsds_uslp_structs.h:102) valid_pvns_mask (0 => allow PVN 0 only; VC-level fallback if MAP mask is 0). |
| USLP-149 | Maximum Packet Length | M | Y | Enforced in [uni_ccsds_uslp_send_packet_ex()](src/uslp.c:479) and [uni_ccsds_uslp_send_vcp_ex()](src/uslp.c:577); managed via [uni_uslp_managed_params_t](include/uni_ccsds_uslp_structs.h:104) max_packet_length (0 => unlimited). |
| USLP-150 | Deliver incomplete packets | M | Y | Receiving-end FHP handling in [uni_ccsds_uslp_accept_frame()](src/uslp.c:1337) (Rule ‘000’). When [uni_uslp_managed_params_t](include/uni_ccsds_uslp_structs.h:105) deliver_incomplete_packets=true, pre-FHP bytes are delivered with PQI=PARTIAL and remainder with PQI=COMPLETE; see code [src/uslp.c](src/uslp.c:1551) and tests [src_tests/test_packet_service.cpp](src_tests/test_packet_service.cpp). |

### Table A-7: Protocol Specification with SDLS Option

| Item | Component | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-151 | SDLS Protocol | §6 | O | Y | Option implemented: suites NULL, HMAC-SHA256 (auth-only), AES-GCM/AES-CCM (AEAD). Register built-in engine [uni_ccsds_uslp_register_builtin_sdls()](src/uslp_sdls.c:122). Configuration per-VC [uni_ccsds_uslp_configure_sdls()](src/uslp.c:271). Exercised by [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:66) and [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:65). |
| USLP-152 | Security Header | §6.3.4 | C3 | Y | Header inserted before TFDF: SPI(1) + Sequence Number(8) = 9 octets by default (HMAC/AEAD). Build path: [uni_ccsds_uslp_build_frame()](src/uslp.c:475) calls SDLS Apply; engine [uni_ccsds_uslp_sdls_builtin_apply()](src/uslp_sdls.c:168). Verified in [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:88) and [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:108). |
| USLP-153 | Security Trailer | §6.3.6 | C4 | Y | Trailer after TFDF: ICV/tag length configurable (default 16). AEAD tag or HMAC ICV. Build path and engine as above: [uni_ccsds_uslp_build_frame()](src/uslp.c:475), [uni_ccsds_uslp_sdls_builtin_apply()](src/uslp_sdls.c:168). Covered by [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:88) and [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:108). |
| USLP-154 | TFDF (with SDLS) | §6.3.5 | C3 | Y | Integrity/confidentiality scope: TFDF Header + TFDZ only; Insert/OCF/FECF excluded. ApplySecurity input: TFDF; output encapsulates SecHeader/Trailer. See [uni_ccsds_uslp_build_frame()](src/uslp.c:475), [uni_ccsds_uslp_sdls_builtin_apply()](src/uslp_sdls.c:168). AEAD/HMAC end-to-end verified by [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:136) and [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:118). |
| USLP-155 | OCF (with SDLS) | §6.3.7 | C3 | Y | OCF remains unprotected and placed after Security Trailer and before FECF. See [uni_ccsds_uslp_build_frame()](src/uslp.c:605) and RX extraction [uni_ccsds_uslp_accept_frame()](src/uslp.c:1021). Non-interference confirmed in SDLS tests [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:118) / [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:146). |
| USLP-156 | FECF (with SDLS) | §6.3.8 | C3 | Y | FECF computed over frame fields excluding FECF, thus covering SDLS header/trailer per §6.3.8. Append [uni_crypto_crc16_ccitt_append()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:85). Mixed SDLS+FECF behaviour covered in [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:142) (no FECF to isolate SDLS) and CRC validation [test_crc16_lfsr.cpp](src_tests/test_crc16_lfsr.cpp:41). |
| USLP-157–165 | Sending-end procedures with SDLS | §6.4 | C3 | Y | Frame initialization → SDLS ApplySecurity → optional OCF → FECF. Implementation: [uni_ccsds_uslp_build_frame()](src/uslp.c:475) invoking [sdls_apply_callback](src/uslp.c:620) with built-in [uni_ccsds_uslp_sdls_builtin_apply()](src/uslp_sdls.c:168). Exercised by [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:118) and [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:142), including replay/tamper coverage. |
| USLP-166–175 | Receiving-end procedures with SDLS | §6.5 | C3 | Y | After FECF verification, SDLS ProcessSecurity, then TFDF unpack and delivery. Anti-replay sliding window (default 64). Implementation: [uni_ccsds_uslp_accept_frame()](src/uslp.c:835) invoking [sdls_process_callback](src/uslp.c:1002) with [uni_ccsds_uslp_sdls_builtin_process()](src/uslp_sdls.c:262). Replay/tamper/verification assertions in [test_sdls_hmac.cpp](src_tests/test_sdls_hmac.cpp:121) and [test_sdls_aead.cpp](src_tests/test_sdls_aead.cpp:147). |

### Table A-8: Additional Managed Parameters with SDLS Option

| Item | Parameter | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-176 | Presence of SDLS Header | §6.6.2 | C5 | Y | Managed per VC via [uni_ccsds_uslp_configure_sdls()](src/uslp.c:271): sec_header_present=true (default with SDLS enabled). |
| USLP-177 | Presence of SDLS Trailer | §6.6.2 | C5 | Y | Managed per VC via [uni_ccsds_uslp_configure_sdls()](src/uslp.c:271): sec_trailer_present=true (default with SDLS enabled). |
| USLP-178 | SDLS Header Length (octets) | §6.6.2 | C5 | Y | Default 9 (SPI(1)+SN(8)) for HMAC/AES-GCM/AES-CCM; configurable: [uni_uslp_sdls_config_t](include/uni_ccsds_uslp_structs.h:114). |
| USLP-179 | SDLS Trailer Length (octets) | §6.6.2 | C5 | Y | Default 16 (ICV/tag); configurable per suite: [uni_uslp_sdls_config_t](include/uni_ccsds_uslp_structs.h:114). |

### Table A-9: Frame Error Control Field Coding Procedures

| Item | Procedure | Ref | Status | Support | Notes / Code |
|---|---|---|---|---|---|
| USLP-180 | CRC-16 FECF Encoding | Annex B1.1 | M | Y | [uni_crypto_crc16_ccitt_append()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:85) |
| USLP-181 | CRC-16 FECF Decoding | Annex B1.2 | M | Y | [uni_crypto_crc16_ccitt_verify()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:76) |

### Table A-10: Relationship of Version-3 and Version-4 Transfer Frames

| Item | Component | Ref | Status | Support | Notes |
|---|---|---|---|---|---|
| USLP-182 | V3–V4 equivalencies (gateway) | Annex C | C6 | N/A | Not a gateway |

Conditional Notes

- C2: O if SDLS Option else N/A.
- C3: M if SDLS Option else N/A.
- C4: O if SDLS Option else N/A.
- C5: M if SDLS Option else N/A.
- C6: M if gateway else N/A.

Conformance Statement

This IUT implements core frame structures (non-truncated/truncated), TFDF header, FECF, OCF, MAPA and Octet Stream minimal paths, and SDLS option per §6 with the following suites: NULL, HMAC-SHA256 (authentication-only), AES-GCM and AES-CCM (AEAD). SDLS coverage: USLP-151..USLP-179 supported with defaults: Security Header 9 octets (SPI+SN), Trailer 16 octets (ICV/tag), anti-replay sliding window (64), AAD scope TFDF only, AEAD IV derived from SN (12 bytes). See [uni_ccsds_uslp_build_frame()](src/uslp.c:475), [uni_ccsds_uslp_accept_frame()](src/uslp.c:835), [uni_ccsds_uslp_register_builtin_sdls()](src/uslp_sdls.c:122), [uni_ccsds_uslp_sdls_builtin_apply()](src/uslp_sdls.c:168), [uni_ccsds_uslp_sdls_builtin_process()](src/uslp_sdls.c:262).

Appendix: Clickable Code Index

| Component | Pointers |
|---|---|
| Primary Header | [uni_ccsds_uslp_primary_header_pack()](src/uslp_primary_header.c:117), [uni_ccsds_uslp_primary_header_unpack()](src/uslp_primary_header.c:209), [uni_ccsds_uslp_validate_primary_header()](src/uslp_primary_header.c:68) |
| TFDF Header | [uni_ccsds_uslp_tfdf_header_pack()](src/uslp_tfdf_header.c:96), [uni_ccsds_uslp_tfdf_header_unpack()](src/uslp_tfdf_header.c:143), [uni_ccsds_uslp_validate_tfdf_header()](src/uslp_tfdf_header.c:36) |
| OCF | [uni_ccsds_uslp_send_ocf()](src/uslp.c:649), [uni_ccsds_uslp_build_frame()](src/uslp.c:837), [uni_ccsds_uslp_accept_frame()](src/uslp.c:1397) |
| Insert Service | [uni_ccsds_uslp_send_insert()](src/uslp.c:661), [uni_ccsds_uslp_register_insert_callback()](src/uslp.c:323), [uni_ccsds_uslp_build_frame()](src/uslp.c:819), [uni_ccsds_uslp_accept_frame()](src/uslp.c:1249) |
| FECF (Annex B) | [uni_crypto_crc16_ccitt_append()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:85), [uni_crypto_crc16_ccitt_verify()](3rdparty/uni.crypto/src/uni_crypto_crc16.c:76) |
| SDLS (apply/process) | [uni_ccsds_uslp_register_builtin_sdls()](src/uslp_sdls.c:122), [uni_ccsds_uslp_sdls_builtin_apply()](src/uslp_sdls.c:168), [uni_ccsds_uslp_sdls_builtin_process()](src/uslp_sdls.c:262), [uni_ccsds_uslp_configure_sdls()](src/uslp.c:293) |
| OID LFSR/OID builder | [uni_ccsds_uslp_oid_lfsr_next()](src/lfsr_oid.c:67), [uni_ccsds_uslp_oid_lfsr_fill()](src/lfsr_oid.c:142), [uni_ccsds_uslp_build_oid()](src/uslp.c:978) |
| Truncated Frames | [uni_ccsds_uslp_build_truncated()](src/uslp.c:1065) |
| VCF Count Length | [vc_vcf_count_len_code()](src/uslp.c:44) |