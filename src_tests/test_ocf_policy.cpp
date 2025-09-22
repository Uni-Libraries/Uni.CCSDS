/**
 * @file test_ocf_policy.cpp
 * @brief Tests for USLP-139/USLP-140 OCF inclusion policy
 *
 * References:
 *  - CCSDS 732.1-B-3 §4.1.5 Operational Control Field
 *  - Table 5-3 VC Managed Parameters (USLP-139, USLP-140)
 */

#include <catch2/catch_test_macros.hpp>
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"
#include <vector>

namespace {
struct OcfCap { bool called=false; uint8_t vcid=0; uni_uslp_ocf_t ocf{}; };
static void ocf_cb(uni_uslp_context_t* ctx, uint8_t vcid, const uni_uslp_ocf_t* ocf, void* user) {
  (void)ctx; auto* c = static_cast<OcfCap*>(user); c->called=true; c->vcid=vcid; c->ocf=*ocf;
}
struct SduCap { bool called=false; };
static void sdu_cb(uni_uslp_context_t*, uint8_t, uint8_t, uni_uslp_service_type_t, const uint8_t*, size_t, uni_uslp_verification_status_t, bool, void* u) {
  static_cast<SduCap*>(u)->called=true;
}
} // namespace

TEST_CASE("USLP-139: Variable-length OCF allowed gate", "[uslp][ocf][policy][var]") {
  uni_uslp_managed_params_t base{};
  base.max_frame_length = 1024; base.min_frame_length = 0; // variable
  base.fecf_capability = false; base.ocf_capability = true;
  base.insert_zone_capability = false; base.truncated_frame_capable=false;
  base.max_sdu_length = 512;

  uni_uslp_context_t ctx{};
  REQUIRE(uni_ccsds_uslp_init(&ctx, 0x4242, &base) == UNI_USLP_SUCCESS);
  const uint8_t VC=1, MAP=2;
  // VC params: ocf allowed variable = false
  auto vc_params = base; vc_params.ocf_allowed_variable = false;
  REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &vc_params) == UNI_USLP_SUCCESS);
  auto map_params = base;
  REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);
  SduCap scap{}; OcfCap ocap{};
  REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC, MAP, sdu_cb, &scap) == UNI_USLP_SUCCESS);
  REQUIRE(uni_ccsds_uslp_register_ocf_callback(&ctx, VC, ocf_cb, &ocap) == UNI_USLP_SUCCESS);

  // Queue SDU and OCF (pending)
  std::vector<uint8_t> sdu{0x01,0x02,0x03};
  REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
  uni_uslp_ocf_t ocf{}; ocf.type=UNI_USLP_OCF_TYPE_1; ocf.data=0x01020304u;
  REQUIRE(uni_ccsds_uslp_send_ocf(&ctx, VC, &ocf) == UNI_USLP_SUCCESS);

  // Build frame -> since ocf_allowed_variable=false but OCF is pending, build should fail
  std::vector<uint8_t> frame(256, 0x00);
  size_t fl = frame.size();
  REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &fl) == UNI_USLP_ERROR_INVALID_PARAM);

  // Clear OCF pending and retry -> now should succeed without OCF
  REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
  // Don't queue OCF this time
  fl = frame.size();
  REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &fl) == UNI_USLP_SUCCESS);
  frame.resize(fl);

  // Check PH.ocf_flag == 0
  uni_uslp_primary_header_t ph{}; size_t ph_read=0;
  REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
  REQUIRE(ph.ocf_flag == false);
  // Accept: OCF callback must NOT be called
  REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
  REQUIRE(ocap.called == false);

  // Now allow OCF on variable-length and rebuild
  vc_params.ocf_allowed_variable = true;
  REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &vc_params) == UNI_USLP_SUCCESS);
  REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
  REQUIRE(uni_ccsds_uslp_send_ocf(&ctx, VC, &ocf) == UNI_USLP_SUCCESS);
  fl = frame.size();
  REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &fl) == UNI_USLP_SUCCESS);
  frame.resize(fl);
  REQUIRE(uni_ccsds_uslp_primary_header_unpack(frame.data(), frame.size(), &ph, &ph_read) == UNI_USLP_SUCCESS);
  REQUIRE(ph.ocf_flag == true);
  REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
  REQUIRE(ocap.called == true);
}

TEST_CASE("USLP-140: Fixed-length OCF required enforcement", "[uslp][ocf][policy][fixed]") {
  uni_uslp_managed_params_t base{};
  base.max_frame_length = 32; base.min_frame_length = 32; // fixed
  base.fecf_capability = false; base.ocf_capability = true;
  base.insert_zone_capability = false; base.truncated_frame_capable=false;
  base.max_sdu_length = 512;

  uni_uslp_context_t ctx{};
  REQUIRE(uni_ccsds_uslp_init(&ctx, 0x5151, &base) == UNI_USLP_SUCCESS);
  const uint8_t VC=2, MAP=1;
  auto vc_params = base; vc_params.ocf_required_fixed = true;
  REQUIRE(uni_ccsds_uslp_configure_vc(&ctx, VC, &vc_params) == UNI_USLP_SUCCESS);
  auto map_params = base;
  REQUIRE(uni_ccsds_uslp_configure_map(&ctx, VC, MAP, UNI_USLP_SERVICE_MAPA, &map_params) == UNI_USLP_SUCCESS);
  SduCap scap{}; OcfCap ocap{};
  REQUIRE(uni_ccsds_uslp_register_sdu_callback(&ctx, VC, MAP, sdu_cb, &scap) == UNI_USLP_SUCCESS);
  REQUIRE(uni_ccsds_uslp_register_ocf_callback(&ctx, VC, ocf_cb, &ocap) == UNI_USLP_SUCCESS);

  // Compute exact SDU length for fixed: total(32) = PH(7) + TFDF(1) + SDU + OCF(4)
  const size_t sdu_len = 32 - (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH - 1 - (size_t)UNI_USLP_OCF_LENGTH;
  REQUIRE(sdu_len > 0);
  std::vector<uint8_t> sdu(sdu_len, 0xAB);

  // Queue SDU only; no OCF pending => build must fail
  REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
  std::vector<uint8_t> frame(64, 0x00); size_t fl = frame.size();
  REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &fl) == UNI_USLP_ERROR_INVALID_PARAM);

  // Now queue OCF and retry -> should succeed and ocf callback on accept
  uni_uslp_ocf_t ocf{}; ocf.type=UNI_USLP_OCF_TYPE_1; ocf.data=0xDEADBEEFu;
  REQUIRE(uni_ccsds_uslp_send_mapa(&ctx, VC, MAP, sdu.data(), sdu.size()) == UNI_USLP_SUCCESS);
  REQUIRE(uni_ccsds_uslp_send_ocf(&ctx, VC, &ocf) == UNI_USLP_SUCCESS);
  fl = frame.size();
  REQUIRE(uni_ccsds_uslp_build_frame(&ctx, VC, MAP, frame.data(), &fl) == UNI_USLP_SUCCESS);
  frame.resize(fl);
  REQUIRE(uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size()) == UNI_USLP_SUCCESS);
  REQUIRE(ocap.called == true);
}