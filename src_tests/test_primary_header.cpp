/**
 * @file test_primary_header.cpp
 * @brief Unit Tests for USLP Primary Header pack/unpack per CCSDS 732.1-B-3 §4.1.2
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstring>

static void require_equal_headers(const uni_uslp_primary_header_t& a, const uni_uslp_primary_header_t& b)
{
    REQUIRE(a.tfvn == b.tfvn);
    REQUIRE(a.scid == b.scid);
    REQUIRE(a.source_dest == b.source_dest);
    REQUIRE(a.vcid == b.vcid);
    REQUIRE(a.map_id == b.map_id);
    REQUIRE(a.eof_ph_flag == b.eof_ph_flag);
    REQUIRE(a.frame_length == b.frame_length);
    REQUIRE(a.bypass_flag == b.bypass_flag);
    REQUIRE(a.cc_flag == b.cc_flag);
    REQUIRE(a.ocf_flag == b.ocf_flag);
    REQUIRE(a.vcf_count_len == b.vcf_count_len);
    REQUIRE(a.vcf_count == b.vcf_count);
}

TEST_CASE("USLP Primary Header pack/unpack round-trip (with VCF Count)", "[primary_header]")
{
    uni_uslp_primary_header_t hdr{};
    hdr.tfvn = UNI_USLP_TFVN;        // 1100b
    hdr.scid = 0x1234;
    hdr.source_dest = true;          // destination
    hdr.vcid = 5;
    hdr.map_id = 3;                  // 4-bit field
    hdr.eof_ph_flag = false;
    hdr.frame_length = 100;          // C = total_octets - 1 (value not validated against a full frame here)
    hdr.bypass_flag = true;
    hdr.cc_flag = false;
    hdr.ocf_flag = true;
    hdr.vcf_count_len = 2;           // two octets per Table 4-2 => up to 65535
    hdr.vcf_count = 0x3456;

    uint8_t buf[32]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_primary_header_pack(&hdr, buf, sizeof(buf), &written) == UNI_USLP_SUCCESS);
    REQUIRE(written == (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH + 2);

    uni_uslp_primary_header_t parsed{};
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(buf, written, &parsed, &read) == UNI_USLP_SUCCESS);
    REQUIRE(read == written);

    require_equal_headers(hdr, parsed);
}

TEST_CASE("USLP Primary Header pack/unpack round-trip (no VCF Count)", "[primary_header]")
{
    uni_uslp_primary_header_t hdr{};
    hdr.tfvn = UNI_USLP_TFVN;
    hdr.scid = 0xBEEF;
    hdr.source_dest = false;         // source
    hdr.vcid = 62;
    hdr.map_id = 15;                 // max 4-bit
    hdr.eof_ph_flag = true;
    hdr.frame_length = 2000;
    hdr.bypass_flag = false;
    hdr.cc_flag = true;
    hdr.ocf_flag = false;
    hdr.vcf_count_len = 0;           // no VCF Count field present
    hdr.vcf_count = 0;               // must be zero

    uint8_t buf[32]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_primary_header_pack(&hdr, buf, sizeof(buf), &written) == UNI_USLP_SUCCESS);
    REQUIRE(written == (size_t)UNI_USLP_PRIMARY_HEADER_LENGTH);

    uni_uslp_primary_header_t parsed{};
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_primary_header_unpack(buf, written, &parsed, &read) == UNI_USLP_SUCCESS);
    REQUIRE(read == written);

    require_equal_headers(hdr, parsed);
}

TEST_CASE("USLP Primary Header validation errors", "[primary_header]")
{
    SECTION("Invalid TFVN fails validation")
    {
        uni_uslp_primary_header_t hdr{};
        hdr.tfvn = 0x0;             // wrong version
        hdr.scid = 0x0001;
        hdr.vcid = 1;
        hdr.map_id = 0;
        hdr.frame_length = UNI_USLP_MIN_FRAME_LENGTH;
        hdr.vcf_count_len = 0;
        hdr.vcf_count = 0;

        REQUIRE(uni_ccsds_uslp_validate_primary_header(&hdr) == UNI_USLP_ERROR_INVALID_PARAM);
    }

    SECTION("MAP ID beyond 4-bit range fails")
    {
        uni_uslp_primary_header_t hdr{};
        hdr.tfvn = UNI_USLP_TFVN;
        hdr.scid = 1;
        hdr.vcid = 1;
        hdr.map_id = 16;            // invalid (4-bit max 15)
        hdr.frame_length = UNI_USLP_MIN_FRAME_LENGTH;
        hdr.vcf_count_len = 0;
        hdr.vcf_count = 0;

        REQUIRE(uni_ccsds_uslp_validate_primary_header(&hdr) == UNI_USLP_ERROR_INVALID_PARAM);
    }

    SECTION("VCF Count present but too large for indicated length")
    {
        uni_uslp_primary_header_t hdr{};
        hdr.tfvn = UNI_USLP_TFVN;
        hdr.scid = 1;
        hdr.vcid = 1;
        hdr.map_id = 1;
        hdr.frame_length = UNI_USLP_MIN_FRAME_LENGTH;
        hdr.vcf_count_len = 1;      // 1 octet => up to 255
        hdr.vcf_count = 0x1FF;      // 511 (too large for 1 octet)

        uint8_t buf[32]{};
        size_t written = 0;
        REQUIRE(uni_ccsds_uslp_primary_header_pack(&hdr, buf, sizeof(buf), &written) == UNI_USLP_ERROR_INVALID_PARAM);
    }

    SECTION("VCF Count length zero but count non-zero fails")
    {
        uni_uslp_primary_header_t hdr{};
        hdr.tfvn = UNI_USLP_TFVN;
        hdr.scid = 1;
        hdr.vcid = 1;
        hdr.map_id = 1;
        hdr.frame_length = UNI_USLP_MIN_FRAME_LENGTH;
        hdr.vcf_count_len = 0;
        hdr.vcf_count = 1;          // illegal if no VCF field

        REQUIRE(uni_ccsds_uslp_validate_primary_header(&hdr) == UNI_USLP_ERROR_INVALID_PARAM);
    }

    SECTION("Frame length lower than minimum fails")
    {
        uni_uslp_primary_header_t hdr{};
        hdr.tfvn = UNI_USLP_TFVN;
        hdr.scid = 1;
        hdr.vcid = 1;
        hdr.map_id = 1;
        hdr.frame_length = (uint16_t)(UNI_USLP_MIN_FRAME_LENGTH - 1);
        hdr.vcf_count_len = 0;
        hdr.vcf_count = 0;

        REQUIRE(uni_ccsds_uslp_validate_primary_header(&hdr) == UNI_USLP_ERROR_INVALID_PARAM);
    }
}