/**
 * @file test_tfdf_header.cpp
 * @brief Unit Tests for USLP TFDF Header pack/unpack per CCSDS 732.1-B-3 §4.1.4.2
 *
 * - TFDZ Construction Rules (3 bits) (Table 4-3)
 * - UPID (5 bits)
 * - First Header/Last Valid Octet Pointer (16 bits, optional for rules 000/001/010)
 *
 * © 2025 Uni-Libraries contributors — MIT License
 */

#include <catch2/catch_test_macros.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstring>

static void require_equal_tfdf(const uni_uslp_tfdf_header_t& a, const uni_uslp_tfdf_header_t& b)
{
    REQUIRE(a.construction_rule == b.construction_rule);
    REQUIRE(a.upid == b.upid);
    REQUIRE(a.first_header_ptr == b.first_header_ptr);
    REQUIRE(a.last_valid_ptr == b.last_valid_ptr);
}

TEST_CASE("TFDF Header pack/unpack: Rule 000 (Packets spanning frames) with FHP", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_0; // '000' (§4.1.4.2.2.2.1)
    h.upid = 10;                                 // valid UPID (0..31)
    h.first_header_ptr = 0x0123;                 // FHP present (§4.1.4.2.4.3)
    h.last_valid_ptr = 0;                        // must be zero for rule 000

    uint8_t buf[8]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&h, buf, sizeof(buf), &written) == UNI_USLP_SUCCESS);
    REQUIRE(written == 3);

    // First octet: rule in bits 0..2 (MSBs), UPID in bits 3..7
    uint8_t expected_o0 = (uint8_t)((0u << 5) | (h.upid & 0x1Fu));
    REQUIRE(buf[0] == expected_o0);
    REQUIRE(buf[1] == 0x01);
    REQUIRE(buf[2] == 0x23);

    uni_uslp_tfdf_header_t parsed{};
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(buf, written, &parsed, &read) == UNI_USLP_SUCCESS);
    REQUIRE(read == written);

    require_equal_tfdf(h, parsed);
}

TEST_CASE("TFDF Header pack/unpack: Rule 001 (Start of MAPA/VCA) with LVOP", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_1; // '001' (§4.1.4.2.2.2.2)
    h.upid = 3;
    h.first_header_ptr = 0;                     // must be zero for 001/010
    h.last_valid_ptr = 0xFFFF;                  // LVOP (§4.1.4.2.4.5, .4.6)

    uint8_t buf[8]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&h, buf, sizeof(buf), &written) == UNI_USLP_SUCCESS);
    REQUIRE(written == 3);

    // Check top octet fields
    uint8_t expected_o0 = (uint8_t)((1u << 5) | (h.upid & 0x1Fu));
    REQUIRE(buf[0] == expected_o0);
    REQUIRE(buf[1] == 0xFF);
    REQUIRE(buf[2] == 0xFF);

    uni_uslp_tfdf_header_t parsed{};
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(buf, written, &parsed, &read) == UNI_USLP_SUCCESS);
    REQUIRE(read == written);
    require_equal_tfdf(h, parsed);
}

TEST_CASE("TFDF Header pack/unpack: Rule 010 (Continue MAPA/VCA) with LVOP", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_2; // '010' (§4.1.4.2.2.2.3)
    h.upid = 31;                                // max UPID
    h.first_header_ptr = 0;
    h.last_valid_ptr = 0x0001;

    uint8_t buf[8]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&h, buf, sizeof(buf), &written) == UNI_USLP_SUCCESS);
    REQUIRE(written == 3);

    uint8_t expected_o0 = (uint8_t)((2u << 5) | (h.upid & 0x1Fu));
    REQUIRE(buf[0] == expected_o0);
    REQUIRE(buf[1] == 0x00);
    REQUIRE(buf[2] == 0x01);

    uni_uslp_tfdf_header_t parsed{};
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(buf, written, &parsed, &read) == UNI_USLP_SUCCESS);
    REQUIRE(read == written);
    require_equal_tfdf(h, parsed);
}

TEST_CASE("TFDF Header pack/unpack: Rule 011 (Octet Stream) no pointer", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_3; // '011' (§4.1.4.2.2.2.4)
    h.upid = 7;
    h.first_header_ptr = 0;
    h.last_valid_ptr = 0;

    uint8_t buf[8]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&h, buf, sizeof(buf), &written) == UNI_USLP_SUCCESS);
    REQUIRE(written == 1);

    uint8_t expected_o0 = (uint8_t)((3u << 5) | (h.upid & 0x1Fu));
    REQUIRE(buf[0] == expected_o0);

    uni_uslp_tfdf_header_t parsed{};
    size_t read = 0;
    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(buf, written, &parsed, &read) == UNI_USLP_SUCCESS);
    REQUIRE(read == written);
    require_equal_tfdf(h, parsed);
}

TEST_CASE("TFDF Header validation: no pointer allowed for rules 011..111", "[tfdf_header]")
{
    // Try setting a forbidden pointer for rule 011
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_3;
    h.upid = 1;
    h.first_header_ptr = 1; // illegal
    h.last_valid_ptr = 0;

    REQUIRE(uni_ccsds_uslp_validate_tfdf_header(&h) == UNI_USLP_ERROR_INVALID_PARAM);

    // For rule 111 as well
    h.construction_rule = UNI_USLP_TFDZ_RULE_7;
    h.first_header_ptr = 0;
    h.last_valid_ptr = 2; // illegal
    REQUIRE(uni_ccsds_uslp_validate_tfdf_header(&h) == UNI_USLP_ERROR_INVALID_PARAM);
}

TEST_CASE("TFDF Header validation: UPID out of range fails", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_0;
    h.upid = 32;                 // invalid (5-bit max 31)
    h.first_header_ptr = 0;
    h.last_valid_ptr = 0;

    REQUIRE(uni_ccsds_uslp_validate_tfdf_header(&h) == UNI_USLP_ERROR_INVALID_PARAM);
}

TEST_CASE("TFDF Header validation: malformed pointer usage", "[tfdf_header]")
{
    // Rule 000 requires FHP; LVOP must be zero
    {
        uni_uslp_tfdf_header_t h{};
        h.construction_rule = UNI_USLP_TFDZ_RULE_0;
        h.upid = 0;
        h.first_header_ptr = 0x0000;
        h.last_valid_ptr = 1; // should be zero
        REQUIRE(uni_ccsds_uslp_validate_tfdf_header(&h) == UNI_USLP_ERROR_INVALID_PARAM);
    }

    // Rule 001/010 require LVOP; FHP must be zero
    {
        uni_uslp_tfdf_header_t h{};
        h.construction_rule = UNI_USLP_TFDZ_RULE_1;
        h.upid = 0;
        h.first_header_ptr = 1;  // should be zero
        h.last_valid_ptr = 0x0000;
        REQUIRE(uni_ccsds_uslp_validate_tfdf_header(&h) == UNI_USLP_ERROR_INVALID_PARAM);
    }
}

TEST_CASE("TFDF Header pack: buffer too small", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = UNI_USLP_TFDZ_RULE_0;
    h.upid = 5;
    h.first_header_ptr = 0xAAAA;
    h.last_valid_ptr = 0;

    uint8_t buf[1]{};
    size_t written = 0;

    REQUIRE(uni_ccsds_uslp_tfdf_header_pack(&h, buf, sizeof(buf), &written) == UNI_USLP_ERROR_BUFFER_TOO_SMALL);
}

TEST_CASE("TFDF Header unpack: buffer too small when pointer is present", "[tfdf_header]")
{
    // Construct raw header: rule=000, upid=1 -> requires 3 bytes
    uint8_t raw[1]{};
    raw[0] = (uint8_t)((0u << 5) | 1u);

    uni_uslp_tfdf_header_t parsed{};
    size_t read = 0;

    REQUIRE(uni_ccsds_uslp_tfdf_header_unpack(raw, sizeof(raw), &parsed, &read) == UNI_USLP_ERROR_BUFFER_TOO_SMALL);
}

TEST_CASE("TFDF Header validation: invalid rule value rejected", "[tfdf_header]")
{
    uni_uslp_tfdf_header_t h{};
    h.construction_rule = (uni_uslp_tfdz_construction_rule_t)8; // invalid (>7)
    h.upid = 0;
    h.first_header_ptr = 0;
    h.last_valid_ptr = 0;

    REQUIRE(uni_ccsds_uslp_validate_tfdf_header(&h) == UNI_USLP_ERROR_INVALID_PARAM);
}