/**
 * @file test_crc16_lfsr.cpp
 * @brief Unit Tests for OID LFSR
 * 
 * @author Uni-Libraries contributors
 * @date 2025
 * @copyright MIT License
 */

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Uni-Libraries contributors

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
// uni.ccsds
#include "uni_ccsds.h"
#include "uni_ccsds_uslp_internal.h"

#include <vector>
#include <cstring>

/* ========================================================================== */
/* CRC-16 CCSDS TESTS                                                         */
/* ========================================================================== */





/* ========================================================================== */
/* OID LFSR TESTS                                                             */
/* ========================================================================== */

TEST_CASE("OID LFSR Basic Functionality", "[lfsr]") {
    SECTION("LFSR initialization") {
        uint32_t lfsr_state;
        
        uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_init(&lfsr_state, 0x12345678);
        REQUIRE(status == UNI_USLP_SUCCESS);
        REQUIRE(lfsr_state == 0x12345678);
    }
    
    SECTION("LFSR initialization with zero seed") {
        uint32_t lfsr_state;
        
        uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_init(&lfsr_state, 0);
        REQUIRE(status == UNI_USLP_SUCCESS);
        REQUIRE(lfsr_state == UNI_USLP_OID_LFSR_INITIAL_SEED);
    }
    
    SECTION("LFSR generates non-zero values") {
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        
        uint32_t value1 = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state);
        REQUIRE(value1 != 0);
        REQUIRE(value1 != UNI_USLP_OID_LFSR_INITIAL_SEED);
        
        uint32_t value2 = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state);
        REQUIRE(value2 != 0);
        REQUIRE(value2 != value1);
    }
    
    SECTION("LFSR sequence is deterministic") {
        uint32_t lfsr_state1 = 0x12345678;
        uint32_t lfsr_state2 = 0x12345678;
        
        for (int i = 0; i < 10; i++) {
            uint32_t value1 = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state1);
            uint32_t value2 = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state2);
            REQUIRE(value1 == value2);
        }
    }
}

TEST_CASE("OID LFSR Buffer Fill", "[lfsr]") {
    SECTION("Fill small buffer") {
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        uint8_t buffer[16];
        
        uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state, buffer, sizeof(buffer));
        REQUIRE(status == UNI_USLP_SUCCESS);
        
        // Verify buffer is not all zeros
        bool all_zeros = true;
        for (size_t i = 0; i < sizeof(buffer); i++) {
            if (buffer[i] != 0) {
                all_zeros = false;
                break;
            }
        }
        REQUIRE(all_zeros == false);
    }
    
    SECTION("Fill large buffer") {
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        std::vector<uint8_t> buffer(1024);
        
        uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state, buffer.data(), buffer.size());
        REQUIRE(status == UNI_USLP_SUCCESS);
        
        // Verify buffer has some variation
        uint8_t first_byte = buffer[0];
        bool has_variation = false;
        for (size_t i = 1; i < buffer.size(); i++) {
            if (buffer[i] != first_byte) {
                has_variation = true;
                break;
            }
        }
        REQUIRE(has_variation == true);
    }
    
    SECTION("Reproducible fill") {
        uint32_t lfsr_state1 = 0x12345678;
        uint32_t lfsr_state2 = 0x12345678;
        uint8_t buffer1[32];
        uint8_t buffer2[32];
        
        uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state1, buffer1, sizeof(buffer1));
        uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state2, buffer2, sizeof(buffer2));
        
        REQUIRE(std::memcmp(buffer1, buffer2, sizeof(buffer1)) == 0);
    }
}

TEST_CASE("OID LFSR Edge Cases", "[lfsr]") {
    SECTION("Null pointer handling") {
        uint32_t value = uni_ccsds_uslp_oid_lfsr_next(nullptr);
        REQUIRE(value == 0);
        
        uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_init(nullptr, 0x12345678);
        REQUIRE(status == UNI_USLP_ERROR_NULL_POINTER);
        
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        status = uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state, nullptr, 10);
        REQUIRE(status == UNI_USLP_ERROR_NULL_POINTER);
    }
    
    SECTION("Zero state handling") {
        uint32_t lfsr_state = 0;
        uint32_t value = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state);
        REQUIRE(value != 0);
        REQUIRE(lfsr_state != 0);
    }
    
    SECTION("Zero length fill") {
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        uint8_t buffer[1];
        
        uni_uslp_status_t status = uni_ccsds_uslp_oid_lfsr_fill(&lfsr_state, buffer, 0);
        REQUIRE(status == UNI_USLP_SUCCESS);
    }
}

TEST_CASE("OID LFSR Statistical Properties", "[lfsr]") {
    SECTION("Bit distribution") {
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        std::vector<uint32_t> values(1000);
        
        for (size_t i = 0; i < values.size(); i++) {
            values[i] = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state);
        }
        
        // Count bits in each position
        std::vector<int> bit_counts(32, 0);
        for (uint32_t value : values) {
            for (int bit = 0; bit < 32; bit++) {
                if (value & (1U << bit)) {
                    bit_counts[bit]++;
                }
            }
        }
        
        // Each bit position should have roughly 50% ones
        for (int bit = 0; bit < 32; bit++) {
            double ratio = static_cast<double>(bit_counts[bit]) / values.size();
            REQUIRE(ratio > 0.3);  // At least 30%
            REQUIRE(ratio < 0.7);  // At most 70%
        }
    }
    
    SECTION("No immediate repetition") {
        uint32_t lfsr_state = UNI_USLP_OID_LFSR_INITIAL_SEED;
        std::vector<uint32_t> values(100);
        
        for (size_t i = 0; i < values.size(); i++) {
            values[i] = uni_ccsds_uslp_oid_lfsr_next(&lfsr_state);
        }
        
        // Check for immediate repetitions
        for (size_t i = 1; i < values.size(); i++) {
            REQUIRE(values[i] != values[i-1]);
        }
    }
}

TEST_CASE("OID LFSR Self-Test", "[lfsr]") {
    SECTION("Self-test passes") {
        bool result = uni_ccsds_uslp_oid_lfsr_self_test();
        REQUIRE(result == true);
    }
}

/* ========================================================================== */
/* INTEGRATION TESTS                                                          */
/* ========================================================================== */
