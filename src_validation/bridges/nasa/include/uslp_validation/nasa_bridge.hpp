#pragma once

/* forward-declared Scenario; include in .cpp */

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace uslp { namespace validation { struct Scenario; } }
namespace uslp::validation::nasa_bridge
{
// Bring the core Scenario type into scope for concise signatures.
using ::uslp::validation::Scenario;

/**
 * NASA bridge scaffolding.
 *
 * This interface will wrap the proof-of-concept NASA USLP implementation found under
 * src_validation/3rdparty/nasa-uslp. The initial version is a stub which allows the overall
 * validation harness to compile and link. Subsequent revisions will:
 *  - build the NASA sources with USLP_VALIDATION_CAPTURE to replace UDP I/O by in-memory capture
 *    buffers (CCSDS 732.1-B-3 §4.1.4.1.6 OID frames, TFDF construction visibility),
 *  - expose deterministic encode/decode functions without side effects,
 *  - surface diagnostic logs and parsed service units (MAP Packet, MAPA SDU, Octet Stream).
 */
class Session
{
public:
    struct Config
    {
        // Directory containing the NASA PoC (optional, defaults to the vendored tree).
        std::filesystem::path nasa_root;
        // Path to the NASA MIB config file (e.g., 3rdparty/nasa-uslp/mibconfig).
        std::filesystem::path mib_config;
    };

    explicit Session(Config cfg);

    // Returns true when the session has been initialised successfully
    // (MIB parsed, runtime state prepared).
    [[nodiscard]] bool initialized() const noexcept { return ready_; }

    // Bundle produced by an encode call. Both full frame and TFDF are exposed
    // to facilitate cross-actor comparisons (bitwise).
    struct FrameBundle
    {
        std::vector<std::uint8_t> frame;  // Entire USLP frame (header + counters + TFDF + trailers)
        std::vector<std::uint8_t> tfdf;   // Transfer Frame Data Field only (incl. TFDF header)
    };

    // Bundle produced by a decode call. Carries semantic reconstruction results.
    struct DecodeBundle
    {
        // Raw payload reconstructed (packet bytes, MAPA SDU bytes, or octet stream slice).
        std::vector<std::uint8_t> payload;

        // Additional fields parsed (e.g., construction rule, UPID, FHP/LVO, ocf bytes).
        std::map<std::string, std::string> fields;
    };

    /**
     * Initialise the NASA bridge with the configured mib_config.
     * Diagnostics are appended to diag_out.
     *
     * Returns:
     *  - true on success
     *  - false on failure, with a human readable message in diag_out
     */
    bool init(std::string& diag_out);

    /**
     * Encode a frame using the NASA implementation.
     * The current stub returns false with a diagnostic message.
     *
     * Parameters:
     *  - scenario: Normalised scenario attributes (e.g., VCID, MAPID, flags)
     *  - payload:  Input payload (MAP Packet, MAPA SDU, or octet stream bytes)
     *  - out:      Receives frame and TFDF bytes
     *  - diag_out: Receives diagnostic messages and warnings
     */
    bool encode(const ::uslp::validation::Scenario& scenario,
                const std::vector<std::uint8_t>& payload,
                FrameBundle& out,
                std::string& diag_out) const;

    /**
     * Decode a frame using the NASA implementation.
     * The current stub returns false with a diagnostic message.
     *
     * Parameters:
     *  - scenario: Normalised scenario attributes
     *  - in:       Frame bundle (at least \a frame should be populated)
     *  - out:      Receives reconstructed payload and semantic fields
     *  - diag_out: Receives diagnostic messages and warnings
     */
    bool decode(const ::uslp::validation::Scenario& scenario,
                const FrameBundle& in,
                DecodeBundle& out,
                std::string& diag_out) const;

private:
    Config cfg_;
    bool ready_{false};
};

} // namespace uslp::validation::nasa_bridge