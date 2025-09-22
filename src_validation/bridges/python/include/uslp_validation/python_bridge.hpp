#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace uslp { namespace validation { struct Scenario; } }

namespace uslp::validation::python_bridge
{

// Bring the core Scenario type into scope for concise signatures.
using ::uslp::validation::Scenario;

/**
 * Python bridge scaffolding (spacepackets-py).
 *
 * This interface wraps a Python runner which uses the IRS spacepackets USLP implementation
 * (vendored under src_validation/3rdparty/spacepackets-py) to perform encode/decode operations.
 *
 * Transport between C++ and Python is JSON over subprocess with temporary files, which avoids
 * embedding the Python interpreter by default. An alternative embedding mode can be added later.
 *
 * CCSDS-732.1-B-3 references:
 * - §4.1..§4.6: Service profiles and TFDF construction (Construction Rules, UPID, FHP/LVO)
 * - §1.4.1: Interoperability objectives (cross-actor round-trip)
 */
class Session
{
public:
    struct Config
    {
        // Python executable to use (e.g. "python3")
        std::string python_exe{"python3"};

        // Path to the Python runner script (runner/runner.py).
        std::filesystem::path runner_script;

        // Path to the spacepackets package root (…/spacepackets-py/src)
        std::filesystem::path spacepackets_src;

        // Optional working directory for temporary artifacts (JSON in/out files).
        std::filesystem::path work_dir;

        // Per-invocation timeout in seconds for the runner (0 = no explicit timeout handling here).
        int timeout_sec{0};
    };

    explicit Session(Config cfg);

    // Returns true when the session has been initialised successfully
    // (runner and spacepackets roots discovered).
    [[nodiscard]] bool initialized() const noexcept { return ready_; }

    struct FrameBundle
    {
        std::vector<std::uint8_t> frame;  // Entire USLP frame
        std::vector<std::uint8_t> tfdf;   // TFDF (incl. TFDF header)
    };

    struct DecodeBundle
    {
        std::vector<std::uint8_t> payload;                  // Reconstructed service data
        std::map<std::string, std::string> fields;          // Parsed fields (CR, UPID, FHP/LVO,…)
    };

    /**
     * Initialise the Python bridge; verifies runner and spacepackets presence.
     * Returns true on success. Diagnostics appended to diag_out.
     */
    bool init(std::string& diag_out);

    /**
     * Encode a frame using spacepackets.
     *
     * Parameters:
     *  - scenario:  Normalised scenario with attributes (e.g., VCID/MAPID/bypass/etc.)
     *  - payload:   Input service data (MAP Packet bytes, MAPA SDU bytes, or octet stream slice)
     *  - out:       Receives frame and TFDF bytes
     *  - diag_out:  Receives diagnostics
     *
     * Returns true on success.
     */
    bool encode(const ::uslp::validation::Scenario& scenario,
                const std::vector<std::uint8_t>& payload,
                FrameBundle& out,
                std::string& diag_out) const;

    /**
     * Decode a frame using spacepackets.
     *
     * Parameters:
     *  - scenario:  Normalised scenario with attributes (used for contextual checks)
     *  - in:        Frame bundle; at least 'frame' must be populated
     *  - out:       Receives reconstructed payload and parsed fields
     *  - diag_out:  Receives diagnostics
     *
     * Returns true on success.
     */
    bool decode(const ::uslp::validation::Scenario& scenario,
                const FrameBundle& in,
                DecodeBundle& out,
                std::string& diag_out) const;

private:
    Config cfg_;
    bool ready_{false};
};

} // namespace uslp::validation::python_bridge