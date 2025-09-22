#pragma once

#include "engine.hpp"

#include <filesystem>
#include <vector>

namespace uslp::validation {

/**
 * \brief Emits machine-readable and human-friendly reports for validation runs.
 *
 * - write_summary(): Produces a JSON document containing per-scenario results and aggregate counts.
 * - write_detailed(): Produces an HTML report with a tabular view of the outcomes.
 */
class MetricsWriter {
public:
    MetricsWriter() = default;

    void write_summary(const std::filesystem::path& destination,
                       const std::vector<ScenarioOutcome>& outcomes) const;

    void write_detailed(const std::filesystem::path& destination,
                        const std::vector<ScenarioOutcome>& outcomes) const;
};

}  // namespace uslp::validation