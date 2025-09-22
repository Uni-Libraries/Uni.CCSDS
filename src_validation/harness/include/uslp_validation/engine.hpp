#pragma once

#include <filesystem>
#include <vector>

#include "scenario.hpp"

namespace uslp::validation {

struct ScenarioOutcome {
    Scenario scenario;
    std::string status;   ///< PASS / FAIL / SKIP / BLOCKED / ERROR
    std::string message;  ///< Human readable diagnostics
};

/**
 * \brief Minimal stub for the validation engine.
 *
 * The current implementation only returns placeholder results so that the
 * harness can be built and iterated upon incrementally.
 */
class Engine {
public:
    struct Config {
        std::filesystem::path artifact_root{};
    };

    explicit Engine(Config config);

    [[nodiscard]] std::vector<ScenarioOutcome> run(const ScenarioPack& pack) const;

private:
    Config config_;
};

}  // namespace uslp::validation