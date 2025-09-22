#pragma once

#include <map>
#include <string>
#include <vector>

namespace uslp::validation {

/**
 * \brief Identifies which actors should participate in a scenario.
 *
 * The flags are placeholders until the NASA/Python bridges are wired.
 */
struct ActorMatrix {
    bool local_encode{true};
    bool local_decode{true};
    bool nasa_encode{false};
    bool nasa_decode{false};
    bool python_encode{false};
    bool python_decode{false};
};

/**
 * \brief Normalised validation scenario after matrix expansion.
 *
 * Each scenario owns a flat map of attributes. The interpretation of the keys
 * follows the declarative schema (see docs), but the execution layer treats
 * them as opaque strings.
 */
struct Scenario {
    std::string id;
    std::string suite;
    std::map<std::string, std::string> attributes;
    ActorMatrix actors{};
};

/**
 * \brief Convenience bundle carrying multiple scenarios emitted from one file.
 */
struct ScenarioPack {
    std::string source_file;
    std::vector<Scenario> scenarios;
};

}  // namespace uslp::validation