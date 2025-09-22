#pragma once

#include "scenario.hpp"

#include <filesystem>
#include <vector>

namespace uslp::validation {

/**
 * \brief Loads declarative validation scenarios from disk.
 *
 * The loader currently understands a lightweight line-oriented syntax that is easy to
 * author by hand and friendly to version control. Each file is composed of one or more
 * scenario blocks separated by a line containing three dashes (`---`). Within a block,
 * key/value pairs take the form `key=value` with leading/trailing whitespace ignored.
 *
 * Recognised keys:
 *   - `suite`: Optional logical grouping name. Falls back to the file stem.
 *   - `id`: Optional scenario identifier. Falls back to `<file-stem>#<index>`.
 *   - `attr.<name>`: Arbitrary attribute propagated to the execution engine.
 *   - `actor.<field>`: Boolean flag selecting encoder/decoder participants. Valid fields are
 *                      `local_encode`, `local_decode`, `nasa_encode`, `nasa_decode`,
 *                      `python_encode`, `python_decode`. Boolean values honour `true/false`,
 *                      `yes/no`, and `1/0` (case-insensitive).
 *
 * Example:
 * \code{.txt}
 * suite=baseline
 * id=mapa_with_insert
 * attr.map_id=5
 * attr.payload_length=256
 * actor.nasa_decode=true
 * ---
 * attr.map_id=6
 * attr.payload_length=1024
 * actor.python_decode=true
 * \endcode
 *
 * Lines starting with `#` or empty lines are ignored. Unknown keys are preserved as generic
 * attributes (without the `attr.` prefix).
 */
class ScenarioLoader {
public:
    ScenarioLoader() = default;

    [[nodiscard]] ScenarioPack load(const std::filesystem::path& file) const;

    [[nodiscard]] std::vector<ScenarioPack> load_directory(const std::filesystem::path& root) const;
};

}  // namespace uslp::validation