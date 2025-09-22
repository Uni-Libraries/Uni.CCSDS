#include "uslp_validation/scenario_loader.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view kWhitespace = " \t\n\r\f\v";

std::string trim_copy(std::string_view input) {
    const auto begin = input.find_first_not_of(kWhitespace);
    if (begin == std::string_view::npos) {
        return {};
    }
    const auto end = input.find_last_not_of(kWhitespace);
    return std::string{input.substr(begin, end - begin + 1)};
}

std::string to_lower_copy(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (unsigned char ch : input) {
        result.push_back(static_cast<char>(std::tolower(ch)));
    }
    return result;
}

bool parse_boolean(std::string_view raw,
                   const std::filesystem::path& file,
                   std::size_t line_no) {
    const auto lowered = to_lower_copy(raw);
    if (lowered == "true" || lowered == "yes" || lowered == "1") {
        return true;
    }
    if (lowered == "false" || lowered == "no" || lowered == "0") {
        return false;
    }
    throw std::runtime_error("Invalid boolean value '" + std::string{raw} + "' at " +
                             file.string() + ":" + std::to_string(line_no));
}

void apply_actor_flag(uslp::validation::ActorMatrix& actors,
                      const std::string& field,
                      bool value,
                      const std::filesystem::path& file,
                      std::size_t line_no) {
    using uslp::validation::ActorMatrix;

    if (field == "local_encode") {
        actors.local_encode = value;
    } else if (field == "local_decode") {
        actors.local_decode = value;
    } else if (field == "nasa_encode") {
        actors.nasa_encode = value;
    } else if (field == "nasa_decode") {
        actors.nasa_decode = value;
    } else if (field == "python_encode") {
        actors.python_encode = value;
    } else if (field == "python_decode") {
        actors.python_decode = value;
    } else {
        throw std::runtime_error("Unknown actor field '" + field + "' at " +
                                 file.string() + ":" + std::to_string(line_no));
    }
}

}  // namespace

namespace uslp::validation {

ScenarioPack ScenarioLoader::load(const std::filesystem::path& file) const {
    if (!std::filesystem::exists(file)) {
        throw std::runtime_error("Scenario file does not exist: " + file.string());
    }
    if (!std::filesystem::is_regular_file(file)) {
        throw std::runtime_error("Scenario path is not a regular file: " + file.string());
    }

    std::ifstream input(file);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open scenario file: " + file.string());
    }

    ScenarioPack pack;
    pack.source_file = file.string();

    std::string default_suite = file.stem().string();
    if (default_suite.empty()) {
        default_suite = file.filename().string();
    }
    if (default_suite.empty()) {
        default_suite = pack.source_file;
    }
    const std::string id_prefix = default_suite;

    Scenario current;
    current.suite = default_suite;

    auto reset_current = [&]() {
        current = Scenario{};
        current.suite = default_suite;
    };

    bool touched = false;

    auto push_current = [&]() {
        if (!touched) {
            reset_current();
            return;
        }
        if (current.suite.empty()) {
            current.suite = default_suite;
        }
        if (current.id.empty()) {
            current.id = id_prefix + "#" + std::to_string(pack.scenarios.size() + 1);
        }
        pack.scenarios.emplace_back(std::move(current));
        reset_current();
        touched = false;
    };

    std::string raw_line;
    std::size_t line_no = 0;
    while (std::getline(input, raw_line)) {
        ++line_no;

        const auto trimmed = trim_copy(raw_line);
        if (trimmed.empty() || trimmed.front() == '#') {
            continue;
        }

        if (trimmed == "---") {
            push_current();
            continue;
        }

        const auto delimiter = trimmed.find('=');
        if (delimiter == std::string::npos) {
            throw std::runtime_error("Expected 'key=value' entry at " + file.string() + ":" +
                                     std::to_string(line_no));
        }

        auto key = trim_copy(trimmed.substr(0, delimiter));
        auto value = trim_copy(trimmed.substr(delimiter + 1));

        if (key.empty()) {
            throw std::runtime_error("Empty key at " + file.string() + ":" +
                                     std::to_string(line_no));
        }

        touched = true;

        if (key == "suite") {
            current.suite = std::move(value);
        } else if (key == "id") {
            current.id = std::move(value);
        } else if (key.rfind("attr.", 0) == 0) {
            const auto attr_key = key.substr(5);
            if (attr_key.empty()) {
                throw std::runtime_error("Empty attribute name at " + file.string() + ":" +
                                         std::to_string(line_no));
            }
            current.attributes[attr_key] = std::move(value);
        } else if (key.rfind("actor.", 0) == 0) {
            const auto actor_field = key.substr(6);
            const bool flag_value = parse_boolean(value, file, line_no);
            apply_actor_flag(current.actors, actor_field, flag_value, file, line_no);
        } else {
            current.attributes[std::move(key)] = std::move(value);
        }
    }

    push_current();
    return pack;
}

std::vector<ScenarioPack> ScenarioLoader::load_directory(const std::filesystem::path& root) const {
    if (!std::filesystem::exists(root)) {
        throw std::runtime_error("Scenario root does not exist: " + root.string());
    }

    if (!std::filesystem::is_directory(root)) {
        return {load(root)};
    }

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            files.emplace_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end());

    std::vector<ScenarioPack> packs;
    packs.reserve(files.size());
    for (const auto& path : files) {
        packs.emplace_back(load(path));
    }
    return packs;
}

}  // namespace uslp::validation