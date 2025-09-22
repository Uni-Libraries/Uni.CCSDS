#include "uslp_validation/metrics_writer.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

using nlohmann::json;

json outcome_to_json(const uslp::validation::ScenarioOutcome& outcome) {
    json attributes = json::object();
    for (const auto& [key, value] : outcome.scenario.attributes) {
        attributes[key] = value;
    }

    json actor_flags = {
        {"local_encode", outcome.scenario.actors.local_encode},
        {"local_decode", outcome.scenario.actors.local_decode},
        {"nasa_encode", outcome.scenario.actors.nasa_encode},
        {"nasa_decode", outcome.scenario.actors.nasa_decode},
        {"python_encode", outcome.scenario.actors.python_encode},
        {"python_decode", outcome.scenario.actors.python_decode},
    };

    return json{
        {"id", outcome.scenario.id},
        {"suite", outcome.scenario.suite},
        {"status", outcome.status},
        {"message", outcome.message},
        {"attributes", std::move(attributes)},
        {"actors", std::move(actor_flags)},
    };
}

json build_summary(const std::vector<uslp::validation::ScenarioOutcome>& outcomes) {
    json summary = {
        {"total", outcomes.size()},
        {"by_status", json::object()},
        {"scenarios", json::array()},
    };

    auto& by_status = summary["by_status"];
    for (const auto& outcome : outcomes) {
        summary["scenarios"].push_back(outcome_to_json(outcome));
        auto& counter = by_status[outcome.status];
        if (!counter.is_number()) {
            counter = 0;
        }
        counter = counter.get<std::size_t>() + 1;
    }

    return summary;
}

std::string escape_html(const std::string& input) {
    std::ostringstream oss;
    for (char ch : input) {
        switch (ch) {
            case '&':
                oss << "&amp;";
                break;
            case '<':
                oss << "<";
                break;
            case '>':
                oss << ">";
                break;
            case '"':
                oss << "\"";
                break;
            case '\'':
                oss << "'";
                break;
            default:
                oss << ch;
        }
    }
    return oss.str();
}

std::string attributes_to_html(const std::map<std::string, std::string>& attributes) {
    if (attributes.empty()) {
        return {};
    }
    std::ostringstream oss;
    oss << "<ul>";
    for (const auto& [key, value] : attributes) {
        oss << "<li><strong>" << escape_html(key) << ":</strong> " << escape_html(value)
            << "</li>";
    }
    oss << "</ul>";
    return oss.str();
}

std::string actors_to_html(const uslp::validation::ActorMatrix& actors) {
    std::ostringstream oss;
    oss << "<ul>";
    oss << "<li>local_encode: " << (actors.local_encode ? "true" : "false") << "</li>";
    oss << "<li>local_decode: " << (actors.local_decode ? "true" : "false") << "</li>";
    oss << "<li>nasa_encode: " << (actors.nasa_encode ? "true" : "false") << "</li>";
    oss << "<li>nasa_decode: " << (actors.nasa_decode ? "true" : "false") << "</li>";
    oss << "<li>python_encode: " << (actors.python_encode ? "true" : "false") << "</li>";
    oss << "<li>python_decode: " << (actors.python_decode ? "true" : "false") << "</li>";
    oss << "</ul>";
    return oss.str();
}

std::string render_html(const std::vector<uslp::validation::ScenarioOutcome>& outcomes) {
    std::ostringstream oss;
    oss << "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>"
        << "<title>USLP Validation Report</title>"
        << "<style>"
        << "body{font-family:system-ui, sans-serif;margin:2rem;}"
        << "table{border-collapse:collapse;width:100%;}"
        << "th,td{border:1px solid #ccc;padding:0.5rem;vertical-align:top;}"
        << "th{background:#f5f5f5;text-align:left;}"
        << ".status-PASS{color:#0a7c2f;font-weight:bold;}"
        << ".status-FAIL{color:#c1121f;font-weight:bold;}"
        << ".status-SKIP{color:#7a7a7a;}"
        << ".status-BLOCKED{color:#ff8800;font-weight:bold;}"
        << ".status-ERROR{color:#b000b5;font-weight:bold;}"
        << "</style></head><body>";

    oss << "<h1>USLP Validation Report</h1>";

    std::map<std::string, std::size_t> counts;
    for (const auto& outcome : outcomes) {
        ++counts[outcome.status];
    }

    oss << "<section><h2>Summary</h2><ul>";
    oss << "<li>Total scenarios: " << outcomes.size() << "</li>";
    for (const auto& [status, count] : counts) {
        oss << "<li>" << escape_html(status) << ": " << count << "</li>";
    }
    oss << "</ul></section>";

    oss << "<section><h2>Scenarios</h2><table>";
    oss << "<thead><tr>"
        << "<th>#</th>"
        << "<th>Suite</th>"
        << "<th>Scenario</th>"
        << "<th>Status</th>"
        << "<th>Message</th>"
        << "<th>Attributes</th>"
        << "<th>Actors</th>"
        << "</tr></thead><tbody>";

    for (std::size_t index = 0; index < outcomes.size(); ++index) {
        const auto& outcome = outcomes[index];
        const auto status_class = "status-" + outcome.status;

        oss << "<tr>";
        oss << "<td>" << (index + 1) << "</td>";
        oss << "<td>" << escape_html(outcome.scenario.suite) << "</td>";
        oss << "<td>" << escape_html(outcome.scenario.id) << "</td>";
        oss << "<td class=\"" << escape_html(status_class) << "\">"
            << escape_html(outcome.status) << "</td>";
        oss << "<td>" << escape_html(outcome.message) << "</td>";
        oss << "<td>" << attributes_to_html(outcome.scenario.attributes) << "</td>";
        oss << "<td>" << actors_to_html(outcome.scenario.actors) << "</td>";
        oss << "</tr>";
    }

    oss << "</tbody></table></section>";
    oss << "</body></html>";
    return oss.str();
}

void ensure_parent(const std::filesystem::path& destination) {
    const auto parent = destination.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::filesystem::create_directories(parent);
    }
}

void write_file(const std::filesystem::path& destination, const std::string& content) {
    ensure_parent(destination);
    std::ofstream output(destination, std::ios::binary);
    if (!output.is_open()) {
        throw std::runtime_error("Unable to open output file: " + destination.string());
    }
    output << content;
}

}  // namespace

namespace uslp::validation {

void MetricsWriter::write_summary(const std::filesystem::path& destination,
                                  const std::vector<ScenarioOutcome>& outcomes) const {
    const json summary = build_summary(outcomes);
    write_file(destination, summary.dump(2));
}

void MetricsWriter::write_detailed(const std::filesystem::path& destination,
                                   const std::vector<ScenarioOutcome>& outcomes) const {
    const auto html = render_html(outcomes);
    write_file(destination, html);
}

}  // namespace uslp::validation