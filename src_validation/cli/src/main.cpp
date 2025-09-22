#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <iterator>

#include "uslp_validation/engine.hpp"
#include "uslp_validation/metrics_writer.hpp"
#include "uslp_validation/scenario_loader.hpp"

using uslp::validation::Engine;
using uslp::validation::MetricsWriter;
using uslp::validation::ScenarioLoader;
using uslp::validation::ScenarioOutcome;
using uslp::validation::ScenarioPack;

namespace {

struct Args {
    std::vector<std::filesystem::path> scenario_paths;
    std::filesystem::path artifact_root{"build/validation"};
    std::filesystem::path summary_path{};
    std::filesystem::path html_path{};
    bool emit_html{true};
    bool help{false};
};

void print_usage(const char* argv0) {
    std::cerr
        << "USLP Cross-Validation CLI\n"
        << "Usage:\n"
        << "  " << argv0 << " --scenarios <file-or-dir> [--scenarios <file-or-dir> ...]\n"
        << "                 [--artifact-dir <dir>] [--summary <path>] [--html <path>] [--ci]\n"
        << "\n"
        << "Options:\n"
        << "  --scenarios    One or more scenario files or directories (line-oriented *.scn).\n"
        << "  --artifact-dir Root directory for outputs (default: build/validation).\n"
        << "  --summary      Write JSON summary to this path (default: <artifact-dir>/summary.json).\n"
        << "  --html         Write HTML report to this path (default: <artifact-dir>/report.html).\n"
        << "  --ci           CI mode: suppress HTML generation (JSON only), deterministic paths.\n"
        << "  -h, --help     Show this help message.\n"
        << "\n"
        << "Default: Without arguments, scans src_validation/resources/suites for all *.scn recursively.\n"
        << std::endl;
}

bool arg_eq(std::string_view a, std::string_view b) {
    return a == b;
}

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string_view tok = argv[i];
        if (arg_eq(tok, "-h") || arg_eq(tok, "--help")) {
            args.help = true;
            break;
        } else if (arg_eq(tok, "--scenarios")) {
            if (i + 1 >= argc) {
                throw std::runtime_error("--scenarios expects a value");
            }
            args.scenario_paths.emplace_back(argv[++i]);
        } else if (arg_eq(tok, "--artifact-dir")) {
            if (i + 1 >= argc) {
                throw std::runtime_error("--artifact-dir expects a value");
            }
            args.artifact_root = std::filesystem::path(argv[++i]);
        } else if (arg_eq(tok, "--summary")) {
            if (i + 1 >= argc) {
                throw std::runtime_error("--summary expects a value");
            }
            args.summary_path = std::filesystem::path(argv[++i]);
        } else if (arg_eq(tok, "--html")) {
            if (i + 1 >= argc) {
                throw std::runtime_error("--html expects a value");
            }
            args.html_path = std::filesystem::path(argv[++i]);
        } else if (arg_eq(tok, "--ci")) {
            args.emit_html = false;
        } else {
            // Treat as scenario path for convenience
            args.scenario_paths.emplace_back(std::string(tok));
        }
    }

    if (args.scenario_paths.empty()) {
        // Provide a sensible default if the user hasn't supplied scenarios:
        // try the baseline suite within the repository.
        const auto fallback_root = std::filesystem::path("src_validation/resources/suites");
        if (std::filesystem::exists(fallback_root) && std::filesystem::is_directory(fallback_root)) {
            // Scan all scenarios recursively from resources/suites
            args.scenario_paths.push_back(fallback_root);
        } else {
            // Fallback to baseline.scn if directory is unavailable
            const auto fallback_file = fallback_root / "baseline.scn";
            if (std::filesystem::exists(fallback_file)) {
                args.scenario_paths.push_back(fallback_file);
            } else {
                throw std::runtime_error(
                    "No scenarios specified and no resources found under src_validation/resources/suites");
            }
        }
    }

    if (args.summary_path.empty()) {
        args.summary_path = args.artifact_root / "summary.json";
    }
    if (args.html_path.empty()) {
        args.html_path = args.artifact_root / "report.html";
    }

    return args;
}

int aggregate_exit_code(const std::vector<ScenarioOutcome>& outcomes) {
    bool any_fail = false;
    bool any_error = false;
    bool any_blocked = false;
    for (const auto& o : outcomes) {
        if (o.status == "ERROR") any_error = true;
        else if (o.status == "FAIL") any_fail = true;
        else if (o.status == "BLOCKED") any_blocked = true;
    }
    if (any_error || any_fail || any_blocked) return 1;
    return 0; // PASS or SKIP only
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto args = parse_args(argc, argv);
        if (args.help) {
            print_usage(argv[0]);
            return 0;
        }

        // Load scenarios (each file or directory yields a pack)
        ScenarioLoader loader;
        std::vector<ScenarioPack> packs;
        for (const auto& path : args.scenario_paths) {
            auto loaded = loader.load_directory(path);
            packs.insert(packs.end(),
                         std::make_move_iterator(loaded.begin()),
                         std::make_move_iterator(loaded.end()));
        }

        // Execute engine per pack
        std::vector<ScenarioOutcome> all_outcomes;
        // Ensure artifact root exists
        std::filesystem::create_directories(args.artifact_root);
        Engine engine(Engine::Config{.artifact_root = args.artifact_root});
        for (const auto& pack : packs) {
            auto partial = engine.run(pack);
            all_outcomes.insert(all_outcomes.end(),
                                std::make_move_iterator(partial.begin()),
                                std::make_move_iterator(partial.end()));
        }

        // Emit artifacts
        MetricsWriter writer;
        writer.write_summary(args.summary_path, all_outcomes);
        if (args.emit_html) {
            writer.write_detailed(args.html_path, all_outcomes);
        }

        // Console summary
        std::size_t total = all_outcomes.size();
        std::size_t pass_cnt = 0, fail_cnt = 0, skip_cnt = 0, blk_cnt = 0, err_cnt = 0;
        for (const auto& o : all_outcomes) {
            if (o.status == "PASS") ++pass_cnt;
            else if (o.status == "FAIL") ++fail_cnt;
            else if (o.status == "SKIP") ++skip_cnt;
            else if (o.status == "BLOCKED") ++blk_cnt;
            else if (o.status == "ERROR") ++err_cnt;
        }

        std::cout << "USLP Validation\n"
                  << "  Scenarios: " << total << "\n"
                  << "  PASS: " << pass_cnt << "  FAIL: " << fail_cnt
                  << "  BLOCKED: " << blk_cnt << "  ERROR: " << err_cnt
                  << "  SKIP: " << skip_cnt << "\n"
                  << "Artifacts:\n"
                  << "  JSON: " << args.summary_path << "\n";
        if (args.emit_html) {
            std::cout << "  HTML: " << args.html_path << "\n";
        }

        return aggregate_exit_code(all_outcomes);
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        print_usage(argv[0]);
        return 2; // configuration/environment issue
    } catch (...) {
        std::cerr << "ERROR: Unknown exception\n";
        return 3; // internal error
    }
}