#include "../include/uslp_validation/python_bridge.hpp"
#include "../../harness/include/uslp_validation/scenario.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace uslp::validation::python_bridge {

static std::string quote(const std::string& s) {
    std::ostringstream os;
    os << '\"' << s << '\"';
    return os.str();
}

static std::string quote(const fs::path& p) { return quote(p.string()); }

static bool write_binary(const fs::path& p, const std::vector<std::uint8_t>& data, std::string& diag) {
    std::error_code ec;
    if (auto parent = p.parent_path(); !parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            diag += "Failed to create directory " + parent.string() + ": " + ec.message() + "\n";
            return false;
        }
    }
    std::ofstream ofs(p, std::ios::binary);
    if (!ofs) {
        diag += "Failed to open for write: " + p.string() + "\n";
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!ofs) {
        diag += "Short write: " + p.string() + "\n";
        return false;
    }
    return true;
}

static bool read_binary(const fs::path& p, std::vector<std::uint8_t>& out, std::string& diag) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) {
        diag += "Failed to open for read: " + p.string() + "\n";
        return false;
    }
    ifs.seekg(0, std::ios::end);
    const auto sz = static_cast<std::size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz > 0) {
        ifs.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
        if (!ifs) {
            diag += "Short read: " + p.string() + "\n";
            return false;
        }
    }
    return true;
}

static std::string read_text(const fs::path& p) {
    std::ifstream ifs(p);
    if (!ifs) return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

static void parse_kv_file(const fs::path& p, std::map<std::string, std::string>& out) {
    std::ifstream ifs(p);
    if (!ifs) return;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        auto key = line.substr(0, pos);
        auto val = line.substr(pos + 1);
        // trim spaces
        auto ltrim = [](std::string& s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        };
        auto rtrim = [](std::string& s) {
            s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
        };
        ltrim(key); rtrim(key);
        ltrim(val); rtrim(val);
        out[key] = val;
    }
}

static fs::path make_unique_dir(const fs::path& base, const std::string& prefix) {
    auto now = std::chrono::system_clock::now();
    auto since_epoch = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    std::ostringstream os;
    os << prefix << since_epoch;
    return base / os.str();
}

Session::Session(Config cfg) : cfg_(std::move(cfg)) {}

static int run_cmd(const std::string& cmd, std::string& diag) {
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        diag += "cmd failed: " + cmd + " rc=" + std::to_string(rc) + "\n";
    }
    return rc;
}

bool Session::init(std::string& diag_out) {
    if (ready_) return true;

    if (cfg_.runner_script.empty() || !fs::exists(cfg_.runner_script)) {
        diag_out += "Python runner script not found at: " + cfg_.runner_script.string() + "\n";
        return false;
    }
    if (cfg_.spacepackets_src.empty() || !fs::exists(cfg_.spacepackets_src)) {
        diag_out += "spacepackets source root not found at: " + cfg_.spacepackets_src.string() + "\n";
        return false;
    }

    // Ensure work_dir exists (or fallback to system temp)
    std::error_code ec;
    fs::path base_tmp = fs::temp_directory_path(ec);
    fs::path work_root = cfg_.work_dir.empty() ? base_tmp : cfg_.work_dir;
    if (!cfg_.work_dir.empty()) {
        fs::create_directories(cfg_.work_dir, ec);
        if (ec) {
            diag_out += "Failed to create work_dir: " + cfg_.work_dir.string() + " : " + ec.message() + "\n";
            return false;
        }
    }

    // Probe Python importability of vendored spacepackets without relying on pip.
    // Create a temporary probe script to avoid shell quoting pitfalls.
    const fs::path probe_dir = make_unique_dir(work_root, "pyprobe_");
    fs::create_directories(probe_dir, ec);
    if (ec) {
        diag_out += "Failed to create probe dir: " + probe_dir.string() + " : " + ec.message() + "\n";
        return false;
    }
    const fs::path probe_script = probe_dir / "probe.py";
    {
        std::ofstream ofs(probe_script);
        if (!ofs) {
            diag_out += "Failed to create probe script: " + probe_script.string() + "\n";
            return false;
        }
        ofs << "import sys\n";
        ofs << "sys.path.insert(0, r'" << cfg_.spacepackets_src.string() << "')\n";
        ofs << "try:\n";
        ofs << "    import spacepackets\n";
        ofs << "    print('ok')\n";
        ofs << "except Exception:\n";
        ofs << "    import traceback\n";
        ofs << "    traceback.print_exc()\n";
        ofs << "    raise\n";
    }

    const std::string cmd = quote(cfg_.python_exe) + " " + quote(probe_script);
    const int rc = run_cmd(cmd, diag_out);
    if (rc != 0) {
        diag_out += "Python bridge init failed during probe\n";
        return false;
    }

    ready_ = true;
    return true;
}

static std::optional<std::string> attr_of(const Scenario& scn, const char* key) {
    auto it = scn.attributes.find(key);
    if (it == scn.attributes.end()) return std::nullopt;
    return it->second;
}

bool Session::encode(const ::uslp::validation::Scenario& scenario,
                     const std::vector<std::uint8_t>& payload,
                     FrameBundle& out,
                     std::string& diag_out) const {
    if (!ready_) {
        diag_out += "Python bridge not initialized\n";
        return false;
    }
    std::error_code ec;
    const fs::path base = cfg_.work_dir.empty() ? fs::temp_directory_path(ec) : cfg_.work_dir;
    fs::path out_dir = make_unique_dir(base, "pyenc_");
    fs::create_directories(out_dir, ec);
    if (ec) {
        diag_out += "Failed to create out_dir: " + out_dir.string() + " : " + ec.message() + "\n";
        return false;
    }

    const fs::path payload_path = out_dir / "payload.bin";
    if (!write_binary(payload_path, payload, diag_out)) {
        return false;
    }

    // Compose command
    std::ostringstream cmd;
    cmd << quote(cfg_.python_exe) << " " << quote(cfg_.runner_script) << " encode"
        << " --spacepackets-src " << quote(cfg_.spacepackets_src)
        << " --payload " << quote(payload_path)
        << " --out " << quote(out_dir);

    // Optional scenario-driven overrides
    if (auto scid = attr_of(scenario, "scid")) cmd << " --scid " << quote(*scid);
    if (auto vcid = attr_of(scenario, "vcid")) cmd << " --vcid " << quote(*vcid);
    if (auto mapid = attr_of(scenario, "mapid")) cmd << " --mapid " << quote(*mapid);
    if (auto upid = attr_of(scenario, "upid")) cmd << " --upid " << quote(*upid);
    if (auto ftype = attr_of(scenario, "frame_type")) cmd << " --frame-type " << quote(*ftype);
    if (auto has_fecf = attr_of(scenario, "has_fecf")) cmd << " --has-fecf " << quote(*has_fecf);

    const int rc = std::system(cmd.str().c_str());
    if (rc != 0) {
        diag_out += "Runner encode failed, rc=" + std::to_string(rc) + "\n";
        diag_out += "Cmd: " + cmd.str() + "\n";
        // try to read diag
    }

    const fs::path frame_path = out_dir / "frame.bin";
    const fs::path tfdf_path  = out_dir / "tfdf.bin";
    const fs::path diag_path  = out_dir / "diag.txt";

    // Try to read diag even if rc==0
    {
        auto diag_txt = read_text(diag_path);
        if (!diag_txt.empty()) {
            diag_out += diag_txt;
            if (!diag_txt.empty() && diag_txt.back() != '\n') diag_out += "\n";
        }
    }

    std::vector<std::uint8_t> frame_bytes;
    std::vector<std::uint8_t> tfdf_bytes;
    bool ok = true;
    ok &= read_binary(frame_path, frame_bytes, diag_out);
    ok &= read_binary(tfdf_path, tfdf_bytes, diag_out);
    if (!ok) {
        if (frame_bytes.empty()) diag_out += "Missing or empty frame.bin\n";
        if (tfdf_bytes.empty()) diag_out += "Missing or empty tfdf.bin\n";
        return false;
    }

    out.frame = std::move(frame_bytes);
    out.tfdf  = std::move(tfdf_bytes);
    return rc == 0;
}

bool Session::decode(const ::uslp::validation::Scenario& scenario,
                     const FrameBundle& in,
                     DecodeBundle& out,
                     std::string& diag_out) const {
    if (!ready_) {
        diag_out += "Python bridge not initialized\n";
        return false;
    }
    if (in.frame.empty()) {
        diag_out += "No input frame bytes for decode\n";
        return false;
    }

    std::error_code ec;
    const fs::path base = cfg_.work_dir.empty() ? fs::temp_directory_path(ec) : cfg_.work_dir;
    fs::path out_dir = make_unique_dir(base, "pydec_");
    fs::create_directories(out_dir, ec);
    if (ec) {
        diag_out += "Failed to create out_dir: " + out_dir.string() + " : " + ec.message() + "\n";
        return false;
    }

    const fs::path frame_path = out_dir / "frame.bin";
    if (!write_binary(frame_path, in.frame, diag_out)) {
        return false;
    }

    // Compose command
    std::ostringstream cmd;
    cmd << quote(cfg_.python_exe) << " " << quote(cfg_.runner_script) << " decode"
        << " --spacepackets-src " << quote(cfg_.spacepackets_src)
        << " --frame " << quote(frame_path)
        << " --out " << quote(out_dir);

    // Optional scenario-driven hints
    if (auto ftype = attr_of(scenario, "frame_type")) cmd << " --frame-type " << quote(*ftype);
    if (auto has_fecf = attr_of(scenario, "has_fecf")) cmd << " --has-fecf " << quote(*has_fecf);
    if (auto iz = attr_of(scenario, "has_insert_zone")) cmd << " --iz " << quote(*iz);
    if (auto izlen = attr_of(scenario, "insert_zone_len")) cmd << " --iz-len " << quote(*izlen);
    if (auto trunc = attr_of(scenario, "truncated_frame_len")) cmd << " --trunc-len " << quote(*trunc);

    const int rc = std::system(cmd.str().c_str());
    if (rc != 0) {
        diag_out += "Runner decode failed, rc=" + std::to_string(rc) + "\n";
        diag_out += "Cmd: " + cmd.str() + "\n";
    }

    const fs::path payload_path = out_dir / "payload.bin";
    const fs::path fields_path  = out_dir / "fields.txt";
    const fs::path diag_path    = out_dir / "diag.txt";

    // diagnostics (best-effort)
    {
        auto diag_txt = read_text(diag_path);
        if (!diag_txt.empty()) {
            diag_out += diag_txt;
            if (!diag_txt.empty() && diag_txt.back() != '\n') diag_out += "\n";
        }
    }

    std::vector<std::uint8_t> payload_bytes;
    bool ok = read_binary(payload_path, payload_bytes, diag_out);
    if (!ok) {
        diag_out += "Missing or empty payload.bin\n";
        return false;
    }
    out.payload = std::move(payload_bytes);

    std::map<std::string, std::string> kv;
    parse_kv_file(fields_path, kv);
    out.fields = std::move(kv);

    return rc == 0;
}

}  // namespace uslp::validation::python_bridge