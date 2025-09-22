#include "uslp_validation/engine.hpp"
#include "uslp_validation/scenario.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifdef USLP_VALIDATION_WITH_PYTHON
  #include "uslp_validation/python_bridge.hpp"
#endif

#ifdef USLP_VALIDATION_WITH_NASA
  #include "uslp_validation/nasa_bridge.hpp"
#endif

extern "C" {
  #include "uni_ccsds_uslp.h"
  #include "uni_ccsds_uslp_internal.h"
}

namespace fs = std::filesystem;

namespace {

// Helpers to read scenario attributes
std::optional<std::string> get_attr(const uslp::validation::Scenario& scn, const char* key) {
    auto it = scn.attributes.find(key);
    if (it == scn.attributes.end()) return std::nullopt;
    return it->second;
}

std::string get_attr_str(const uslp::validation::Scenario& scn, const char* key, std::string def) {
    auto v = get_attr(scn, key);
    return v ? *v : std::move(def);
}

int get_attr_int(const uslp::validation::Scenario& scn, const char* key, int def) {
    auto v = get_attr(scn, key);
    if (!v) return def;
    try { return std::stoi(*v); } catch (...) { return def; }
}

bool parse_bool(const std::string& s, bool def) {
    std::string t; t.reserve(s.size());
    for (unsigned char c : s) t.push_back(static_cast<char>(std::tolower(c)));
    if (t == "1" || t == "true" || t == "yes" || t == "on") return true;
    if (t == "0" || t == "false" || t == "no" || t == "off") return false;
    return def;
}

bool get_attr_bool(const uslp::validation::Scenario& scn, const char* key, bool def) {
    auto v = get_attr(scn, key);
    return v ? parse_bool(*v, def) : def;
}

// File utilities
bool write_binary(const fs::path& path, const std::vector<std::uint8_t>& data, std::string& diag) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) { diag += "open failed: " + path.string() + "\n"; return false; }
    ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!ofs) { diag += "write failed: " + path.string() + "\n"; return false; }
    return true;
}
bool write_text(const fs::path& path, const std::string& text, std::string& diag) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    std::ofstream ofs(path);
    if (!ofs) { diag += "open failed: " + path.string() + "\n"; return false; }
    ofs << text;
    if (!ofs) { diag += "write failed: " + path.string() + "\n"; return false; }
    return true;
}

// Payload builders
std::vector<std::uint8_t> build_space_packet_payload(std::size_t total_len, int pvn) {
    // NASA PoC getPacketLength() expects CCSDS header bytes [4,5] to carry the (len-minus-1) field
    // and assumes a primary header of 6 octets. We craft a minimal header accordingly.
    const std::size_t min_len = 7; // 6 header + at least 1 data (because len field is "minus one")
    std::size_t n = std::max(total_len, min_len);
    std::vector<std::uint8_t> buf(n, 0);

    // First octet: PVN in bits 0..2 (MSB-first semantics not enforced here; PoC does not check)
    buf[0] = static_cast<std::uint8_t>((pvn & 0x07) << 5); // PVN in top 3 bits

    // Length field at bytes [4],[5]: total length minus primary header (6) minus one
    std::size_t sp_len_field = (n >= 6) ? (n - 6 - 1) : 0;
    buf[4] = static_cast<std::uint8_t>((sp_len_field >> 8) & 0xFF);
    buf[5] = static_cast<std::uint8_t>(sp_len_field & 0xFF);

    // Fill human-readable trailer for easier diffs
    for (std::size_t i = 6; i < n; ++i) {
        buf[i] = static_cast<std::uint8_t>(0x41 + (i - 6) % 26); // 'A'..'Z'
    }
    return buf;
}

std::vector<std::uint8_t> build_payload(const uslp::validation::Scenario& scn) {
    const std::string profile = get_attr_str(scn, "payload_profile", "map_packet_nominal");
    const int length = get_attr_int(scn, "payload_length", 64);
    const int pvn = get_attr_int(scn, "pvn", 0);

    if (profile == "map_packet_nominal") {
        return build_space_packet_payload(static_cast<std::size_t>(length), pvn);
    }
    if (profile == "mapa_boundary") {
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(length));
        for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<std::uint8_t>(i & 0xFF);
        return buf;
    }
    if (profile == "octet_stream_2k") {
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(length));
        for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<std::uint8_t>(0x30 + (i % 10)); // '0'..'9'
        return buf;
    }
    if (profile == "truncated_sample") {
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(length), 0xEE);
        return buf;
    }
    // Fallback
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(std::max(1, length)), 0xAB);
    return buf;
}

// Local USLP adapters
enum class LocalService { Packet, MAPA, OctetStream };

LocalService service_from_upid(int upid) {
    switch (upid) {
        case 5: return LocalService::MAPA;         // MAPA_SDU
        case 4: return LocalService::OctetStream;  // Octet Stream
        default: return LocalService::Packet;      // MAP Packet
    }
}

struct LocalDecodeSink {
    uint8_t expect_vcid{};
    uint8_t expect_mapid{};
    std::vector<uint8_t> sdu;
    static void sdu_cb(uni_uslp_context_t*, uint8_t vcid, uint8_t map_id, uni_uslp_service_type_t,
                       const uint8_t* sdu_data, size_t sdu_len,
                       uni_uslp_verification_status_t, bool, void* user) {
        auto* self = static_cast<LocalDecodeSink*>(user);
        if (vcid != self->expect_vcid || map_id != self->expect_mapid) return;
        self->sdu.assign(sdu_data, sdu_data + sdu_len);
    }
};

std::string init_default_params(uni_uslp_managed_params_t& p,
                                const uslp::validation::Scenario& scn,
                                uint16_t scid) {
    // Zero-init then set a minimal, standard-compliant configuration
    std::memset(&p, 0, sizeof(p));
    // Physical/MC/VC defaults
    // Avoid dangling pointer: keep null or a static literal (builder does not require PC name)
    p.physical_channel_name = nullptr;

    // Frame length policy from scenario:
    // - fixed: min == max (use attr.fixed_frame_length or default 256)
    // - variable: min != max (defaults)
    const std::string ftype = get_attr_str(scn, "frame_type", "variable");
    if (ftype == "fixed") {
        int fixed_len = get_attr_int(scn, "fixed_frame_length", 256);
        if (fixed_len < static_cast<int>(UNI_USLP_MIN_FRAME_LENGTH)) fixed_len = static_cast<int>(UNI_USLP_MIN_FRAME_LENGTH);
        if (fixed_len > static_cast<int>(UNI_USLP_MAX_FRAME_LENGTH)) fixed_len = static_cast<int>(UNI_USLP_MAX_FRAME_LENGTH);
        p.max_frame_length = static_cast<uint16_t>(fixed_len);
        p.min_frame_length = static_cast<uint16_t>(fixed_len);
    } else {
        p.max_frame_length      = UNI_USLP_MAX_FRAME_LENGTH;
        p.min_frame_length      = UNI_USLP_MIN_FRAME_LENGTH;
    }
    p.truncated_frame_capable = true;
    {
        int tlen = static_cast<int>(UNI_USLP_TRUNCATED_MIN_LENGTH);
        if (ftype == "truncated") {
            const int payload_len_for_trunc = get_attr_int(scn, "payload_length", 1);
            tlen = static_cast<int>(UNI_USLP_TRUNCATED_PH_LENGTH) + 1 + payload_len_for_trunc;
            if (tlen < static_cast<int>(UNI_USLP_TRUNCATED_MIN_LENGTH)) tlen = static_cast<int>(UNI_USLP_TRUNCATED_MIN_LENGTH);
            if (tlen > 32) tlen = 32;
        }
        p.truncated_frame_length = static_cast<uint16_t>(tlen);
    }
    p.mcf_count_length = 1;
    p.mc_mux_scheme    = UNI_USLP_MC_MUX_SINGLE;
    p.vc_mux_scheme    = UNI_USLP_VC_MUX_SINGLE;
    // VC counters: no VCF count in PH by default
    p.vcf_count_length = 0;
    p.vcf_seq_count_len_octets = 0;
    p.vcf_exp_count_len_octets = 0;
    p.vcf_persist = false;
    p.vcf_duplicate_window = 1;
    p.cop_in_effect = UNI_USLP_COP_NONE;
    p.map_mux_scheme = UNI_USLP_MAP_MUX_SINGLE;
    // OCF and IZ capability inferred from attributes
    const bool has_iz   = get_attr_bool(scn, "has_insert_zone", false);
    const int  iz_len   = get_attr_int(scn, "insert_zone_len", has_iz ? 12 : 0);
    p.ocf_capability         = false;
    p.insert_zone_capability = has_iz;
    p.insert_zone_length     = static_cast<uint16_t>(std::max(0, iz_len));
    // MAP/TFDF options
    const bool has_fecf = get_attr_bool(scn, "has_fecf", false);
    p.fecf_capability = has_fecf;
    p.segmentation_permitted = true;
    p.blocking_permitted = true;
    p.max_sdu_length = UNI_USLP_MAX_SDU_SIZE;
    // Packet transfer params
    p.valid_pvns_mask = 0x01; // allow PVN 0
    p.max_packet_length = 4096;
    p.deliver_incomplete_packets = false;

    std::ostringstream oss;
    oss << "params(scid=" << scid
        << ", iz=" << (has_iz ? "Y" : "N")
        << ", fecf=" << (has_fecf ? "Y" : "N") << ")";
    return oss.str();
}

bool local_encode_frame(const uslp::validation::Scenario& scn,
                        const std::vector<std::uint8_t>& payload,
                        std::vector<std::uint8_t>& out_frame,
                        std::string& diag) {
    uni_uslp_context_t ctx{};
    const uint16_t scid = static_cast<uint16_t>(get_attr_int(scn, "scid", 42));
    const uint8_t  vcid = static_cast<uint8_t>(get_attr_int(scn, "vcid", 0));
    const uint8_t  mapid= static_cast<uint8_t>(get_attr_int(scn, "mapid", 0));
    const int      upid = get_attr_int(scn, "upid", 0);
    const bool expedited = get_attr_str(scn, "bypass", "sequence") == "expedited";
    const std::string frame_type = get_attr_str(scn, "frame_type", "variable");

    uni_uslp_managed_params_t params{};
    diag += init_default_params(params, scn, scid) + "\n";

    if (uni_ccsds_uslp_init(&ctx, scid, &params) != UNI_USLP_SUCCESS) {
        diag += "local: init failed\n";
        return false;
    }
    if (uni_ccsds_uslp_configure_vc(&ctx, vcid, &params) != UNI_USLP_SUCCESS) {
        diag += "local: configure_vc failed\n";
        return false;
    }

    LocalService svc = service_from_upid(upid);
    // Truncated frames shall carry one complete MAPA_SDU (Annex D), override service mapping
    if (frame_type == "truncated") {
        svc = LocalService::MAPA;
    }
    uni_uslp_service_type_t svc_type = UNI_USLP_SERVICE_PACKET;
    switch (svc) {
        case LocalService::Packet:      svc_type = UNI_USLP_SERVICE_PACKET; break;
        case LocalService::MAPA:        svc_type = UNI_USLP_SERVICE_MAPA; break;
        case LocalService::OctetStream: svc_type = UNI_USLP_SERVICE_OCTET_STREAM; break;
    }
    if (uni_ccsds_uslp_configure_map(&ctx, vcid, mapid, svc_type, &params) != UNI_USLP_SUCCESS) {
        diag += "local: configure_map failed\n";
        return false;
    }


    // Optional Insert Zone
    if (params.insert_zone_capability && params.insert_zone_length > 0) {
        std::vector<std::uint8_t> iz(params.insert_zone_length, 0x49 /*'I'*/);
        (void)uni_ccsds_uslp_send_insert(&ctx, vcid, iz.data(), iz.size());
    }

    uni_uslp_status_t st = UNI_USLP_SUCCESS;
    switch (svc) {
        case LocalService::Packet: {
            const int pvn = get_attr_int(scn, "pvn", 0);
            st = uni_ccsds_uslp_send_packet_ex(&ctx, vcid, mapid, payload.data(), payload.size(),
                                               static_cast<uint8_t>(pvn), expedited, 0);
            break;
        }
        case LocalService::MAPA:
            st = uni_ccsds_uslp_send_mapa(&ctx, vcid, mapid, payload.data(), payload.size());
            break;
        case LocalService::OctetStream:
            st = uni_ccsds_uslp_send_octet_stream_ex(&ctx, vcid, mapid, payload.data(), payload.size(),
                                                     expedited, 0);
            break;
    }
    if (st != UNI_USLP_SUCCESS) {
        diag += "local: send_* failed: " + std::string(uni_ccsds_uslp_status_string(st)) + "\n";
        return false;
    }

    // Build frame
    std::vector<std::uint8_t> frame(UNI_USLP_MAX_FRAME_LENGTH);
    size_t out_len = frame.size();

    if (frame_type == "truncated") {
        st = uni_ccsds_uslp_build_truncated(&ctx, vcid, frame.data(), &out_len);
    } else {
        st = uni_ccsds_uslp_build_frame(&ctx, vcid, mapid, frame.data(), &out_len);
    }
    if (st != UNI_USLP_SUCCESS) {
        diag += "local: build_frame failed: " + std::string(uni_ccsds_uslp_status_string(st)) + "\n";
        return false;
    }
    frame.resize(out_len);


    out_frame = std::move(frame);
    return true;
}

bool local_decode_frame(const uslp::validation::Scenario& scn,
                        const std::vector<std::uint8_t>& frame,
                        std::vector<std::uint8_t>& out_payload,
                        std::string& diag) {
    uni_uslp_context_t ctx{};
    const uint16_t scid = static_cast<uint16_t>(get_attr_int(scn, "scid", 42));
    const uint8_t  vcid = static_cast<uint8_t>(get_attr_int(scn, "vcid", 0));
    const uint8_t  mapid= static_cast<uint8_t>(get_attr_int(scn, "mapid", 0));

    uni_uslp_managed_params_t params{};
    diag += init_default_params(params, scn, scid) + "\n";

    if (uni_ccsds_uslp_init(&ctx, scid, &params) != UNI_USLP_SUCCESS) { diag += "local(rx): init failed\n"; return false; }
    if (uni_ccsds_uslp_configure_vc(&ctx, vcid, &params) != UNI_USLP_SUCCESS) { diag += "local(rx): cfg vc failed\n"; return false; }
    if (uni_ccsds_uslp_configure_map(&ctx, vcid, mapid, UNI_USLP_SERVICE_PACKET, &params) != UNI_USLP_SUCCESS) {
        // Service type here is not critical for generic SDU callback
    }

    LocalDecodeSink sink{};
    sink.expect_vcid = vcid;
    sink.expect_mapid = mapid;
    (void)uni_ccsds_uslp_register_sdu_callback(&ctx, vcid, mapid, &LocalDecodeSink::sdu_cb, &sink);

    const uni_uslp_status_t st = uni_ccsds_uslp_accept_frame(&ctx, frame.data(), frame.size());
    if (st != UNI_USLP_SUCCESS) {
        diag += "local(rx): accept_frame failed: " + std::string(uni_ccsds_uslp_status_string(st)) + "\n";
        return false;
    }
    out_payload = std::move(sink.sdu);
    return true;
}

} // namespace

namespace uslp::validation {

Engine::Engine(Config config) : config_{std::move(config)} {}

std::vector<ScenarioOutcome> Engine::run(const ScenarioPack& pack) const {
    std::vector<ScenarioOutcome> outcomes;
    outcomes.reserve(pack.scenarios.size());

#ifdef USLP_VALIDATION_WITH_PYTHON
    // Prepare Python bridge once
    // Resolve absolute project root for runner and spacepackets src
    const fs::path project_root =
    #ifdef USLP_VALIDATION_PROJECT_ROOT
        fs::path(USLP_VALIDATION_PROJECT_ROOT);
    #else
        fs::current_path();
    #endif
    ;

    python_bridge::Session::Config py_cfg;
    py_cfg.python_exe   = "python3";
    py_cfg.runner_script= project_root / "src_validation/bridges/python/runner/runner.py";
    py_cfg.spacepackets_src = project_root / "src_validation/3rdparty/spacepackets-py/src";
    py_cfg.work_dir     = config_.artifact_root / "tmp_py";

    python_bridge::Session py(py_cfg);
    std::string py_init_diag;
    bool py_ok = py.init(py_init_diag);
#else
    bool py_ok = false;
#endif

#ifdef USLP_VALIDATION_WITH_NASA
    // Prepare NASA bridge once
    nasa_bridge::Session::Config na_cfg;
    {
        const fs::path project_root2 =
        #ifdef USLP_VALIDATION_PROJECT_ROOT
            fs::path(USLP_VALIDATION_PROJECT_ROOT);
        #else
            fs::current_path();
        #endif
        ;
        na_cfg.mib_config = project_root2 / "src_validation/3rdparty/nasa-uslp/mibconfig";
    }
    nasa_bridge::Session na(na_cfg);
    std::string na_init_diag;
    bool na_ok = na.init(na_init_diag);
#else
    bool na_ok = false;
#endif

    for (const auto& scenario : pack.scenarios) {
        std::string diag;
        const fs::path art_dir = config_.artifact_root / scenario.suite / scenario.id;
        std::error_code ec; fs::create_directories(art_dir, ec);

        // Build input payload per scenario
        const auto payload = build_payload(scenario);
        (void)write_binary(art_dir / "payload.bin", payload, diag);

        // Local encode
        std::vector<std::uint8_t> local_frame;
        bool local_ok = local_encode_frame(scenario, payload, local_frame, diag);
        if (local_ok) {
            (void)write_binary(art_dir / "local_frame.bin", local_frame, diag);
        } else {
            (void)write_text(art_dir / "local_diag.txt", diag, diag);
        }

        bool all_pass = true;
        std::ostringstream msg;

        // Route: Local -> Python decode
        if (scenario.actors.python_decode) {
#ifdef USLP_VALIDATION_WITH_PYTHON
            if (py_ok && local_ok) {
                python_bridge::Session::DecodeBundle py_out{};
                python_bridge::Session::FrameBundle in{};
                in.frame = local_frame;
                std::string py_diag;
                const bool ok = py.decode(scenario, in, py_out, py_diag);
                (void)write_text(art_dir / "python_diag.txt", py_diag, diag);
                (void)write_binary(art_dir / "python_decoded.bin", py_out.payload, diag);

                if (!ok) {
                    all_pass = false;
                    msg << "[Local->Python:DECODE_ERR] ";
                } else if (py_out.payload != payload) {
                    all_pass = false;
                    msg << "[Local->Python:MISMATCH] ";
                } else {
                    msg << "[Local->Python:PASS] ";
                }
            } else {
                all_pass = false;
                if (!py_ok) { msg << "[Local->Python:FAIL] "; }
                else if (!local_ok) { msg << "[Local->Python:FAIL] "; }
                else { msg << "[Local->Python:FAIL] "; }
            }
#else
            all_pass = false;
            msg << "[Local->Python:FAIL] ";
#endif
        }

        // Route: Local -> NASA decode
        if (scenario.actors.nasa_decode) {
#ifdef USLP_VALIDATION_WITH_NASA
            if (na_ok && local_ok) {
                nasa_bridge::Session::DecodeBundle na_out{};
                nasa_bridge::Session::FrameBundle in{};
                in.frame = local_frame;
                std::string na_diag;
                const bool ok = na.decode(scenario, in, na_out, na_diag);
                (void)write_text(art_dir / "nasa_diag.txt", na_diag, diag);
                (void)write_binary(art_dir / "nasa_decoded.bin", na_out.payload, diag);

                if (!ok) {
                    all_pass = false;
                    msg << "[Local->NASA:DECODE_ERR] ";
                } else if (na_out.payload != payload) {
                    // NOTE: For PC2 (fixed + IZ + FECF) the local builder may not yet emit IZ/FECF.
                    // Mismatches are expected until IZ/FECF piping is implemented.
                    all_pass = false;
                    msg << "[Local->NASA:MISMATCH] ";
                } else {
                    msg << "[Local->NASA:PASS] ";
                }
            } else {
                all_pass = false;
                if (!na_ok) { msg << "[Local->NASA:FAIL] "; }
                else if (!local_ok) { msg << "[Local->NASA:FAIL] "; }
                else { msg << "[Local->NASA:FAIL] "; }
            }
#else
            all_pass = false;
            msg << "[Local->NASA:FAIL] ";
#endif
        }

        // Optional: NASA/Python -> Local decode (only if actors request it)
        if (scenario.actors.python_encode) {
#ifdef USLP_VALIDATION_WITH_PYTHON
            if (py_ok) {
                python_bridge::Session::FrameBundle py_enc{};
                std::string py_diag;
                if (py.encode(scenario, payload, py_enc, py_diag)) {
                    (void)write_binary(art_dir / "python_frame.bin", py_enc.frame, diag);
                    std::vector<std::uint8_t> rx_payload;
                    std::string rx_diag;
                    if (local_decode_frame(scenario, py_enc.frame, rx_payload, rx_diag) && rx_payload == payload) {
                        msg << "[Python->Local:PASS] ";
                    } else {
                        all_pass = false;
                        msg << "[Python->Local:FAIL] ";
                    }
                    (void)write_text(art_dir / "local_rx_from_python.txt", rx_diag, diag);
                    (void)write_binary(art_dir / "local_rx_from_python.bin", rx_payload, diag);
                } else {
                    all_pass = false;
                    msg << "[Python:ENCODE_ERR] ";
                }
                (void)write_text(art_dir / "python_encode_diag.txt", py_diag, diag);
            } else {
                all_pass = false;
                msg << "[Python->Local:FAIL] ";
            }
#endif
        }

        if (scenario.actors.nasa_encode) {
#ifdef USLP_VALIDATION_WITH_NASA
            if (na_ok) {
                nasa_bridge::Session::FrameBundle na_enc{};
                std::string na_diag2;
                if (na.encode(scenario, payload, na_enc, na_diag2)) {
                    (void)write_binary(art_dir / "nasa_frame.bin", na_enc.frame, diag);
                    std::vector<std::uint8_t> rx_payload;
                    std::string rx_diag;
                    if (local_decode_frame(scenario, na_enc.frame, rx_payload, rx_diag) && rx_payload == payload) {
                        msg << "[NASA->Local:PASS] ";
                    } else {
                        all_pass = false;
                        msg << "[NASA->Local:FAIL] ";
                    }
                    (void)write_text(art_dir / "local_rx_from_nasa.txt", rx_diag, diag);
                    (void)write_binary(art_dir / "local_rx_from_nasa.bin", rx_payload, diag);
                } else {
                    all_pass = false;
                    msg << "[NASA:ENCODE_ERR] ";
                }
                (void)write_text(art_dir / "nasa_encode_diag.txt", na_diag2, diag);
            } else {
                all_pass = false;
                msg << "[NASA->Local:FAIL] ";
            }
#endif
        }

        ScenarioOutcome outcome{};
        outcome.scenario = scenario;
        outcome.status = all_pass ? "PASS" : "FAIL";
        outcome.message = msg.str();

        // Persist diagnostic accumulator as well
        (void)write_text(art_dir / "engine_diag.txt", diag + outcome.message + "\n", diag);

        outcomes.push_back(std::move(outcome));
    }

    if (outcomes.empty()) {
        ScenarioOutcome placeholder{};
        placeholder.scenario.id = "placeholder";
        placeholder.scenario.suite = pack.source_file;
        placeholder.status = "SKIP";
        placeholder.message = "no scenarios provided";
        outcomes.push_back(std::move(placeholder));
    }

    return outcomes;
}

}  // namespace uslp::validation