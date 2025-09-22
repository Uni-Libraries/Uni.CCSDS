# Unified USLP Cross-Validation Suite

## 1. Mission and Scope  
The validation harness ensures that the local UNI USLP stack proves interoperable with two independent implementations, satisfying CCSDS 732.1-B-3 §1.4.1 (interoperability objectives) and §4.1–§4.6 (service profiles, TFDF construction, managed parameters, SDLS encapsulation). The suite delivers repeatable, automated confidence checks across:

- **Local implementation** (C23 core in [`src/uslp.c`](../src/uslp.c))
- **NASA C++ reference** (proof-of-concept code in [`src_validation/3rdparty/nasa-uslp`](3rdparty/nasa-uslp))
- **IRS Spacepackets Python stack** (modern USLP API in [`src_validation/3rdparty/spacepackets-py`](3rdparty/spacepackets-py))

## 2. Architectural Overview  

```
┌─────────────────────────────┐
│ Declarative Test Matrix     │  (YAML / JSON5)
└──────────────┬──────────────┘
               │
        ┌──────▼──────┐
        │ Scenario    │
        │ Expander    │  Generates Cartesian permutations (CCSDS 732.1-B-3 §4.1.4)
        └──────┬──────┘
               │
     ┌─────────▼─────────┐
     │ Validation Engine │
     │ (C++ executable)  │
     └─────────┬─────────┘
     Local     │     NASA Bridge        Python Bridge
  ┌────────┐   │   ┌─────────────┐     ┌─────────────┐
  │uni.uslp│◄──┼──►│nasa_bridge  │◄──►│Py runner     │
  └────────┘   │   └─────────────┘     └─────────────┘
               │
     ┌─────────▼─────────┐
     │ Metrics & Artifacts│
     │ JSON / CSV / HTML │  (CCSDS 732.1-B-3 §1.6 verification logs)
     └─────────┬─────────┘
               │
     ┌─────────▼──────────┐
     │ CLI & CI frontends │
     └────────────────────┘
```

### Core Components
| Component | Description |
|-----------|-------------|
| **Scenario Expander** | Normalizes user-supplied declarative test descriptions into concrete permutations (VCID, MAPID, FHP/LVO modes, segmentation flags, SDLS options per §7). |
| **Validation Engine** | C++17 binary that orchestrates encode/decode flows, marshals reference implementations, records timing, and synthesizes results. |
| **NASA Bridge** | Thin wrapper around `mibclass` providing deterministic encode/decode without UDP I/O. Captures frames, MAPA SDUs, OCF per §4.1.4.1.6. |
| **Python Bridge** | Spawns the `spacepackets` interpreter inside a controlled environment, exchanging JSON over stdin/stdout. Covers USLP frame and service APIs. |
| **Metrics Collector** | Aggregates verdicts, diffs, and timing. Emits machine-readable JSONL (one record per scenario) and optional CSV. |
| **Report Generator** | Builds HTML (standalone) with coverage tables, charts, and hyperlinks to raw artifacts (CCSDS PICS mapping §1.6). |
| **CLI Frontend** | `uslp-validate` executable enabling filters, report regeneration, and CI-friendly exit codes. |

## 3. CMake & Directory Layout  

| Path | Purpose |
|------|---------|
| [`src_validation/CMakeLists.txt`](CMakeLists.txt) | Root validation project entry; options for NASA/Python bridges, report generation, and packaging. |
| `src_validation/cmake/` | Helper modules (Python discovery, NASA build flags, YAML schema checks). |
| `src_validation/include/` | Public headers for harness consumers (e.g., custom CI drivers). |
| `src_validation/harness/` | Validation engine sources (`engine_main.cpp`, `scenario_loader.cpp`, `metrics_writer.cpp`). |
| `src_validation/bridges/nasa/` | Bridge wrappers (`nasa_bridge.cpp`) and patched NASA sources compiled as TUs. |
| `src_validation/bridges/python/` | Python entrypoint script (`runner.py`), C++ shim for process management. |
| `src_validation/resources/` | Default scenario packs (YAML), HTML templates, CSS, sample configs. |
| `src_validation/tools/` | Utilities (report regeneration, artifact pruning). |
| `src_validation/tests/` | Catch2 validation tests asserting harness invariants. |

Targets (namespace `uni_ccsds_validation::`):
1. `core` – engine library exposing scenario orchestration primitives.
2. `cli` – `uslp-validate` executable.
3. `nasa_bridge` (optional) – static lib with NASA wrapper and config loader.
4. `python_bridge` (optional) – helper linking against `Python::Python`, spawns interpreter if embedding disabled.
5. `reports` – custom command producing HTML from collected JSON.

## 4. Declarative Scenario Format  

YAML schema validated by `src_validation/resources/schema/scenario.schema.json`:

```yaml
suite: "baseline-nominal"
defaults:
  phys_channel: PC1
  vcid: 0
  mapid: 0
  bypass: sequence
  fecf: crc16-ccsds
  ocf_policy: absent
matrix:
  payload_profile: [map_packet_nominal, mapa_boundary, octet_stream_2k]
  segmentation_flag: [single, begin, middle, end]
  sdls_profile: [none, aes-gcm-256]
  nasa_role: [encode, decode]
  python_role: [encode, decode]
```

Each expanded scenario records:
- Packet/service metadata (per CCSDS 732.1-B-3 §4.1)
- Input payload fingerprint (CRC32 + SHA256)
- Expected TFDF header bits (Construction Rule, UPID, FHP/LVO)
- Actors executed and verdict (PASS/FAIL/SKIP/BLOCKED)
- Timings (wall/CPU) and errors collected.

## 5. Execution Pipeline  

1. **Load & Validate** scenario files (YAML → JSON AST) with schema + custom validators for CCSDS managed parameters (e.g., MAPID/VCID coherence).
2. **Expand Matrix** into deterministic order; support `--filter` (glob) and `--limit`.
3. **Prepare Actors**  
   - Local: direct calls into `uni_ccsds_uslp_build_frame()` and parser wrappers.  
   - NASA: initialize once per suite (load `mibconfig`), re-use map handles.  
   - Python: ensure venv, install `spacepackets` editable, warm interpreter (imports).  
4. **Execute** encode/decode combos, capturing frames and semantic outputs (MAPA SDU reassembly, OCF counters, SDLS verification flags).  
5. **Compare** canonicalized artifacts (bit-perfect frame, service semantics, managed parameter compliance) and annotate mismatches with diffs (hex + field-level explanation referencing CCSDS clauses).  
6. **Record** metrics, logs, and raw artifacts (stored under `build/validation/artifacts/<suite>/<scenario_id>/`).  
7. **Generate Reports** (HTML + JSON summary, CSV for regression dashboards).  

## 6. NASA Reference Integration  

- Build the existing sources under a controlled compilation unit with `-DUSLP_VALIDATION_CAPTURE` to replace UDP sockets by in-memory capture hooks (CCSDS 732.1-B-3 §4.1.4.1.6).  
- Provide wrapper functions:
  - `nasa_init(config_path)` – load `mibconfig`, prepare maps.  
  - `nasa_encode(const Scenario&, const Payload&, Frame&)` – produce full frame.  
  - `nasa_decode(const Scenario&, const Frame&, DecodeResult&)` – parse frame, output service units.  
- Use mutex-protected capture buffers to intercept `kphysicalChannel::txFrame`.  
- Expose errors (`bool` + rich error struct) for harness logging.

## 7. Python (`spacepackets`) Bridge  

- Re-use vendored source as Git submodule.  
- Harness executes `python_runner.py` with JSON RPC payload (scenario metadata, command).  
- Python script performs encode/decode with `spacepackets.uslp` classes, validates outputs, returns structured JSON.  
- Optional embedding via `pybind11` when `USLP_VALIDATION_EMBED_PYTHON=ON`.  

## 8. Metrics & Reporting  

Artifacts per scenario:
- `result.json` – canonical record (status, timings, digests, references to raw files).  
- `frame.hex`, `tfdf.bin`, `payload.bin`, `logs/*.txt`.  
- `diff/*.html` – colored diff for mismatches.  

Aggregated outputs:
- `summary.json` – JSONL file for trend dashboards.  
- `summary.csv` – optional, controlled by `--emit-csv`.  
- `report.html` – single-page summary (Bootstrap + D3) with filters, counts, CCSDS clause references.  
- PICS hooks: automatically update `docs/CCSDS-USLP-PICS.md` sections with latest coverage statuses (append table rows referencing suite and timestamp).

## 9. CLI Usage  

```
$ uslp-validate --suite baseline --scenario "*octet*" \
    --artifact-dir build/validation \
    --emit-html --emit-jsonl --threads 8
```

Exit codes:
- `0` success (all PASS)
- `1` failures detected
- `2` configuration or environment issues
- `3` internal harness errors

CI integration: add `ctest -L validation` target invoking the CLI with `--ci` (suppresses HTML, enforces deterministic output paths).

## 10. Roadmap / TODO

1. Implement NASA capture hook patch and bridge wrappers.  
2. Implement Python JSON-RPC runner and venv bootstrap logic.  
3. Flesh out scenario schema tests (Catch2).  
4. Build metrics writer + HTML template (with coverage overlay).  
5. Integrate CLI target and add GitHub Actions job.  
6. Update `docs/CCSDS-USLP-PICS.md` with validation table.  
7. Extend CLI with incremental run support (reuse artifacts).  
