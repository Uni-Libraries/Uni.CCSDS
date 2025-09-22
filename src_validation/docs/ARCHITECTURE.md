# USLP Validation Harness Architecture

## 1. Objectives
- Deliver reproducible cross-validation runs across UNI, NASA reference, and IRS spacepackets implementations.
- Demonstrate coverage of CCSDS 732.1-B-3 §1.4.1 (interoperability objectives) and the managed parameter behaviours defined in §4.1–§4.6.
- Produce machine-readable artefacts for CI gating and human-friendly HTML reports for reviews.
- Remain composable so that additional actors (e.g., new vendors) can be plugged in with minimal boilerplate.

## 2. Source Layout
- `src_validation/harness/`: core engine, scenario loader, metrics writer.
- `src_validation/bridges/nasa/`: wrapper library compiling the NASA proof-of-concept sources with capture hooks.
- `src_validation/bridges/python/`: subprocess bridge and optional embedded interpreter wrapper.
- `src_validation/resources/`: default scenario packs, JSON schema, HTML templates.
- `src_validation/cli/`: command-line front-end wiring options to engine APIs.
- `src_validation/tests/`: Catch2 coverage for loader, engine, bridges.

## 3. Scenario Ingestion
1. Declarative files use YAML (or JSON) and are validated against `resources/schema/scenario.schema.json`.
2. `ScenarioLoader` normalises each file into a `ScenarioPack` containing flat attributes and actor flags.
3. Matrix expansion occurs in a dedicated expander component that produces concrete permutations per suite.
4. Loader guarantees deterministic ordering (sorted file paths + stable iteration) to keep CI results reproducible.

### 3.1 Attribute Semantics
- Mandatory keys: suite (default = file stem), id (auto numbered when omitted).
- Common attributes: vcid, mapid, tfdf.construction_rule, payload.profile, segmentation.flag, sdls.profile.
- Unknown keys are preserved verbatim so that bridges can interpret implementation-specific tunables.
- Actor flags (`actor.local_encode`, etc.) decide which encoders/decoders must be exercised for the scenario.

## 4. Engine Lifecycle
The `Engine` runs each scenario in the following phases:
1. **Pre-flight** – ensures artifact directories exist, materialises scenario-specific working folders, fetches shared resources (e.g., default payload corpora).
2. **Actor Preparation** – lazily initialises each actor (local, NASA, Python) only when a scenario requires it. Managed parameter changes trigger cache invalidation (`Scenario` attributes hashed).
3. **Execution Graph** – builds ordered steps: local encode → NASA decode, NASA encode → local decode, etc., depending on actor flags. Each step is modelled as a `ValidationEdge` with inputs, expected outputs, and assertion callbacks.
4. **Comparison & Assertions** – normalises frames, TFDFs, and service units before comparison. Differences are emitted both as structured JSON and colourised HTML snippets referencing CCSDS clauses.
5. **Metrics Collection** – records wall-clock + cpu time, digest fingerprints (CRC32 + SHA256), and verdicts.
6. **Teardown** – keeps actors alive for reuse unless scenario attributes request isolation.

## 5. Actor Interface
All actors implement a thin C++ interface:

```cpp
struct Actor {
    virtual ~Actor() = default;
    virtual EncodeResult encode(const Scenario&);
    virtual DecodeResult decode(const Scenario&, const EncodedFrame&);
};
```

Implementations:
- **LocalActor** – wraps existing `uni_ccsds` encode/decode APIs, exposing payload assembly helpers and error context.
- **NasaActor** – links statically against the patched NASA sources, providing deterministic capture buffers instead of UDP sockets.
- **PythonActor** – communicates with the spacepackets library via JSON-RPC. A reusable helper manages launching the interpreter, request multiplexing, and timeouts.

### 5.1 NASA Bridge
- Build system defines `USLP_VALIDATION_CAPTURE` to replace UDP sockets with in-memory capture buffers.
- `nasa_bridge::Session` loads `mibconfig`, prepares MAPID/VCID state, and exposes C APIs:
  - `nasa_bridge_encode(const Scenario&, FrameBundle&)`
  - `nasa_bridge_decode(const Scenario&, const FrameBundle&, DecodeBundle&)`
- Capture buffers yield TFDF raw bytes, MAPA SDUs, OCF payloads, and diagnostic logs.
- Errors map to a structured enum, preserving NASA diagnostic messages in outcome logs.

### 5.2 Python Bridge
- Default mode launches the vendored `python_runner.py` via a portable process wrapper.
- Request payload: scenario metadata, action (encode/decode), payload hex/base64, managed parameter overrides.
- Response payload: status, frame bytes, semantic fields, log stream, timing.
- Optional embed mode uses `pybind11` to execute the same entry points inside the host process (guarded by `USLP_VALIDATION_EMBED_PYTHON`).
- Both modes share JSON schema for requests/responses, validated at runtime for robustness.

## 6. Artifact Layout
For each scenario we create `<artifact_root>/<suite>/<scenario-id>/` containing:
- `inputs/`: expanded scenario description, payload corpora.
- `frames/`: `<actor>-<action>.bin`, `<actor>-<action>.hex`.
- `logs/`: structured JSON and textual debug logs from each actor.
- `diffs/`: HTML diff files when mismatches occur.
- `metrics.json`: per-scenario metrics consumed by the summary writer.
The top-level summary (`summary.json`, `summary.csv`) and HTML report are emitted under `<artifact_root>/reports/`.

## 7. Reporting
- `MetricsWriter::write_summary()` produces JSON with aggregate counts and scenario records.
- `MetricsWriter::write_detailed()` renders standalone HTML with CSS embedded for easy artifact sharing.
- Both functions ensure parent directories exist and are safe for parallel writes via coarse file locks (future enhancement).
- Reports embed CCSDS references so reviewers can jump to relevant clauses when inspecting failures.

## 8. CLI & CTest Integration
- `uslp-validate` CLI accepts options:
  - `--suite`, `--scenario` (glob filters)
  - `--artifact-dir`
  - `--threads` (worker pool size)
  - `--emit-html`, `--emit-jsonl`, `--emit-csv`
  - `--ci` (enforces deterministic paths, suppresses HTML)
- CTest target `validation` invokes the CLI with `--ci` and canonical scenario packs.
- Exit codes follow: 0 success, 1 failures, 2 configuration errors, 3 internal errors.

## 9. Concurrency & Extensibility
- Engine exposes a thread-safe queue; each worker consumes scenarios while respecting actor reuse constraints (NASA session not thread-safe, Python runner serialised).
- Future actors can be registered via a factory discovered from scenario attributes (e.g., `actor.vendor=acme`).
- Payload generators pluggable via strategy objects bound through scenario attributes (`payload.generator=pcap:/path`).
- Hooks exist for SDLS security plug-ins to assert authentication tags per CCSDS 355.x guidelines.

## 10. Compliance Hooks
- Each assertion attaches metadata: CCSDS clause, managed parameter reference, and coverage bucket.
- `docs/CCSDS-USLP-PICS.md` gains an auto-generated section summarising latest run status (timestamp + suite).
- Scenario packs include boundary cases (max MAP A SDU, truncated frames, segmentation flags) mandated by CCSDS 732.1-B-3 Annex A.