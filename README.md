# uni.ccsds

C library implementing the CCSDS Unified Space Data Link Protocol (USLP, CCSDS 732.1-B-3) with the Space Data Link
Security option (SDLS, CCSDS 355.0-B-2). Allocation-free core (the caller supplies all buffers), C17, tested with
Catch2 and cross-validated against the NASA USLP reference implementation.

Version 2.0.0 — see [docs/uslp_sdls.md](docs/uslp_sdls.md#migration-from-1x) for the SDLS API changes from 1.x.

## Features

- Frame build and accept: fixed- and variable-length frames, truncated frames, OID frames, Insert Zone, OCF, FECF
  (CRC-16/CCITT), VCF counters with loss/duplicate detection.
- Services: MAPA, MAP Packet, VC Packet, VCA, Octet Stream, Insert, OCF, VCF, MCF, COP management primitives.
- SDLS: Security Association table with 16-bit SPI, AES-GCM / AES-CCM / HMAC-SHA-256, Annex E baseline profile,
  authenticated Primary and Security Headers, anti-replay per §4.2.4.4 (plus an opt-in sliding window for diversity
  reception), transmit SN persistence and restore, per-reason rejection codes and counters.
- TM synchronization and channel coding (`uni_ccsds_tm.h`, CCSDS 131.0-B-5): Attached Sync Marker, pseudo-randomizer,
  rate 1/2 K = 7 convolutional encoder, and the Eb/N0 estimate from a channel symbol error rate.
- PICS: [docs/uslp_pics.md](docs/uslp_pics.md) (USLP) and [docs/uslp_sdls.md](docs/uslp_sdls.md) (SDLS, including the
  list of deviations from 355.0-B-2).

## Dependencies

- [uni.crypto](https://github.com/uni-libraries/uni.crypto) (CRC-16, AEAD, HMAC on Mbed TLS 3.x). As a top-level
  project it is fetched with CPM at the commit pinned in `cmake/cpm-uni.crypto.cmake`; override with
  `-DCPM_uni.crypto_SOURCE=<path>`. When embedded (`add_subdirectory`), the parent provides the `uni_crypto` target.
- Catch2 v3 for the tests (CPM, or an installed one with `-DCPM_USE_LOCAL_PACKAGES=ON`).

## Build and test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure

# sanitizers (GCC/Clang)
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DUNI_CCSDS_ENABLE_ASAN=ON -DUNI_CCSDS_ENABLE_UBSAN=ON -DUSLP_VALIDATION_WITH_NASA=OFF

# cross-validation against the NASA USLP reference (src_validation/)
build/src_validation/cli/uslp-validate --scenarios src_validation/resources/suites --artifact-dir build/validation --ci
```

Options: `UNI_CCSDS_ENABLE_ASAN`, `UNI_CCSDS_ENABLE_UBSAN`, `UNI_CCSDS_ENABLE_COVERAGE`, and the harness options in
`src_validation/CMakeLists.txt` (`USLP_VALIDATION_WITH_NASA`, `USLP_VALIDATION_WITH_PYTHON`).

Use from another project:

```cmake
add_subdirectory(path/to/uni.ccsds)
target_link_libraries(your_app PRIVATE uni_ccsds)
```

## Documentation

- [docs/uslp.md](docs/uslp.md) — API overview, memory model, errors, limits, examples
- [docs/uslp_sdls.md](docs/uslp_sdls.md) — SDLS model, profiles, receive procedure, PICS, deviations
- [docs/uslp_faq.md](docs/uslp_faq.md) — how-to sequences
- [examples/sdls_quickstart.c](examples/sdls_quickstart.c) — compiled and run by ctest
- API reference: `doxygen Doxyfile` (or `cmake --build build --target uni_ccsds_docs`) → `build/docs/html/index.html`

## CI

`.github/workflows/ci.yml`: GCC/Clang/MSVC build and tests, Clang ASan+UBSan, the NASA cross-validation harness, and
Doxygen with warnings as errors.

## License

MIT, see `LICENSE.md`.
