# uni.ccsds

C library implementing CCSDS USLP framing (CCSDS 732.1‑B‑3) with optional SDLS authenticated encryption (CCSDS 355.0‑B‑2). 

## Build
- Configure, build, test:
  - mkdir -p build && cmake -S . -B build
  - cmake --build build -j
  - ctest --test-dir build --output-on-failure
- Link from another project:
  - add_subdirectory(path/to/uni.ccsds)
  - target_link_libraries(your_app PRIVATE uni_ccsds)

## Docs

[[docs/uslp.md]]
