# AirBB Threshold Anonymous Credentials

This repository implements a Rust prototype of the "AirBB: Lightweight Threshold Anonymous Credentials without Random Oracles from BB Signatures" paper, including tests and benchmarks.

Builds on the [arkworks](https://github.com/arkworks-rs/algebra) BLS12-381 elliptic curve implementation and uses Criterion for benchmarks. After running the benchmarks, the results are written in the `target/criterion` directory.
The benchmarks include non-blind and blind signing (issuance), presentation, verification, and (for the threshold variant) partial-signature aggregation.
For a comparison, the benchmarks additionally cover the BBS signature scheme from the [docknetwork/crypto](https://github.com/docknetwork/crypto) library.

## Getting Started

```bash
cargo test                               # Run all tests
cargo bench                              # Run all benchmarks
cargo bench --bench signing              # Only run signing benchmarks
cargo bench --bench presentation present # Only run credential presentation benchmarks
cargo bench --bench threshold            # Only run threshold aggregation benchmarks
cargo bench --bench bbs                  # Only run benchmarks for BBS
```

## Benchmark Report

The benchmark numbers below compare the AirBB prototype against BBS on the same BLS12-381 curve. 
All benchmarks below were run on a MacBook Pro with an Apple M3 Max chip and 36 GB of RAM.

### Runtime comparison

| Attributes | AirBB issuance | BBS issuance | AirBB blind issuance | BBS blind issuance | AirBB presentation verification | BBS presentation verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.525 ms | 0.379 ms | 2.043 ms | 0.440 ms | 3.243 ms | 1.435 ms |
| 10 | 0.614 ms | 0.466 ms | 2.132 ms | 0.785 ms | 3.324 ms | 1.529 ms |
| 25 | 0.693 ms | 0.528 ms | 2.271 ms | 0.972 ms | 3.475 ms | 1.644 ms |
| 50 | 0.788 ms | 0.614 ms | 2.420 ms | 1.017 ms | 3.574 ms | 1.722 ms |
| 100 | 0.941 ms | 0.716 ms | 2.612 ms | 1.191 ms | 3.778 ms | 2.023 ms |


Issuance corresponds to the signing benchmark (`sign`), blind issuance corresponds to the blind signing benchmark (`blind_sign`), and presentation verification corresponds to `verify_present` for a credential with selective disclosure.

### Presentation size comparison

For a presentation with `n` hidden attributes, the proof size is roughly:

- BBS: `2 * G1 + (3 + n) * F = 96 + (3 + n) * 32` bytes
- AirBB: Constant-size with `3 * G1 + G2 = 240` bytes

| Hidden attributes | AirBB | BBS |
| --- | ---: | ---: |
| 1 | 240 B | 224 B |
| 10 | 240 B | 512 B |
| 25 | 240 B | 992 B |
| 50 | 240 B | 1,792 B |
| 100 | 240 B | 3,392 B |

### Threshold aggregation cost

The threshold variant adds an aggregation step over the partial signatures.
The benchmark isolates the aggregation, since partial and blind-partial signing are analogous to the already-benchmarked non-threshold methods and thus have essentially the same cost profile. 
The additional runtime overhead introduced is therefore dominated by the Lagrange interpolation step used during aggregation. 
Presentation and verification remain the same as in the non-threshold setting.

We report the mean aggregation runtime for different threshold parameters `(t, n)` below.

| Threshold `(t, n)` | Aggregation time |
| --- | ---: |
| `(2, 3)` | 484.00 µs    |
| `(3, 5)` | 489.40 µs    |
| `(5, 8)` | 531.30 µs    |
| `(10, 15)` | 700.80 µs  |
| `(100, 150)` | 14.12 ms |
