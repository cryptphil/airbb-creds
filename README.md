# AirBB Threshold Anonymous Credentials

This repository implements a Rust prototype of the "AirBB: Lightweight Threshold Anonymous Credentials without Random Oracles from BB Signatures" paper, including tests and benchmarks.

Builds on the [arkworks](https://github.com/arkworks-rs/algebra) BLS12-381 elliptic curve implementation and uses Criterion for benchmarks. After running the benchmarks, you can find the results in the `target/criterion` directory.
The benchmarks include non-blind and blind signing (issuance), presentation, verification, and (for the threshold variant) partial-signature aggregation.
For a comparison, the benchmarks additionally cover the BBS signature scheme from the [docknetwork/crypto](https://github.com/docknetwork/crypto) library.

## Getting Started

```bash
cargo test                               # Run all tests
cargo bench                              # Run all benchmarks
cargo bench --bench signing              # Only run signing benchmarks of our scheme
cargo bench --bench presentation present # Only run credential presentation benchmarks of our scheme
cargo bench --bench threshold            # Only run threshold aggregation benchmarks
cargo bench --bench bbs                  # Only run benchmarks for the BBS signature scheme
```

## Benchmark Report

The benchmark numbers below compare the AirBB prototype against BBS on the same BLS12-381 curve. 
All benchmarks below were run on a MacBook Pro with an Apple M3 Max chip and 36 GB of RAM.

### Runtime comparison

| Attributes | AirBB issuance | BBS issuance | AirBB blind issuance | BBS blind issuance | AirBB presentation verification | BBS presentation verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.515 ms | 0.379 ms | 1.873 ms | 0.440 ms | 3.184 ms | 1.435 ms |
| 10 | 0.622 ms | 0.466 ms | 1.962 ms | 0.785 ms | 3.276 ms | 1.529 ms |
| 25 | 0.675 ms | 0.528 ms | 2.136 ms | 0.972 ms | 3.424 ms | 1.644 ms |
| 50 | 0.764 ms | 0.614 ms | 2.277 ms | 1.017 ms | 3.531 ms | 1.722 ms |
| 100 | 0.923 ms | 0.716 ms | 2.471 ms | 1.191 ms | 3.737 ms | 2.023 ms |


**Note**: Issuance corresponds to the signing benchmark (`sign`), blind issuance corresponds to the blind signing benchmark (`blind_sign`), and presentation verification corresponds to `verify_present` for a credential with selective disclosure.

### Presentation size comparison

For a presentation with `n` hidden attributes, the proof size is roughly:

- BBS: `2 * G1 + (3 + n) * F = 96 + (3 + n) * 32` bytes
- AirBB: constant-size proof, approximately `3 * G1 + G2 = 240` bytes

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
| `(2, 3)` | 605.45 µs    |
| `(3, 5)` | 613.14 µs    |
| `(5, 8)` | 664.26 µs    |
| `(10, 15)` | 891.85 µs  |
| `(100, 150)` | 20.24 ms |
