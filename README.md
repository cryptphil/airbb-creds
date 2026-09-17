# AirBB Threshold Anonymous Credentials

This repository implements a Rust prototype of the "AirBB: Lightweight Threshold Anonymous Credentials without Random Oracles from BB Signatures" paper, including tests and benchmarks.

Builds on the [arkworks](https://github.com/arkworks-rs/algebra) BLS12-381 elliptic curve implementation.

## Getting Started

The project uses Criterion for benchmarking.
Run the following commands to run the tests and specific benchmarks:

```bash
cargo test                               # Run all tests
cargo bench                              # Run all benchmarks
cargo bench --bench signing              # Only benchmark signing
cargo bench --bench presentation         # Only benchmark credential presentation & verification
cargo bench --bench threshold            # Only benchmark threshold aggregation
cargo bench --bench bbs                  # Only run BBS benchmarks
```

After running the benchmarks, Criterion writes the results to the `target/criterion` directory.

## Benchmark Report

The benchmarks include non-blind and blind signing (issuance), presentation,
verification, and, for the threshold variant, partial-signature aggregation.
For comparison, they also cover the BBS signature scheme from the [docknetwork/crypto](https://github.com/docknetwork/crypto) library.

The benchmark numbers below compare the AirBB prototype against BBS on the same BLS12-381 curve.
All benchmarks below were run on a MacBook Pro with an Apple M3 Max chip and 36 GB of RAM.

### Runtime comparison

| Attributes | AirBB issuance | BBS issuance | AirBB blind issuance | BBS blind issuance | AirBB presentation verification | BBS presentation verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.512 ms | 0.377 ms | 1.476 ms | 0.431 ms | 1.818 ms | 1.410 ms |
| 10 | 0.602 ms | 0.473 ms | 1.563 ms | 0.781 ms | 1.912 ms | 1.512 ms |
| 25 | 0.663 ms | 0.530 ms | 1.709 ms | 0.947 ms | 2.057 ms | 1.642 ms |
| 50 | 0.799 ms | 0.614 ms | 1.836 ms | 1.019 ms | 2.177 ms | 1.729 ms |
| 100 | 0.930 ms | 0.718 ms | 2.058 ms | 1.199 ms | 2.449 ms | 1.910 ms |


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
Aggregation combines a Lagrange interpolation step over the `t` participating shares with one group scalar multiplication per share; for large `t` the scalar multiplications dominate the cost.
Presentation and verification remain the same as in the non-threshold setting.

We report the mean aggregation runtime for different threshold parameters `(t, n)` below.

| Threshold `(t, n)` | Aggregation time |
| --- | ---: |
| `(2, 3)` | 524.90 µs    |
| `(3, 5)` | 550.40 µs    |
| `(5, 8)` | 532.90 µs    |
| `(10, 15)` | 674.50 µs  |
| `(100, 150)` | 1.63 ms  |
