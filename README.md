# Recursive hashing benchmarks for ZK

## Goal

Create rough benchmarks for Nova vs Circom / Halo2 for recursive hashing.

Inspired by https://github.com/celer-network/zk-benchmark but doing hashing
recursively to take advantage of things like Nova+IVC.

That is, computations of the form $h(h(h(h(h(x)))))$, or similar.

Assuming useful, upstream to zk-benchmark and/or https://www.zk-bench.org/

## Details

Can also generalize to Merkle Tree.

Initially SHA256, but later on Keccak256.

NOTE: Different curves

### Parameters

- `k` steps
- `t` paralleization/threads (or similar)

(Ignoring `n` preimage size for now)

### Targets

- Nova
- Circom
- Halo2?

## How to run

- Make sure update submodules first: `git submodule update --init --recursive`
- You also need Circom setup with pasta curves, see https://github.com/nalinbhardwaj/Nova-Scotia#how

For Circom benchmarks:

`./circom/compile.sh`

For Nova:

```
(cd nova/examples/sha256/circom && npm install)
./nova/examples/sha256/circom/compile.sh
(cd nova && cargo run --examples sha256_wasm --release)
```

## Initial results

### Hardware

Run on Macbook Pro M1 Max (2021), 64GB memory

### Prover time

| n     | Circom | Nova (total) | Nova (step sum) |
|-------|--------|--------------|-----------------|
| 1     | 0.3s   | 0.2s         | 0.1s            |
| 10    | 7.3s   | 2.4s         | 1.2s            |
| 100   | 62s    | 24s          | 12.5s           |
| 1000  | -      | 240s         | 125s            |


### Notes

- Circom constrains grow O(n) from 30k, and thus runs out of powers of tau quickly (ptau23 needed for n=100, 3m constraints) - compilation starts to take a long tme on n=100 too
- Nova's prove step time is ~120-130ms, without witness/WASM file overhead this is a factor of two - summing up each individual time we get a "step sum"
- Nova only counts the recursive proof part not the SNARK verify part (currently done with Spartan using IPA-PC, not a huge overhead)
- For Nova at n=1000 we sometimes get segfault with wasm => run C++ prover prover (doesn't work on M1) or wee_alloc allocator (intermittent problems work)
- For Nova, number of constraints per step is constant at ~44k for primary circuit and ~10k for secondary