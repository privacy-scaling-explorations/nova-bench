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

- `n` preimage
- `k` steps
- `t` threads (or similar)

### Targets

- Nova
- Circom
- Halo2?

## How to run

For Circom:

`./circom/compile.sh`

For Nova:

```
./nova/examples/sha256/circom/compile.sh
(cd nova && cargo run --examples sha256_wasm --release)
```
