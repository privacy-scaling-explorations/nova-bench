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

- (`n` preimage)
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

## Initial results

# Initial benchmarking

## Hardware

Run on Macbook Pro M1 Max (2021), 64GB memory

## Circom (proving)

### n=1

- 29636 non-linear constraints
- mem 694691.200000
- time 0.953000
- cpu 378.800000

### n=10

- non-linear constraints: 296360
- mem 148928.000000
- time 0.282000
- cpu 232.300000

### n=100

- Compiling starts to take a long time
- Circuit too big for this power of tau ceremony. 2963600*2 > 2**17
- => Need to download ptau23 (2**23=~8m) vs ~6m
- Increases linearly
- TODO: Download ptau23

## Nova

Number of constraints per step (primary circuit): 44176
Number of constraints per step (secondary circuit): 10347

(Same for all)

### n=1

RecursiveSNARK creation took 195.841458ms
CompressedSNARK::prove: true, took 3.099014917s

### n=10

Number of constraints per step (primary circuit): 44176
Number of constraints per step (secondary circuit): 10347

RecursiveSNARK creation took 2.428390917s
CompressedSNARK::prove: true, took 2.916614208s

### n=100

RecursiveSNARK creation took 24.352297666s
CompressedSNARK::prove: true, took 2.984685667s

### n=1000

Segfault (?)

`zsh: segmentation fault  cargo run --example sha256_wasm --release 1000`

- TODO: Figure out what is going on here
