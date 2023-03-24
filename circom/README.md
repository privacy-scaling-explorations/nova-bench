# Circom

## Goal

Create a benchmark for recursive variant of https://github.com/celer-network/zk-benchmark

## Description

Recursively hashes a 32 byte input k times using SHA256 in Circom.

Uses forked version of Circom with Pasta curves (for better comparison with current Nova implementation): https://github.com/nalinbhardwaj/circom/tree/pasta

## To run

`./groth16/test_sha256_groth16_macos.sh 1 17`

## Acknowledgements

Testing structure taken from https://github.com/celer-network/zk-benchmark 
