#!/bin/bash

circom ./examples/sha256/circom/sha256_test_nova2.circom --r1cs --wasm --sym --c --output ./examples/sha256/circom/ --prime vesta

#Doesn't work on M1, using WASM instead
#cd examples/sha256/circom/toy_cpp && make

# NOTE: This is just one step of the computation
# Full computation happens inside sha256_wasm.rs
(cd ./examples/sha256/circom/sha256_test_nova2_js && node generate_witness.js sha256_test_nova2.wasm ../input_32_first_step2.json output.wtns)
