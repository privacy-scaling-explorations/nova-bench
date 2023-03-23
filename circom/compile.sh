#!/bin/bash

#circom ./examples/sha256/circom/sha256_test.circom --r1cs --wasm --sym --c --output ./examples/sha256/circom/ --prime vesta
circom ./circom/sha256_test.circom --r1cs --wasm --sym --c --output ./circom/ --prime vesta

#Doesn't work on M1, using WASM instead
#cd examples/sha256/toy_cpp && make

#(cd ./examples/sha256/circom/sha256_test_js && node generate_witness.js sha256_test.wasm ../input_64.json output.wtns)
(cd ./circom/sha256_test_js && node generate_witness.js sha256_test.wasm ../input_32.json output.wtns)
