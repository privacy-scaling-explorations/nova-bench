#!/bin/bash

circom ./circom/sha256_test.circom --r1cs --wasm --sym --c --output ./circom/ --prime vesta

#Doesn't work on M1, using WASM instead
#cd circom/sha256_test/toy_cpp && make

(cd ./circom/sha256_test_js && node generate_witness.js sha256_test.wasm ../input_32_recursive.json output.wtns)
