/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

pragma circom 2.0.3;

include "sha256_bytes.circom";

template RecursiveShaTest(N, depth) {

    signal input in[N];
    signal input hash[32]; // XXX Not using this check
    signal output out[32];

    signal value[depth+1][N];

    component hasher[depth];

    value[0] <== in;

    for (var i = 0; i < depth; i++) {
        hasher[i] = Sha256Bytes(N);
        hasher[i].in <== value[i];

        value[i+1] <== hasher[i].out;
    }

    out <== value[depth];
}

template Main(depth_per_fold) {
    signal input in[32];
    signal input step_in[32];
    signal output step_out[32];

    // Single fold case
    //component hasher = Sha256Bytes(32);
    //hasher.in <== step_in;

    // XXX Ignore private input check for now
    //in === step_in;
    
    //step_out <== hasher.out;

    // Many folds case
    component chainedSha = RecursiveShaTest(32, depth_per_fold);
    chainedSha.in <== step_in; // was in, we ignore in now
    chainedSha.hash <== step_in;

    // The final output should be same as the inputed hash
    // XXX Ignore private input check for now
    //hash === chainedSha.out;

    step_out <== chainedSha.out;
}

// render this file before compilation
component main { public [step_in] } = Main(10);