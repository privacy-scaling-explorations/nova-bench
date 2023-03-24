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
    signal input hash[32];
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

template Main(depth) {
    signal input in[32];
    signal input hash[32];
    signal output out[32];

    component chainedSha = RecursiveShaTest(32, depth);
    chainedSha.in <== in;
    chainedSha.hash <== hash;

    // The final output should be same as the inputed hash
    hash === chainedSha.out;
    out <== chainedSha.out;
}

component main = Main(10);