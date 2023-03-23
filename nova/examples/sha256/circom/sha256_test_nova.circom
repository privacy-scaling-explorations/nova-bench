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

template Main() {
    signal input in[32];
    signal input step_in[32];
    signal output step_out[32];

    component hasher = Sha256Bytes(32);

    hasher.in <== in;
    in === step_in;
    step_out <== hasher.out;

}

// render this file before compilation
component main { public [step_in] } = Main();