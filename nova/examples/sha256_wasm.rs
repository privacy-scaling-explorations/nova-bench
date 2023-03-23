use std::{collections::HashMap, env::current_dir, time::Instant};

use ff::PrimeField;
use ff::derive::bitvec::vec;
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F1,
    G2, S1, S2,
};

use num_bigint::BigInt;
use num_traits::Num;
use nova_snark::{traits::Group, CompressedSNARK};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn main() {
    let iteration_count = 5;
    let root = current_dir().unwrap();

    let circuit_file = root.join("../circom/sha256_test.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join("../circom/sha256_test_js/sha256_test.wasm");

    // TODO Generate this in Rust instead
    let in_vector = vec![
        vec![0; 32],
        vec![102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37],
        vec![43, 50, 219, 108, 44, 10, 98, 53, 251, 19, 151, 232, 34, 94, 168, 94, 15, 14, 110, 140, 123, 18, 109, 0, 22, 204, 189, 224, 230, 103, 21, 30],
        vec![18, 119, 19, 85, 228, 108, 212, 124, 113, 237, 23, 33, 253, 83, 25, 179, 131, 204, 163, 161, 249, 252, 227, 170, 28, 140, 211, 189, 55, 175, 32, 215],
        vec![254, 21, 192, 211, 235, 227, 20, 250, 215, 32, 160, 139, 131, 154, 0, 76, 46, 99, 134, 245, 174, 204, 25, 236, 116, 128, 125, 25, 32, 203, 106, 235],
        vec![55, 109, 161, 31, 227, 171, 61, 14, 170, 221, 180, 24, 204, 180, 155, 84, 38, 213, 194, 80, 79, 82, 111, 119, 102, 88, 15, 110, 69, 152, 78, 59],
        vec![67, 145, 165, 199, 159, 253, 199, 152, 131, 3, 101, 3, 202, 85, 22, 115, 192, 157, 238, 194, 141, 244, 50, 168, 216, 141, 235, 199, 250, 46, 201, 30],
        vec![93, 26, 220, 181, 121, 124, 46, 255, 27, 160, 70, 10, 249, 50, 74, 198, 223, 91, 111, 251, 102, 190, 109, 242, 84, 120, 114, 194, 242, 155, 164, 194],
        vec![106, 155, 113, 28, 229, 211, 116, 158, 206, 41, 70, 49, 16, 182, 22, 77, 187, 40, 221, 162, 137, 2, 88, 107, 246, 110, 134, 94, 140, 41, 195, 80],
        vec![78, 110, 106, 206, 245, 149, 58, 106, 32, 135, 216, 221, 125, 56, 164, 155, 60, 160, 98, 125, 138, 179, 57, 135, 44, 229, 108, 91, 211, 181, 161, 18],
        vec![241, 53, 135, 188, 137, 254, 72, 130, 199, 200, 137, 48, 37, 17, 255, 215, 56, 209, 54, 18, 155, 159, 91, 228, 196, 146, 203, 73, 72, 169, 58, 137]
    ];

    let step_in_vector = vec![vec![0; 32], vec![102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37]];

    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(in_vector[i]));
        private_inputs.push(private_input);
    }

    println!("Private inputs: {:?}", private_inputs);

    let flatten_array: Vec<_> = step_in_vector.iter().flatten().cloned().collect();

    // NOTE: Circom doesn't deal well with 2d arrays, so we flatten input
    let start_public_input = flatten_array.into_iter().map(|x| F1::from(x)).collect::<Vec<_>>();

    let pp = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();

    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.clone(),
        z0_secondary,
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
}