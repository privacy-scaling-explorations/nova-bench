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

use sha2::{Sha256, Digest};

fn main() {
    let iteration_count = 5;
    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/sha256/circom/sha256_test_nova.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join("./examples/sha256/circom/sha256_test_nova_js/sha256_test_nova.wasm");


    fn gen_nth_sha256_hash(n: usize) -> Vec<u8> {
        let mut hash = vec![0; 32];
        for _ in 0..n {
            let new_hash = Sha256::digest(&hash);
            hash = new_hash.as_slice().to_owned();
        }
        hash
    }

    let mut in_vector = vec![];
    for i in 0..10 {
        in_vector.push(gen_nth_sha256_hash(i));
    }

    // TODO For benchmarking we want to compare [1,10,100,1k,10k,100k,1m]
    // 1st recursive SHA256 hash: [102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37]
    // 10th recursive SHA256 hash: [241, 53, 135, 188, 137, 254, 72, 130, 199, 200, 137, 48, 37, 17, 255, 215, 56, 209, 54, 18, 155, 159, 91, 228, 196, 146, 203, 73, 72, 169, 58, 137]
    // 100th recursive SHA256 hash: [45, 118, 149, 168, 135, 196, 92, 182, 26, 128, 117, 113, 39, 175, 214, 118, 189, 22, 52, 26, 94, 28, 240, 248, 203, 105, 98, 229, 252, 164, 37, 23]
    // 10kth recursive SHA256 hash: [54, 193, 203, 79, 130, 106, 228, 44, 235, 168, 72, 34, 126, 12, 95, 120, 97, 120, 202, 157, 206, 202, 103, 114, 229, 215, 40, 208, 156, 48, 162, 246]
    // 10kth recursive SHA256 hash: [82, 229, 228, 9, 207, 11, 252, 118, 235, 27, 13, 44, 75, 164, 54, 106, 253, 126, 193, 14, 54, 32, 188, 119, 81, 120, 47, 45, 222, 206, 161, 159]
    // 100kth recursive SHA256 hash: [180, 34, 188, 156, 6, 70, 164, 50, 67, 60, 36, 16, 153, 28, 149, 226, 216, 151, 88, 227, 180, 245, 64, 172, 168, 99, 56, 159, 40, 161, 19, 121]
    // 1mth recursive SHA256 hash: [42, 94, 139, 135, 137, 79, 194, 209, 190, 70, 196, 12, 232, 249, 87, 69, 204, 106, 72, 33, 211, 177, 190, 147, 228, 251, 165, 32, 92, 117, 124, 64]
    println!("1st recursive SHA256 hash: {:?}", gen_nth_sha256_hash(1));
    println!("10th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(10));
    println!("100th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100));
    println!("10kth recursive SHA256 hash: {:?}", gen_nth_sha256_hash(1000));
    println!("10kth recursive SHA256 hash: {:?}", gen_nth_sha256_hash(10000));
    println!("100kth recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100000));
    println!("1mth recursive SHA256 hash: {:?}", gen_nth_sha256_hash(1000000));

    let step_in_vector = vec![0; 32];
    
   let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(in_vector[i]));
        private_inputs.push(private_input);
    }

    println!("Private inputs: {:?}", private_inputs);

    // XXX Possibly outdated
    // let flatten_array: Vec<_> = step_in_vector.iter().flatten().cloned().collect();
    // NOTE: Circom doesn't deal well with 2d arrays, so we flatten input

    let start_public_input = step_in_vector.into_iter().map(|x| F1::from(x)).collect::<Vec<_>>();

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