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
    println!("1st recursive SHA256 hash: {:?}", gen_nth_sha256_hash(1));
    println!("10th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(10));
    println!("100th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100));

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