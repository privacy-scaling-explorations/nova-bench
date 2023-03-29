use ark_std::{end_timer, start_timer};

use std::{env, collections::HashMap, env::current_dir, time::Instant};

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

extern crate wee_alloc;

// NOTE: Supposedly this helps against segfaults, but seems intermittent
// Consider trying jemallocator (?)
// Alternatively, just run larger benchmarks on a server (with C++ version)
// 
// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// TODO: Add naive Keccak circuit (check one step vs vanilla Circom)

fn gen_nth_sha256_hash(n: usize) -> Vec<u8> {
    let mut hash = vec![0; 32];
    for _ in 0..n {
        let new_hash = Sha256::digest(&hash);
        hash = new_hash.as_slice().to_owned();
    }
    hash
}

fn recursive_hashing(depth: usize) {
    println!{"Using recursive depth: {:?}", depth};

    let iteration_count = depth;
    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/sha256/circom/sha256_test_nova.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join("./examples/sha256/circom/sha256_test_nova_js/sha256_test_nova.wasm");

    let mut in_vector = vec![];
    for i in 0..depth {
        in_vector.push(gen_nth_sha256_hash(i));
    }
 
    // println!("100th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100));

    let step_in_vector = vec![0; 32];
    
   let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(in_vector[i]));
        private_inputs.push(private_input);
    }

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

    // create a recursive SNARK
    let timer_create_proof = start_timer!(|| "Create RecursiveSNARK");
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    end_timer!(timer_create_proof);

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];


    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let timer_verify_snark = start_timer!(|| "verify SNARK");
    let start = Instant::now();
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    assert!(res.is_ok());

    end_timer!(timer_verify_snark);



    // produce a compressed SNARK
    let timer_gen_compressed_snark = start_timer!(|| "Generate a CompressedSNARK using Spartan with IPA-PC");
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();
    end_timer!(timer_gen_compressed_snark);

    let timer_verify_compressed_snark = start_timer!(|| "Verify CompressedSNARK");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.clone(),
        z0_secondary,
    );
    end_timer!(timer_verify_compressed_snark);

    assert!(res.is_ok());
}


// Primary and secondary circuit optimized inputs for more efficient folding
fn recursive_hashing2(depth: usize) {

    let iteration_count = depth;
    let half_depth = depth/2;

    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/sha256/circom/sha256_test_nova2.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join("./examples/sha256/circom/sha256_test_nova2_js/sha256_test_nova2.wasm");

    // XXX Should we only iterate over half? Since we do 0..n/2 and n/2..n at each step
    // I.e. for n=10 we do 0..5 and 5..10
    let mut in_vector = vec![];

    // Confirm that we are doing half
    println!("half_depth: {}", half_depth);

    // This is number od iterations
     for i in 0..half_depth {
        in_vector.push(gen_nth_sha256_hash(i));
    }
 
    // This is different, we want vec of vec, with second vec being n/2 hash
    let midpoint = gen_nth_sha256_hash(half_depth);

    // XXX here atm

    // XXX: Issues with Vec<u8> / Vec<u64> conversion bleh
    let midpoint5 = vec![55, 109, 161, 31, 227, 171, 61, 14, 170, 221, 180, 24, 204, 180, 155, 84, 38, 213, 194, 80, 79, 82, 111, 119, 102, 88, 15, 110, 69, 152, 78, 59];

    println!("midpoint: {:?}", midpoint);

    let step_in_vector = vec![vec![0; 32], midpoint5];

    //let step_in_vector = vec![vec![0; 32], vec![0; 32]];

    println!("step_in_vector: {:?}", step_in_vector);
    
    let mut private_inputs = Vec::new();
    for i in 0..half_depth {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(in_vector[i]));
        private_inputs.push(private_input);
    }

    // XXX Possibly outdated
    let flatten_array: Vec<_> = step_in_vector.iter().flatten().cloned().collect();
    // NOTE: Circom doesn't deal well with 2d arrays, so we flatten input

    // XXX Not working for some reason
    // start_public_input should be flatten_array but we need to convert to F1
    let start_public_input = flatten_array.into_iter().map(|x| F1::from(x)).collect::<Vec<_>>();
  
    // This worked before
    //let start_public_input = step_in_vector.into_iter().map(|x| F1::from(x)).collect::<Vec<_>>();

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

    let timer_create_proof = start_timer!(|| "RecursiveSNARK creation");

    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    end_timer!(timer_create_proof);

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    let timer_verify_snark = start_timer!(|| "Verifying a RecursiveSNARK");
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    assert!(res.is_ok());
    end_timer!(timer_verify_snark);


    // produce a compressed SNARK
    let timer_gen_compressed_snark = start_timer!(|| "Generating CompressedSNARK using Spartan with IPA-PC");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    end_timer!(timer_gen_compressed_snark);

    let timer_verify_compressed_snark = start_timer!(|| "verify compressed snark");

    // verify the compressed SNARK
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.clone(),
        z0_secondary,
    );

    end_timer!(timer_verify_compressed_snark);

    assert!(res.is_ok());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let k: usize = args[1].parse().unwrap();
    //let sha_block: u64 = args[2].parse().unwrap();

    // NOTE: Toggle here
    recursive_hashing(k);
    //recursive_hashing2(k);
}