use ark_std::{end_timer, start_timer};

use std::{collections::HashMap, env, env::current_dir, time::Instant};

use ff::derive::bitvec::vec;
use ff::PrimeField;
use nova_scotia::{
    circom::{circuit::CircomCircuit, reader::load_r1cs},
    create_public_params, create_public_params_par, create_recursive_circuit, FileLocation, F1, F2,
    G1, G2, S1, S2,
};
// Ignore create_recursive_circuit

use nova_snark::{
    parallel_prover::{FoldInput, NovaTreeNode, PublicParams},
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::json;

use sha2::{Digest, Sha256};

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
    println! {"Using recursive depth: {:?} times depth_per_fold in circuit (default 10 or 100, check yourself! :D)", depth};

    let iteration_count = depth;
    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/sha256/circom/sha256_test_nova.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("./examples/sha256/circom/sha256_test_nova_cpp/sha256_test_nova");

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

    let start_public_input = step_in_vector
        .into_iter()
        .map(|x| F1::from(x))
        .collect::<Vec<_>>();

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
        FileLocation::PathBuf(witness_generator_file),
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
    let timer_gen_compressed_snark =
        start_timer!(|| "Generate a CompressedSNARK using Spartan with IPA-PC");
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

fn recursive_hashing_par(depth: usize) {
    println! {"Using recursive depth: {:?}", depth};

    let iteration_count = depth;
    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/sha256/circom/sha256_test_nova.r1cs");
    let r1cs_circom = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("./examples/sha256/circom/sha256_test_nova_cpp/sha256_test_nova");

    let mut in_vector = vec![];
    let mut hash: Vec<u8> = vec![0; 32];
    for _ in 0..depth {
        let new_hash = Sha256::digest(&hash);
        hash = new_hash.as_slice().to_owned();
        in_vector.push(new_hash);
    }

    // println!("100th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100));

    let step_in_vector = vec![0; 32];

    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(*in_vector[i]));
        private_inputs.push(private_input);
    }

    let start_public_input = step_in_vector
        .into_iter()
        .map(|x| F1::from(x))
        .collect::<Vec<_>>();

    let pp: nova_snark::parallel_prover::PublicParams<
        G1,
        G2,
        CircomCircuit<F1>,
        TrivialTestCircuit<F2>,
    > = create_public_params_par(r1cs_circom.clone());

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

    let folds: Vec<FoldInput<G1>> = nova_scotia::prepare_folds(
        FileLocation::PathBuf(witness_generator_file),
        r1cs_circom.clone(),
        private_inputs,
        depth,
        // This is wrong and we should be passing all the PIs here.
        start_public_input.clone(),
    );

    let primary_circuit = CircomCircuit {
        r1cs: r1cs_circom,
        witness: None,
    };
    let secondary_circuit = TrivialTestCircuit::<<G2 as Group>::Scalar>::default();

    let proving_time = start_timer!(|| "Proving time");
    let res = nova_snark::parallel_prover::par_digest_folds(
        pp,
        folds,
        primary_circuit,
        secondary_circuit,
    );
    end_timer!(proving_time);

    assert!(res.is_ok());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let k: usize = args[1].parse().unwrap();
    //let sha_block: u64 = args[2].parse().unwrap();

    // NOTE: Toggle here
    recursive_hashing(k);
    //recursive_hashing2(k);
    //recursive_hashing_par(k);
}
