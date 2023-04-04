use std::{
    collections::HashMap,
    env::current_dir,
    io::Write,
    time::{Duration, Instant},
};

use ark_std::{end_timer, start_timer};

use ff::PrimeField;
use nova_scotia::{
    circom::{circuit::CircomCircuit, reader::load_r1cs},
    create_public_params, 
    create_public_params_par,
    create_recursive_circuit, FileLocation,
    F1, F2, G2, G1, S1, S2,

};
use nova_snark::{
    parallel_prover::{FoldInput, NovaTreeNode, PublicParams},
    traits::{circuit::TrivialTestCircuit, Group},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct Blocks {
    prevBlockHash: [String; 2],
    blockHashes: Vec<[String; 2]>,
    blockHeaders: Vec<Vec<u8>>,
}

fn bench_seq(iteration_count: usize, per_iteration_count: usize) -> (Duration, Duration) {
    let root = current_dir().unwrap();

    let depth = iteration_count;

    let circuit_file = root.join("examples/bitcoin/circom/bitcoin_benchmark.r1cs");
    let r1cs_circom = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("examples/bitcoin/circom/bitcoin_benchmark_cpp/bitcoin_benchmark");

    // load serde json
    let btc_blocks: Blocks =
        serde_json::from_str(include_str!("bitcoin/fetcher/btc-blocks.json")).unwrap();

    let start_public_input = vec![
        F1::from_str_vartime(&btc_blocks.prevBlockHash[0]).unwrap(),
        F1::from_str_vartime(&btc_blocks.prevBlockHash[1]).unwrap(),
    ];

    let mut private_inputs = Vec::new();

    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert(
            "blockHashes".to_string(),
            json!(
                btc_blocks.blockHashes
                    [i * per_iteration_count..i * per_iteration_count + per_iteration_count]
            ),
        );
        private_input.insert(
            "blockHeaders".to_string(),
            json!(
                btc_blocks.blockHeaders
                    [i * per_iteration_count..i * per_iteration_count + per_iteration_count]
            ),
        );
        private_inputs.push(private_input);
    }

    // println!("{:?} {:?}", start_public_input, private_inputs);

    let pp = create_public_params(r1cs_circom.clone());

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

    // Sequential case
    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file),
        r1cs_circom,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    let prover_time = start.elapsed();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());
    //--------------------------------

    // Parallel case
    // let folds: Vec<FoldInput<G1>> = nova_scotia::prepare_folds(
    //     FileLocation::PathBuf(witness_generator_file),
    //     r1cs_circom.clone(),
    //     private_inputs,
    //     depth,
    //     // This is wrong and we should be passing all the PIs here.
    //     start_public_input.clone(),
    // );

    // let primary_circuit = CircomCircuit {
    //     r1cs: r1cs_circom,
    //     witness: None,
    // };
    // let secondary_circuit = TrivialTestCircuit::<<G2 as Group>::Scalar>::default();

    // let proving_time = start_timer!(|| "Proving time");
    // let res = nova_snark::parallel_prover::par_digest_folds(
    //     pp_par,
    //     folds,
    //     primary_circuit,
    //     secondary_circuit,
    // );
    // assert!(res.is_ok());
    // end_timer!(proving_time);
    //--------------------------------

    // NOTE: Verify not implemented in parallel case yet

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
    let verifier_time = start.elapsed();
    assert!(res.is_ok());

    //produce a compressed SNARK
    // println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    // let start = Instant::now();
    // type S1 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G1>;
    // type S2 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G2>;
    // let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &recursive_snark);
    // println!(
    //     "CompressedSNARK::prove: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
    // let compressed_snark = res.unwrap();

    // // verify the compressed SNARK
    // println!("Verifying a CompressedSNARK...");
    // let start = Instant::now();
    // let res = compressed_snark.verify(
    //     &pp,
    //     iteration_count,
    //     start_public_input.clone(),
    //     z0_secondary,
    // );
    // println!(
    //     "CompressedSNARK::verify: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());

    let verifier_time = Duration::from_secs(999);
    (prover_time, verifier_time)
}

fn bench_par(iteration_count: usize, per_iteration_count: usize) -> (Duration, Duration) {
    let root = current_dir().unwrap();

    let depth = iteration_count;

    let circuit_file = root.join("examples/bitcoin/circom/bitcoin_benchmark.r1cs");
    let r1cs_circom = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("examples/bitcoin/circom/bitcoin_benchmark_cpp/bitcoin_benchmark");

    // load serde json
    let btc_blocks: Blocks =
        serde_json::from_str(include_str!("bitcoin/fetcher/btc-blocks.json")).unwrap();

    let start_public_input = vec![
        F1::from_str_vartime(&btc_blocks.prevBlockHash[0]).unwrap(),
        F1::from_str_vartime(&btc_blocks.prevBlockHash[1]).unwrap(),
    ];

    let mut private_inputs = Vec::new();

    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert(
            "blockHashes".to_string(),
            json!(
                btc_blocks.blockHashes
                    [i * per_iteration_count..i * per_iteration_count + per_iteration_count]
            ),
        );
        private_input.insert(
            "blockHeaders".to_string(),
            json!(
                btc_blocks.blockHeaders
                    [i * per_iteration_count..i * per_iteration_count + per_iteration_count]
            ),
        );
        private_inputs.push(private_input);
    }

    // println!("{:?} {:?}", start_public_input, private_inputs);

    let pp_par: nova_snark::parallel_prover::PublicParams<
    G1,
    G2,
    CircomCircuit<F1>,
    TrivialTestCircuit<F2>,
> = create_public_params_par(r1cs_circom.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp_par.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp_par.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp_par.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp_par.num_variables().1
    );

    // Sequential case
    // println!("Creating a RecursiveSNARK...");
    // let start = Instant::now();
    // let recursive_snark = create_recursive_circuit(
    //     FileLocation::PathBuf(witness_generator_file),
    //     r1cs_circom,
    //     private_inputs,
    //     start_public_input.clone(),
    //     &pp,
    // )
    // .unwrap();
    // let prover_time = start.elapsed();
    // println!("RecursiveSNARK creation took {:?}", start.elapsed());
    //--------------------------------

    //Parallel case
    println!("Creating a RecursiveSNARK parallel...");
    let start = Instant::now();
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
        pp_par,
        folds,
        primary_circuit,
        secondary_circuit,
    );
    assert!(res.is_ok());
    //end_timer!(proving_time);
    let prover_time = start.elapsed();

    //--------------------------------

    // NOTE: Verify not implemented in parallel case yet

    // let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // // verify the recursive SNARK
    // println!("Verifying a RecursiveSNARK...");
    // let start = Instant::now();
    // let res = recursive_snark.verify(
    //     &pp,
    //     iteration_count,
    //     start_public_input.clone(),
    //     z0_secondary.clone(),
    // );
    // println!(
    //     "RecursiveSNARK::verify: {:?}, took {:?}",
    //     res,
    //     start.elapsed()
    // );
    // let verifier_time = start.elapsed();
    // assert!(res.is_ok());

    // produce a compressed SNARK
    // println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    // let start = Instant::now();
    // type S1 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G1>;
    // type S2 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G2>;
    // let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &recursive_snark);
    // println!(
    //     "CompressedSNARK::prove: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
    // let compressed_snark = res.unwrap();

    // // verify the compressed SNARK
    // println!("Verifying a CompressedSNARK...");
    // let start = Instant::now();
    // let res = compressed_snark.verify(
    //     &pp,
    //     iteration_count,
    //     start_public_input.clone(),
    //     z0_secondary,
    // );
    // println!(
    //     "CompressedSNARK::verify: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
    //(prover_time, verifier_time)
    let verifier_time = Duration::from_secs(999);
    (prover_time, verifier_time)
}

fn main() {
    // create benchmark file
    let mut file_seq = std::fs::File::create("examples/bitcoin/benchmark_seq.csv").unwrap();
    let mut file_par = std::fs::File::create("examples/bitcoin/benchmark_par.csv").unwrap();

    file_seq.write_all(b"iteration_count,per_iteration_count,prover_time,verifier_time\n")
        .unwrap();
    file_par.write_all(b"iteration_count,per_iteration_count,prover_time,verifier_time\n")
    .unwrap();
    for i in 1..=5 {
        let j = 120 / i;

        // run bash script
        std::process::Command::new("bash")
            .arg("examples/bitcoin/circom/compile.sh")
            .arg(i.to_string())
            .output()
            .expect("failed to execute process");

        let (prover_time_seq, verifier_time_seq) = bench_seq(j, i);
        let (prover_time_par, verifier_time_par) = bench_par(j, i);

        file_seq.write_all(format!("{},{},{:?},{:?}\n", j, i, prover_time_seq, verifier_time_seq).as_bytes())
            .unwrap();

        file_par.write_all(format!("{},{},{:?},{:?}\n", j, i, prover_time_par, verifier_time_par).as_bytes())
        .unwrap();
    }
}
