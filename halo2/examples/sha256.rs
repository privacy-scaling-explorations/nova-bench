use ark_std::{end_timer, start_timer};
use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config, BLOCK_SIZE};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;

use halo2_proofs::{
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};

// Todo: Allow to pass an input and constrain correctness against a PI or similar.
#[derive(Default)]
struct MyCircuit {
    iter_num: usize,
}

impl Circuit<Fr> for MyCircuit {
    type Config = Table16Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Table16Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        Table16Chip::load(config.clone(), &mut layouter)?;
        let table16_chip = Table16Chip::construct(config);

        let mut test_input = [BlockWord(Value::known(0xff)); 8];

        for _ in 0..self.iter_num {
            test_input = Sha256::digest(
                table16_chip.clone(),
                layouter.namespace(|| "'abc' * 2"),
                &test_input,
            )?
            .0;
        }
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let k: usize = args[2].parse().unwrap();
    let params_size: u32 = args[1].parse().unwrap();

    let params = ParamsKZG::<Bn256>::setup(params_size, OsRng);
    let circuit = MyCircuit { iter_num: k };

    // Plotting circuit
    // use plotters::prelude::*;
    // let root = BitMapBackend::new("sha_layout.png", (1024, 7680)).into_drawing_area();
    // root.fill(&WHITE).unwrap();
    // let root = root
    //     .titled(&format!("SHA - Depth={}", params_size), ("sans-serif", 60))
    //     .unwrap();

    // halo2_proofs::dev::CircuitLayout::default()
    //     .render(params_size as u32, &circuit, &root)
    //     .unwrap();

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let start = start_timer!(|| "Compute Halo2 recursive hash");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    end_timer!(start);
}
