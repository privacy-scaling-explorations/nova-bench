# Nova benchmarks

Here's a list of some of the benchmarks we've been taking to better understand how Nova performs vs other proof systems.

Live version: https://hackmd.io/0gVClQ9IQiSXHYAK0Up9hg?both=

*NOTE: Disclaimer - these benchmarks are preliminary and should be taken with a grain of salt. Some shortcuts were taken as these were done and we want to check the correctness of these calculations before being 100% confident in them.*

## Recursive hashing

Recursively hashing of SHA256 $k$ times. That is, computations of the form $h(h(h(h(h(x)))))$.

This also show how doing many recursives hashes in a single fold in Nova improves performance. That is, turning expression above into:

$$h(h(h(x))) \text{(d times)}\rightarrow h(h(h(x))) \text{(d times)} \rightarrow \dots$$

With the same number of recursive hashes, just batching more in a single fold.

Rationale: Similar to https://github.com/celer-network/zk-benchmark but doing hashing recursively to take advantage of Nova+IVC.

Code: https://github.com/privacy-scaling-explorations/nova-bench

#### Proving systems

| Framework        | Arithmetization | Algorithm | Curve  | Other        |
|------------------|-----------------|-----------|--------|--------------|
| Circom (snarkjs) | R1CS            | Groth16   | Pasta  |              |
| Nova (seq)       | Relaxed R1CS    | Nova      | Pasta  |              |
| Nova (par)       | Relaxed R1CS    | Nova      | Pasta  | parallel PoC |
| Halo2            | Plonkish        | KZG       | BN254  |              |

### Prover time

#### Powerful laptop

Hardware: Macbook Pro M1 Max (2021), 64GB memory.

| k     | Circom | Nova (total) d=1 | Nova (step sum) d=1 | Halo 2 (KZG) |
|-------|--------|------------------|---------------------|--------------|
| 1     | 0.3s   | 0.2s             | 0.1s                | 0.8s         |
| 10    | 7.3s   | 2.4s             | 1.2s                | 0.8s         |
| 100   | 62s    | 24s              | 12.5s               | 1.6s         |
| 1000  | -      | 240s             | 125s                | 25s          |

#### Powerful server

Hardware: Server with 72 cores and ~350GB RAM.

| k       | Nova d=1       | Nova d=10 | Nova d=100  | Nova d=100 par | Halo 2 (KZG) |
|---------|----------------|-----------|-------------|----------------|--------------|
| 100     | 19s            | 3.6s      | -           |  -             | 2.5s         |
| 1000    | 190s           | 36s       | 26.5s       |  28.5s         | 41.6s        |
| 10000   | 1900s          | 360s      | 265s        |  226s          | 389.1s       |
| 100000  | 19000s         |           |             |                | ?            |

#### Comments

This is not completely an apples-to-apples comparison, as: (i) Circom implements the recursive hashing "in-circuit", and (ii) Halo2 uses a different aritmeitization and lookup tables with a highly optimized implementation. However, it shows how a standard operation behaves when called recursively and expressed in a (somewhat) idiomatic fashion.

Step sum is the sum of all the individual folds, i.e. it doesn't account for the witness generation etc that is done when calling `create_recursive_circuit` in Nova Scotia. The witness generation overhead is quite high, especially when running it in WASM (MBP M1 limitation). The step sum is the more representative metric. For Nova, we also don't count the SNARK verification part (currently done with Spartan using IPA-PC, not a huge overhead).

The `d` parameter is how many recursive hashes we do inside each fold. For the Nova examples we use step sum.

Circom (Groth16) and Nova are run with the Pasta (Pallas/Vesta) curves and use (Relaxed) R1CS arithmetization. Halo2 (KZG) is using BN254 and Plonkish arithmetization.

### Memory usage and SRS

#### Powerful server

Hardware: Server with 72 cores and ~350GB RAM

| k       |  Nova (seq) d=1 | Halo 2 (KZG) | Nova (par PoC) |
|---------|-----------------|--------------|-------------|
| 100     |  1.6GB          | 3.7GB        | 9GB         | 
| 1000    |  1.6GB          | 32GB         | 244GB       | 
| 10000   |  1.6GB          | 245GB        | OOM         | 
| 100000  |  1.6GB          | ?            | ?           |

#### Comments

For Circom, at k=100 the number of constraints is 3m, and we need 23 powers of tau or structured reference string (SRS), 2^23. This is a 9GB file and it increases linearly, quickly becomes infeasible.

For Halo2, which is Plonkish, the situation is a bit better. The SRS of Halo2 is 2^18 for k=100, 2^22 for k=1000, and 2^25 for k=10000. Because the arithmetization is more efficient, Halo2 needs a shorter SRS than Circom.

Nova, assuming it is run natively or with Circom C++ witness generator, has constant memory overhead. Note that we use Nova Scotia and Circom for writing the circuits. With d=1 we have ~30k constraints, d=10 300k constraints, etc.

In the current parallel PoC of Nova there's a bug in the code that leads to linearly increasing memory. This isn't intrinsic to Nova though, and more of a software bug.

### Conclusion

Based on the above we draw the following conclusions:

1. **Nova is memory-efficient.** For large circuits this matters a lot, where Circom and Halo2 both require a big SRS and run out of memory. This is especially important in low-memory environments.
2. **R1CS vs Plonkish matters a lot.** Plonkish with lookup tables leads to a much faster prover time for Halo2 (KZG) with e.g. SHA256 recursive hashing for d=1. This motivates work on alternative folding schemes, such as Sangria.
3. **Be mindful of constraints vs recursion overheard.** For SHA256 and d=1 the number of constraints isn't big enough (~30k) compared to recursive overhead (~10k) to see huge performance gains. As we increase to d=10 and d=100 we see how Nova starts to perform better than Halo 2 (KZG). This suggests that we want to use somewhat large circuits for Nova folding.
4. **For large circuits, Nova appears to be faster than Halo2 (KZG)**. We see that even with less than perfect parallelization, we get ~75% improvement over Halo2 for 10 000 recursive hashes.


*NOTE: We also did a benchmark for Bitcoin blocks, but this is comparing against an old prototype of Halo so is less relevant. See [here](https://hackmd.io/El1yL_65T9-3L-LnUpzoRQ).*


## Future benchmarks

While above benchmarks gives us some insight, it'd be useful to do further benchmarks to better understand how Nova behaves. These are not in order of priority.

1) Better standard operation benchmark in Nova with more constraints that also exists in Circom/Halo2. This could be porting Halo Bitcoin to Halo2, or only doing one fold with larger preimage in SHA256, or something similar. Note: Partially done now with d=10,100 parameter, see [issue](https://github.com/privacy-scaling-explorations/nova-bench/issues/1).
2) Halo2 comparable example with two column layout. This would show a more realistic comparison vs R1CS based Nova.
3) Halo2 example using recursion. Current "recursive hashing" SHA256 example uses lookup tables only.
4) Better parallel comparison. Currently parallel implementation only shows 35% improvement + memory increase. We expect this can be done a lot better. (Parallelization can partially be simulated with one thread vs many threads on a single machine).
6) GPU comparison. GPU should show significant improvement vs CPU, but so far we've not been able to get it to work / show big improvement.
7) FPGA comparison. Assuming only MSM + addition operations this could lead to massive improvements. Perhaps limited to only benchmarking MSM + additions to see if this investment makes sense.
8) Different curves. Currently we use pasta curves for Nova vs BN254. It might be useful to compare different curves here, as Nova doesn't require FFT-friendly curves.
