# Green IT: AI-Assisted Argon2id Optimisation

Experimental research on Argon2id energy efficiency
on the University of Luxembourg Aion HPC cluster.

## Configuration

- Base implementation: P-H-C/phc-winner-argon2
- Base commit: f57e61e19229e23c4445b85494dbf7c07de721cb
- Hardware: AMD EPYC 7H12
- Algorithm: Argon2id v19
- Memory: 65536 KiB
- Iterations: 3
- Parallelism: 4
- Compiler: GCC, -O3 -march=native

## Optimisation

Experimental per-hash persistent worker threads.

Enable with:
-DARGON2_EXPERIMENT_PERSISTENT_WORKERS

The baseline implementation is compiled without this macro.

## Experimental results

Job 16229084:
- Runtime reduction: 3.52%

Job 16229164:
- Runtime reduction: 3.29%
- Idle-corrected two-package RAPL estimate: -3.44%

RAPL measurements cover shared CPU packages and cannot
establish causally attributable per-job energy savings.

## Reproduction

On Aion, submit from the repository root:

sbatch experiments/pw_bench.slurm
sbatch experiments/pw_energy.slurm

## Limitations

This is a research prototype, not production-ready
cryptographic code. Exceptional pthread error paths
require further correction and testing.
