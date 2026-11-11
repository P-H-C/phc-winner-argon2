#!/bin/bash
#SBATCH --job-name=argon2-pw-exp
#SBATCH --partition=batch
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=2G
#SBATCH --time=01:00:00
#SBATCH --output=experiments/pw_%j.out
#SBATCH --error=experiments/pw_%j.err
#SBATCH --export=ALL

# ---------------------------------------------------------------------------
# Reproducible Argon2id persistent-workers experiment (Linux, AMD EPYC 7H12).
#
# Compares the unmodified baseline against the experimental build enabled by
# -DARGON2_EXPERIMENT_PERSISTENT_WORKERS. Both builds use identical compiler
# flags (-O3 -march=native); the experimental macro is the only difference.
# The experiment is fully contained in the repo: it never writes system
# settings, needs no root, and the correctness tests (make test, KATs, and a
# byte-identical digest comparison across many parameter sets) are run inside
# the job before any timing.
#
# Submit from the repository root:
#   cd ~/greenit && sbatch experiments/pw_bench.slurm
#
# Workload: Argon2id v19, t=3, m=65536 KiB, p=4, outlen=32.
# Benchmark: experiments/thp_bench.c (--variant malloc --no-rapl), 6
# counterbalanced paired rounds (AB/BA alternation) of 400 hashes per build
# per round with warmup, plus node/compiler/commit metadata and CSV output.
# ---------------------------------------------------------------------------

set -euo pipefail

ROOT="${SLURM_SUBMIT_DIR:-$(pwd)}"
cd "$ROOT"
[[ -f src/opt.c && -f experiments/thp_bench.c && -f experiments/digest_check.c ]] || {
  echo "ERROR: submit from the Argon2 repository root (missing src/opt.c or experiment sources)" >&2
  exit 1
}

JOB="${SLURM_JOB_ID:-manual}"
OUT="$ROOT/experiments/pw_results_${JOB}"
mkdir -p "$OUT"

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "node=$(hostname)"
  echo "kernel=$(uname -r)"
  echo "cpu_model=$(grep -m1 'model name' /proc/cpuinfo)"
  echo "cpu_sockets=$(grep 'physical id' /proc/cpuinfo | sort -u | wc -l)"
  echo "cpu_cores=$(grep -c '^processor' /proc/cpuinfo)"
  echo "allowed_cpu=$(grep Cpus_allowed_list /proc/self/status)"
  echo "thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo unknown)"
  echo "source_commit=$(git rev-parse HEAD)"
  echo "repo=$(git remote get-url origin 2>/dev/null || echo unknown)"
  echo "compiler=$(${CC:-cc} --version | head -1)"
  echo "workload=Argon2id v19,t3,m65536KiB,p4,out32,400_hashes_per_build_per_round,6_rounds"
} | tee "$OUT/metadata.txt"

CC="${CC:-cc}"
# Aion's AMD EPYC 7H12 should expose AVX2; fail safely otherwise so that the
# baseline is never silently compared without the intended SIMD path.
if ! "$CC" -march=native -dM -E -x c /dev/null | grep -q 'define __AVX2__'; then
  echo "ERROR: -march=native does not enable AVX2 on this node." >&2
  exit 1
fi

echo "== make test (baseline, no macro) =="
make test > "$OUT/make-test-baseline.log" 2>&1

echo "== make test (with -DARGON2_EXPERIMENT_PERSISTENT_WORKERS) =="
CFLAGS="-DARGON2_EXPERIMENT_PERSISTENT_WORKERS" make test > "$OUT/make-test-pw.log" 2>&1

echo "== building experiment binaries (identical flags, macro is the only difference) =="
make -C experiments clean > /dev/null
make -C experiments > "$OUT/build.log" 2>&1
sha256sum experiments/thp_bench experiments/thp_bench_pw \
          experiments/digest_check experiments/digest_check_pw \
          experiments/digest_check_pwdbg > "$OUT/binary_sha256.txt"

echo "== digest verification across parameter sets =="
experiments/digest_check       > "$OUT/digest_base.out"    2> "$OUT/digest_base.err"
experiments/digest_check_pw    > "$OUT/digest_pw.out"      2> "$OUT/digest_pw.err"
experiments/digest_check_pwdbg > "$OUT/digest_pwdbg.out"   2> "$OUT/digest_pwdbg.err"

if ! diff -q "$OUT/digest_base.out" "$OUT/digest_pw.out" >/dev/null; then
  echo "ERROR: digest mismatch between baseline and persistent-workers builds" >&2
  exit 1
fi
if ! diff -q "$OUT/digest_base.out" "$OUT/digest_pwdbg.out" >/dev/null; then
  echo "ERROR: digest mismatch with the debug-tagged persistent-workers build" >&2
  exit 1
fi
if ! grep -q 'experimental persistent workers active' "$OUT/digest_pwdbg.err"; then
  echo "ERROR: the persistent-workers path was NOT exercised on this node" >&2
  exit 1
fi
echo "digest_check: baseline == persistent-workers across $(grep -c ' rc=0 ' "$OUT/digest_base.out") cases (identical)"

echo "== smoke runs and digest anchoring =="
ARGS=( --variant malloc --no-rapl --m-cost 65536 --t-cost 3 --lanes 4 --outlen 32 )
EXPECTED=''
for b in baseline pw; do
  if [ "$b" = baseline ]; then bin="experiments/thp_bench"; else bin="experiments/thp_bench_pw"; fi
  "$bin" "${ARGS[@]}" --hashes 2 --trials 1 --warmup 1 --quiet \
    --csv "$OUT/smoke_${b}.csv" > "$OUT/smoke_${b}.log" 2>&1
  d=$(sed -n 's/^malloc digest:[[:space:]]*//p' "$OUT/smoke_${b}.log" | tail -1)
  [[ -n "$d" ]] || { echo "ERROR: no digest in smoke_${b}.log" >&2; exit 1; }
  if [[ -z "$EXPECTED" ]]; then EXPECTED="$d"; fi
  [[ "$d" == "$EXPECTED" ]] || { echo "ERROR: smoke digest mismatch for $b" >&2; exit 1; }
  echo "smoke $b: digest OK ($d)"
done

echo "== 6 counterbalanced paired rounds of 400 hashes each =="
ORDERS=(
  'baseline pw'
  'pw baseline'
  'baseline pw'
  'pw baseline'
  'baseline pw'
  'pw baseline'
)

: > "$OUT/summary.csv"
echo "round,position,build,order,per_hash_ms,t_wall_s,digest" > "$OUT/summary.csv"
for round in 0 1 2 3 4 5; do
  read -r -a builds <<< "${ORDERS[$round]}"
  echo "== round $round: ${ORDERS[$round]} =="
  for pos in 0 1; do
    build="${builds[$pos]}"
    if [ "$build" = baseline ]; then bin="experiments/thp_bench"; else bin="experiments/thp_bench_pw"; fi
    name="r$(printf '%02d' "$round")_p${pos}_${build}"
    "$bin" "${ARGS[@]}" --hashes 400 --trials 1 --warmup 3 --quiet \
      --csv "$OUT/${name}.csv" > "$OUT/${name}.log" 2>&1
    d=$(sed -n 's/^malloc digest:[[:space:]]*//p' "$OUT/${name}.log" | tail -1)
    [[ "$d" == "$EXPECTED" ]] || { echo "ERROR: digest mismatch in $name" >&2; exit 1; }
    ms=$(sed -n '2p' "$OUT/${name}.csv" | cut -d, -f8)
    wall=$(sed -n '2p' "$OUT/${name}.csv" | cut -d, -f6)
    echo "$round,$pos,$build,${ORDERS[$round]},$ms,$wall,$d" >> "$OUT/summary.csv"
    echo "$name: ${ms} ms/hash, digest OK"
  done
done

echo "== summary.csv =="
cat "$OUT/summary.csv"

echo "== aggregated comparison =="
python3 experiments/pw_analyze.py "$OUT" | tee "$OUT/summary.txt"

echo "RESULTS_DIRECTORY=$OUT"
echo "== Done =="
