#!/usr/bin/env bash
#SBATCH --job-name=argon2-pw-energy
#SBATCH --partition=batch
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=2G
#SBATCH --time=00:25:00
#SBATCH --output=experiments/pw_energy_%j.out
#SBATCH --error=experiments/pw_energy_%j.err
#SBATCH --export=ALL

# Energy experiment for a source-audited, EXPERIMENTAL research build only.
# Submit from ~/greenit with: sbatch experiments/pw_energy.slurm
# Shared-node, two-package RAPL is NOT process energy; it is a partial proxy.
set -euo pipefail
ROOT="${SLURM_SUBMIT_DIR:-$(pwd)}"
cd "$ROOT"
[[ -f src/core.c && -f experiments/thp_bench.c && -f experiments/digest_check.c ]] || {
  echo 'ERROR: submit from the Argon2 repository root.' >&2; exit 1;
}
JOB="${SLURM_JOB_ID:-manual}"
OUT="$ROOT/experiments/pw_energy_results_${JOB}"
mkdir -p "$OUT"
CC="${CC:-cc}"
{
  printf 'utc=%s\n' "$(date -u +%FT%TZ)"
  printf 'node=%s\n' "$(hostname)"
  printf 'slurm_job=%s\n' "$JOB"
  printf 'partition=%s\n' "${SLURM_JOB_PARTITION:-unknown}"
  printf 'num_tasks=%s\n' "${SLURM_NTASKS:-unknown}"
  printf 'cpus_per_task=%s\n' "${SLURM_CPUS_PER_TASK:-unknown}"
  printf 'allowed_cpus=%s\n' "$(grep Cpus_allowed_list /proc/self/status)"
  printf 'cpu_model=%s\n' "$(grep -m1 'model name' /proc/cpuinfo)"
  printf 'compiler=%s\n' "$($CC --version | head -1)"
  printf 'commit=%s\n' "$(git rev-parse HEAD)"
  printf 'repo=%s\n' "$(git remote get-url origin 2>/dev/null || echo unknown)"
  printf 'core_sha256=%s\n' "$(sha256sum src/core.c | awk '{print $1}')"
  printf 'harness_sha256=%s\n' "$(sha256sum experiments/thp_bench.c | awk '{print $1}')"
  printf 'thp=%s\n' "$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo unknown)"
  printf 'workload=Argon2id_v19_t3_m65536KiB_p4_out32;6_paired_rounds_400_hashes_each\n'
} | tee "$OUT/metadata.txt"

# Confirm that builds target the intended AVX2 implementation.
"$CC" -march=native -dM -E -x c /dev/null | grep -q 'define __AVX2__' || {
  echo 'ERROR: native compiler target lacks AVX2.' >&2; exit 1;
}

# Rebuild both in one node allocation. The macro is the only intended change.
make -C experiments clean > "$OUT/clean.log" 2>&1
make -C experiments thp_bench thp_bench_pw digest_check digest_check_pw \
  > "$OUT/build.log" 2>&1
sha256sum experiments/thp_bench experiments/thp_bench_pw > "$OUT/binary_sha256.txt"

# Correctness gate before energy measurements.
timeout 120s experiments/digest_check > "$OUT/digest_baseline.txt"
timeout 120s experiments/digest_check_pw > "$OUT/digest_pw.txt"
diff -u "$OUT/digest_baseline.txt" "$OUT/digest_pw.txt" > "$OUT/digest.diff" || {
  echo 'ERROR: digest check differs.' >&2; exit 1;
}
[[ $(grep -c ' rc=0 ' "$OUT/digest_baseline.txt") -ge 10 ]] || {
  echo 'ERROR: insufficient verified digest cases.' >&2; exit 1;
}

EXPECTED=''
ARGS=(--variant malloc --m-cost 65536 --t-cost 3 --lanes 4 --outlen 32)
# An even number of pairs, alternating AB and BA; six round-level paired measurements.
ORDERS=('baseline pw' 'pw baseline' 'baseline pw' 'pw baseline' 'baseline pw' 'pw baseline')
CSV="$OUT/paired_runs.csv"
printf 'round,position,build,hashes,wall_s,ms_per_hash,rapl_domains,raw_uj,idle_uj,corrected_uj,digest\n' > "$CSV"

for round in 0 1 2 3 4 5; do
  read -r -a builds <<< "${ORDERS[$round]}"
  for pos in 0 1; do
    build="${builds[$pos]}"
    if [[ "$build" == 'baseline' ]]; then
      bin='experiments/thp_bench'
    else
      bin='experiments/thp_bench_pw'
    fi
    label="r$(printf '%02d' "$round")_p${pos}_${build}"
    echo "RUN $label at $(date -u +%FT%TZ)"
    timeout 180s "$bin" "${ARGS[@]}" \
      --hashes 400 --trials 1 --warmup 3 --quiet \
      --csv "$OUT/${label}.csv" --per-hash "$OUT/${label}_perhash.csv" \
      > "$OUT/${label}.log" 2>&1
    digest="$(sed -n 's/^malloc digest:[[:space:]]*//p' "$OUT/${label}.log" | tail -1)"
    [[ -n "$digest" ]] || { echo "ERROR: digest absent for $label" >&2; exit 1; }
    if [[ -z "$EXPECTED" ]]; then EXPECTED="$digest"; fi
    [[ "$digest" == "$EXPECTED" ]] || { echo "ERROR: digest mismatch for $label" >&2; exit 1; }
    # Read a CSV row using the standard library to reject absent energy or wrong workload.
    python3 - "$OUT/${label}.csv" "$OUT/${label}_perhash.csv" "$CSV" "$round" "$pos" "$build" "$EXPECTED" <<'PY'
import csv,sys
source,perhash,target,round_id,pos,build,digest=sys.argv[1:]
with open(source,newline='') as f:
    rows=list(csv.DictReader(f))
if len(rows)!=1: raise SystemExit('ERROR: unexpected benchmark CSV row count')
r=rows[0]
if r['variant']!='malloc' or int(r['hashes'])!=400 or int(r['warmup'])!=3:
    raise SystemExit('ERROR: unintended workload configuration')
if int(r['rapl_energy_uj'])<=0 or r['rapl_domains']=='unsupported':
    raise SystemExit('ERROR: RAPL unavailable. Do not interpret zero as energy.')
domains=r['rapl_domains'].split('+')
if len(domains)!=2 or len(set(domains))!=2:
    raise SystemExit('ERROR: expected precisely two distinct CPU-package RAPL domains, got '+str(domains))
if int(r['energy_estimated'])!=1:
    raise SystemExit('ERROR: unexpected RAPL methodology flag')
with open(perhash,newline='') as f:
    hashes=list(csv.DictReader(f))
if len(hashes)!=400 or any(int(x['rc']) for x in hashes):
    raise SystemExit('ERROR: per-hash status or count invalid')
with open(target,'a',newline='') as f:
    csv.writer(f).writerow([round_id,pos,build,r['hashes'],r['t_wall_s'],
        r['per_hash_ms'],r['rapl_domains'],r['rapl_energy_uj'],
        r['rapl_idle_uj'],r['rapl_corrected_uj'],digest])
PY
  done
done
python3 experiments/pw_energy_analyze.py "$OUT" | tee "$OUT/energy_summary.txt"
echo "RESULTS_DIRECTORY=$OUT"
