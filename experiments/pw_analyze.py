#!/usr/bin/env python3
"""Aggregates the persistent-workers experiment CSV rows into a comparison.

Reads experiments/pw_results_<job>/summary.csv (one row per timed run,
produced by experiments/pw_bench.slurm) and prints per-build aggregates and
the paired per-round delta. The CSVs are the raw evidence; this script only
summarizes them and does not decide whether any speedup is real.
"""

import csv
import statistics
import sys
import os


def main(dirpath):
    path = os.path.join(dirpath, "summary.csv")
    if not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 1
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("error: summary.csv is empty", file=sys.stderr)
        return 1

    per = {}
    rounds = {}
    for r in rows:
        per.setdefault(r["build"], []).append(float(r["per_hash_ms"]))
        rounds.setdefault(r["round"], {})[r["build"]] = float(r["per_hash_ms"])

    print(f"File: {path}  ({len(rows)} timed runs of 400 hashes)")
    print(f"{'build':<10}{'n':>3}{'mean ms':>10}{'median ms':>11}"
          f"{'min ms':>9}{'max ms':>9}")
    for b in sorted(per):
        v = per[b]
        print(f"{b:<10}{len(v):>3}{statistics.mean(v):>10.4f}"
              f"{statistics.median(v):>11.4f}{min(v):>9.4f}{max(v):>9.4f}")

    if "baseline" in per and "pw" in per:
        base = statistics.mean(per["baseline"])
        pw = statistics.mean(per["pw"])
        print(f"\nmean baseline = {base:.4f} ms/hash")
        print(f"mean pw       = {pw:.4f} ms/hash")
        print(f"mean delta (pw - baseline) = {pw - base:+.4f} ms/hash "
              f"({(pw / base - 1) * 100:+.2f}%)")

        deltas = []
        for rnd in sorted(rounds, key=int):
            rd = rounds[rnd]
            if "baseline" in rd and "pw" in rd:
                deltas.append(rd["pw"] - rd["baseline"])
        if deltas:
            print(f"paired per-round deltas (pw - baseline): "
                  f"{[round(d, 4) for d in deltas]}")
            print(f"mean paired delta = {statistics.mean(deltas):+.4f} ms/hash")

        print("\nRaw measurement only. Do not claim a speedup without further")
        print("analysis: node noise, run-to-run variance, more jobs, and")
        print("significance testing (e.g. paired t-test / bootstrap).")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
