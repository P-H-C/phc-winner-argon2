#!/usr/bin/env python3
"""Analyze PAIRS of Argon2 baselines and persistent-worker experimental builds.

Every RAPL number includes OTHER JOBS on both entire physical CPU packages.
There is no process-attributable energy measurement here. Negative idle-
corrected results are valid diagnostic outcomes, not clamped or discarded.
"""
import csv
import math
import statistics as st
import sys
from pathlib import Path


def mean_ci(diff):
    n = len(diff)
    if n != 6:
        raise ValueError(f'expected 6 paired rounds, not {n}')
    sd = st.stdev(diff)
    # 97.5th percentile of Student t with 5 degrees of freedom, not 1.96.
    half = 2.570581835636305 * sd / math.sqrt(n)
    m = st.mean(diff)
    return m, sd, (m - half, m + half)


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
    with (root / 'paired_runs.csv').open(newline='') as f:
        rows = list(csv.DictReader(f))
    if len(rows) != 12:
        raise ValueError(f'expected 12 timed runs, found {len(rows)}')
    paired = {i: {} for i in range(6)}
    for r in rows:
        rd = int(r['round'])
        key = r['build']
        if rd not in paired or key not in ('baseline', 'pw') or key in paired[rd]:
            raise ValueError('bad round/build labels')
        if int(r['hashes']) != 400:
            raise ValueError('hash count mismatch')
        paired[rd][key] = r
    if any(set(d) != {'baseline', 'pw'} for d in paired.values()):
        raise ValueError('incomplete pairing')
    for rd, d in paired.items():
        if d['baseline']['digest'] != d['pw']['digest']:
            raise ValueError(f'digest mismatch in round {rd}')
        for build in d:
            if int(d[build]['raw_uj']) <= 0:
                raise ValueError('missing energy cannot be treated as 0')
            if len(d[build]['rapl_domains'].split('+')) != 2:
                raise ValueError('expected both package domains')
    print('Aion Argon2id persistent-worker energy screen (one SHARED node)')
    print('One experimental unit = 400 hashes, fixed t=3 m=65536KiB p=4.')
    print('Energy = TWO FULL CPU PACKAGE RAPL domains, not four-CPU task energy.')
    print('Idle-corrected values: estimates based on prior ~5-s idle sampling.')
    print('Negative corrected values are NOT forced to zero.')
    print()
    metrics = [
       ('ms/hash','ms_per_hash', 1.0),
       ('raw package J/1000 hashes','raw_uj',1/400.0/1000.0),
       ('idle-corrected package J/1000 hashes','corrected_uj',1/400.0/1000.0),
    ]
    for label,key,factor in metrics:
        a = [float(paired[i]['baseline'][key])*factor for i in range(6)]
        b = [float(paired[i]['pw'][key])*factor for i in range(6)]
        diffs = [y-x for x,y in zip(a,b)]
        mean,sd,ci = mean_ci(diffs)
        print(f'{label}:')
        print('  baseline means:', ', '.join(f'{x:.3f}' for x in a))
        print('  optimized means:', ', '.join(f'{x:.3f}' for x in b))
        print(f'  baseline={st.mean(a):.5f}, optimized={st.mean(b):.5f}')
        print(f'  paired optimized-minus-baseline={mean:+.5f} (SD={sd:.5f}), 95% CI [{ci[0]:+.5f}, {ci[1]:+.5f}]')
        if key == 'ms_per_hash':
            print(f'  time change = {100*mean/st.mean(a):+.2f}%')
        else:
            print('  Whole-package / shared-node RAPL; NOT causal energy attribution.')
            if key == 'corrected_uj':
                print(f'  conditional point-estimate saving = {-mean:+.5f} J/1000 hashes')
                print('  if uncertainty includes zero, NO demonstrated positive savings / finite payback.')
        print()
    print('Limitations: 6 pairs from ONE job; background load, CPU frequencies and')
    print('idle-power drift may violate independent-pair assumptions; no exclusive node.')
    print('An energy difference is credible only if reproducible and attributable.')

if __name__ == '__main__':
    main()
